use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::sync::Mutex;

use crate::config::{
    OuterLine, close_like, comment_at, parse_outer, split_rule_line, split_single_line,
    strip_comment,
};

pub enum RuleEdit {
    Ok,
    NotFound,
    Conflict,
    Malformed,
    IoErr,
}

static WRITE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, PartialEq)]
enum PkgLine {
    Standalone(usize),
    OpenInline(usize),
    BareOpen(usize),
    BarePending(usize),
}

#[derive(Clone, Copy)]
struct ThreadLoc {
    idx: usize,
    single: bool,
    closed: bool,
    open: bool,
}

#[derive(Clone)]
struct Target {
    pkg_line: Option<PkgLine>,
    block_open: Option<usize>,
    block_close: Option<usize>,
    threads: HashMap<String, Vec<ThreadLoc>>,
    unterminated: bool,
    sub_pkgs: HashMap<String, Target>,
}

impl Target {
    fn new() -> Self {
        Self {
            pkg_line: None,
            block_open: None,
            block_close: None,
            threads: HashMap::new(),
            unterminated: false,
            sub_pkgs: HashMap::new(),
        }
    }

    fn singles(&self) -> impl Iterator<Item = &ThreadLoc> {
        self.threads.values().flatten().filter(|l| l.single)
    }

    fn any_line(&self) -> bool {
        self.pkg_line.is_some() || self.singles().next().is_some() || !self.sub_pkgs.is_empty()
    }
}

fn target_scan(lines: &[String], pkg: &str) -> Target {
    let mut t = Target::new();
    let mut pending: Option<usize> = None;
    let mut in_block = false;
    let mut target_block = false;

    let mut in_sub_block = false;
    let mut current_sub = String::new();
    let mut sub_lines: Vec<String> = Vec::new();

    let block_close = |t: &mut Target, target_block: &mut bool, i: usize| {
        if *target_block && t.block_close.is_none() {
            t.block_close = Some(i);
        }
        *target_block = false;
    };

    let block_open = |t: &mut Target, i: usize| {
        if t.block_close.is_none() {
            t.block_open = Some(i);
        }
    };

    for (i, raw) in lines.iter().enumerate() {
        let p = raw.trim();
        if p.is_empty() || p.starts_with('#') || p.starts_with("//") {
            if in_sub_block {
                sub_lines.push(raw.clone());
            }
            continue;
        }

        // ---- 子包块结束 ----
        if in_sub_block && close_like(p) {
            if !sub_lines.is_empty() {
                let sub_target = target_scan(&sub_lines, &current_sub);
                t.sub_pkgs.insert(current_sub.clone(), sub_target);
            }
            sub_lines.clear();
            in_sub_block = false;
            current_sub.clear();
            continue;
        }

        // ---- 子包块开始 :子包 { ----
        if !in_block && !in_sub_block {
            if let Some(rest) = p.strip_prefix(':') {
                if let Some(rest2) = rest.strip_suffix('{') {
                    let sub = rest2.trim();
                    if !sub.is_empty() {
                        in_sub_block = true;
                        current_sub = sub.to_string();
                        sub_lines.clear();
                        continue;
                    }
                }
            }
        }

        if in_sub_block {
            sub_lines.push(raw.clone());
            continue;
        }

        // ---- 主包块内 ----
        if in_block {
            if close_like(p) {
                in_block = false;
                block_close(&mut t, &mut target_block, i);
                continue;
            }

            let trimmed = p.trim();

            // ---- 识别块内的子包包级规则 :子包 = CPU ----
            if trimmed.starts_with(':') && trimmed.contains('=') {
                if let Some(eq_pos) = trimmed.rfind('=') {
                    let sub = trimmed[1..eq_pos].trim();
                    let cpus = trimmed[eq_pos + 1..].trim();
                    if !sub.is_empty() && !cpus.is_empty() {
                        // 记录子包存在
                        t.sub_pkgs
                            .entry(sub.to_string())
                            .or_insert_with(Target::new);
                        // 如果是 :子包=CPU {，则后面会进入子包块，但这里我们已经记录了子包
                        // 继续处理可能会跳过该行，但这里我们只是记录，不解析内容
                        continue;
                    }
                }
            }

            // ---- 处理块内的子包块开始 :子包 { ----
            // 只有在主包块内（非子包块内）才允许开启新的子包块
            if !in_sub_block && trimmed.starts_with(':') && trimmed.ends_with('{') {
                let sub = trimmed[1..trimmed.len() - 1].trim();
                if !sub.is_empty() {
                    let _sub_pkg = format!("{}:{}", pkg, sub);
                    // 并确保子包被记录
                    t.sub_pkgs
                        .entry(sub.to_string())
                        .or_insert_with(Target::new);
                    in_sub_block = true;
                    continue;
                }
            }

            // ---- 原有线程规则解析 ----
            match split_rule_line(p) {
                Some((name, _, closed)) => {
                    if target_block && !name.is_empty() {
                        t.threads
                            .entry(name.to_string())
                            .or_default()
                            .push(ThreadLoc {
                                idx: i,
                                single: false,
                                closed,
                                open: false,
                            });
                    }
                    if closed {
                        in_block = false;
                        block_close(&mut t, &mut target_block, i);
                    }
                }
                None => {
                    if p.contains('}') {
                        in_block = false;
                        block_close(&mut t, &mut target_block, i);
                    }
                }
            }
            continue;
        }

        // ---- 外层解析 ----
        match parse_outer(p) {
            OuterLine::Single {
                pkg: pg,
                thread: th,
                open,
                ..
            } => {
                pending = None;
                if pg == pkg && !th.is_empty() {
                    t.threads
                        .entry(th.to_string())
                        .or_default()
                        .push(ThreadLoc {
                            idx: i,
                            single: true,
                            closed: false,
                            open,
                        });
                }
                if open {
                    in_block = true;
                    if pg == pkg {
                        target_block = true;
                        block_open(&mut t, i);
                    }
                }
            }
            OuterLine::Rule { pkg: pg, open, .. } => {
                if open {
                    in_block = true;
                    pending = None;
                    if pg == pkg {
                        target_block = true;
                        block_open(&mut t, i);
                        if t.pkg_line.is_none() {
                            t.pkg_line = Some(PkgLine::OpenInline(i));
                        }
                    }
                } else {
                    pending = None;
                    if pg == pkg && t.pkg_line.is_none() {
                        t.pkg_line = Some(PkgLine::Standalone(i));
                    }
                }
            }
            OuterLine::BareOpen { pkg: owner } => {
                if !owner.is_empty() {
                    pending = None;
                    in_block = true;
                    if owner == pkg {
                        target_block = true;
                        block_open(&mut t, i);
                        if t.pkg_line.is_none() {
                            t.pkg_line = Some(PkgLine::BareOpen(i));
                        }
                    }
                } else if let Some(pi) = pending.take() {
                    in_block = true;
                    if let OuterLine::Pending { pkg: pp } = parse_outer(lines[pi].trim())
                        && pp == pkg
                    {
                        target_block = true;
                        block_open(&mut t, i);
                        if t.pkg_line.is_none() {
                            t.pkg_line = Some(PkgLine::BarePending(pi));
                        }
                    }
                }
            }
            OuterLine::Pending { .. } => {
                pending = Some(i);
            }
            OuterLine::Junk => {
                pending = None;
            }
            OuterLine::SubPkgRule { sub, .. } => {
                // 记录子包存在
                t.sub_pkgs
                    .entry(sub.to_string())
                    .or_insert_with(Target::new);
                let _sub_pkg = format!("{}:{}", pkg, sub);
            }
            OuterLine::SubPkgBlock { sub: _ } => {}
        }
    }

    if in_sub_block {
        t.unterminated = true;
    }
    t
}

fn normalize_singles(lines: &mut Vec<String>, pkg: &str) {
    let t = target_scan(lines, pkg);
    let mut items: Vec<(ThreadLoc, String)> = Vec::new();
    for loc in t.singles() {
        let raw_line = lines[loc.idx].trim();
        let raw = strip_comment(raw_line);
        let body = raw.strip_suffix('{').map(str::trim_end).unwrap_or(raw);
        if let Some((_, th, cp)) = split_single_line(body) {
            let line = with_comment(&format!("\t{}={}", th, cp), raw_line);
            items.push((*loc, line));
        }
    }
    if items.is_empty() {
        return;
    }
    items.sort_unstable_by_key(|(l, _)| l.idx);
    if t.block_close.is_none()
        && (items.iter().any(|(l, _)| l.open)
            || !matches!(t.pkg_line, None | Some(PkgLine::Standalone(_))))
    {
        return;
    }

    let at = items[0].0.idx;
    for (loc, _) in items.iter().rev() {
        line_remove(lines, pkg, loc);
    }
    let items: Vec<String> = items.into_iter().map(|(_, line)| line).collect();

    let t2 = target_scan(lines, pkg);
    if let Some(close) = t2.block_close {
        for (off, line) in items.into_iter().enumerate() {
            lines.insert(close + off, line);
        }
    } else if let Some(PkgLine::Standalone(i)) = t2.pkg_line {
        lines[i] = format!("{} {{", lines[i].trim_end());
        let chunk: Vec<String> = items
            .into_iter()
            .chain(std::iter::once("}".to_string()))
            .collect();
        lines.splice(i + 1..i + 1, chunk);
    } else {
        let chunk: Vec<String> = std::iter::once(bare_open_line(pkg))
            .chain(items)
            .chain(std::iter::once("}".to_string()))
            .collect();
        let at = at.min(lines.len());
        lines.splice(at..at, chunk);
    }
}

fn normalize_sub_pkgs(lines: &mut Vec<String>, pkg: &str) {
    let t = target_scan(lines, pkg);
    for (sub, _) in &t.sub_pkgs {
        let sub_pkg = format!("{}:{}", pkg, sub);
        normalize_singles(lines, &sub_pkg);
        normalize_sub_pkgs(lines, &sub_pkg);
    }
    normalize_singles(lines, pkg);
}

fn bare_open_line(pkg: &str) -> String {
    if pkg.contains('=') {
        format!("{}= {{", pkg)
    } else {
        format!("{} {{", pkg)
    }
}

fn with_comment(new_line: &str, old: &str) -> String {
    match comment_at(old) {
        Some(at) => format!("{}{}", new_line, &old[at..]),
        None => new_line.to_string(),
    }
}

fn spec_swap(raw: &str, cpus: &str) -> String {
    let cut = comment_at(raw).unwrap_or(raw.len());
    let Some(eq) = raw[..cut].rfind('=') else {
        return raw.into();
    };
    let rhs = &raw[eq + 1..cut];
    let val = rhs.trim_start();
    let lead = rhs.len() - val.len();
    let v_end = val
        .find(|c: char| c.is_whitespace() || c == '{' || c == '}')
        .unwrap_or(val.len());
    let tail: String = val[v_end..]
        .chars()
        .filter(|c| c.is_whitespace() || *c == '{' || *c == '}')
        .collect();
    format!("{}{}{}{}", &raw[..eq + 1 + lead], cpus, tail, &raw[cut..])
}

fn line_remove(lines: &mut Vec<String>, pkg: &str, loc: &ThreadLoc) {
    if loc.open {
        lines[loc.idx] = with_comment(&bare_open_line(pkg), &lines[loc.idx]);
    } else if loc.closed {
        lines[loc.idx] = with_comment("}", &lines[loc.idx]);
    } else {
        lines.remove(loc.idx);
    }
}

fn file_write(path: &str, lines: &[String]) -> RuleEdit {
    let mut out = lines.join("\n");
    out.push('\n');
    let tmp = format!("{}.tmp", path);
    let res = fs::File::create(&tmp)
        .and_then(|mut f| {
            f.write_all(out.as_bytes())?;
            f.sync_all()
        })
        .and_then(|_| fs::rename(&tmp, path));
    if res.is_ok() {
        RuleEdit::Ok
    } else {
        RuleEdit::IoErr
    }
}

fn collect_all_lines(lines: &[String], pkg: &str) -> Vec<usize> {
    let t = target_scan(lines, pkg);
    let mut idxs: Vec<usize> = Vec::new();

    if let Some(
        PkgLine::Standalone(i)
        | PkgLine::OpenInline(i)
        | PkgLine::BareOpen(i)
        | PkgLine::BarePending(i),
    ) = t.pkg_line
    {
        idxs.push(i);
    }
    if let Some(open) = t.block_open {
        let end = t
            .block_close
            .or_else(|| {
                t.threads
                    .values()
                    .flatten()
                    .filter(|l| !l.single)
                    .map(|l| l.idx)
                    .max()
            })
            .unwrap_or(open);
        idxs.extend(open..=end);
    }
    idxs.extend(t.singles().map(|l| l.idx));

    for (sub, _) in &t.sub_pkgs {
        let sub_pkg = format!("{}:{}", pkg, sub);
        idxs.extend(collect_all_lines(lines, &sub_pkg));
    }

    idxs.sort_unstable();
    idxs.dedup();
    idxs
}

/// 以子包块格式写入或删除规则（自动合并包级和线程规则）
fn write_sub_pkg_block(
    lines: &mut Vec<String>,
    pkg: &str,
    sub: &str,
    thread: &str,
    cpus: &str,
    is_delete: bool,
) -> RuleEdit {
    let full_pkg = format!("{}:{}", pkg, sub);
    let mut t = target_scan(lines, pkg);

    // ---- 第一步：确保主包是块 ----
    if t.block_open.is_none() {
        if let Some(PkgLine::Standalone(idx)) = t.pkg_line {
            let line = &lines[idx];
            let trimmed = line.trim();
            if !trimmed.ends_with('{') {
                let comment = match comment_at(line) {
                    Some(pos) => &line[pos..],
                    None => "",
                };
                let base = if trimmed.contains('=') {
                    trimmed.trim_end_matches('{').trim_end().to_string()
                } else {
                    format!("{} =", trimmed)
                };
                let new_line = if comment.is_empty() {
                    format!("{} {{", base)
                } else {
                    format!("{} {{{}", base, comment)
                };
                lines[idx] = new_line;
                let last = lines.last().map(|s| s.trim()).unwrap_or("");
                if !close_like(last) {
                    lines.push("}".to_string());
                }
                t = target_scan(lines, pkg);
            }
        } else {
            // 主包无任何规则，创建新块
            let sub_line = if thread.is_empty() {
                format!(" :{}={}", sub, cpus)
            } else {
                format!("    :{} {{\n        {}={}\n    }}", sub, thread, cpus)
            };
            let block = format!("{} {{\n{}\n}}", pkg, sub_line);
            lines.push(block);
            return RuleEdit::Ok;
        }
    }

    // ---- 第二步：处理独立行子包 ----
    let mut standalone_idx = None;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with(&format!("{}=", full_pkg))
            || trimmed.starts_with(&format!("{} =", full_pkg))
        {
            standalone_idx = Some(i);
            break;
        }
    }
    if let Some(idx) = standalone_idx {
        lines.remove(idx);
        t = target_scan(lines, pkg);
    }

    // ---- 第三步：处理子包 ----
    let sub_in_block = t.sub_pkgs.contains_key(sub);

    if is_delete {
        if sub_in_block {
            let mut removed = false;
            // 删除 :子包 = CPU 行
            if let Some(close) = t.block_close {
                let start = t.block_open.unwrap_or(0);
                for i in (start..close).rev() {
                    let trimmed = lines[i].trim();
                    if trimmed.starts_with(&format!(":{} =", sub))
                        || trimmed.starts_with(&format!(":{}=", sub))
                    {
                        lines.remove(i);
                        removed = true;
                    }
                }
            }
            // 删除 :子包 { ... } 块
            let sub_lines = lines.clone();
            let sub_target = target_scan(&sub_lines, &full_pkg);
            if let Some(block_start) = sub_target.block_open {
                let block_end = sub_target.block_close.unwrap_or(block_start);
                for i in (block_start..=block_end).rev() {
                    lines.remove(i);
                }
                removed = true;
            }
            if !removed {
                return RuleEdit::NotFound;
            }
        } else {
            return RuleEdit::NotFound;
        }
        return RuleEdit::Ok;
    }

    // ---- 更新或插入 ----
    if sub_in_block {
        let sub_lines = lines.clone();
        let sub_target = target_scan(&sub_lines, &full_pkg);

        // 先处理本次更新
        if thread.is_empty() {
            // 更新包级规则
            let mut found_line = false;
            if let Some(close) = t.block_close {
                let start = t.block_open.unwrap_or(0);
                for i in start..close {
                    let trimmed = lines[i].trim();
                    if trimmed.starts_with(&format!(":{} =", sub))
                        || trimmed.starts_with(&format!(":{}=", sub))
                    {
                        let line = &lines[i];
                        if let Some(comment_pos) = comment_at(line) {
                            lines[i] = format!(" :{}={}{}", sub, cpus, &line[comment_pos..]);
                        } else {
                            lines[i] = format!(" :{}={}", sub, cpus);
                        }
                        found_line = true;
                        break;
                    }
                }
            }
            if !found_line {
                if let Some(close) = t.block_close {
                    lines.insert(close, format!(" :{}={}", sub, cpus));
                } else if let Some(open) = t.block_open {
                    lines.insert(open + 1, format!(" :{}={}", sub, cpus));
                } else {
                    lines.push(format!(" :{}={}", sub, cpus));
                }
            }
        } else {
            // 更新线程规则
            let mut found = false;
            if let Some(block_start) = sub_target.block_open {
                let block_end = sub_target.block_close.unwrap_or(block_start);
                for i in block_start..block_end {
                    let trimmed = lines[i].trim();
                    if trimmed.starts_with(&format!("{}=", thread)) && !trimmed.starts_with(':') {
                        if let Some(comment_pos) = comment_at(&lines[i]) {
                            lines[i] =
                                format!("        {}={}{}", thread, cpus, &lines[i][comment_pos..]);
                        } else {
                            lines[i] = format!("        {}={}", thread, cpus);
                        }
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                if let Some(block_end) = sub_target.block_close {
                    lines.insert(block_end, format!("        {}={}", thread, cpus));
                } else if let Some(block_start) = sub_target.block_open {
                    lines.insert(block_start + 1, format!("        {}={}", thread, cpus));
                } else {
                    // 没有块，创建子包块
                    let sub_block = format!("    :{} {{\n        {}={}\n    }}", sub, thread, cpus);
                    if let Some(close) = t.block_close {
                        lines.insert(close, sub_block);
                    } else if let Some(open) = t.block_open {
                        lines.insert(open + 1, sub_block);
                    } else {
                        lines.push(sub_block);
                    }
                }
            }
        }

        // ===== 合并逻辑：如果同时有包级规则和线程规则，合并为一行 =====
        // 重新扫描以获取最新状态
        let t2 = target_scan(lines, pkg);
        let sub_in_block2 = t2.sub_pkgs.contains_key(sub);
        if sub_in_block2 {
            let sub_lines2 = lines.clone();
            let sub_target2 = target_scan(&sub_lines2, &full_pkg);
            let has_pkg2 = sub_target2.pkg_line.is_some();
            let has_thread2 = !sub_target2.threads.is_empty() || sub_target2.block_open.is_some();

            if has_pkg2 && has_thread2 {
                // 找到独立的 :子包 = CPU 行
                let mut pkg_line_idx = None;
                if let Some(close) = t2.block_close {
                    let start = t2.block_open.unwrap_or(0);
                    for i in start..close {
                        let trimmed = lines[i].trim();
                        if trimmed.starts_with(&format!(":{} =", sub))
                            || trimmed.starts_with(&format!(":{}=", sub))
                        {
                            pkg_line_idx = Some(i);
                            break;
                        }
                    }
                }
                // 找到子包块的位置
                let sub_block_start = sub_target2.block_open;
                let sub_block_end = sub_target2.block_close;

                if let (Some(idx), Some(start), Some(end)) =
                    (pkg_line_idx, sub_block_start, sub_block_end)
                {
                    // 提取块内的线程规则（去掉缩进）
                    let mut thread_lines: Vec<String> = Vec::new();
                    for i in (start + 1)..end {
                        let line = lines[i].trim().to_string();
                        if !line.is_empty() && !line.starts_with(':') && !line.starts_with('}') {
                            thread_lines.push(line);
                        }
                    }
                    // 如果线程规则为空，则不合并，保留原样
                    if !thread_lines.is_empty() {
                        // 构建合并行
                        let pkg_line = &lines[idx];
                        let cpus_val = if let Some(eq_pos) = pkg_line.rfind('=') {
                            pkg_line[eq_pos + 1..].trim()
                        } else {
                            ""
                        };
                        let merged_line = format!(" :{}={} {{", sub, cpus_val);

                        // 替换包级规则行为合并行
                        lines[idx] = merged_line;

                        // 删除子包块的所有行（包括开始和结束）
                        let mut remove_indices: Vec<usize> = (start..=end).collect();
                        // 如果 idx 在移除范围内，需要保留 idx（它已经被替换）
                        remove_indices.retain(|&i| i != idx);
                        // 从大到小删除
                        for i in remove_indices.iter().rev() {
                            lines.remove(*i);
                        }

                        // 插入线程规则（在 idx 后面）
                        let insert_pos = idx + 1;
                        for (offset, thread_line) in thread_lines.iter().enumerate() {
                            // 线程规则缩进对齐（使用 4 个空格）
                            lines.insert(insert_pos + offset, format!("        {}", thread_line));
                        }
                        // 插入闭合括号
                        lines.insert(insert_pos + thread_lines.len(), "    }".to_string());
                    }
                }
            }
        }

        RuleEdit::Ok
    } else {
        // 子包不存在，首次添加
        if let Some(close) = t.block_close {
            let sub_block = if thread.is_empty() {
                format!(" :{}={}", sub, cpus)
            } else {
                format!("    :{} {{\n        {}={}\n    }}", sub, thread, cpus)
            };
            lines.insert(close, sub_block);
        } else if let Some(open) = t.block_open {
            let sub_block = if thread.is_empty() {
                format!(" :{}={}", sub, cpus)
            } else {
                format!("    :{} {{\n        {}={}\n    }}", sub, thread, cpus)
            };
            lines.insert(open + 1, sub_block);
        } else {
            return RuleEdit::IoErr;
        }
        RuleEdit::Ok
    }
}

/// 辅助函数：合并子包的包级规则和线程规则到一行
fn merge_sub_pkg_rules(lines: &mut Vec<String>, pkg: &str, sub: &str, t: &Target) {
    let full_pkg = format!("{}:{}", pkg, sub);
    let sub_lines = lines.clone();
    let sub_target = target_scan(&sub_lines, &full_pkg);
    let has_pkg_rule = sub_target.pkg_line.is_some();
    let has_thread_rules = sub_target
        .threads
        .iter()
        .any(|(name, _)| !name.starts_with(':'));

    if !has_pkg_rule || !has_thread_rules {
        return;
    }

    // 查找包级规则行
    let mut pkg_line_idx = None;
    if let Some(close) = t.block_close {
        let start = t.block_open.unwrap_or(0);
        for i in start..close {
            let trimmed = lines[i].trim();
            if trimmed.starts_with(&format!(":{} =", sub))
                || trimmed.starts_with(&format!(":{}=", sub))
            {
                pkg_line_idx = Some(i);
                break;
            }
        }
    }
    let Some(idx) = pkg_line_idx else { return };

    // 查找子包块内容
    let sub_block_start = sub_target.block_open;
    let sub_block_end = sub_target.block_close;
    if let (Some(start), Some(end)) = (sub_block_start, sub_block_end) {
        let pkg_line = &lines[idx];
        // 提取 CPU 值
        let cpus_val = if let Some(eq_pos) = pkg_line.rfind('=') {
            pkg_line[eq_pos + 1..].trim()
        } else {
            return;
        };
        // 提取块内的线程规则（去除缩进）
        let mut thread_lines: Vec<String> = Vec::new();
        for i in (start + 1)..end {
            let trimmed = lines[i].trim();
            if !trimmed.is_empty() && !trimmed.starts_with(':') && !close_like(trimmed) {
                thread_lines.push(trimmed.to_string());
            }
        }
        if thread_lines.is_empty() {
            return;
        }
        // 构建合并行： :子包=CPU {
        let merged_line = format!(" :{}={} {{", sub, cpus_val);
        lines[idx] = merged_line;
        // 删除子包块开始和结束行
        let mut remove_indices: Vec<usize> = Vec::new();
        for i in (start..=end).rev() {
            if i != idx {
                remove_indices.push(i);
            }
        }
        for i in remove_indices {
            lines.remove(i);
        }
        // 将线程规则插入到合并行后面
        let insert_pos = idx + 1;
        for (offset, thread_line) in thread_lines.iter().enumerate() {
            lines.insert(insert_pos + offset, format!("        {}", thread_line));
        }
        // 确保有闭合
        let last_line = lines.last().map(|s| s.trim()).unwrap_or("");
        if !close_like(last_line) {
            lines.insert(insert_pos + thread_lines.len(), "    }".to_string());
        }
    }
}

pub fn rule_upsert(path: &str, pkg: &str, thread: &str, cpus: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    // 处理子包：如果 pkg 包含 ':' 且恰好两部分，则使用子包写入逻辑
    let parts: Vec<&str> = pkg.split(':').collect();
    if parts.len() == 2 {
        let main_pkg = parts[0];
        let sub = parts[1];
        let result = write_sub_pkg_block(&mut lines, main_pkg, sub, thread, cpus, false);
        // 直接返回，不进行常规回退
        return match result {
            RuleEdit::Ok => file_write(path, &lines),
            _ => result,
        };
    }

    // ---- 常规方式（原有逻辑） ----
    normalize_sub_pkgs(&mut lines, pkg);
    let t = target_scan(&lines, pkg);

    if thread.is_empty() {
        match t.pkg_line {
            Some(PkgLine::Standalone(i)) => {
                lines[i] = spec_swap(&lines[i], cpus);
            }
            Some(PkgLine::BarePending(i)) => {
                lines[i] = with_comment(&format!("{}={} {{", pkg, cpus), &lines[i]);
                if let Some(open) = t.block_open
                    && matches!(
                        parse_outer(lines[open].trim()),
                        OuterLine::BareOpen { pkg: "" }
                    )
                {
                    lines.remove(open);
                }
            }
            Some(PkgLine::OpenInline(i)) => {
                lines[i] = spec_swap(&lines[i], cpus);
            }
            Some(PkgLine::BareOpen(i)) => {
                lines[i] = with_comment(&format!("{}={} {{", pkg, cpus), &lines[i]);
            }
            None if t.unterminated => return RuleEdit::Malformed,
            None => lines.push(format!("{}={}", pkg, cpus)),
        }
    } else if let Some(locs) = t.threads.get(thread) {
        let last = locs.last().copied().unwrap();
        lines[last.idx] = spec_swap(&lines[last.idx], cpus);
        for loc in locs[..locs.len() - 1].iter().rev() {
            line_remove(&mut lines, pkg, loc);
        }
    } else if let Some(close) = t.block_close {
        lines.insert(close, format!("\t{}={}", thread, cpus));
    } else if let Some(PkgLine::Standalone(i)) = t.pkg_line {
        lines[i] = format!("{} {{", lines[i].trim_end());
        lines.splice(
            i + 1..i + 1,
            [format!("\t{}={}", thread, cpus), "}".to_string()],
        );
    } else if t.unterminated {
        return RuleEdit::Malformed;
    } else {
        lines.push(bare_open_line(pkg));
        lines.push(format!("\t{}={}", thread, cpus));
        lines.push("}".to_string());
    }

    file_write(path, &lines)
}

pub fn rule_delete(path: &str, pkg: &str, thread: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    // 处理子包
    let parts: Vec<&str> = pkg.split(':').collect();
    if parts.len() == 2 {
        let main_pkg = parts[0];
        let sub = parts[1];
        let result = write_sub_pkg_block(&mut lines, main_pkg, sub, thread, "", true);
        // 直接返回结果，不进行回退
        return match result {
            RuleEdit::Ok => file_write(path, &lines),
            _ => result,
        };
    }

    // ---- 常规方式（原有逻辑） ----
    normalize_sub_pkgs(&mut lines, pkg);
    let t = target_scan(&lines, pkg);

    if thread.is_empty() {
        match t.pkg_line {
            Some(PkgLine::Standalone(i)) => {
                lines.remove(i);
            }
            Some(PkgLine::OpenInline(i)) => {
                lines[i] = bare_open_line(pkg);
            }
            _ => return RuleEdit::NotFound,
        }
    } else if let Some(locs) = t.threads.get(thread) {
        for loc in locs.iter().rev() {
            line_remove(&mut lines, pkg, loc);
        }
    } else {
        return RuleEdit::NotFound;
    }

    file_write(path, &lines)
}
pub fn rule_delete_pkg(path: &str, pkg: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    // 检查是否是子包
    let parts: Vec<&str> = pkg.split(':').collect();
    if parts.len() == 2 {
        let main_pkg = parts[0];
        let sub = parts[1];
        // 删除子包的所有规则
        let result = write_sub_pkg_block(&mut lines, main_pkg, sub, "", "", true);
        if let RuleEdit::Ok = result {
            return file_write(path, &lines);
        }
    }

    normalize_sub_pkgs(&mut lines, pkg);
    let idxs = collect_all_lines(&lines, pkg);
    if idxs.is_empty() {
        return RuleEdit::NotFound;
    }
    for i in idxs.into_iter().rev() {
        lines.remove(i);
    }
    file_write(path, &lines)
}
pub fn rule_rename(path: &str, old: &str, new: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    normalize_sub_pkgs(&mut lines, old);
    if !target_scan(&lines, old).any_line() {
        return RuleEdit::NotFound;
    }
    if target_scan(&lines, new).any_line() {
        return RuleEdit::Conflict;
    }

    let old_parts: Vec<&str> = old.split(':').collect();
    let new_parts: Vec<&str> = new.split(':').collect();
    if old_parts.len() == 2 && new_parts.len() == 2 {
        let old_main = old_parts[0];
        let old_sub = old_parts[1];
        let new_main = new_parts[0];
        let new_sub = new_parts[1];
        if old_main == new_main {
            for line in &mut lines {
                if let Some(rest) = line.trim().strip_prefix(&format!(":{}", old_sub)) {
                    if rest.trim().starts_with('{') || rest.trim().starts_with('=') {
                        let new_line =
                            line.replace(&format!(":{}", old_sub), &format!(":{}", new_sub));
                        *line = new_line;
                    }
                }
            }
            return file_write(path, &lines);
        }
    }

    loop {
        let t = target_scan(&lines, old);
        let mut idxs: Vec<usize> = t.singles().map(|l| l.idx).collect();
        if let Some(
            PkgLine::Standalone(i)
            | PkgLine::OpenInline(i)
            | PkgLine::BareOpen(i)
            | PkgLine::BarePending(i),
        ) = t.pkg_line
        {
            idxs.push(i);
        }
        if idxs.is_empty() {
            break;
        }
        for i in idxs {
            if let Some(rest) = lines[i].trim().strip_prefix(old) {
                let tail = match (new.contains('='), rest.trim()) {
                    (true, "" | "=") => "=",
                    (true, "{") => "= {",
                    _ => rest,
                };
                lines[i] = format!("{}{}", new, tail);
            }
        }
    }
    file_write(path, &lines)
}
