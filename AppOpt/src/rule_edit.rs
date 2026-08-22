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

/// 强制合并子包的所有规则为一个统一的块
fn consolidate_sub_pkg(lines: &mut Vec<String>, pkg: &str, sub: &str) -> RuleEdit {
    let full_pkg = format!("{}:{}", pkg, sub);
    // 收集所有属于该子包的条目
    let mut pkg_rule_idx = None;
    let mut block_indices = Vec::new(); // (start, end)
    let mut thread_lines = Vec::new();

    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        // 包级规则（可能是 :子包=CPU 或 :子包=CPU {）
        if trimmed.starts_with(&format!(":{} =", sub)) || trimmed.starts_with(&format!(":{}=", sub)) {
            pkg_rule_idx = Some(i);
            // 如果该行以 '{' 结尾，说明是合并格式，后续行包含线程
            if trimmed.ends_with('{') {
                // 提取该行后的线程，直到遇到 '}'
                let start = i;
                let mut depth = 1;
                let mut end = start;
                for j in (i + 1)..lines.len() {
                    let next_trimmed = lines[j].trim();
                    if close_like(next_trimmed) {
                        depth -= 1;
                        if depth == 0 {
                            end = j;
                            break;
                        }
                    } else if next_trimmed.starts_with(':') && next_trimmed.ends_with('{') {
                        depth += 1;
                    }
                }
                if end > start {
                    // 收集线程行
                    for k in (start + 1)..end {
                        let line = lines[k].trim();
                        if !line.is_empty() && !close_like(line) && !line.starts_with(':') {
                            thread_lines.push(line.to_string());
                        }
                    }
                    block_indices.push((start, end));
                    i = end + 1;
                    continue;
                }
            }
            i += 1;
            continue;
        }
        // 子包块开始 :子包 {
        if trimmed == format!(":{} {{", sub) || trimmed == format!(":{}={{", sub) {
            let start = i;
            let mut depth = 1;
            let mut end = start;
            for j in (i + 1)..lines.len() {
                let next_trimmed = lines[j].trim();
                if close_like(next_trimmed) {
                    depth -= 1;
                    if depth == 0 {
                        end = j;
                        break;
                    }
                } else if next_trimmed.starts_with(':') && next_trimmed.ends_with('{') {
                    depth += 1;
                }
            }
            if end > start {
                for k in (start + 1)..end {
                    let line = lines[k].trim();
                    if !line.is_empty() && !line.starts_with(':') && !close_like(line) {
                        thread_lines.push(line.to_string());
                    }
                }
                block_indices.push((start, end));
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }

    // 必须有包级规则
    let pkg_idx = match pkg_rule_idx {
        Some(idx) => idx,
        None => return RuleEdit::NotFound,
    };

    // 提取 CPU 值（修复借用冲突：将结果转为 String）
    let pkg_line = &lines[pkg_idx];
    let cpus_val = if let Some(eq_pos) = pkg_line.rfind('=') {
        pkg_line[eq_pos + 1..].trim().trim_end_matches('{').trim().to_string()
    } else {
        return RuleEdit::Malformed;
    };

    // 去重线程规则（保留顺序）
    let mut threads: Vec<String> = Vec::new();
    for line in thread_lines {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('}') {
            if !threads.contains(&trimmed.to_string()) {
                threads.push(trimmed.to_string());
            }
        }
    }

    // 删除所有相关条目（包级规则和所有块）
    let mut remove_indices: Vec<usize> = Vec::new();
    remove_indices.push(pkg_idx);
    for (start, end) in &block_indices {
        for idx in *start..=*end {
            if idx != pkg_idx {
                remove_indices.push(idx);
            }
        }
    }
    remove_indices.sort_unstable();
    remove_indices.dedup();
    for idx in remove_indices.iter().rev() {
        lines.remove(*idx);
    }

    // 插入合并行（使用 cpus_val 字符串）
    let merged_line = format!(" :{}={} {{", sub, cpus_val);
    // 找到主包块的闭合括号位置
    let mut insert_pos = lines.len();
    for i in (0..lines.len()).rev() {
        if close_like(lines[i].trim()) {
            insert_pos = i;
            break;
        }
    }
    // 在闭合括号前插入
    lines.insert(insert_pos, merged_line);
    let mut offset = 1;
    for thread_line in threads {
        lines.insert(insert_pos + offset, format!("        {}", thread_line));
        offset += 1;
    }
    // 如果存在线程，添加闭合括号
    if offset > 1 {
        lines.insert(insert_pos + offset, "    }".to_string());
    }

    RuleEdit::Ok
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

    // ---- 确保主包是块 ----
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
            // 主包无规则，创建新块
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

    // ---- 处理独立行子包（如果存在） ----
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

    // ---- 处理子包 ----
    let sub_in_block = t.sub_pkgs.contains_key(sub);

    // === 删除逻辑 ===
    if is_delete {
        if sub_in_block {
            let sub_lines = lines.clone();
            let sub_target = target_scan(&sub_lines, &full_pkg);
            let mut removed = false;

            if thread.is_empty() {
                // 删除包级规则（:子包 = CPU 行）
                if let Some(close) = t.block_close {
                    let start = t.block_open.unwrap_or(0);
                    for i in (start..close).rev() {
                        let trimmed = lines[i].trim();
                        if trimmed.starts_with(&format!(":{} =", sub))
                            || trimmed.starts_with(&format!(":{}=", sub))
                        {
                            lines.remove(i);
                            removed = true;
                            break;
                        }
                    }
                }
                if !removed {
                    // 如果没找到包级规则，则删除整个子包块（如果存在）
                    if let Some(block_start) = sub_target.block_open {
                        let block_end = sub_target.block_close.unwrap_or(block_start);
                        for i in (block_start..=block_end).rev() {
                            lines.remove(i);
                        }
                        removed = true;
                    }
                }
            } else {
                // ==== 新的删除线程规则逻辑 ====
                // 直接在主包块内查找匹配行，并确保它属于该子包
                if let Some(close) = t.block_close {
                    let start = t.block_open.unwrap_or(0);
                    // 先找到子包包级规则或块所在的范围
                    let mut sub_start = None;
                    let mut sub_end = None;
                    for i in start..close {
                        let trimmed = lines[i].trim();
                        if trimmed.starts_with(&format!(":{} =", sub)) || trimmed.starts_with(&format!(":{}=", sub)) {
                            // 如果包级规则行以 '{' 结尾，则范围直到对应的 '}'
                            if trimmed.ends_with('{') {
                                let mut depth = 1;
                                for j in (i + 1)..close {
                                    let next_trimmed = lines[j].trim();
                                    if close_like(next_trimmed) {
                                        depth -= 1;
                                        if depth == 0 {
                                            sub_start = Some(i);
                                            sub_end = Some(j);
                                            break;
                                        }
                                    } else if next_trimmed.starts_with(':') && next_trimmed.ends_with('{') {
                                        depth += 1;
                                    }
                                }
                            } else {
                                // 独立包级规则，没有块，无法删除线程（因为没有线程）
                                return RuleEdit::NotFound;
                            }
                            break;
                        } else if trimmed == format!(":{} {{", sub) || trimmed == format!(":{}={{", sub) {
                            // 独立子包块
                            let mut depth = 1;
                            let mut end = i;
                            for j in (i + 1)..close {
                                let next_trimmed = lines[j].trim();
                                if close_like(next_trimmed) {
                                    depth -= 1;
                                    if depth == 0 {
                                        sub_start = Some(i);
                                        sub_end = Some(j);
                                        break;
                                    }
                                } else if next_trimmed.starts_with(':') && next_trimmed.ends_with('{') {
                                    depth += 1;
                                }
                            }
                            break;
                        }
                    }
                    if let (Some(start_idx), Some(end_idx)) = (sub_start, sub_end) {
                        // 在块内查找线程行
                        for i in (start_idx + 1)..end_idx {
                            let trimmed = lines[i].trim();
                            if trimmed.starts_with(&format!("{}=", thread)) && !trimmed.starts_with(':') {
                                lines.remove(i);
                                removed = true;
                                break;
                            }
                        }
                    }
                }
                if !removed {
                    return RuleEdit::NotFound;
                }
            }

            // 删除后，调用 consolidate 整理（可选，但为了安全，我们保留）
            // 这里不调用，因为合并逻辑由更新操作触发，删除时不合并
            return RuleEdit::Ok;
        } else {
            return RuleEdit::NotFound;
        }
    }

    // === 更新或插入 ===
    if sub_in_block {
        // 子包已存在
        let sub_lines = lines.clone();
        let sub_target = target_scan(&sub_lines, &full_pkg);

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
                // 没有包级规则行，插入新的
                if let Some(close) = t.block_close {
                    lines.insert(close, format!(" :{}={}", sub, cpus));
                } else if let Some(open) = t.block_open {
                    lines.insert(open + 1, format!(" :{}={}", sub, cpus));
                } else {
                    lines.push(format!(" :{}={}", sub, cpus));
                }
            }
        } else {
            // 线程规则：在子包块内查找并更新或插入
            // 首先找到子包块的范围（包括合并格式）
            let mut sub_block_start = sub_target.block_open;
            let mut sub_block_end = sub_target.block_close;
            // 如果子包没有块，但可能有合并格式的包级规则，我们需要查找范围
            if sub_block_start.is_none() || sub_block_end.is_none() {
                // 查找合并格式 :子包=CPU {
                if let Some(close) = t.block_close {
                    let start = t.block_open.unwrap_or(0);
                    for i in start..close {
                        let trimmed = lines[i].trim();
                        if trimmed.starts_with(&format!(":{} =", sub)) && trimmed.ends_with('{') {
                            let mut depth = 1;
                            let mut end = i;
                            for j in (i + 1)..close {
                                let next_trimmed = lines[j].trim();
                                if close_like(next_trimmed) {
                                    depth -= 1;
                                    if depth == 0 {
                                        sub_block_start = Some(i);
                                        sub_block_end = Some(j);
                                        break;
                                    }
                                } else if next_trimmed.starts_with(':') && next_trimmed.ends_with('{') {
                                    depth += 1;
                                }
                            }
                            break;
                        }
                    }
                }
            }

            if let (Some(start), Some(end)) = (sub_block_start, sub_block_end) {
                // 在块内查找现有线程
                let mut found = false;
                for i in (start + 1)..end {
                    let trimmed = lines[i].trim();
                    if trimmed.starts_with(&format!("{}=", thread)) && !trimmed.starts_with(':') {
                        // 更新
                        if let Some(comment_pos) = comment_at(&lines[i]) {
                            lines[i] = format!("        {}={}{}", thread, cpus, &lines[i][comment_pos..]);
                        } else {
                            lines[i] = format!("        {}={}", thread, cpus);
                        }
                        found = true;
                        break;
                    }
                }
                if !found {
                    // 在块结束前插入新线程
                    lines.insert(end, format!("        {}={}", thread, cpus));
                }
            } else {
                // 子包没有块，创建块（但前提是子包有包级规则）
                // 我们直接创建 :子包 { 线程 } 块，并将它插入到包级规则后
                let sub_block = format!("    :{} {{\n        {}={}\n    }}", sub, thread, cpus);
                // 查找包级规则行位置
                if let Some(pkg_line_idx) = sub_target.pkg_line {
                    // 获取索引
                    let pkg_idx = if let Some(PkgLine::Standalone(i)) = sub_target.pkg_line {
                        i
                    } else if let Some(PkgLine::OpenInline(i)) = sub_target.pkg_line {
                        i
                    } else {
                        // 找不到，使用块结束位置
                        if let Some(close) = t.block_close {
                            lines.insert(close, sub_block.clone());
                        } else {
                            lines.push(sub_block.clone());
                        }
                        // 调用 consolidate 整理
                        let _ = consolidate_sub_pkg(lines, pkg, sub);
                        return RuleEdit::Ok;
                    };
                    // 在包级规则行后面插入块
                    lines.insert(pkg_idx + 1, sub_block);
                } else {
                    // 没有包级规则，在块结束前插入
                    if let Some(close) = t.block_close {
                        lines.insert(close, sub_block);
                    } else {
                        lines.push(sub_block);
                    }
                }
            }
        }

        // 调用合并函数，整理所有子包规则
        let _ = consolidate_sub_pkg(lines, pkg, sub);
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

/// 辅助函数：查找所有以 :子包 { 开头的块的范围
fn find_all_sub_blocks(lines: &[String], sub: &str) -> Vec<(usize, usize)> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed == format!(":{} {{", sub) || trimmed == format!(":{}={{", sub) {
            let start = i;
            let mut depth = 1;
            let mut end = start;
            for j in (i + 1)..lines.len() {
                let next_trimmed = lines[j].trim();
                if close_like(next_trimmed) {
                    depth -= 1;
                    if depth == 0 {
                        end = j;
                        break;
                    }
                } else if next_trimmed.starts_with(':') && next_trimmed.ends_with('{') {
                    depth += 1;
                }
            }
            if end > start {
                blocks.push((start, end));
                i = end + 1;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    blocks
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