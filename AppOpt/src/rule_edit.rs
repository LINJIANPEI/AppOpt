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

/// 存储一个包（或子包）的合并结果
#[derive(Default, Clone)]
struct PackageData {
    cpus: Vec<String>,                      // 包级 CPU 列表（未去重）
    threads: HashMap<String, String>,       // 线程名 -> CPU 列表（未去重）
    sub_pkgs: HashMap<String, PackageData>, // 子包名 -> 子包数据
}

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

/// 清理连续空行（只保留一个空行）
fn clean_empty_lines(lines: &mut Vec<String>) {
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim().is_empty() {
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim().is_empty() {
                j += 1;
            }
            if j > i + 1 {
                lines.drain(i + 1..j);
            }
            i += 1;
        } else {
            i += 1;
        }
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
                        t.sub_pkgs
                            .entry(sub.to_string())
                            .or_insert_with(Target::new);
                        continue;
                    }
                }
            }

            // ---- 处理块内的子包块开始 :子包 { ----
            if !in_sub_block && trimmed.starts_with(':') && trimmed.ends_with('{') {
                let sub = trimmed[1..trimmed.len() - 1].trim();
                if !sub.is_empty() {
                    let _sub_pkg = format!("{}:{}", pkg, sub);
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
                    // 增加边界检查
                    if pi < lines.len() {
                        if let OuterLine::Pending { pkg: pp } = parse_outer(lines[pi].trim()) {
                            if pp == pkg {
                                target_block = true;
                                block_open(&mut t, i);
                                if t.pkg_line.is_none() {
                                    t.pkg_line = Some(PkgLine::BarePending(pi));
                                }
                            }
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
    let sub_keys: Vec<String> = t
        .sub_pkgs
        .iter()
        .filter_map(|(k, _)| {
            let k = k.trim();
            if k.is_empty() {
                None
            } else {
                Some(k.to_string())
            }
        })
        .collect();
    for sub in sub_keys {
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

fn consolidate_sub_pkg(lines: &mut Vec<String>, pkg: &str, sub: &str) -> RuleEdit {
    // 重新扫描主包块闭合索引
    let t = target_scan(lines, pkg);
    let block_close = match t.block_close {
        Some(c) => c,
        None => return RuleEdit::NotFound,
    };

    // 收集所有属于该子包的条目
    let mut pkg_rule_idx = None;
    let mut block_indices = Vec::new();
    let mut thread_lines = Vec::new();

    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.starts_with(&format!(":{} =", sub)) || trimmed.starts_with(&format!(":{}=", sub))
        {
            pkg_rule_idx = Some(i);
            if trimmed.ends_with('{') {
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

    let pkg_idx = match pkg_rule_idx {
        Some(idx) => idx,
        None => return RuleEdit::NotFound,
    };

    let pkg_line = &lines[pkg_idx];
    let cpus_val = if let Some(eq_pos) = pkg_line.rfind('=') {
        pkg_line[eq_pos + 1..]
            .trim()
            .trim_end_matches('{')
            .trim()
            .to_string()
    } else {
        return RuleEdit::Malformed;
    };

    let mut threads: Vec<String> = Vec::new();
    for line in thread_lines {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('}') {
            if !threads.contains(&trimmed.to_string()) {
                threads.push(trimmed.to_string());
            }
        }
    }

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

    let merged_line = format!(" :{}={} {{", sub, cpus_val);
    lines.insert(block_close, merged_line);
    let mut offset = 1;
    for thread_line in threads {
        lines.insert(block_close + offset, format!("        {}", thread_line));
        offset += 1;
    }
    if offset > 1 {
        lines.insert(block_close + offset, "    }".to_string());
    }

    RuleEdit::Ok
}

/// 查找所有以 `:子包 {` 开头的独立块的范围
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

fn write_sub_pkg_block(
    lines: &mut Vec<String>,
    pkg: &str,
    sub: &str,
    thread: &str,
    cpus: &str,
    delete_all: bool,
) -> RuleEdit {
    // 辅助：从行中提取线程名（等号左侧去除空格）
    fn extract_thread_name(line: &str) -> Option<String> {
        let trimmed = line.trim();
        trimmed.find('=').and_then(|eq_pos| {
            let name = trimmed[..eq_pos].trim();
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        })
    }

    // 辅助：判断一行是否为子包块开始（包括合并格式和独立块）
    fn is_sub_block_start(line: &str, sub: &str) -> bool {
        let trimmed = line.trim();
        // 匹配 :sub 开头，且以 { 结尾（中间可能有 = 和 CPU 列表）
        trimmed.starts_with(&format!(":{}", sub)) && trimmed.ends_with('{')
    }

    // 辅助：在指定范围内查找子包块的范围（开始行索引，结束行索引）
    // 如果找不到返回 None
    fn find_sub_block_range(
        lines: &[String],
        start: usize,
        end: usize,
        sub: &str,
    ) -> Option<(usize, usize)> {
        for i in start..end {
            let trimmed = lines[i].trim();
            if is_sub_block_start(trimmed, sub) {
                // 找到块开始，寻找匹配的闭合 '}'
                let mut depth = 1;
                for j in (i + 1)..lines.len() {
                    let next_trimmed = lines[j].trim();
                    if close_like(next_trimmed) {
                        depth -= 1;
                        if depth == 0 {
                            return Some((i, j));
                        }
                    } else if is_sub_block_start(next_trimmed, sub) {
                        depth += 1;
                    }
                }
                // 如果未找到闭合，返回 None
                return None;
            }
        }
        None
    }

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
                format!("    :{}={}", sub, cpus)
            } else {
                format!("    :{} {{\n        {}={}\n    }}", sub, thread, cpus)
            };
            let block = format!("{} {{\n{}\n}}", pkg, sub_line);
            lines.push(block);
            return RuleEdit::Ok;
        }
    }

    // 再次确保主包有闭合括号
    let t2 = target_scan(lines, pkg);
    if t2.block_close.is_none() {
        lines.push("}".to_string());
        t = target_scan(lines, pkg);
    } else {
        t = t2;
    }

    // 确保 block_open 和 block_close 都存在
    let (block_open, block_close) = match (t.block_open, t.block_close) {
        (Some(open), Some(close)) => (open, close),
        _ => return RuleEdit::Malformed,
    };

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
        let (open, close) = match (t.block_open, t.block_close) {
            (Some(o), Some(c)) => (o, c),
            _ => return RuleEdit::Malformed,
        };
        // 更新 block_close（不再直接使用，但保持一致性）
        let block_close = close;
    }

    // === 删除整个子包（delete_all = true） ===
    if delete_all {
        let mut remove_indices = Vec::new();
        // 1. 删除包级规则行（:sub=CPU 或 :sub = CPU）及其合并块
        if let Some(close) = t.block_close {
            let start = t.block_open.unwrap_or(0);
            for i in start..close {
                let trimmed = lines[i].trim();
                if trimmed.starts_with(&format!(":{} =", sub))
                    || trimmed.starts_with(&format!(":{}=", sub))
                {
                    remove_indices.push(i);
                    if trimmed.ends_with('{') {
                        if let Some((start_idx, end_idx)) =
                            find_sub_block_range(lines, i, lines.len(), sub)
                        {
                            for k in start_idx..=end_idx {
                                remove_indices.push(k);
                            }
                        }
                    }
                }
            }
        }
        // 2. 删除所有独立子包块（:sub { ... }）
        let blocks = find_all_sub_blocks(lines, sub);
        for (start, end) in blocks {
            for i in start..=end {
                remove_indices.push(i);
            }
        }
        if remove_indices.is_empty() {
            return RuleEdit::NotFound;
        }
        remove_indices.sort_unstable();
        remove_indices.dedup();
        for idx in remove_indices.iter().rev() {
            lines.remove(*idx);
        }
        return RuleEdit::Ok;
    }

    // === 非删除整个子包 ===
    if thread.is_empty() {
        // ---- 包级规则操作 ----
        if !cpus.is_empty() {
            // 更新或插入包级规则
            // 1. 收集所有与该子包相关的行（包级规则行、独立块、合并块）
            let mut remove_indices = Vec::new();
            let mut thread_lines = Vec::new();

            if let Some(close) = t.block_close {
                let start = t.block_open.unwrap_or(0);
                // 先找包级规则行（包括合并格式）
                for i in start..close {
                    let trimmed = lines[i].trim();
                    if trimmed.starts_with(&format!(":{} =", sub))
                        || trimmed.starts_with(&format!(":{}=", sub))
                    {
                        remove_indices.push(i);
                        // 如果是合并格式，收集其中的线程
                        if trimmed.ends_with('{') {
                            if let Some((start_idx, end_idx)) =
                                find_sub_block_range(lines, i, lines.len(), sub)
                            {
                                for k in (start_idx + 1)..end_idx {
                                    let line_content = lines[k].trim();
                                    if !line_content.is_empty()
                                        && !line_content.starts_with(':')
                                        && !close_like(line_content)
                                    {
                                        thread_lines.push(lines[k].clone());
                                    }
                                }
                                for k in start_idx..=end_idx {
                                    remove_indices.push(k);
                                }
                            }
                        }
                    }
                }

                // 再找独立块 :sub { ... }
                let blocks = find_all_sub_blocks(lines, sub);
                for (start_idx, end_idx) in blocks {
                    for i in start_idx..=end_idx {
                        remove_indices.push(i);
                    }
                    for k in (start_idx + 1)..end_idx {
                        let line_content = lines[k].trim();
                        if !line_content.is_empty()
                            && !line_content.starts_with(':')
                            && !close_like(line_content)
                        {
                            thread_lines.push(lines[k].clone());
                        }
                    }
                }
            }

            remove_indices.sort_unstable();
            remove_indices.dedup();
            for idx in remove_indices.iter().rev() {
                lines.remove(*idx);
            }

            let t_after = target_scan(lines, pkg);
            let block_close_after = match t_after.block_close {
                Some(c) => c,
                None => return RuleEdit::Malformed,
            };

            if thread_lines.is_empty() {
                lines.insert(block_close_after, format!("    :{}={}", sub, cpus));
            } else {
                let mut insert_lines = Vec::new();
                insert_lines.push(format!("    :{}={} {{", sub, cpus));
                for tl in &thread_lines {
                    let trimmed = tl.trim();
                    if !trimmed.is_empty() {
                        insert_lines.push(format!("        {}", trimmed));
                    }
                }
                insert_lines.push("    }".to_string());
                for (offset, line) in insert_lines.iter().enumerate() {
                    lines.insert(block_close_after + offset, line.clone());
                }
            }

            RuleEdit::Ok
        } else {
            // 删除包级规则（只删除规则行，保留线程块）
            let mut found = false;
            if let Some(close) = t.block_close {
                let start = t.block_open.unwrap_or(0);
                let mut pkg_rule_idx = None;
                let mut is_block = false;
                for i in start..close {
                    let trimmed = lines[i].trim();
                    if trimmed.starts_with(&format!(":{} =", sub))
                        || trimmed.starts_with(&format!(":{}=", sub))
                    {
                        pkg_rule_idx = Some(i);
                        is_block = trimmed.ends_with('{');
                        break;
                    }
                }
                if let Some(idx) = pkg_rule_idx {
                    if is_block {
                        // 合并格式转为独立块（去掉 =CPU）
                        let line = &lines[idx];
                        let comment = match comment_at(line) {
                            Some(pos) => &line[pos..],
                            None => "",
                        };
                        let new_line = if comment.is_empty() {
                            format!("    :{} {{", sub)
                        } else {
                            format!("    :{} {{{}", sub, comment)
                        };
                        lines[idx] = new_line;
                    } else {
                        lines.remove(idx);
                    }
                    found = true;
                }
            }
            if !found {
                return RuleEdit::NotFound;
            }
            RuleEdit::Ok
        }
    } else {
        // ---- 线程规则操作 ----
        if cpus.is_empty() {
            // 删除指定线程
            let mut removed = false;
            if let Some(close) = t.block_close {
                let start = t.block_open.unwrap_or(0);
                // 查找子包块范围
                if let Some((block_start, block_end)) =
                    find_sub_block_range(lines, start, close, sub)
                {
                    // 在块内查找目标线程
                    for i in (block_start + 1)..block_end {
                        let line = &lines[i];
                        if let Some(name) = extract_thread_name(line) {
                            if name == thread {
                                lines.remove(i);
                                removed = true;
                                break;
                            }
                        }
                    }
                }
            }
            if !removed {
                return RuleEdit::NotFound;
            }
            RuleEdit::Ok
        } else {
            // ---- 更新或插入线程 ----
            let mut pkg_rule_line_idx = None;
            let mut pkg_rule_is_block = false;
            if let Some(close) = t.block_close {
                let start = t.block_open.unwrap_or(0);
                for i in start..close {
                    let trimmed = lines[i].trim();
                    if is_sub_block_start(trimmed, sub) {
                        pkg_rule_line_idx = Some(i);
                        pkg_rule_is_block = true;
                        break;
                    } else if trimmed.starts_with(&format!(":{} =", sub))
                        || trimmed.starts_with(&format!(":{}=", sub))
                    {
                        pkg_rule_line_idx = Some(i);
                        pkg_rule_is_block = false;
                        break;
                    }
                }
            }

            if let Some(idx) = pkg_rule_line_idx {
                if pkg_rule_is_block {
                    // 合并格式，在其块内查找/插入线程
                    if let Some((block_start, block_end)) =
                        find_sub_block_range(lines, idx, lines.len(), sub)
                    {
                        let mut found = false;
                        for i in (block_start + 1)..block_end {
                            let line = &lines[i];
                            if let Some(name) = extract_thread_name(line) {
                                if name == thread {
                                    if let Some(comment_pos) = comment_at(line) {
                                        lines[i] = format!(
                                            "        {}={}{}",
                                            thread,
                                            cpus,
                                            &line[comment_pos..]
                                        );
                                    } else {
                                        lines[i] = format!("        {}={}", thread, cpus);
                                    }
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if !found {
                            lines.insert(block_end, format!("        {}={}", thread, cpus));
                        }
                    } else {
                        // 理论上不会发生
                        return RuleEdit::Malformed;
                    }
                } else {
                    // 包级规则行不带 '{'，转换为合并格式
                    let line = &lines[idx];
                    let comment = match comment_at(line) {
                        Some(pos) => &line[pos..],
                        None => "",
                    };
                    let cpus_val = if let Some(eq_pos) = line.rfind('=') {
                        line[eq_pos + 1..].trim().to_string()
                    } else {
                        return RuleEdit::Malformed;
                    };
                    let new_line = if comment.is_empty() {
                        format!("    :{}={} {{", sub, cpus_val)
                    } else {
                        format!("    :{}={} {{{}", sub, cpus_val, comment)
                    };
                    lines[idx] = new_line;
                    lines.insert(idx + 1, format!("        {}={}", thread, cpus));
                    lines.insert(idx + 2, "    }".to_string());
                }
            } else {
                // 子包没有包级规则，创建包级规则和线程块
                if let Some(close) = t.block_close {
                    lines.insert(close, format!("    :{}={}", sub, cpus));
                    lines.insert(
                        close + 1,
                        format!("    :{} {{\n        {}={}\n    }}", sub, thread, cpus),
                    );
                } else {
                    lines.push(format!("    :{}={}", sub, cpus));
                    lines.push(format!(
                        "    :{} {{\n        {}={}\n    }}",
                        sub, thread, cpus
                    ));
                }
            }

            RuleEdit::Ok
        }
    }
}

/// 查找包的所有定义范围（包级行及其块）
fn find_package_ranges(lines: &[String], pkg: &str) -> Vec<(usize, usize)> {
    let pkg_prefix = format!("{}", pkg);
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            i += 1;
            continue;
        }
        if trimmed.starts_with(&pkg_prefix) {
            let after = &trimmed[pkg_prefix.len()..];
            if after.is_empty()
                || after.starts_with('=')
                || after.starts_with('{')
                || after.starts_with(' ')
            {
                let start = i;
                let mut end = i;
                if trimmed.ends_with('{') || after.trim_start().starts_with('{') {
                    let mut depth = 1;
                    let mut j = i + 1;
                    while j < lines.len() {
                        let t = lines[j].trim();
                        if t.ends_with('{') && !t.ends_with("{{") && !t.starts_with('}') {
                            depth += 1;
                        } else if t == "}" || (t.ends_with('}') && !t.starts_with('{')) {
                            depth -= 1;
                            if depth == 0 {
                                end = j;
                                break;
                            }
                        }
                        j += 1;
                    }
                }
                ranges.push((start, end));
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    ranges
}

/// 从给定的行范围中提取包级CPU、线程和子包信息
fn extract_package_data(lines: &[String], ranges: &[(usize, usize)], pkg: &str) -> PackageData {
    let mut data = PackageData::default();

    for (start, end) in ranges {
        for idx in *start..=*end {
            let line = &lines[idx];
            let trimmed = line.trim();
            // 包级行
            if trimmed.starts_with(&format!("{}", pkg)) {
                if let Some(eq_pos) = trimmed.rfind('=') {
                    let cpu_part = trimmed[eq_pos + 1..].trim();
                    for part in cpu_part.split(',') {
                        let p = part.trim();
                        if !p.is_empty() {
                            data.cpus.push(p.to_string());
                        }
                    }
                }
            } else {
                let inner = trimmed.trim_start();
                // 子包（以 ':' 开头）
                if inner.starts_with(':') {
                    let sub_name = if let Some(eq_pos) = inner.find('=') {
                        inner[1..eq_pos].trim()
                    } else if let Some(brace_pos) = inner.find('{') {
                        inner[1..brace_pos].trim()
                    } else {
                        ""
                    };
                    if !sub_name.is_empty() {
                        let sub_ranges =
                            find_package_ranges(lines, &format!("{}:{}", pkg, sub_name));
                        if !sub_ranges.is_empty() {
                            let sub_data = extract_package_data(
                                lines,
                                &sub_ranges,
                                &format!("{}:{}", pkg, sub_name),
                            );
                            data.sub_pkgs.insert(sub_name.to_string(), sub_data);
                        }
                    }
                } else if !inner.is_empty() && !inner.starts_with('{') && !inner.starts_with('}') {
                    // 线程行
                    if let Some(eq_pos) = inner.rfind('=') {
                        let thread_name = inner[..eq_pos].trim();
                        let cpus_val = inner[eq_pos + 1..].trim();
                        if !thread_name.is_empty() && !cpus_val.is_empty() {
                            data.threads
                                .entry(thread_name.to_string())
                                .and_modify(|e| *e = format!("{},{}", e, cpus_val))
                                .or_insert(cpus_val.to_string());
                        }
                    }
                }
            }
        }
    }
    data
}

/// 收集指定包（主包或子包）的所有数据，并返回相关行索引
fn collect_package(lines: &[String], pkg: &str) -> (PackageData, Vec<usize>) {
    // 使用 find_package_ranges 获取精确的行范围
    let ranges = find_package_ranges(lines, pkg);
    if ranges.is_empty() {
        return (PackageData::default(), Vec::new());
    }

    // 从这些范围中提取数据（包级CPU、线程、子包递归）
    let data = extract_package_data(lines, &ranges, pkg);

    // 生成所有相关行的索引列表（用于删除）
    let mut indices = Vec::new();
    for (start, end) in &ranges {
        for idx in *start..=*end {
            indices.push(idx);
        }
    }
    indices.sort();
    indices.dedup();

    (data, indices)
}

/// 合并去重 PackageData
fn merge_data(mut data: PackageData) -> PackageData {
    data.cpus.sort();
    data.cpus.dedup();

    for (_, cpus_str) in data.threads.iter_mut() {
        let parts: Vec<&str> = cpus_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        let mut unique = parts.clone();
        unique.sort();
        unique.dedup();
        *cpus_str = unique.join(",");
    }

    for (_, sub_data) in data.sub_pkgs.iter_mut() {
        *sub_data = merge_data(sub_data.clone());
    }
    data
}

/// 根据合并后的数据构建规范块
fn build_block(pkg: &str, data: &PackageData) -> Vec<String> {
    let mut block = Vec::new();
    let has_cpus = !data.cpus.is_empty();
    let has_threads = !data.threads.is_empty();
    let has_subs = !data.sub_pkgs.is_empty();

    let first_line = if has_cpus {
        format!("{}={} {{", pkg, data.cpus.join(","))
    } else {
        format!("{} {{", pkg)
    };

    if has_threads || has_subs {
        block.push(first_line);
        let mut threads: Vec<(&String, &String)> = data.threads.iter().collect();
        threads.sort_by(|a, b| a.0.cmp(b.0));
        for (name, cpus_val) in threads {
            block.push(format!("    {}={}", name, cpus_val));
        }
        let mut subs: Vec<(&String, &PackageData)> = data.sub_pkgs.iter().collect();
        subs.sort_by(|a, b| a.0.cmp(b.0));
        for (sub_name, sub_data) in subs {
            let sub_lines = build_block(&format!("{}:{}", pkg, sub_name), sub_data);
            for line in sub_lines {
                block.push(format!("    {}", line));
            }
        }
        block.push("}".to_string());
    } else if has_cpus {
        block.push(format!("{}={}", pkg, data.cpus.join(",")));
    } else {
        block.push(format!("{} {{", pkg));
        block.push("}".to_string());
    }
    block
}

/// 查找插入位置（第一个非注释行之后）
fn find_insert_pos(lines: &[String]) -> usize {
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with("//") {
            return idx + 1;
        }
    }
    lines.len()
}

pub fn rule_upsert(config_path: &str, pkg: &str, thread: &str, cpus: &str) -> RuleEdit {
    let result = std::panic::catch_unwind(|| {
        let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
        let mut lines: Vec<String> = fs::read_to_string(config_path)
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect();

        // 子包处理（编辑子包时，仍使用原 write_sub_pkg_block）
        if pkg.contains(':') {
            let parts: Vec<&str> = pkg.split(':').collect();
            if parts.len() == 2 {
                let main_pkg = parts[0];
                let sub = parts[1];
                let result = write_sub_pkg_block(&mut lines, main_pkg, sub, thread, cpus, false);
                if let RuleEdit::Ok = result {
                    clean_empty_lines(&mut lines);
                    return file_write(config_path, &lines);
                }
                return result;
            }
            return RuleEdit::Ok;
        }

        // --- 主包处理：使用 collect_package 递归收集 ---
        let (mut data, indices) = collect_package(&lines, pkg);
        if indices.is_empty() && thread.is_empty() && cpus.is_empty() {
            return RuleEdit::NotFound;
        }

        // 应用用户更新
        if !thread.is_empty() && !cpus.is_empty() {
            data.threads
                .entry(thread.to_string())
                .and_modify(|e| *e = format!("{},{}", e, cpus))
                .or_insert(cpus.to_string());
        } else if thread.is_empty() && !cpus.is_empty() {
            data.cpus.push(cpus.to_string());
        }

        // 合并去重
        let merged = merge_data(data);

        // 删除所有旧定义（collect_package 已返回所有相关行索引）
        let mut remove_indices = indices.clone();
        remove_indices.sort();
        remove_indices.dedup();
        for idx in remove_indices.into_iter().rev() {
            lines.remove(idx);
        }

        // 构建新块
        let new_block = build_block(pkg, &merged);

        // 插入到合适位置
        let insert_pos = find_insert_pos(&lines);
        lines.splice(insert_pos..insert_pos, new_block);
        clean_empty_lines(&mut lines);
        file_write(config_path, &lines)
    });

    match result {
        Ok(edit) => edit,
        Err(e) => {
            eprintln!("!!! rule_upsert panic: {:?}", e);
            RuleEdit::IoErr
        }
    }
}
/// 清理空块（若块内只有注释或空行，则删除整个块）
fn clean_empty_blocks(lines: &mut Vec<String>, pkg: &str) {
    let ranges = find_package_ranges(lines, pkg);
    for (start, end) in ranges.iter().rev() {
        let start_line = &lines[*start];
        if start_line.trim().ends_with('{') {
            let mut has_content = false;
            for idx in (*start + 1)..*end {
                let trimmed = lines[idx].trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with("//") {
                    has_content = true;
                    break;
                }
            }
            if !has_content {
                for idx in (*start..=*end).rev() {
                    lines.remove(idx);
                }
            }
        }
    }
}

/// 子包删除辅助
fn delete_sub_pkg(lines: &mut Vec<String>, main_pkg: &str, sub: &str, thread: &str) -> RuleEdit {
    let sub_pkg = format!("{}:{}", main_pkg, sub);
    let ranges = find_package_ranges(lines, &sub_pkg);
    if ranges.is_empty() {
        return RuleEdit::NotFound;
    }

    if thread.is_empty() {
        // 删除整个子包
        let mut indices = Vec::new();
        for (start, end) in &ranges {
            for idx in *start..=*end {
                indices.push(idx);
            }
        }
        indices.sort();
        indices.dedup();
        for idx in indices.into_iter().rev() {
            lines.remove(idx);
        }
    } else {
        // 删除子包内指定线程
        let mut found = false;
        for (start, end) in &ranges {
            for idx in (*start + 1)..*end {
                let trimmed = lines[idx].trim();
                let inner = trimmed.trim_start();
                if inner.starts_with(&format!("{}=", thread))
                    || inner.starts_with(&format!("{} =", thread))
                {
                    if let Some(eq_pos) = inner.find('=') {
                        let name_part = inner[..eq_pos].trim();
                        if name_part == thread {
                            lines.remove(idx);
                            found = true;
                            break;
                        }
                    }
                }
            }
            if found {
                break;
            }
        }
        if !found {
            return RuleEdit::NotFound;
        }
        clean_empty_blocks(lines, &sub_pkg);
    }
    clean_empty_blocks(lines, main_pkg);
    RuleEdit::Ok
}

pub fn rule_delete(config_path: &str, pkg: &str, thread: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(config_path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    if pkg.contains(':') {
        let parts: Vec<&str> = pkg.split(':').collect();
        if parts.len() == 2 {
            let main_pkg = parts[0];
            let sub = parts[1];
            let result = delete_sub_pkg(&mut lines, main_pkg, sub, thread);
            if let RuleEdit::Ok = result {
                clean_empty_lines(&mut lines);
                return file_write(config_path, &lines);
            }
            return result;
        }
        return RuleEdit::NotFound;
    }

    let ranges = find_package_ranges(&lines, pkg);
    if ranges.is_empty() {
        return RuleEdit::NotFound;
    }

    if thread.is_empty() {
        // 删除整个包
        let mut indices = Vec::new();
        for (start, end) in &ranges {
            for idx in *start..=*end {
                indices.push(idx);
            }
        }
        indices.sort();
        indices.dedup();
        for idx in indices.into_iter().rev() {
            lines.remove(idx);
        }
    } else {
        // 删除线程
        let mut found = false;
        for (start, end) in &ranges {
            for idx in (*start + 1)..*end {
                let trimmed = lines[idx].trim();
                let inner = trimmed.trim_start();
                if inner.starts_with(&format!("{}=", thread))
                    || inner.starts_with(&format!("{} =", thread))
                {
                    if let Some(eq_pos) = inner.find('=') {
                        let name_part = inner[..eq_pos].trim();
                        if name_part == thread {
                            lines.remove(idx);
                            found = true;
                            break;
                        }
                    }
                }
            }
            if found {
                break;
            }
        }
        if !found {
            return RuleEdit::NotFound;
        }
        clean_empty_blocks(&mut lines, pkg);
    }

    clean_empty_lines(&mut lines);
    file_write(config_path, &lines)
}

pub fn rule_delete_pkg(config_path: &str, pkg: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(config_path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    if pkg.contains(':') {
        let parts: Vec<&str> = pkg.split(':').collect();
        if parts.len() == 2 {
            let main_pkg = parts[0];
            let sub = parts[1];
            let result = delete_sub_pkg(&mut lines, main_pkg, sub, "");
            if let RuleEdit::Ok = result {
                clean_empty_lines(&mut lines);
                return file_write(config_path, &lines);
            }
            return result;
        }
        return RuleEdit::NotFound;
    }

    let ranges = find_package_ranges(&lines, pkg);
    if ranges.is_empty() {
        return RuleEdit::NotFound;
    }

    let mut indices = Vec::new();
    for (start, end) in &ranges {
        for idx in *start..=*end {
            indices.push(idx);
        }
    }
    indices.sort();
    indices.dedup();
    for idx in indices.into_iter().rev() {
        lines.remove(idx);
    }
    clean_empty_lines(&mut lines);
    file_write(config_path, &lines)
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
