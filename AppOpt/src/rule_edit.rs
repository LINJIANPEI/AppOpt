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

#[derive(Default, Clone)]
struct PackageData {
    cpus: Vec<String>,
    threads: HashMap<String, String>, // thread_name -> cpus (merged string)
    sub_pkgs: HashMap<String, PackageData>,
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

/// 删除连续空行，只保留最多一个空行
fn clean_empty_lines(lines: &mut Vec<String>) {
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.is_empty() {
            // 向后看是否还有空行
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim().is_empty() {
                j += 1;
            }
            if j > i + 1 {
                // 保留 i 行，删除 i+1..j-1
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
/// 收集指定包（可能是主包或子包）的所有相关行及解析数据
fn collect_package(lines: &[String], pkg: &str) -> (PackageData, Vec<usize>) {
    let mut data = PackageData::default();
    let mut indices = Vec::new();

    // 判断是否为子包（包含 ':'）
    let is_sub = pkg.contains(':');
    let prefix = if is_sub {
        let sub_name = pkg.split(':').last().unwrap();
        format!(":{}", sub_name)
    } else {
        pkg.to_string()
    };

    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            i += 1;
            continue;
        }

        // 匹配包级行（以 prefix 开头，且后面是 =、{、空格或结束）
        if trimmed.starts_with(&prefix) {
            let after = &trimmed[prefix.len()..];
            if after.is_empty()
                || after.starts_with('=')
                || after.starts_with('{')
                || after.starts_with(' ')
            {
                let start = i;
                let mut end = i;
                // 如果是块开始，找到匹配的 '}'
                if trimmed.ends_with('{') || after.trim_start().starts_with('{') {
                    let mut depth = 1;
                    for j in i + 1..lines.len() {
                        let t = lines[j].trim();
                        if t.ends_with('{') && !t.ends_with("{{") {
                            depth += 1;
                        } else if t == "}" || t.ends_with('}') && !t.starts_with('{') {
                            depth -= 1;
                            if depth == 0 {
                                end = j;
                                break;
                            }
                        }
                    }
                }
                // 收集这些行
                let collected: Vec<usize> = (start..=end).collect();
                indices.extend(collected.clone());

                // 解析这些行内容
                for idx in start..=end {
                    let line = &lines[idx];
                    let ln = line.trim();
                    if ln.starts_with(&prefix) {
                        // 包级行
                        if let Some(eq_pos) = ln.rfind('=') {
                            let cpus_str = ln[eq_pos + 1..].trim();
                            for part in cpus_str.split(',') {
                                let p = part.trim();
                                if !p.is_empty() {
                                    data.cpus.push(p.to_string());
                                }
                            }
                        }
                    } else {
                        // 可能是线程或子包
                        let inner = ln.trim_start();
                        if inner.starts_with(':') {
                            // 子包行：提取子包名，但不立即处理（由后续递归处理）
                            // 我们这里仅记录子包存在，后续通过递归收集
                            // 但为了不重复，我们跳过，在循环外递归
                        } else if !inner.is_empty()
                            && !inner.starts_with('{')
                            && !inner.starts_with('}')
                        {
                            // 线程行
                            if let Some(eq_pos) = inner.rfind('=') {
                                let thread_name = inner[..eq_pos].trim();
                                let cpus = inner[eq_pos + 1..].trim();
                                if !thread_name.is_empty()
                                    && !cpus.is_empty()
                                    && !thread_name.starts_with(':')
                                {
                                    data.threads
                                        .entry(thread_name.to_string())
                                        .and_modify(|e| {
                                            // 合并 CPU（简单追加，后续统一去重）
                                            if !e.split(',').any(|x| x.trim() == cpus) {
                                                e.push_str(",");
                                                e.push_str(cpus);
                                            }
                                        })
                                        .or_insert(cpus.to_string());
                                }
                            }
                        }
                    }
                }

                i = end + 1;
                continue;
            }
        }
        i += 1;
    }

    // 递归收集子包
    // 我们需要在已经收集的 indices 中找子包行，但为了简洁，我们重新扫描 lines，但只针对子包行
    // 更高效：在解析过程中记录子包名，但为简化，我们再次扫描所有行（但只在 indices 范围内）
    let mut sub_pkgs_to_collect = Vec::new();
    for &idx in &indices {
        let line = &lines[idx];
        let trimmed = line.trim();
        if trimmed.starts_with(':') && !trimmed.starts_with("::") {
            // 提取子包名
            let sub_name = if let Some(eq_pos) = trimmed.find('=') {
                trimmed[1..eq_pos].trim()
            } else if let Some(brace_pos) = trimmed.find('{') {
                trimmed[1..brace_pos].trim()
            } else {
                continue;
            };
            if !sub_name.is_empty() {
                sub_pkgs_to_collect.push(sub_name.to_string());
            }
        }
    }
    // 去重子包名
    sub_pkgs_to_collect.sort();
    sub_pkgs_to_collect.dedup();

    for sub_name in sub_pkgs_to_collect {
        let sub_full_pkg = if is_sub {
            format!("{}:{}", pkg, sub_name)
        } else {
            format!("{}:{}", pkg, sub_name)
        };
        let (sub_data, sub_indices) = collect_package(lines, &sub_full_pkg);
        data.sub_pkgs.insert(sub_name, sub_data);
        // 合并子包的索引到主索引
        for idx in sub_indices {
            if !indices.contains(&idx) {
                indices.push(idx);
            }
        }
    }

    // 排序去重索引
    indices.sort();
    indices.dedup();

    (data, indices)
}

/// 生成子包的规范化块字符串（返回多行）
fn format_sub_package(sub_name: &str, data: &PackageData) -> Vec<String> {
    let mut lines = Vec::new();
    let cpus = data.cpus.join(",");
    let has_threads = !data.threads.is_empty();
    let has_subs = !data.sub_pkgs.is_empty();

    if cpus.is_empty() && !has_threads && !has_subs {
        return lines;
    }

    let first_line = if cpus.is_empty() {
        format!("    :{} {{", sub_name)
    } else {
        format!("    :{}={} {{", sub_name, cpus)
    };
    lines.push(first_line);

    // 线程
    let mut thread_vec: Vec<(String, String)> = data
        .threads
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    thread_vec.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, cpus) in thread_vec {
        // 合并去重 CPU
        let parts: Vec<&str> = cpus
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        let mut unique = parts;
        unique.sort();
        unique.dedup();
        let merged = unique.join(",");
        lines.push(format!("        {}={}", name, merged));
    }

    // 子包（递归）
    let mut sub_vec: Vec<(String, PackageData)> = data
        .sub_pkgs
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    sub_vec.sort_by(|a, b| a.0.cmp(&b.0));
    for (sub, sub_data) in sub_vec {
        let sub_lines = format_sub_package(&sub, &sub_data);
        // 缩进调整：每行增加两个空格
        for line in sub_lines {
            lines.push(format!("    {}", line));
        }
    }

    lines.push("    }".to_string());
    lines
}

pub fn rule_upsert(path: &str, pkg: &str, thread: &str, cpus: &str) -> RuleEdit {
    let result = std::panic::catch_unwind(|| {
        let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
        let mut lines: Vec<String> = fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect();

        // ---- 如果是子包（含 ':'），委托给专门逻辑（暂不处理，但可扩展） ----
        // 但为了简单，我们统一处理主包和子包，但子包需要单独处理，这里先忽略。
        // 因为用户主要操作主包，我们暂时只处理主包（不含 ':'）的情况。
        // 若需子包，可以递归调用。
        if pkg.contains(':') {
            // 简单处理：直接调用原有子包逻辑（但可能不稳定，我们暂时保留）
            let parts: Vec<&str> = pkg.split(':').collect();
            if parts.len() == 2 {
                let main_pkg = parts[0];
                let sub = parts[1];
                let result = write_sub_pkg_block(&mut lines, main_pkg, sub, thread, cpus, false);
                return match result {
                    RuleEdit::Ok => file_write(path, &lines),
                    _ => result,
                };
            }
            return RuleEdit::Ok;
        }

        // ---- 主包处理 ----
        // 第一步：收集该包的所有相关行范围（包级行及其块）
        let pkg_prefix = format!("{}", pkg);
        let mut ranges = Vec::new(); // 存储 (start, end) 行索引
        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                i += 1;
                continue;
            }
            // 匹配包级行（以包名开头，后面跟着 '='、'{' 或空格）
            if trimmed.starts_with(&pkg_prefix) {
                let after = &trimmed[pkg_prefix.len()..];
                if after.is_empty()
                    || after.starts_with('=')
                    || after.starts_with('{')
                    || after.starts_with(' ')
                {
                    let start = i;
                    let mut end = i;
                    // 如果该行是块开始（以 '{' 结尾），则寻找对应的 '}'
                    if trimmed.ends_with('{') || after.trim_start().starts_with('{') {
                        let mut depth = 1;
                        let mut j = i + 1;
                        while j < lines.len() {
                            let t = lines[j].trim();
                            // 简单判断：以 '{' 结尾且不是空块标志（如 "{{"），则增加深度
                            if t.ends_with('{') && !t.ends_with("{{") && !t.starts_with('}') {
                                depth += 1;
                            } else if t == "}" || t.ends_with('}') && !t.starts_with('{') {
                                depth -= 1;
                                if depth == 0 {
                                    end = j;
                                    break;
                                }
                            }
                            j += 1;
                        }
                        // 如果未找到闭合，则只取本行（但这种情况不应该发生）
                    }
                    ranges.push((start, end));
                    i = end + 1;
                    continue;
                }
            }
            i += 1;
        }

        // 如果没有找到任何相关行，且没有提供新规则（thread 和 cpus 都为空），则返回 NotFound
        if ranges.is_empty() && thread.is_empty() && cpus.is_empty() {
            return RuleEdit::NotFound;
        }

        // ---- 第二步：从这些范围中提取包级 CPU 和所有线程规则（忽略子包） ----
        let mut all_cpus = Vec::new();
        let mut thread_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        for (start, end) in &ranges {
            for idx in *start..=*end {
                let line = &lines[idx];
                let trimmed = line.trim();
                // 包级行（可能包含 CPU）
                if trimmed.starts_with(&pkg_prefix) {
                    if let Some(eq_pos) = trimmed.rfind('=') {
                        let cpu_part = trimmed[eq_pos + 1..].trim();
                        for part in cpu_part.split(',') {
                            let p = part.trim();
                            if !p.is_empty() {
                                all_cpus.push(p.to_string());
                            }
                        }
                    }
                } else {
                    // 可能是线程或子包，我们只关注线程（不以 ':' 开头，且包含 '='）
                    let inner = trimmed.trim_start();
                    if !inner.starts_with(':')
                        && !inner.is_empty()
                        && !inner.starts_with('{')
                        && !inner.starts_with('}')
                    {
                        if let Some(eq_pos) = inner.rfind('=') {
                            let thread_name = inner[..eq_pos].trim();
                            let cpus_val = inner[eq_pos + 1..].trim();
                            if !thread_name.is_empty() && !cpus_val.is_empty() {
                                thread_map
                                    .entry(thread_name.to_string())
                                    .and_modify(|e| *e = format!("{},{}", e, cpus_val))
                                    .or_insert(cpus_val.to_string());
                            }
                        }
                    }
                }
            }
        }

        // ---- 第三步：合并去重 ----
        all_cpus.sort();
        all_cpus.dedup();
        let merged_cpus = all_cpus.join(",");

        // 对每个线程的 CPU 去重
        for (_, cpus_str) in thread_map.iter_mut() {
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

        // ---- 第四步：删除所有相关行（从后往前删，避免索引变化） ----
        let mut remove_indices = Vec::new();
        for (start, end) in &ranges {
            for idx in *start..=*end {
                remove_indices.push(idx);
            }
        }
        remove_indices.sort();
        remove_indices.dedup();
        for idx in remove_indices.into_iter().rev() {
            if idx < lines.len() {
                lines.remove(idx);
            }
        }

        // ---- 第五步：构建新块 ----
        let mut new_block = Vec::new();
        // 决定第一行
        let has_cpus = !merged_cpus.is_empty();
        let has_threads = !thread_map.is_empty();

        // 如果既有 CPU 又有线程，或者只有线程，则采用块形式
        if has_threads || has_cpus {
            let first_line = if has_cpus {
                format!("{}={} {{", pkg, merged_cpus)
            } else {
                format!("{} {{", pkg)
            };
            new_block.push(first_line);

            // 将线程按名称排序，以便输出稳定
            let mut threads_vec: Vec<(&String, &String)> = thread_map.iter().collect();
            threads_vec.sort_by(|a, b| a.0.cmp(b.0));
            for (name, cpus_val) in threads_vec {
                new_block.push(format!("    {}={}", name, cpus_val));
            }
            new_block.push("}".to_string());
        } else {
            // 只有包级 CPU，没有线程，采用单行
            if has_cpus {
                new_block.push(format!("{}={}", pkg, merged_cpus));
            } else {
                // 什么都没有（不可能发生，因为如果没提供新规则，我们已提前返回）
                // 但以防万一，直接返回 Ok
                return RuleEdit::Ok;
            }
        }

        // ---- 第六步：将新块插入到合适位置 ----
        // 插入到第一个非注释行之后（若无，则插入到文件末尾）
        let mut insert_pos = lines.len();
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with("//") {
                insert_pos = idx + 1;
                break;
            }
        }
        lines.splice(insert_pos..insert_pos, new_block);

        // ---- 写回 ----
        file_write(path, &lines)
    });

    match result {
        Ok(edit) => edit,
        Err(e) => {
            eprintln!("!!! rule_upsert panic: {:?}", e);
            RuleEdit::IoErr
        }
    }
}

/// 删除子包内容，thread 为空时删除整个子包，否则删除该子包内的指定线程
fn delete_sub_pkg_advanced(
    lines: &mut Vec<String>,
    main_pkg: &str,
    sub: &str,
    thread: &str,
) -> RuleEdit {
    let sub_prefix = format!(":{}", sub);
    let mut found = false;

    if thread.is_empty() {
        // 删除整个子包（包括包级行和所有线程）
        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();
            if trimmed.starts_with(&sub_prefix) && (trimmed.contains('=') || trimmed.ends_with('{'))
            {
                // 判断是否为块
                let is_block = trimmed.ends_with('{') || trimmed.trim_end().ends_with('{');
                if is_block {
                    let start = i;
                    let mut depth = 1;
                    let mut end = i;
                    for j in i + 1..lines.len() {
                        let t = lines[j].trim();
                        if t.ends_with('{') && !t.ends_with("{{") {
                            depth += 1;
                        } else if t == "}" || t.ends_with('}') && !t.starts_with('{') {
                            depth -= 1;
                            if depth == 0 {
                                end = j;
                                break;
                            }
                        }
                    }
                    lines.drain(start..=end);
                    found = true;
                    break;
                } else {
                    lines.remove(i);
                    found = true;
                    break;
                }
            }
            i += 1;
        }
        if !found {
            return RuleEdit::NotFound;
        }
        // 检查主包块是否因删除子包而变空，若空则删除主包块
        // 重新扫描主包
        let t_main = target_scan(lines, main_pkg);
        if let (Some(open), Some(close)) = (t_main.block_open, t_main.block_close) {
            let mut inner_non_empty = false;
            for i in open + 1..close {
                let trimmed = lines[i].trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with(':') {
                    inner_non_empty = true;
                    break;
                }
            }
            if !inner_non_empty {
                // 主包块为空，删除整个主包块
                lines.drain(open..=close);
            }
        }
        RuleEdit::Ok
    } else {
        // 删除子包内的线程
        // 定位子包块
        let mut sub_block_start = None;
        let mut sub_block_end = None;
        for i in 0..lines.len() {
            let trimmed = lines[i].trim();
            if trimmed.starts_with(&sub_prefix)
                && (trimmed.ends_with('{') || trimmed.trim_end().ends_with('{'))
            {
                sub_block_start = Some(i);
                let mut depth = 1;
                for j in i + 1..lines.len() {
                    let t = lines[j].trim();
                    if t.ends_with('{') && !t.ends_with("{{") {
                        depth += 1;
                    } else if t == "}" || t.ends_with('}') && !t.starts_with('{') {
                        depth -= 1;
                        if depth == 0 {
                            sub_block_end = Some(j);
                            break;
                        }
                    }
                }
                break;
            }
        }
        if let (Some(start), Some(end)) = (sub_block_start, sub_block_end) {
            let mut removed = false;
            for i in (start + 1..end).rev() {
                let trimmed = lines[i].trim();
                if trimmed.starts_with(&format!("{}=", thread))
                    || trimmed.starts_with(&format!("{} =", thread))
                {
                    // 精确匹配线程名
                    if let Some(eq_pos) = trimmed.find('=') {
                        let name_part = trimmed[..eq_pos].trim();
                        if name_part == thread {
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
            // 检查子包块内是否还有有效内容（线程或子包）
            let mut inner_non_empty = false;
            for i in start + 1..end {
                let trimmed = lines[i].trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with(':') {
                    inner_non_empty = true;
                    break;
                }
            }
            if !inner_non_empty {
                // 子包块为空，删除整个子包块
                lines.drain(start..=end);
            }
            // 检查主包块是否为空（只包含子包已删除，可能变空）
            let t_main = target_scan(lines, main_pkg);
            if let (Some(open), Some(close)) = (t_main.block_open, t_main.block_close) {
                let mut main_inner_non_empty = false;
                for i in open + 1..close {
                    let trimmed = lines[i].trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with(':')
                    {
                        main_inner_non_empty = true;
                        break;
                    }
                }
                if !main_inner_non_empty {
                    lines.drain(open..=close);
                }
            }
            RuleEdit::Ok
        } else {
            RuleEdit::NotFound
        }
    }
}

pub fn rule_delete(path: &str, pkg: &str, thread: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    // ---- 子包处理 ----
    let parts: Vec<&str> = pkg.split(':').collect();
    if parts.len() == 2 {
        let main_pkg = parts[0];
        let sub = parts[1];
        // 使用改进后的子包删除函数（见后文）
        let result = delete_sub_pkg_advanced(&mut lines, main_pkg, sub, thread);
        if let RuleEdit::Ok = result {
            clean_empty_lines(&mut lines);
            return file_write(path, &lines);
        }
        return result;
    }

    // ---- 主包删除 ----
    if thread.is_empty() {
        // 删除整个包（包括块）
        let mut found = false;
        let pkg_prefix = format!("{}", pkg);
        for i in (0..lines.len()).rev() {
            let trimmed = lines[i].trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }
            if trimmed.starts_with(&pkg_prefix) {
                let after_pkg = &trimmed[pkg_prefix.len()..];
                if after_pkg.is_empty()
                    || after_pkg.starts_with('=')
                    || after_pkg.starts_with('{')
                    || after_pkg.starts_with(' ')
                {
                    // 如果是块开始行（含 '{'），删除整个块
                    if trimmed.ends_with('{') || after_pkg.trim_start().starts_with('{') {
                        let mut depth = 1;
                        let mut end = i;
                        for j in i + 1..lines.len() {
                            let t = lines[j].trim();
                            if t.ends_with('{') && !t.ends_with("{{") {
                                depth += 1;
                            } else if t == "}" || t.ends_with('}') && !t.starts_with('{') {
                                depth -= 1;
                                if depth == 0 {
                                    end = j;
                                    break;
                                }
                            }
                        }
                        lines.drain(i..=end);
                    } else {
                        lines.remove(i);
                    }
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return RuleEdit::NotFound;
        }
    } else {
        // 删除线程规则
        let t = target_scan(&lines, pkg);
        if let Some(locs) = t.threads.get(thread) {
            for loc in locs.iter().rev() {
                line_remove(&mut lines, pkg, loc);
            }
            // 检查块是否为空（仅剩 "{" 和 "}"）
            // 重新扫描该包块
            let new_t = target_scan(&lines, pkg);
            if let (Some(open), Some(close)) = (new_t.block_open, new_t.block_close) {
                let mut inner_non_empty = false;
                for i in open + 1..close {
                    let trimmed = lines[i].trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        inner_non_empty = true;
                        break;
                    }
                }
                if !inner_non_empty {
                    // 删除整个块
                    lines.drain(open..=close);
                }
            }
        } else {
            return RuleEdit::NotFound;
        }
    }

    clean_empty_lines(&mut lines);
    file_write(path, &lines)
}

pub fn rule_delete_pkg(path: &str, pkg: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    // ---- 子包处理 ----
    let parts: Vec<&str> = pkg.split(':').collect();
    if parts.len() == 2 {
        let main_pkg = parts[0];
        let sub = parts[1];
        // 使用子包高级删除（删除整个子包）
        let result = delete_sub_pkg_advanced(&mut lines, main_pkg, sub, "");
        if let RuleEdit::Ok = result {
            clean_empty_lines(&mut lines);
            return file_write(path, &lines);
        }
        return result;
    }

    // ---- 主包删除全部 ----
    let mut start_line = None;
    let mut end_line = None;
    let pkg_prefix = format!("{}", pkg);

    for i in 0..lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        if trimmed.starts_with(&pkg_prefix) {
            let after_pkg = &trimmed[pkg_prefix.len()..];
            if after_pkg.is_empty()
                || after_pkg.starts_with('=')
                || after_pkg.starts_with('{')
                || after_pkg.starts_with(' ')
            {
                start_line = Some(i);
                if trimmed.ends_with('{') || after_pkg.trim_start().starts_with('{') {
                    let mut depth = 1;
                    for j in i + 1..lines.len() {
                        let t = lines[j].trim();
                        if t.ends_with('{') && !t.ends_with("{{") {
                            depth += 1;
                        } else if t == "}" || t.ends_with('}') && !t.starts_with('{') {
                            depth -= 1;
                            if depth == 0 {
                                end_line = Some(j);
                                break;
                            }
                        }
                    }
                    if end_line.is_none() {
                        end_line = Some(i);
                    }
                } else {
                    end_line = Some(i);
                }
                break;
            }
        }
    }

    if let (Some(start), Some(end)) = (start_line, end_line) {
        lines.drain(start..=end);
    } else {
        return RuleEdit::NotFound;
    }

    clean_empty_lines(&mut lines);
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
