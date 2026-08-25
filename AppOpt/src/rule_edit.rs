use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::sync::Mutex;

use crate::config::{
    OuterLine, close_like, comment_at, parse_outer, split_rule_line, split_single_line,
    strip_comment,
};

#[derive(Debug)]
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
        // 精确匹配包级行：行首（忽略前导空格）以 pkg_prefix 开头
        // 但注意，块内线程行也可能以包名开头？实际上线程行不会以包名开头，因为线程名通常不同。
        // 但在当前逻辑中，我们只处理行首（可能缩进）的匹配，但包级行通常顶格（无缩进）。
        // 不过有些用户可能缩进，为了保险，我们检查是否以 pkg_prefix 开头，并且前面不是空格？
        // 更好的：检查该行是否以 pkg_prefix 开头，且前面没有非空格字符（即顶格）。
        // 但为了兼容，我们允许任意缩进，但后面要检查它是不是其他包。
        // 现在我们先使用原逻辑，但后面加一个保护：如果遇到另一个顶格的包行，则提前结束。
        if trimmed.starts_with(&pkg_prefix) {
            let after = &trimmed[pkg_prefix.len()..];
            if after.is_empty()
                || after.starts_with('=')
                || after.starts_with('{')
                || after.starts_with(' ')
            {
                let start = i;
                let mut end = i;
                // 检查是否为块开始（以 '{' 结尾）
                let is_block = trimmed.ends_with('{') || after.trim_start().starts_with('{');
                if is_block {
                    let mut depth = 1;
                    let mut j = i + 1;
                    while j < lines.len() {
                        let t = lines[j].trim();
                        // 检查是否遇到了新的顶格包级行（即行首非空格且不以 # 开头）
                        // 如果遇到了，说明当前块结束，但尚未找到匹配的 }，则强制结束
                        let line_start = lines[j].chars().next().unwrap_or(' ');
                        if !line_start.is_whitespace()
                            && !t.is_empty()
                            && !t.starts_with('#')
                            && !t.starts_with("//")
                        {
                            // 可能是新包开始，但也有可能是注释行，这里我们只当它是新包行则停止
                            // 但还要判断是否是线程行（线程行通常缩进，所以顶格的是包）
                            // 我们可以检查该行是否包含 '=' 或 '{'，若是则很可能是包级行
                            if t.contains('=') || t.contains('{') {
                                // 当前块到此结束
                                end = j - 1;
                                break;
                            }
                        }
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
                    // 如果 j 到达末尾，end 可能未更新，则设置为 i（单行）
                    if end == i {
                        // 未找到闭合，但可能存在后续包行，我们尝试调整
                        // 这里我们简单地只取本行
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

pub fn rule_upsert(
    config_path: &str,
    pkg: &str,
    thread: &str,
    cpus: &str,
    cfg: &crate::config::AppConfig,
) -> RuleEdit {
    use std::collections::HashSet;
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);
    eprintln!("[rule_upsert] 已获取锁");

    let mut lines: Vec<String> = fs::read_to_string(config_path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();
    eprintln!("[rule_upsert] 读取文件，行数={}", lines.len());

    fn validate_cpus(
        cpus: &str,
        topo: &crate::cpuset::CpuTopology,
    ) -> Option<crate::cpuset::CpuSet> {
        if cpus.is_empty() {
            return None;
        }
        let set = crate::cpuset::parse_cpu_spec(cpus, topo);
        if set.count() == 0 {
            eprintln!("[rule_upsert] 无效 CPU 规格: {}", cpus);
            None
        } else {
            Some(set)
        }
    }

    if pkg.contains(':') {
        eprintln!("[rule_upsert] 进入子包分支");
        let parts: Vec<&str> = pkg.split(':').collect();
        if parts.len() == 2 {
            let main_pkg = parts[0];
            let sub = parts[1];
            if !cpus.is_empty() && validate_cpus(cpus, &cfg.topo).is_none() {
                return RuleEdit::Malformed;
            }
            let result = write_sub_pkg_block(&mut lines, main_pkg, sub, thread, cpus, false);
            eprintln!("[rule_upsert] 子包处理结果: {:?}", result);
            if let RuleEdit::Ok = result {
                clean_empty_lines(&mut lines);
                return file_write(config_path, &lines);
            }
            return result;
        }
        return RuleEdit::Ok;
    }

    eprintln!("[rule_upsert] 进入主包分支");
    let mut new_rules = Vec::new();
    for r in &cfg.rules {
        if r.pkg == pkg {
            if thread.is_empty() {
                if r.thread.is_empty() {
                    continue;
                }
            } else {
                if r.thread == thread {
                    continue;
                }
            }
        }
        new_rules.push(r.clone());
    }
    eprintln!("[rule_upsert] 保留 {} 条旧规则", new_rules.len());

    if !cpus.is_empty() {
        eprintln!("[rule_upsert] 准备添加新规则，cpus={}", cpus);
        if let Some(cpuset) = validate_cpus(cpus, &cfg.topo) {
            let cpuset_dir = if thread.is_empty() {
                crate::cpuset::ensure_cpuset_dir(&cpuset, &cfg.topo)
            } else {
                String::new()
            };
            let new_rule = crate::config::AffinityRule {
                pkg: pkg.to_string(),
                thread: thread.to_string(),
                thread_pattern: std::ffi::CString::new(thread).unwrap_or_default(),
                cpuset_dir,
                cpus: cpuset,
                spec: cpus.to_string(),
            };
            new_rules.push(new_rule);
            eprintln!("[rule_upsert] 新规则已加入，总数={}", new_rules.len());
        } else {
            return RuleEdit::Malformed;
        }
    }

    let pkgs: HashSet<String> = new_rules.iter().map(|r| r.pkg.clone()).collect();
    let has_thread_rules: HashSet<String> = new_rules
        .iter()
        .filter(|r| !r.thread.is_empty())
        .map(|r| r.pkg.clone())
        .collect();
    let new_cfg = crate::config::AppConfig {
        rules: new_rules,
        pkgs,
        has_thread_rules,
        topo: cfg.topo.clone(),
    };

    // ================= 核心修改：简化查找旧块 =================
    eprintln!("[rule_upsert] 开始查找旧块");
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut first_start = None;
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        // 判断是否为顶格的包行（以 pkg 开头，后面跟着 =、{、空格或冒号）
        let is_top_level = !lines[i].starts_with(' ') && !lines[i].starts_with('\t');
        let is_pkg_line = is_top_level
            && (trimmed == pkg
                || trimmed.starts_with(&format!("{} ", pkg))
                || trimmed.starts_with(&format!("{}=", pkg))
                || trimmed.starts_with(&format!("{}{{", pkg))
                || trimmed.starts_with(&format!("{}:", pkg)));

        if is_pkg_line {
            let start = i;
            // 检查该行是否包含 '{'（即是否为块）
            let has_brace = trimmed.contains('{');
            if has_brace {
                let mut depth = 0;
                let mut j = i;
                while j < lines.len() {
                    let t = lines[j].trim();
                    if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
                        j += 1;
                        continue;
                    }
                    depth += t.matches('{').count() - t.matches('}').count();
                    if depth == 0 && j > i {
                        // 找到闭合
                        ranges.push((start, j));
                        if first_start.is_none() {
                            first_start = Some(start);
                        }
                        i = j + 1;
                        break;
                    }
                    j += 1;
                    if j - i > 10000 {
                        // 安全保护
                        eprintln!("[rule_upsert] 警告: 查找闭合时达到最大深度");
                        break;
                    }
                }
                if i == start {
                    // 未找到闭合，当作单行
                    ranges.push((start, start));
                    if first_start.is_none() {
                        first_start = Some(start);
                    }
                    i = start + 1;
                }
            } else {
                // 单行规则，无块
                ranges.push((start, start));
                if first_start.is_none() {
                    first_start = Some(start);
                }
                i = start + 1;
            }
        } else {
            i += 1;
        }
    }
    eprintln!("[rule_upsert] 找到 {} 个旧块", ranges.len());

    // ========== 生成新块 ==========
    eprintln!("[rule_upsert] 开始生成新块");
    let new_block = build_package_block(pkg, &new_cfg);
    eprintln!("[rule_upsert] 新块行数={}", new_block.len());

    if ranges.is_empty() {
        eprintln!("[rule_upsert] 无旧块，直接插入");
        if new_block.is_empty() {
            clean_empty_lines(&mut lines);
            return file_write(config_path, &lines);
        }
        if !lines.is_empty() && !lines.last().unwrap().trim().is_empty() {
            lines.push(String::new());
        }
        lines.extend(new_block);
        lines.push(String::new());
        clean_empty_lines(&mut lines);
        return file_write(config_path, &lines);
    }

    eprintln!("[rule_upsert] 删除旧块...");
    ranges.sort_by_key(|(_, end)| *end);
    ranges.reverse();
    for (start, end) in ranges {
        if start <= end && end < lines.len() {
            lines.drain(start..=end);
        } else {
            eprintln!(
                "[rule_upsert] 警告: 跳过无效范围 start={}, end={}",
                start, end
            );
        }
    }

    if !new_block.is_empty() {
        let insert_pos = first_start.unwrap_or(lines.len());
        let pos = if insert_pos > lines.len() {
            lines.len()
        } else {
            insert_pos
        };
        lines.splice(pos..pos, new_block);
        eprintln!("[rule_upsert] 新块已插入在 pos={}", pos);
    }

    clean_empty_lines(&mut lines);
    let result = file_write(config_path, &lines);
    eprintln!("[rule_upsert] file_write 结果: {:?}", result);
    result
}

/// 清理空块（若块内只有注释或空行，则删除整个块）
fn clean_empty_blocks(lines: &mut Vec<String>, pkg: &str) {
    let ranges = find_package_ranges(lines, pkg);
    for (start, end) in ranges.iter().rev() {
        let start_line = &lines[*start];
        let trimmed = start_line.trim();
        if trimmed.ends_with('{') {
            let has_cpus = trimmed.contains('=') && !trimmed.ends_with('{');
            let mut has_content = false;
            for idx in (*start + 1)..*end {
                let inner = lines[idx].trim();
                if !inner.is_empty() && !inner.starts_with('#') && !inner.starts_with("//") {
                    has_content = true;
                    break;
                }
            }
            if !has_cpus && !has_content {
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

    // ---- 子包处理 ----
    if pkg.contains(':') {
        let parts: Vec<&str> = pkg.split(':').collect();
        if parts.len() == 2 {
            let main_pkg = parts[0];
            let sub = parts[1];
            let result = write_sub_pkg_block(&mut lines, main_pkg, sub, thread, "", false);
            if let RuleEdit::Ok = result {
                clean_empty_lines(&mut lines);
                clean_empty_blocks(&mut lines, main_pkg);
                return file_write(config_path, &lines);
            }
            return result;
        }
        return RuleEdit::NotFound;
    }

    // ---- 主包处理 ----
    let ranges = find_package_ranges(&lines, pkg);
    if ranges.is_empty() {
        return RuleEdit::NotFound;
    }

    if thread.is_empty() {
        // 删除包级规则：修改第一行，去掉 =CPU 部分
        let start = ranges[0].0;
        let line = &lines[start];
        let trimmed = line.trim();
        if trimmed.contains('=') {
            if let Some(eq_pos) = trimmed.rfind('=') {
                let pkg_part = trimmed[..eq_pos].trim();
                // ★ 修复：正确处理 Option<usize>
                let has_brace =
                    trimmed.contains('{') && trimmed.rfind('{').is_some_and(|pos| pos > eq_pos);
                let comment = match comment_at(line) {
                    Some(pos) => &line[pos..],
                    None => "",
                };
                let new_line = if has_brace {
                    format!("{} {{", pkg_part)
                } else {
                    pkg_part.to_string()
                };
                let indent = line
                    .chars()
                    .take_while(|c| c.is_whitespace())
                    .collect::<String>();
                lines[start] = format!("{}{}{}", indent, new_line, comment);
            }
        } else {
            // 没有包级规则，无需操作
            return RuleEdit::Ok;
        }
        clean_empty_blocks(&mut lines, pkg);
        clean_empty_lines(&mut lines);
        return file_write(config_path, &lines);
    } else {
        // 删除指定线程（在块内查找，包括子包内的线程）
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
        clean_empty_lines(&mut lines);
        return file_write(config_path, &lines);
    }
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

// ========== 新增规范化函数 ==========

pub fn find_package_range(lines: &[String], pkg: &str) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        let is_top_level = !lines[i].starts_with(' ') && !lines[i].starts_with('\t');
        let is_pkg_line = is_top_level
            && (trimmed == pkg
                || trimmed.starts_with(&format!("{} ", pkg))
                || trimmed.starts_with(&format!("{}=", pkg))
                || trimmed.starts_with(&format!("{}{{", pkg))
                || trimmed.starts_with(&format!("{}:", pkg)));
        if is_pkg_line {
            let mut depth = 0;
            let mut j = i;
            while j < lines.len() {
                let t = lines[j].trim();
                if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
                    j += 1;
                    continue;
                }
                depth += t.matches('{').count() - t.matches('}').count();
                if depth == 0 && j > i {
                    return Some((i, j));
                }
                j += 1;
                if j - i > 10000 {
                    break;
                }
            }
            return Some((i, i));
        }
        i += 1;
    }
    None
}

/// 根据 AppConfig 中的规则生成规范化的主包块（包含子包嵌套）
pub fn build_package_block(pkg: &str, cfg: &crate::config::AppConfig) -> Vec<String> {
    use std::collections::{BTreeMap, HashSet};
    let mut block = Vec::new();

    // ---- 1. 收集主包和子包规则 ----
    let mut main_rules = Vec::new();
    let mut sub_rules: BTreeMap<String, Vec<&crate::config::AffinityRule>> = BTreeMap::new();
    for rule in &cfg.rules {
        if let Some(stripped) = rule.pkg.strip_prefix(&format!("{}:", pkg)) {
            let sub_name = stripped.split(':').next().unwrap_or(stripped);
            sub_rules
                .entry(sub_name.to_string())
                .or_default()
                .push(rule);
        } else if rule.pkg == pkg {
            main_rules.push(rule);
        }
    }

    // ---- 2. 去重主包规则（包级规则和线程规则分别去重） ----
    // 2.1 包级规则：只保留最后一个（取 thread 为空且 spec 相同去重，但通常只有一个，这里不额外处理）
    // 2.2 线程规则：按 (thread, spec) 去重，保留最新（后面的覆盖前面的）
    let mut seen = HashSet::new();
    let mut main_dedup = Vec::new();
    for rule in main_rules.into_iter().rev() {
        let key = (rule.thread.clone(), rule.spec.clone());
        if !seen.contains(&key) {
            seen.insert(key);
            main_dedup.push(rule);
        }
    }
    main_dedup.reverse();
    let main_rules = main_dedup;

    // ---- 3. 去重子包规则（每个子包单独去重） ----
    let mut sub_rules_dedup = BTreeMap::new();
    for (sub, rules) in sub_rules {
        let mut seen = HashSet::new();
        let mut dedup = Vec::new();
        for rule in rules.into_iter().rev() {
            let key = (rule.thread.clone(), rule.spec.clone());
            if !seen.contains(&key) {
                seen.insert(key);
                dedup.push(rule);
            }
        }
        dedup.reverse();
        sub_rules_dedup.insert(sub, dedup);
    }
    let sub_rules = sub_rules_dedup;

    // ---- 4. 如果没有规则，返回空块 ----
    if main_rules.is_empty() && sub_rules.is_empty() {
        return block;
    }

    // ---- 5. 生成主包第一行 ----
    let pkg_cpus: Vec<&str> = main_rules
        .iter()
        .filter(|r| r.thread.is_empty())
        .map(|r| r.spec.as_str())
        .collect();
    let thread_rules: Vec<&crate::config::AffinityRule> = main_rules
        .iter()
        .filter(|r| !r.thread.is_empty())
        .map(|&r| r)
        .collect();

    let first_line = if pkg_cpus.is_empty() {
        format!("{} {{", pkg)
    } else {
        format!("{}={} {{", pkg, pkg_cpus.join(","))
    };
    block.push(first_line);

    // ---- 6. 写入主包线程规则 ----
    for rule in thread_rules {
        block.push(format!("    {}={}", rule.thread, rule.spec));
    }

    // ---- 7. 写入子包 ----
    for (sub_name, sub_rules_vec) in sub_rules {
        let sub_cpus: Vec<&str> = sub_rules_vec
            .iter()
            .filter(|r| r.thread.is_empty())
            .map(|r| r.spec.as_str())
            .collect();
        let sub_threads: Vec<&crate::config::AffinityRule> = sub_rules_vec
            .iter()
            .filter(|r| !r.thread.is_empty())
            .map(|&r| r)
            .collect();

        let sub_first = if sub_cpus.is_empty() {
            format!("    :{} {{", sub_name)
        } else {
            format!("    :{}={} {{", sub_name, sub_cpus.join(","))
        };
        block.push(sub_first);
        for rule in sub_threads {
            block.push(format!("        {}={}", rule.thread, rule.spec));
        }
        block.push("    }".to_string());
    }

    // ---- 8. 关闭主包块 ----
    block.push("}".to_string());
    block
}
/// 规范化主包：删除所有顶格子包独立块，替换主包块为规范化新块，保留块外注释
pub fn normalize_package_block(
    lines: &mut Vec<String>,
    pkg: &str,
    cfg: &crate::config::AppConfig,
) -> bool {
    // 1. 循环删除所有顶格的、以 "pkg:" 开头的独立子包块
    let mut changed = true;
    while changed {
        changed = false;
        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();
            let is_top_level = !lines[i].starts_with(' ') && !lines[i].starts_with('\t');
            if is_top_level && trimmed.starts_with(&format!("{}:", pkg)) {
                let pkg_name = trimmed.split('=').next().unwrap_or(trimmed).trim();
                if let Some((start, end)) = find_package_range(lines, pkg_name) {
                    lines.drain(start..=end);
                    changed = true;
                    break;
                }
            }
            i += 1;
        }
    }

    // 2. 查找主包范围
    let (start, end) = match find_package_range(lines, pkg) {
        Some((s, e)) if s <= e && e < lines.len() => (s, e),
        Some(_) => {
            eprintln!("警告: 主包 {} 范围无效，跳过规范化", pkg);
            return false;
        }
        None => {
            // 主包不存在，直接插入新块
            let new_block = build_package_block(pkg, cfg);
            if new_block.is_empty() {
                return false;
            }
            if !lines.is_empty() && !lines.last().unwrap().trim().is_empty() {
                lines.push(String::new());
            }
            lines.extend(new_block);
            lines.push(String::new());
            return true;
        }
    };

    // 3. 生成新块
    let new_block = build_package_block(pkg, cfg);
    if new_block.is_empty() {
        lines.drain(start..=end);
        return true;
    }

    // 4. 替换旧块为新块
    let block_len = new_block.len();
    lines.splice(start..=end, new_block);

    // 5. 删除主包块之后多余的残留行（缩进的非注释行和顶格的 '}'）
    let block_end = start + block_len;
    if block_end < lines.len() {
        let mut remove_indices = Vec::new();
        let mut j = block_end;
        while j < lines.len() {
            let line = &lines[j];
            let trimmed = line.trim();
            // 删除条件：缩进的非注释行，或者顶格的单独的 '}'
            let is_indented = line.starts_with(' ') || line.starts_with('\t');
            let is_sole_brace = trimmed == "}" && !is_indented;
            if (is_indented
                && !trimmed.is_empty()
                && !trimmed.starts_with('#')
                && !trimmed.starts_with("//"))
                || is_sole_brace
            {
                remove_indices.push(j);
                j += 1;
            } else {
                // 遇到空行、注释或顶格非 '}' 行，停止删除
                break;
            }
        }
        for &idx in remove_indices.iter().rev() {
            lines.remove(idx);
        }
    }

    // 6. 确保块后有空行
    let new_block_end = start + block_len;
    if new_block_end < lines.len() && !lines[new_block_end].trim().is_empty() {
        lines.insert(new_block_end, String::new());
    } else if new_block_end == lines.len() {
        lines.push(String::new());
    }

    true
}
