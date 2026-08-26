use std::collections::{BTreeMap, HashMap, HashSet};
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
    comment: Option<&str>,
    delete_all: bool,
) -> RuleEdit {
    // 辅助函数
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

    fn is_sub_block_start(line: &str, sub: &str) -> bool {
        let trimmed = line.trim();
        trimmed.starts_with(&format!(":{}", sub)) && trimmed.ends_with('{')
    }

    fn find_sub_block_range(
        lines: &[String],
        start: usize,
        end: usize,
        sub: &str,
    ) -> Option<(usize, usize)> {
        for i in start..end {
            let trimmed = lines[i].trim();
            if is_sub_block_start(trimmed, sub) {
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
                return None;
            }
        }
        None
    }

    let full_pkg = format!("{}:{}", pkg, sub);
    let mut t = target_scan(lines, pkg);

    // 确保主包是块
    if t.block_open.is_none() {
        if let Some(PkgLine::Standalone(idx)) = t.pkg_line {
            let line = &lines[idx];
            let trimmed = line.trim();
            if !trimmed.ends_with('{') {
                let comment_pos = comment_at(line);
                let new_line = if let Some(pos) = comment_pos {
                    format!("{} {{ {}", &line[..pos].trim(), &line[pos..])
                } else {
                    format!("{} {{", line.trim())
                };
                lines[idx] = new_line;
                let last = lines.last().map(|s| s.trim()).unwrap_or("");
                if !close_like(last) {
                    lines.push("}".to_string());
                }
            }
        } else {
            // 主包无规则，创建新块
            let comment_line = if let Some(c) = comment {
                format!("# {}\n", c)
            } else {
                String::new()
            };
            let sub_line = if thread.is_empty() {
                format!("\t:{}={}", sub, cpus)
            } else {
                format!("\t:{} {{\n\t\t{}={}\n\t}}", sub, thread, cpus)
            };
            let block = format!("{} {{\n{}{}\n}}", pkg, comment_line, sub_line);
            lines.push(block);
            return RuleEdit::Ok;
        }
    }

    // 再次确保闭合
    let t2 = target_scan(lines, pkg);
    if t2.block_close.is_none() {
        lines.push("}".to_string());
        t = target_scan(lines, pkg);
    } else {
        t = t2;
    }

    // 删除独立行子包
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

    // === 删除整个子包 ===
    if delete_all {
        let mut remove_indices = Vec::new();
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

    // === 包级规则操作 ===
    if thread.is_empty() {
        if !cpus.is_empty() {
            // 更新或插入
            let mut remove_indices = Vec::new();
            let mut thread_lines = Vec::new();

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

            let mut insert_lines = Vec::new();
            if let Some(c) = comment {
                if !c.is_empty() {
                    insert_lines.push(format!("\t# {}", c));
                }
            }
            if thread_lines.is_empty() {
                insert_lines.push(format!("\t:{}={}", sub, cpus));
            } else {
                insert_lines.push(format!("\t:{}={} {{", sub, cpus));
                for tl in &thread_lines {
                    let trimmed = tl.trim();
                    if !trimmed.is_empty() {
                        insert_lines.push(format!("\t\t{}", trimmed));
                    }
                }
                insert_lines.push("\t}".to_string());
            }
            for (offset, line) in insert_lines.iter().enumerate() {
                lines.insert(block_close_after + offset, line.clone());
            }
            RuleEdit::Ok
        } else {
            // 删除包级规则
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
                        let line = lines[idx].clone();
                        let comment_part = comment_at(&line)
                            .map(|pos| line[pos..].trim().to_string())
                            .unwrap_or_default();
                        lines[idx] = format!("\t:{} {{", sub);
                        if !comment_part.is_empty() {
                            lines.insert(idx + 1, format!("\t# {}", comment_part));
                        }
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
        // === 线程规则操作 ===
        if cpus.is_empty() {
            // 删除线程
            let mut removed = false;
            if let Some(close) = t.block_close {
                let start = t.block_open.unwrap_or(0);
                if let Some((block_start, block_end)) =
                    find_sub_block_range(lines, start, close, sub)
                {
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
            // 更新或插入线程
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
                    if let Some((block_start, block_end)) =
                        find_sub_block_range(lines, idx, lines.len(), sub)
                    {
                        let mut found = false;
                        for i in (block_start + 1)..block_end {
                            let line = &lines[i];
                            if let Some(name) = extract_thread_name(line) {
                                if name == thread {
                                    let comment_part =
                                        comment.map(|c| format!(" # {}", c)).unwrap_or_default();
                                    lines[i] = format!("\t\t{}={}{}", thread, cpus, comment_part);
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if !found {
                            let comment_part =
                                comment.map(|c| format!(" # {}", c)).unwrap_or_default();
                            lines.insert(
                                block_end,
                                format!("\t\t{}={}{}", thread, cpus, comment_part),
                            );
                        }
                    } else {
                        return RuleEdit::Malformed;
                    }
                } else {
                    // 包级规则行不带 '{'，转换为合并格式
                    let line = &lines[idx];
                    let comment_pos = comment_at(line);
                    let cpus_val = if let Some(eq_pos) = line.rfind('=') {
                        line[eq_pos + 1..].trim().to_string()
                    } else {
                        return RuleEdit::Malformed;
                    };
                    let new_line = if let Some(pos) = comment_pos {
                        format!("\t:{}={} {{ {}", sub, cpus_val, &line[pos..])
                    } else {
                        format!("\t:{}={} {{", sub, cpus_val)
                    };
                    lines[idx] = new_line;
                    let thread_comment = comment.map(|c| format!(" # {}", c)).unwrap_or_default();
                    lines.insert(
                        idx + 1,
                        format!("\t\t{}={}{}", thread, cpus, thread_comment),
                    );
                    lines.insert(idx + 2, "\t}".to_string());
                }
            } else {
                // 没有包级规则，创建完整的子包块
                let comment_part = comment.map(|c| format!(" # {}", c)).unwrap_or_default();
                if let Some(close) = t.block_close {
                    if let Some(c) = comment {
                        if !c.is_empty() {
                            lines.insert(close, format!("\t# {}", c));
                        }
                    }
                    lines.insert(close, format!("\t:{}={}", sub, cpus));
                    lines.insert(
                        close + 1,
                        format!(
                            "\t:{} {{\n\t\t{}={}{}\n\t}}",
                            sub, thread, cpus, comment_part
                        ),
                    );
                } else {
                    lines.push(format!("\t:{}={}", sub, cpus));
                    lines.push(format!(
                        "\t:{} {{\n\t\t{}={}{}\n\t}}",
                        sub, thread, cpus, comment_part
                    ));
                }
            }
            RuleEdit::Ok
        }
    }
}

/// 查找文件中所有名为 pkg 的顶层块范围（包括单行规则），返回 (start, end) 列表
fn find_all_package_ranges(lines: &[String], pkg: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        let is_top_level = !lines[i].starts_with(' ') && !lines[i].starts_with('\t');
        if is_top_level
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !trimmed.starts_with("//")
        {
            let line_pkg = trimmed
                .split(|c| c == '=' || c == ' ' || c == '{' || c == ':')
                .next()
                .unwrap_or("");
            if line_pkg == pkg {
                let start = i;
                let has_brace = trimmed.contains('{');
                if !has_brace {
                    ranges.push((start, start));
                    i += 1;
                    continue;
                }
                let mut depth = 0;
                let mut j = i;
                while j < lines.len() {
                    let t = lines[j].trim();
                    if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
                        j += 1;
                        continue;
                    }
                    if j > i {
                        let is_new_top = !lines[j].starts_with(' ')
                            && !lines[j].starts_with('\t')
                            && !t.is_empty()
                            && !t.starts_with('#')
                            && !t.starts_with("//");
                        if is_new_top {
                            ranges.push((start, j - 1));
                            i = j;
                            break;
                        }
                    }
                    for ch in t.chars() {
                        if ch == '{' {
                            depth += 1;
                        } else if ch == '}' {
                            depth -= 1;
                        }
                    }
                    if depth == 0 && j > i {
                        ranges.push((start, j));
                        i = j + 1;
                        break;
                    }
                    j += 1;
                }
                if i == start {
                    i += 1;
                }
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    ranges
}

pub fn normalize_package_block(
    lines: &mut Vec<String>,
    pkg: &str,
    cfg: &crate::config::AppConfig,
) -> bool {
    let first_pos = remove_all_package_blocks(lines, pkg);

    let new_block = build_package_block(pkg, cfg);
    if new_block.is_empty() {
        return true;
    }

    let insert_pos = first_pos.unwrap_or(lines.len());
    if insert_pos > 0 && !lines[insert_pos - 1].trim().is_empty() {
        lines.insert(insert_pos, String::new());
        let actual_pos = insert_pos + 1;
        let block_len = new_block.len();
        lines.splice(actual_pos..actual_pos, new_block);
        if actual_pos + block_len < lines.len() && !lines[actual_pos + block_len].trim().is_empty()
        {
            lines.insert(actual_pos + block_len, String::new());
        }
    } else {
        let block_len = new_block.len();
        lines.splice(insert_pos..insert_pos, new_block);
        if insert_pos + block_len < lines.len() && !lines[insert_pos + block_len].trim().is_empty()
        {
            lines.insert(insert_pos + block_len, String::new());
        }
    }

    true
}

pub fn rule_upsert(
    config_path: &str,
    pkg: &str,
    thread: &str,
    cpus: &str,
    comment: Option<&str>,
    cfg: &crate::config::AppConfig,
) -> RuleEdit {
    use std::collections::{HashMap, HashSet};

    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);

    let mut lines: Vec<String> = fs::read_to_string(config_path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    fn validate_cpus(
        cpus: &str,
        topo: &crate::cpuset::CpuTopology,
    ) -> Option<crate::cpuset::CpuSet> {
        if cpus.is_empty() {
            return None;
        }
        let set = crate::cpuset::parse_cpu_spec(cpus, topo);
        if set.count() == 0 { None } else { Some(set) }
    }

    let (main_pkg, sub_thread, actual_thread) = if pkg.contains(':') {
        let parts: Vec<&str> = pkg.splitn(2, ':').collect();
        if parts.len() == 2 {
            (
                parts[0].to_string(),
                format!(":{}", parts[1]),
                thread.to_string(),
            )
        } else {
            (pkg.to_string(), thread.to_string(), String::new())
        }
    } else if thread.starts_with(':') {
        (pkg.to_string(), thread.to_string(), String::new())
    } else {
        (pkg.to_string(), String::new(), thread.to_string())
    };

    let child_pkg = if !sub_thread.is_empty() && sub_thread.starts_with(':') {
        format!("{}{}", main_pkg, sub_thread)
    } else {
        String::new()
    };

    // ---- 构建新规则集合 ----
    let mut new_rules = Vec::new();

    for r in &cfg.rules {
        // 跳过所有与目标相关的旧规则
        // 情况1：外部子包包级 (pkg==main_pkg, thread==sub_thread)
        if !sub_thread.is_empty() && r.pkg == main_pkg && r.thread == sub_thread {
            continue;
        }
        // 情况2：主包线程 (pkg==main_pkg, thread==actual_thread, sub_thread为空)
        if sub_thread.is_empty()
            && !actual_thread.is_empty()
            && r.pkg == main_pkg
            && r.thread == actual_thread
        {
            continue;
        }
        // 情况3：子包内部线程 (pkg==child_pkg, thread==actual_thread)
        if !sub_thread.is_empty()
            && !actual_thread.is_empty()
            && r.pkg == child_pkg
            && r.thread == actual_thread
        {
            continue;
        }
        // 情况4：主包包级 (sub_thread空且actual_thread空)
        if sub_thread.is_empty()
            && actual_thread.is_empty()
            && r.pkg == main_pkg
            && r.thread.is_empty()
        {
            continue;
        }
        // 情况5：可能残留的其他形式，例如 pkg==main_pkg && thread==actual_thread 但 actual_thread 可能与子包同名？不处理。
        new_rules.push(r.clone());
    }

    // ---- 添加新规则 ----
    if !cpus.is_empty() {
        if let Some(cpuset) = validate_cpus(cpus, &cfg.topo) {
            let (new_pkg, new_thread) = if !sub_thread.is_empty() {
                if actual_thread.is_empty() {
                    (main_pkg.clone(), sub_thread.clone())
                } else {
                    (child_pkg.clone(), actual_thread.clone())
                }
            } else {
                (main_pkg.clone(), actual_thread.clone())
            };

            let cpuset_dir = if new_thread.is_empty() {
                crate::cpuset::ensure_cpuset_dir(&cpuset, &cfg.topo)
            } else {
                String::new()
            };

            let final_comment = if let Some(c) = comment {
                c.to_string()
            } else if let Some(old) = cfg
                .rules
                .iter()
                .find(|r| r.pkg == new_pkg && r.thread == new_thread)
            {
                old.comment.clone()
            } else {
                String::new()
            };

            let new_rule = crate::config::AffinityRule {
                pkg: new_pkg.clone(),
                thread: new_thread.clone(),
                thread_pattern: std::ffi::CString::new(new_thread.as_str()).unwrap_or_default(),
                cpuset_dir,
                cpus: cpuset,
                spec: cpus.to_string(),
                comment: final_comment,
            };

            // 去重：移除已存在的相同 (pkg, thread)
            new_rules.retain(|r| !(r.pkg == new_pkg && r.thread == new_thread));
            new_rules.push(new_rule);
        } else {
            return RuleEdit::Malformed;
        }
    }

    // ---- 最终去重（全局） ----
    let mut seen = HashSet::new();
    new_rules.retain(|r| seen.insert((r.pkg.clone(), r.thread.clone())));

    if new_rules.is_empty() {
        remove_all_package_blocks(&mut lines, &main_pkg);
        clean_empty_lines(&mut lines);
        return file_write(config_path, &lines);
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

    if normalize_package_block(&mut lines, &main_pkg, &new_cfg) {
        clean_empty_lines(&mut lines);
        file_write(config_path, &lines)
    } else {
        RuleEdit::Malformed
    }
}

/// 清理空块（若块内只有注释或空行，则删除整个块）
fn clean_empty_blocks(lines: &mut Vec<String>, pkg: &str) {
    let ranges = find_all_package_ranges(lines, pkg);
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
    let ranges = find_all_package_ranges(lines, &sub_pkg);
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
            let result = write_sub_pkg_block(&mut lines, main_pkg, sub, thread, "", None, false);
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
    let ranges = find_all_package_ranges(&lines, pkg);
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

    let ranges = find_all_package_ranges(&lines, pkg);
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
pub fn build_package_block(pkg: &str, cfg: &crate::config::AppConfig) -> Vec<String> {
    use std::collections::BTreeMap;

    // ---- 子包节点结构 ----
    #[derive(Clone)]
    struct SubPkg {
        pkg_rule: Option<crate::config::AffinityRule>, // 包级规则（thread 为空，spec 非空）
        threads: Vec<crate::config::AffinityRule>,     // 线程规则（thread 不以 ':' 开头）
        subs: BTreeMap<String, SubPkg>,                // 子包（key 为子包名）
    }

    // ---- 递归构建子包树，同时处理内部子包规则 ----
    fn build_sub_pkg_tree(
        parent_pkg: &str,
        cfg: &crate::config::AppConfig,
    ) -> (
        Option<crate::config::AffinityRule>, // 父包自身的包级规则
        Vec<crate::config::AffinityRule>,    // 父包自身的线程规则
        BTreeMap<String, SubPkg>,            // 子包树
    ) {
        let mut pkg_rule: Option<crate::config::AffinityRule> = None;
        let mut threads: Vec<crate::config::AffinityRule> = Vec::new();
        let mut subs: BTreeMap<String, SubPkg> = BTreeMap::new();

        // 1. 收集直接属于 parent_pkg 的规则（pkg 完全相等）
        for rule in cfg.rules.iter().filter(|r| r.pkg == parent_pkg) {
            if rule.thread.is_empty() {
                pkg_rule = Some(rule.clone());
            } else if rule.thread.starts_with(':') {
                // 外部子包规则（thread = :子包名）
                let sub_name = rule.thread.trim_start_matches(':').trim().to_string();
                if !sub_name.is_empty() {
                    let entry = subs.entry(sub_name).or_insert_with(|| SubPkg {
                        pkg_rule: None,
                        threads: Vec::new(),
                        subs: BTreeMap::new(),
                    });
                    entry.pkg_rule = Some(rule.clone());
                }
            } else {
                threads.push(rule.clone());
            }
        }

        // 2. 收集所有内部子包规则（pkg 为 parent_pkg:子包名）
        let prefix = format!("{}:", parent_pkg);
        let internal_rules: Vec<&crate::config::AffinityRule> = cfg
            .rules
            .iter()
            .filter(|r| r.pkg.starts_with(&prefix) && r.pkg != parent_pkg)
            .collect();

        // 按子包名分组
        let mut internal_map: BTreeMap<String, Vec<&crate::config::AffinityRule>> = BTreeMap::new();
        for rule in internal_rules {
            // 提取子包名（去掉前缀）
            let sub_name = rule.pkg.trim_start_matches(&prefix).to_string();
            if !sub_name.is_empty() {
                internal_map.entry(sub_name).or_default().push(rule);
            }
        }

        // 将内部规则合并到对应的子包中
        for (sub_name, rules) in internal_map {
            let entry = subs.entry(sub_name.clone()).or_insert_with(|| SubPkg {
                pkg_rule: None,
                threads: Vec::new(),
                subs: BTreeMap::new(),
            });
            for rule in rules {
                if rule.thread.is_empty() {
                    // 子包包级规则
                    entry.pkg_rule = Some((*rule).clone());
                } else {
                    // 子包内部线程规则
                    entry.threads.push((*rule).clone());
                }
            }
        }

        // 3. 递归处理每个子包的内部结构（即子包的子包）
        // 注意：子包的子包可能以 "parent_pkg:子包名:孙子名" 形式存在，但在我们的数据结构中，
        // 递归调用时，父包变为 "parent_pkg:子包名"，从而自动处理更深层。
        let sub_names: Vec<String> = subs.keys().cloned().collect();
        for sub_name in sub_names {
            let child_pkg = format!("{}:{}", parent_pkg, sub_name);
            let (child_pkg_rule, child_threads, child_subs) = build_sub_pkg_tree(&child_pkg, cfg);
            let entry = subs.get_mut(&sub_name).unwrap();
            // 递归返回的包级规则优先（可能包含更完整的 spec）
            if let Some(rule) = child_pkg_rule {
                entry.pkg_rule = Some(rule);
            }
            // 追加递归返回的线程规则（通常由内部线程规则产生，但可能重复，需去重？简单追加）
            // 为避免重复，可先合并去重，但这里线程名唯一，直接扩展
            entry.threads.extend(child_threads);
            // 合并子包
            for (child_sub, child_sub_data) in child_subs {
                entry.subs.insert(child_sub, child_sub_data);
            }
        }

        (pkg_rule, threads, subs)
    }

    // ---- 构建主包树 ----
    let (main_pkg_rule, main_threads, main_subs) = build_sub_pkg_tree(pkg, cfg);

    let mut block = Vec::new();

    // ---- 主包独立注释 ----
    if let Some(rule) = &main_pkg_rule {
        if !rule.comment.is_empty() {
            block.push(format!("# {}", rule.comment));
        }
    }

    // ---- 主包第一行 ----
    let spec_str = main_pkg_rule
        .as_ref()
        .map(|r| r.spec.as_str())
        .unwrap_or("");
    let first_line = if spec_str.is_empty() {
        format!("{} {{", pkg)
    } else {
        format!("{}={} {{", pkg, spec_str)
    };
    block.push(first_line);

    // ---- 主包线程规则（缩进 4） ----
    for rule in &main_threads {
        let mut line = format!("    {}={}", rule.thread, rule.spec);
        if !rule.comment.is_empty() {
            line.push_str(&format!(" # {}", rule.comment));
        }
        block.push(line);
    }

    // ---- 递归生成子包 ----
    fn generate_sub_pkg(sub_name: &str, sub: &SubPkg, indent: usize, block: &mut Vec<String>) {
        let indent_str = "    ".repeat(indent);
        let inner_indent = "    ".repeat(indent + 1);

        // 子包独立注释
        if let Some(rule) = &sub.pkg_rule {
            if !rule.comment.is_empty() {
                block.push(format!("{}# {}", indent_str, rule.comment));
            }
        }

        // 决定生成单行还是块
        let has_pkg_cpus = sub.pkg_rule.as_ref().map_or(false, |r| !r.spec.is_empty());
        let has_content = !sub.threads.is_empty() || !sub.subs.is_empty();

        if has_pkg_cpus && !has_content {
            // 只有包级规则，没有内容 -> 单行
            let spec = sub.pkg_rule.as_ref().unwrap().spec.as_str();
            block.push(format!("{}:{}={}", indent_str, sub_name, spec));
        } else {
            // 有内容或需要开块
            let sub_first = if has_pkg_cpus {
                let spec = sub.pkg_rule.as_ref().unwrap().spec.as_str();
                format!("{}:{}={} {{", indent_str, sub_name, spec)
            } else {
                format!("{}:{} {{", indent_str, sub_name)
            };
            block.push(sub_first);

            // 线程规则（缩进 +1）
            for rule in &sub.threads {
                let mut line = format!("{}{}={}", inner_indent, rule.thread, rule.spec);
                if !rule.comment.is_empty() {
                    line.push_str(&format!(" # {}", rule.comment));
                }
                block.push(line);
            }

            // 递归生成子包的子包
            for (child_name, child_sub) in &sub.subs {
                generate_sub_pkg(child_name, child_sub, indent + 1, block);
            }

            // 闭合块
            block.push(format!("{}}}", indent_str));
        }
    }

    // 生成所有顶级子包（缩进 1）
    for (sub_name, sub) in &main_subs {
        generate_sub_pkg(sub_name, sub, 1, &mut block);
    }

    // 主包闭合
    block.push("}".to_string());
    block.push(String::new()); // 末尾空行

    block
}

/// 精确查找包名为 pkg 的顶层块范围（不拆分冒号），返回 (start, end)
/// pkg 可以是 "主包" 或 "主包:子包"
fn find_package_range(lines: &[String], pkg: &str) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        let is_top_level = !lines[i].starts_with(' ') && !lines[i].starts_with('\t');
        if is_top_level
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !trimmed.starts_with("//")
        {
            // 精确匹配包名（允许后面跟着 =、{、空格）
            let line_pkg = trimmed
                .split(|c| c == '=' || c == ' ' || c == '{')
                .next()
                .unwrap_or("");
            if line_pkg == pkg {
                let start = i;
                let has_brace = trimmed.contains('{');
                if !has_brace {
                    return Some((start, start));
                }
                let mut depth = 0;
                let mut j = i;
                while j < lines.len() {
                    let t = lines[j].trim();
                    if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
                        j += 1;
                        continue;
                    }
                    if j > i {
                        // 遇到新的顶层包（顶格且不是当前行）则结束
                        let is_new_top = !lines[j].starts_with(' ')
                            && !lines[j].starts_with('\t')
                            && !t.is_empty()
                            && !t.starts_with('#')
                            && !t.starts_with("//");
                        if is_new_top {
                            return Some((start, j - 1));
                        }
                    }
                    for ch in t.chars() {
                        if ch == '{' {
                            depth += 1;
                        } else if ch == '}' {
                            depth -= 1;
                        }
                    }
                    if depth == 0 && j > i {
                        return Some((start, j));
                    }
                    j += 1;
                }
                return Some((start, i));
            }
        }
        i += 1;
    }
    None
}

fn find_package_range_exact(lines: &[String], pkg: &str) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        let is_top_level = !lines[i].starts_with(' ') && !lines[i].starts_with('\t');
        if is_top_level
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !trimmed.starts_with("//")
        {
            let line_pkg = trimmed
                .split(|c| c == '=' || c == ' ' || c == '{')
                .next()
                .unwrap_or("");
            if line_pkg == pkg {
                let start = i;
                let has_brace = trimmed.contains('{');
                if !has_brace {
                    return Some((start, start));
                }
                let mut depth = 0;
                let mut j = i;
                while j < lines.len() {
                    let t = lines[j].trim();
                    if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
                        j += 1;
                        continue;
                    }
                    if j > i {
                        let is_new_top = !lines[j].starts_with(' ')
                            && !lines[j].starts_with('\t')
                            && !t.is_empty()
                            && !t.starts_with('#')
                            && !t.starts_with("//");
                        if is_new_top {
                            return Some((start, j - 1));
                        }
                    }
                    for ch in t.chars() {
                        if ch == '{' {
                            depth += 1;
                        } else if ch == '}' {
                            depth -= 1;
                        }
                    }
                    if depth == 0 && j > i {
                        return Some((start, j));
                    }
                    j += 1;
                }
                return Some((start, lines.len() - 1));
            }
        }
        i += 1;
    }
    None
}

fn remove_all_package_blocks(lines: &mut Vec<String>, pkg: &str) -> Option<usize> {
    let mut first_start = None;
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        let is_top_level = !lines[i].starts_with(' ') && !lines[i].starts_with('\t');
        if is_top_level
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !trimmed.starts_with("//")
        {
            let line_pkg = trimmed
                .split(|c| c == '=' || c == ' ' || c == '{')
                .next()
                .unwrap_or("")
                .trim();
            if line_pkg == pkg || line_pkg.starts_with(&format!("{}:", pkg)) {
                let start = i;
                let mut end = i;
                if trimmed.contains('{') {
                    let mut depth = 0;
                    let mut j = i;
                    while j < lines.len() {
                        let t = lines[j].trim();
                        if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
                            j += 1;
                            continue;
                        }
                        if j > i {
                            let is_new_top = !lines[j].starts_with(' ')
                                && !lines[j].starts_with('\t')
                                && !t.is_empty()
                                && !t.starts_with('#')
                                && !t.starts_with("//");
                            if is_new_top {
                                end = j - 1;
                                break;
                            }
                        }
                        for ch in t.chars() {
                            if ch == '{' {
                                depth += 1;
                            } else if ch == '}' {
                                depth -= 1;
                            }
                        }
                        if depth == 0 && j > i {
                            end = j;
                            break;
                        }
                        j += 1;
                    }
                } else {
                    end = i;
                }

                let mut s = start;
                while s > 0 {
                    let prev = s - 1;
                    let trimmed_prev = lines[prev].trim();
                    if trimmed_prev.is_empty() {
                        break;
                    }
                    if lines[prev].starts_with('#')
                        && !lines[prev].starts_with(' ')
                        && !lines[prev].starts_with('\t')
                    {
                        s = prev;
                    } else {
                        break;
                    }
                }
                let mut e = end;
                let mut next = e + 1;
                while next < lines.len() {
                    let trimmed_next = lines[next].trim();
                    if trimmed_next == "}"
                        && !lines[next].starts_with(' ')
                        && !lines[next].starts_with('\t')
                    {
                        e = next;
                        next += 1;
                    } else if trimmed_next.is_empty() {
                        break;
                    } else {
                        break;
                    }
                }

                if first_start.is_none() {
                    first_start = Some(s);
                }
                lines.drain(s..=e);
                i = s;
                continue;
            }
        }
        i += 1;
    }
    first_start
}
