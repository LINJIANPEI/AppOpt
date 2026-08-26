use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::sync::Mutex;

#[derive(Debug)]
pub enum RuleEdit {
    Ok,
    NotFound,
    Conflict,
    Malformed,
    IoErr,
}

static WRITE_LOCK: Mutex<()> = Mutex::new(());

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
    use std::collections::HashSet;

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

    // ---- 参数规范化 ----
    // 核心修改：区分三种情况
    // 1) pkg 包含 ':' -> 子包自身规则（即 pkg="主包:子包"，thread 为实际线程名或空）
    // 2) thread 以 ':' 开头 -> 外部子包规则（主包中的 :子包=...）
    // 3) 其他 -> 主包自身规则
    let (main_pkg, sub_thread, actual_thread) = if pkg.contains(':') {
        // 子包自身规则（包括包级和线程级）
        (pkg.to_string(), String::new(), thread.to_string())
    } else if thread.starts_with(':') {
        // 外部子包规则（添加子进程时使用）
        (pkg.to_string(), thread.to_string(), String::new())
    } else {
        // 主包规则
        (pkg.to_string(), String::new(), thread.to_string())
    };

    if !sub_thread.is_empty() && sub_thread.starts_with(':') {
        format!("{}{}", main_pkg, sub_thread)
    } else {
        String::new()
    };

    // ---- 精确收集要删除的规则（仅针对目标本身） ----
    let mut to_remove = HashSet::new();

    // 1. 操作子包包级（sub_thread非空，actual_thread空）
    if !sub_thread.is_empty() && actual_thread.is_empty() {
        // 子包自身包级规则
        to_remove.insert((main_pkg.clone(), String::new()));
        // 同时删除可能残留的外部规则（主包中的 :子包=...）
        to_remove.insert((main_pkg.clone(), sub_thread.clone()));
    }
    // 2. 操作主包线程（sub_thread空，actual_thread非空）
    else if sub_thread.is_empty() && !actual_thread.is_empty() {
        to_remove.insert((main_pkg.clone(), actual_thread.clone()));
    }
    // 3. 操作子包内部线程（sub_thread空，actual_thread非空，且 main_pkg 包含 ':'）
    else if sub_thread.is_empty() && !actual_thread.is_empty() && main_pkg.contains(':') {
        to_remove.insert((main_pkg.clone(), actual_thread.clone()));
    }
    // 4. 操作主包包级（两者都空）
    else if sub_thread.is_empty() && actual_thread.is_empty() {
        to_remove.insert((main_pkg.clone(), String::new()));
    }

    // ---- 构建新规则：跳过待删除的，保留所有其他 ----
    let mut new_rules = Vec::new();
    for r in &cfg.rules {
        if to_remove.contains(&(r.pkg.clone(), r.thread.clone())) {
            continue;
        }
        new_rules.push(r.clone());
    }

    // ---- 添加新规则 ----
    if !cpus.is_empty() {
        if let Some(cpuset) = validate_cpus(cpus, &cfg.topo) {
            // 确定新规则的 pkg 和 thread
            let (new_pkg, new_thread) = if !sub_thread.is_empty() && sub_thread.starts_with(':') {
                // 外部子包规则（pkg=主包，thread=:子包）
                (main_pkg.clone(), sub_thread.clone())
            } else if main_pkg.contains(':') {
                // 子包自身规则
                (main_pkg.clone(), actual_thread.clone())
            } else {
                // 主包规则
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

            // 从 new_rules 中移除可能已存在的相同 (pkg, thread)
            new_rules.retain(|r| !(r.pkg == new_pkg && r.thread == new_thread));
            new_rules.push(new_rule);
        } else {
            return RuleEdit::Malformed;
        }
    }

    // ---- 全局去重 ----
    let mut seen = HashSet::new();
    new_rules.retain(|r| seen.insert((r.pkg.clone(), r.thread.clone())));

    // 如果没有任何规则，删除整个主包
    if new_rules.is_empty() {
        let main_pkg_name = main_pkg.split(':').next().unwrap_or(&main_pkg);
        remove_all_package_blocks(&mut lines, main_pkg_name);
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

    let main_pkg_name = main_pkg.split(':').next().unwrap_or(&main_pkg);
    if normalize_package_block(&mut lines, main_pkg_name, &new_cfg) {
        clean_empty_lines(&mut lines);
        file_write(config_path, &lines)
    } else {
        RuleEdit::Malformed
    }
}

pub fn rule_delete(config_path: &str, pkg: &str, thread: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);

    let Some(cfg) = crate::CURRENT_CONFIG.lock().unwrap().clone() else {
        return RuleEdit::NotFound;
    };

    // 构建新规则列表：删除目标 (pkg, thread)
    let mut new_rules = Vec::new();
    for r in cfg.rules.iter() {
        if r.pkg == pkg && r.thread == thread {
            continue;
        }
        // 如果指定了 thread 为空，且传入的 pkg 是子包（含 ':'），则只删除该子包的包级规则（thread空）
        // 但 thread 已经传入，上面已经匹配了，所以这里不用额外处理
        new_rules.push(r.clone());
    }

    // 如果没有变化（找不到规则），返回 NotFound
    if new_rules.len() == cfg.rules.len() {
        return RuleEdit::NotFound;
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

    let mut lines: Vec<String> = fs::read_to_string(config_path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    // 提取主包名（如果 pkg 包含 ':'，取第一部分）
    let main_pkg = pkg.split(':').next().unwrap_or(pkg);

    if normalize_package_block(&mut lines, main_pkg, &new_cfg) {
        clean_empty_lines(&mut lines);
        file_write(config_path, &lines)
    } else {
        RuleEdit::Malformed
    }
}

pub fn rule_delete_pkg(config_path: &str, pkg: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);

    let Some(cfg) = crate::CURRENT_CONFIG.lock().unwrap().clone() else {
        return RuleEdit::NotFound;
    };

    // 删除所有该包名的规则（包括主包和子包）
    let mut new_rules = Vec::new();
    for r in cfg.rules.iter() {
        if r.pkg == pkg || r.pkg.starts_with(&format!("{}:", pkg)) {
            continue;
        }
        new_rules.push(r.clone());
    }

    if new_rules.len() == cfg.rules.len() {
        return RuleEdit::NotFound;
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

    let mut lines: Vec<String> = fs::read_to_string(config_path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    let main_pkg = pkg.split(':').next().unwrap_or(pkg);

    if normalize_package_block(&mut lines, main_pkg, &new_cfg) {
        clean_empty_lines(&mut lines);

        file_write(config_path, &lines)
    } else {
        RuleEdit::Malformed
    }
}

pub fn rule_rename(path: &str, old: &str, new: &str) -> RuleEdit {
    let _guard = crate::lock_ignore_poison(&WRITE_LOCK);

    // 1. 加载当前配置（从文件重新解析，避免缓存）
    let mut tmp_mtime = -1;
    let topo = {
        let cfg_opt = crate::CURRENT_CONFIG.lock().unwrap();
        cfg_opt
            .as_ref()
            .map(|c| c.topo.clone())
            .unwrap_or_else(crate::cpuset::init_cpu_topo)
    };
    let cfg = match crate::config::load_config(path, &topo, &mut tmp_mtime) {
        Some(c) => c,
        None => return RuleEdit::IoErr,
    };

    // 2. 检查旧包是否存在
    let old_exists = cfg
        .rules
        .iter()
        .any(|r| r.pkg == old || r.pkg.starts_with(&format!("{}:", old)));
    if !old_exists {
        return RuleEdit::NotFound;
    }

    // 3. 检查新包是否已存在（不允许覆盖）
    let new_exists = cfg
        .rules
        .iter()
        .any(|r| r.pkg == new || r.pkg.starts_with(&format!("{}:", new)));
    if new_exists {
        return RuleEdit::Conflict;
    }

    // 4. 构建新规则列表：将所有旧包名替换为新包名
    let mut new_rules = Vec::new();
    let old_with_colon = format!("{}:", old);
    let new_with_colon = format!("{}:", new);
    for rule in cfg.rules {
        let mut new_rule = rule.clone();
        if rule.pkg == old {
            new_rule.pkg = new.to_string();
        } else if rule.pkg.starts_with(&old_with_colon) {
            let suffix = &rule.pkg[old_with_colon.len()..];
            new_rule.pkg = format!("{}{}", new_with_colon, suffix);
        } else {
            new_rules.push(rule);
            continue;
        }
        // 更新线程模式（如果 thread 非空）
        new_rule.thread_pattern =
            std::ffi::CString::new(new_rule.thread.as_str()).unwrap_or_default();
        new_rules.push(new_rule);
    }

    // 5. 重新构建 pkgs 和 has_thread_rules
    let pkgs: std::collections::HashSet<String> = new_rules.iter().map(|r| r.pkg.clone()).collect();
    let has_thread_rules: std::collections::HashSet<String> = new_rules
        .iter()
        .filter(|r| !r.thread.is_empty())
        .map(|r| r.pkg.clone())
        .collect();

    let new_cfg = crate::config::AppConfig {
        rules: new_rules,
        pkgs,
        has_thread_rules,
        topo,
    };

    // 6. 读取现有文件内容
    let mut lines: Vec<String> = fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    // 7. 提取主包名（用于定位块）
    let main_pkg_old = old.split(':').next().unwrap_or(old);
    let main_pkg_new = new.split(':').next().unwrap_or(new);

    // 8. 删除所有以旧主包名开头的顶层块（包括主包和子包）
    //    remove_all_package_blocks 返回第一个被删除块的起始索引（如果存在）
    let insert_pos = remove_all_package_blocks(&mut lines, main_pkg_old).unwrap_or_else(|| {
        // 如果没有找到旧块（可能因为文件格式问题），则插入到文件末尾
        lines.len()
    });

    // 9. 构建新块的内容（基于新配置）
    let new_block = build_package_block(main_pkg_new, &new_cfg);
    if new_block.is_empty() {
        // 没有规则，只删除旧块即可
        clean_empty_lines(&mut lines);
        return file_write(path, &lines);
    }

    // 10. 在原来旧块的位置插入新块
    lines.splice(insert_pos..insert_pos, new_block);

    // 11. 清理多余空行，写入文件
    clean_empty_lines(&mut lines);
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
        Option<crate::config::AffinityRule>,
        Vec<crate::config::AffinityRule>,
        BTreeMap<String, SubPkg>,
    ) {
        let mut pkg_rule: Option<crate::config::AffinityRule> = None;
        let mut threads: Vec<crate::config::AffinityRule> = Vec::new();
        let mut subs: BTreeMap<String, SubPkg> = BTreeMap::new();

        // 第一步：收集直接属于 parent_pkg 的规则
        for rule in cfg.rules.iter().filter(|r| r.pkg == parent_pkg) {
            if rule.thread.is_empty() {
                pkg_rule = Some(rule.clone());
            } else if rule.thread.starts_with(':') {
                // 外部子包规则（主包中写 :子包=... 或 :子包 { ... }）
                let sub_name = rule.thread.trim_start_matches(':').trim().to_string();
                if !sub_name.is_empty() {
                    let entry = subs.entry(sub_name.clone()).or_insert_with(|| SubPkg {
                        pkg_rule: None,
                        threads: Vec::new(),
                        subs: BTreeMap::new(),
                    });
                    // 外部规则可作为子包包级规则的候选，但不覆盖子包自身的包级规则
                    if entry.pkg_rule.is_none() {
                        // 克隆外部规则，但稍后需要将其 pkg 改为 child_pkg，thread 设为空
                        entry.pkg_rule = Some(rule.clone());
                    }
                }
            } else {
                threads.push(rule.clone());
            }
        }

        // 第二步：从所有规则中找出以 parent_pkg: 开头的子包（即使没有外部规则）
        let child_prefix = format!("{}:", parent_pkg);
        let sub_names_from_rules: std::collections::HashSet<String> = cfg
            .rules
            .iter()
            .filter_map(|r| {
                if r.pkg.starts_with(&child_prefix) && r.pkg != parent_pkg {
                    r.pkg.strip_prefix(&child_prefix).map(|s| s.to_string())
                } else {
                    None
                }
            })
            .collect();

        for sub_name in sub_names_from_rules {
            if !subs.contains_key(&sub_name) {
                subs.insert(
                    sub_name.clone(),
                    SubPkg {
                        pkg_rule: None,
                        threads: Vec::new(),
                        subs: BTreeMap::new(),
                    },
                );
            }
        }

        // 第三步：递归处理每个子包
        let sub_names: Vec<String> = subs.keys().cloned().collect();
        for sub_name in sub_names {
            let child_pkg = format!("{}:{}", parent_pkg, sub_name);
            let (child_pkg_rule, child_threads, child_subs) = build_sub_pkg_tree(&child_pkg, cfg);

            let entry = subs.get_mut(&sub_name).unwrap();

            // 子包的包级规则：优先使用 child_pkg_rule（即 pkg == child_pkg 且 thread 为空）
            if let Some(rule) = child_pkg_rule {
                entry.pkg_rule = Some(rule);
            } else if let Some(external_rule) = entry.pkg_rule.take() {
                // 外部规则存在，但没有子包自身的包级规则，则将外部规则转换为子包的包级规则
                let mut rule = external_rule.clone();
                rule.pkg = child_pkg.clone();
                rule.thread = String::new();
                rule.thread_pattern = std::ffi::CString::new("").unwrap_or_default();
                entry.pkg_rule = Some(rule);
            }

            // 合并子包的线程规则
            entry.threads.extend(child_threads);

            // 合并子包的子包
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
