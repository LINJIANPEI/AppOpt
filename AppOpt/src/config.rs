use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use crate::cpuset::{CpuSet, CpuTopology, base_cpuset, create_cpuset_dir, parse_cpu_spec};
use crate::{CONFIG_UPDATED, MAX_PKG_LEN, MAX_THREAD_LEN, lock_ignore_poison};

pub static INOTIFY_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static INOTIFY_FD: AtomicI32 = AtomicI32::new(-1);
pub static INOTIFY_WD: AtomicI32 = AtomicI32::new(-1);

/// 运行时可调参数，web 端热更新
pub static CHECK_INTERVAL: AtomicU64 = AtomicU64::new(2);
pub static FORCE_RELOAD: AtomicBool = AtomicBool::new(false);
pub static CONFIG_FILE: Mutex<String> = Mutex::new(String::new());

#[derive(Clone)]
pub struct AffinityRule {
    pub pkg: String,
    pub thread: String,
    pub thread_pattern: CString,
    pub cpuset_dir: String,
    pub cpus: CpuSet,
    pub spec: String,
    pub comment: String, // 注释（不含前缀符号）
}

pub struct AppConfig {
    pub rules: Vec<AffinityRule>,
    pub pkgs: HashSet<String>,
    pub has_thread_rules: HashSet<String>,
    pub topo: CpuTopology,
}

pub static CURRENT_CONFIG: Mutex<Option<Arc<AppConfig>>> = Mutex::new(None);
pub static PARSE_FAILS: AtomicUsize = AtomicUsize::new(0);

/// 校验 CPU 规格形态
pub fn spec_like(s: &str) -> bool {
    let mut any = false;
    for part in s.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        any = true;
        let ok = matches!(t, "e-core" | "p-core" | "hp-core" | "all-core")
            || t.bytes().all(|b| b.is_ascii_digit())
            || t.split_once('-').is_some_and(|(a, b)| {
                !a.is_empty()
                    && !b.is_empty()
                    && a.bytes().all(|b| b.is_ascii_digit())
                    && b.bytes().all(|b| b.is_ascii_digit())
            });
        if !ok {
            return false;
        }
    }
    any
}

/// 返回注释开始位置（不含前导空白）
pub fn comment_at(s: &str) -> Option<usize> {
    let mut prev_ws = false;
    for (i, c) in s.char_indices() {
        if prev_ws && (c == '#' || (c == '/' && s[i..].starts_with("//"))) {
            return Some(s[..i].trim_end().len());
        }
        prev_ws = c.is_whitespace();
    }
    None
}

pub fn strip_comment(s: &str) -> &str {
    &s[..comment_at(s).unwrap_or(s.len())]
}

/// 从一行中分离规则部分和行尾注释（不含 # 或 // 前缀）
pub fn split_comment(line: &str) -> (&str, &str) {
    if let Some(pos) = comment_at(line) {
        let rule = line[..pos].trim();
        let mut comm = line[pos..].trim();
        if let Some(rest) = comm.strip_prefix('#') {
            comm = rest.trim();
        } else if let Some(rest) = comm.strip_prefix("//") {
            comm = rest.trim();
        }
        (rule, comm)
    } else {
        (line.trim(), "")
    }
}

pub fn split_rule_line(p: &str) -> Option<(&str, &str, bool)> {
    let p = strip_comment(p);
    fn kv(s: &str) -> Option<(&str, &str)> {
        s.rfind('=')
            .map(|eq| (s[..eq].trim(), s[eq + 1..].trim()))
            .filter(|(k, _)| !k.is_empty())
    }
    p.match_indices('}')
        .find_map(|(cb, _)| kv(&p[..cb]).map(|(k, v)| (k, v, true)))
        .or_else(|| kv(p).map(|(k, v)| (k, v, false)))
}

pub fn close_like(p: &str) -> bool {
    p.strip_prefix('}').is_some_and(|r| {
        r.is_empty()
            || r.starts_with(char::is_whitespace)
            || r.starts_with('#')
            || r.starts_with("//")
    })
}

pub fn split_single_line(body: &str) -> Option<(&str, &str, &str)> {
    let eq = body.rfind('=')?;
    let cpus = body[eq + 1..].trim();
    let left = body[..eq].trim_end().strip_suffix('}')?.trim_end();
    let ob = left.find('{')?;
    let (pkg, thread) = (left[..ob].trim(), left[ob + 1..].trim());
    (!pkg.is_empty() && !thread.is_empty()).then_some((pkg, thread, cpus))
}

pub enum OuterLine<'a> {
    Rule {
        pkg: &'a str,
        cpus: &'a str,
        open: bool,
    },
    BareOpen {
        pkg: &'a str,
    },
    Pending {
        pkg: &'a str,
    },
    Single {
        pkg: &'a str,
        thread: &'a str,
        cpus: &'a str,
        open: bool,
    },
    Junk,
    SubPkgRule {
        sub: &'a str,
        cpus: &'a str,
        open: bool,
    },
    SubPkgBlock {
        sub: &'a str,
    },
}

pub fn parse_outer(p: &str) -> OuterLine<'_> {
    let p = strip_comment(p);
    let trimmed = p.trim();

    if let Some(rest) = trimmed.strip_prefix(':') {
        if let Some(eq_pos) = rest.rfind('=') {
            let sub = rest[..eq_pos].trim();
            let cpus = rest[eq_pos + 1..].trim();
            if !sub.is_empty() && !cpus.is_empty() {
                let open = rest.ends_with('{') || rest.ends_with(" {");
                return OuterLine::SubPkgRule { sub, cpus, open };
            }
        }
        if let Some(rest2) = rest.strip_suffix('{') {
            let sub = rest2.trim();
            if !sub.is_empty() {
                return OuterLine::SubPkgBlock { sub };
            }
        }
        return OuterLine::Pending { pkg: trimmed };
    }

    let (open, body) = match trimmed.strip_suffix('{') {
        Some(b) => (true, b.trim_end()),
        None => (false, trimmed),
    };

    if let Some((pkg, thread, cpus)) = split_single_line(body) {
        return OuterLine::Single {
            pkg,
            thread,
            cpus,
            open,
        };
    }

    if !open && close_like(body) {
        return OuterLine::Junk;
    }

    match body.rfind('=') {
        Some(eq) => {
            let (pkg, cpus) = (body[..eq].trim(), body[eq + 1..].trim());
            if cpus.is_empty() {
                return if open {
                    OuterLine::BareOpen { pkg }
                } else {
                    OuterLine::Pending { pkg }
                };
            }
            OuterLine::Rule { pkg, cpus, open }
        }
        None => {
            if open {
                OuterLine::BareOpen { pkg: body }
            } else {
                OuterLine::Pending { pkg: body }
            }
        }
    }
}

fn add_rule(
    rules: &mut Vec<AffinityRule>,
    topo: &CpuTopology,
    pkg: &str,
    thread: &str,
    cpus_spec: &str,
    comment: &str,
) -> bool {
    if pkg.is_empty() || pkg.len() >= MAX_PKG_LEN || thread.len() >= MAX_THREAD_LEN {
        return false;
    }
    if pkg
        .bytes()
        .chain(thread.bytes())
        .any(|b| b < 0x20 || b == 0x7f)
    {
        return false;
    }
    if !spec_like(cpus_spec) {
        return false;
    }
    let set = parse_cpu_spec(cpus_spec, topo);
    if set.count() == 0 {
        return false;
    }
    let cpuset_dir = if thread.is_empty() {
        let dir_name = set.to_range_string();
        if topo.cpuset_enabled {
            let path = format!("{}/{}", base_cpuset(), dir_name);
            if create_cpuset_dir(&path, &dir_name, &topo.mems_str) {
                dir_name
            } else {
                Default::default()
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    rules.push(AffinityRule {
        pkg: pkg.to_string(),
        thread: thread.to_string(),
        thread_pattern: CString::new(thread).unwrap_or_default(),
        cpuset_dir,
        cpus: set,
        spec: cpus_spec.to_string(),
        comment: comment.to_string(),
    });
    true
}

/// 加载配置文件，返回 None 表示未变化或解析失败
pub fn load_config(
    config_file: &str,
    topo: &CpuTopology,
    last_mtime: &mut i64,
) -> Option<AppConfig> {
    let metadata = fs::metadata(config_file).ok()?;
    let mtime = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos() as i64;

    if *last_mtime == mtime && *last_mtime != -1 {
        return None;
    }

    let content = fs::read_to_string(config_file).ok()?;

    let mut rules: Vec<AffinityRule> = Vec::new();
    let mut fail_cnt: usize = 0;
    let mut cur_pkg = String::new();
    let mut pending_pkg = String::new();
    let mut in_block = false;
    let mut pkg_stack: Vec<String> = Vec::new();
    let mut in_sub_block = false;

    // ★ 新增：暂存独立注释行内容
    let mut pending_comment: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        // ---- 处理独立注释行 ----
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            let comment = if let Some(rest) = trimmed.strip_prefix('#') {
                rest.trim()
            } else if let Some(rest) = trimmed.strip_prefix("//") {
                rest.trim()
            } else {
                ""
            };
            if !comment.is_empty() {
                pending_comment = Some(comment.to_string());
            }
            continue;
        }

        // ---- 非注释行：分离行尾注释 ----
        let (rule_part, line_comment) = split_comment(line);
        let p = rule_part.trim();

        // 决定最终使用的注释：行尾注释优先，否则取暂存的独立注释
        let final_comment = if !line_comment.is_empty() {
            // 如果有行尾注释，则使用它，并清空暂存
            pending_comment.take();
            line_comment
        } else if let Some(ref c) = pending_comment {
            // 没有行尾注释，但有暂存独立注释
            c.as_str()
        } else {
            ""
        };
        // 注意：此时我们消费了 pending_comment，但如果是规则行，消费掉；如果不是规则行（如 `}`），我们后面会清空。
        // 但为了保险，在规则行真正添加规则时才消费，此处先不取，等到实际添加时再取。
        // 更好的方式：在规则行真正添加时才 take，但我们需要保留 pending_comment 直到被消费或清空。
        // 因此我们将 final_comment 的获取延迟到每个分支中。
        // 重构：在每个需要添加规则的分支中，通过一个函数获取当前注释并消费。

        // 定义一个闭包来获取注释
        let take_comment = || -> &str {
            if !line_comment.is_empty() {
                pending_comment.take();
                line_comment
            } else if let Some(c) = pending_comment.take() {
                // 使用 Box::leak 或返回字符串引用，但为了简单，我们返回字符串切片，但生命周期问题。
                // 由于我们只在分支内使用，可以将注释临时存储为 String。
                // 为了更安全，我们使用一个内部变量。
                // 我们将在每个分支中手动处理。
                // 改用直接处理。
                ""
            } else {
                ""
            }
        };

        // 但由于 borrow 问题，我们在每个分支中单独处理。
        // 下面重构：在每个添加规则的分支中，我们显式地获取注释。

        if in_block {
            if close_like(p) {
                // 块结束，清空暂存注释（避免误关联）
                pending_comment.take();
                if in_sub_block {
                    if let Some(parent) = pkg_stack.pop() {
                        cur_pkg = parent;
                    }
                    in_sub_block = false;
                } else {
                    in_block = false;
                    cur_pkg.clear();
                }
                continue;
            }

            // 处理块内的子包包级规则 :子包 = CPU
            if !in_sub_block && p.starts_with(':') && p.contains('=') {
                if let Some(eq_pos) = p.rfind('=') {
                    let sub = p[1..eq_pos].trim();
                    let raw_cpus = p[eq_pos + 1..].trim();
                    let cpus = raw_cpus.trim_end_matches('{').trim();
                    let has_open = raw_cpus.contains('{') || raw_cpus.ends_with('{');
                    if !sub.is_empty() && !cpus.is_empty() {
                        let full_pkg = format!("{}:{}", cur_pkg, sub);
                        // 获取注释
                        let comment = if !line_comment.is_empty() {
                            pending_comment.take();
                            line_comment
                        } else if let Some(c) = pending_comment.take() {
                            c
                        } else {
                            String::new()
                        };
                        if !add_rule(&mut rules, topo, &full_pkg, "", cpus, &comment) {
                            fail_cnt += 1;
                        }
                        if has_open {
                            pkg_stack.push(cur_pkg.clone());
                            cur_pkg = full_pkg;
                            in_sub_block = true;
                        }
                        if trimmed.contains('}') && !has_open {
                            in_block = false;
                            cur_pkg.clear();
                        }
                        continue;
                    }
                }
            }

            // 块内子包块开始 :子包 {
            if p.starts_with(':') && p.ends_with('{') {
                let sub = p[1..p.len() - 1].trim();
                if !sub.is_empty() {
                    let full_pkg = format!("{}:{}", cur_pkg, sub);
                    pkg_stack.push(cur_pkg.clone());
                    cur_pkg = full_pkg;
                    in_sub_block = true;
                    // 注意：块开始本身不产生规则，但可能之前有注释，我们不清空，让后续规则消费
                    continue;
                }
            }

            // 线程规则
            match split_rule_line(p) {
                Some((thread, cpus, closed)) => {
                    let comment = if !line_comment.is_empty() {
                        pending_comment.take();
                        line_comment
                    } else if let Some(c) = pending_comment.take() {
                        c
                    } else {
                        String::new()
                    };
                    if !add_rule(&mut rules, topo, &cur_pkg, thread, cpus, &comment) {
                        fail_cnt += 1;
                    }
                    if closed {
                        in_block = false;
                        cur_pkg.clear();
                        // 块关闭，清空注释
                        pending_comment.take();
                    }
                }
                None => {
                    fail_cnt += 1;
                    if p.contains('}') {
                        in_block = false;
                        cur_pkg.clear();
                        pending_comment.take();
                    }
                }
            }
            continue;
        }

        // ---- 外层解析 ----
        match parse_outer(p) {
            OuterLine::SubPkgRule { sub, cpus, open } => {
                let full_pkg = format!("{}:{}", cur_pkg, sub);
                let comment = if !line_comment.is_empty() {
                    pending_comment.take();
                    line_comment
                } else if let Some(c) = pending_comment.take() {
                    c
                } else {
                    String::new()
                };
                if !add_rule(&mut rules, topo, &full_pkg, "", cpus, &comment) {
                    fail_cnt += 1;
                }
                if open {
                    pkg_stack.push(cur_pkg.clone());
                    cur_pkg = full_pkg;
                    in_sub_block = true;
                    in_block = true;
                }
            }
            OuterLine::SubPkgBlock { sub } => {
                let full_pkg = format!("{}:{}", cur_pkg, sub);
                pkg_stack.push(cur_pkg.clone());
                cur_pkg = full_pkg;
                in_sub_block = true;
                in_block = true;
                // 块开始不产生规则，注释保留给后续规则
            }
            OuterLine::Single {
                pkg,
                thread,
                cpus,
                open,
            } => {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                pending_pkg.clear();
                let comment = if !line_comment.is_empty() {
                    pending_comment.take();
                    line_comment
                } else if let Some(c) = pending_comment.take() {
                    c
                } else {
                    String::new()
                };
                if !add_rule(&mut rules, topo, pkg, thread, cpus, &comment) {
                    fail_cnt += 1;
                }
                if open {
                    cur_pkg = pkg.to_string();
                    in_block = true;
                }
            }
            OuterLine::Rule { pkg, cpus, open } => {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                let comment = if !line_comment.is_empty() {
                    pending_comment.take();
                    line_comment
                } else if let Some(c) = pending_comment.take() {
                    c
                } else {
                    String::new()
                };
                if !add_rule(&mut rules, topo, pkg, "", cpus, &comment) {
                    fail_cnt += 1;
                }
                if open {
                    cur_pkg = pkg.to_string();
                    in_block = true;
                }
                pending_pkg.clear();
            }
            OuterLine::BareOpen { pkg } => {
                let owner = if !pkg.is_empty() {
                    if !pending_pkg.is_empty() {
                        fail_cnt += 1;
                    }
                    pkg.to_string()
                } else {
                    pending_pkg.clone()
                };
                if owner.is_empty() {
                    fail_cnt += 1;
                    continue;
                }
                cur_pkg = owner;
                pending_pkg.clear();
                in_block = true;
                // 块开始不产生规则，注释保留给后续规则
            }
            OuterLine::Pending { pkg } => {
                if !pending_pkg.is_empty() {
                    fail_cnt += 1;
                }
                pending_pkg = pkg.to_string();
                // 暂存注释可能关联到后面的规则，不清空
            }
            OuterLine::Junk => {
                fail_cnt += 1;
                pending_pkg.clear();
                // 垃圾行，清空注释避免误关联
                pending_comment.take();
            }
        }
    }

    // 文件结束，清空暂存注释
    pending_comment.take();

    if in_block || !pending_pkg.is_empty() {
        fail_cnt += 1;
    }

    *last_mtime = mtime;
    PARSE_FAILS.store(fail_cnt, Ordering::Relaxed);

    let pkgs: HashSet<String> = rules.iter().map(|r| r.pkg.clone()).collect();
    let has_thread_rules: HashSet<String> = rules
        .iter()
        .filter(|r| !r.thread.is_empty())
        .map(|r| r.pkg.clone())
        .collect();
    let num_rules = rules.len();

    println!("配置文件解析完成，共加载 {} 条规则", num_rules);
    if fail_cnt > 0 {
        eprintln!("警告: {} 条规则因格式无效被跳过", fail_cnt);
    }

    Some(AppConfig {
        rules,
        pkgs,
        has_thread_rules,
        topo: topo.clone(),
    })
}

// 以下是原有的 config_loader、inotify 相关函数，保持不变
pub fn config_loader() {
    let name = CString::new("ConfigLoader").unwrap();
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    let mut last_mtime: i64 = -1;

    loop {
        let interval = CHECK_INTERVAL.load(Ordering::Relaxed).max(1);
        if FORCE_RELOAD.swap(false, Ordering::AcqRel) {
            last_mtime = -1;
            if INOTIFY_SUPPORTED.load(Ordering::Acquire) {
                let fd = INOTIFY_FD.load(Ordering::Acquire);
                inotify_rewatch(fd);
            }
            config_reload(&mut last_mtime);
        }
        if INOTIFY_SUPPORTED.load(Ordering::Acquire) {
            inotify_handle(interval, &mut last_mtime);
        } else {
            config_reload(&mut last_mtime);
            thread::sleep(Duration::from_secs(interval));
        }
    }
}

pub fn init_inotify(config_file: &str) {
    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if inotify_fd < 0 {
        println!("inotify初始化失败，使用轮询模式");
        return;
    }
    let cfg_cstr = match CString::new(config_file) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("错误: 配置文件路径包含非法字符，使用轮询模式");
            unsafe {
                libc::close(inotify_fd);
            }
            return;
        }
    };
    let wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            cfg_cstr.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF,
        )
    };
    if wd >= 0 {
        INOTIFY_SUPPORTED.store(true, Ordering::Release);
        INOTIFY_FD.store(inotify_fd, Ordering::Release);
        INOTIFY_WD.store(wd, Ordering::Release);
        println!("启用inotify监控配置文件变更");
    } else {
        unsafe {
            libc::close(inotify_fd);
        }
        println!("inotify初始化失败，使用轮询模式");
    }
}

fn disable_inotify(inotify_fd: i32) {
    INOTIFY_SUPPORTED.store(false, Ordering::Release);
    unsafe {
        libc::close(inotify_fd);
    }
    INOTIFY_FD.store(-1, Ordering::Release);
    INOTIFY_WD.store(-1, Ordering::Release);
}

fn config_reload(last_mtime: &mut i64) {
    let Some(cfg) = lock_ignore_poison(&CURRENT_CONFIG).clone() else {
        return;
    };
    let file = lock_ignore_poison(&CONFIG_FILE).clone();
    let Some(new_cfg) = load_config(&file, &cfg.topo, last_mtime) else {
        return;
    };
    {
        let mut guard = lock_ignore_poison(&CURRENT_CONFIG);
        *guard = Some(Arc::new(new_cfg));
    }
    CONFIG_UPDATED.store(true, Ordering::Release);
}

pub fn config_reload_now() {
    let mut mtime: i64 = -1;
    config_reload(&mut mtime);
}

fn inotify_handle(interval: u64, last_mtime: &mut i64) {
    let inotify_fd = INOTIFY_FD.load(Ordering::Acquire);

    let mut pfd = libc::pollfd {
        fd: inotify_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let ret = unsafe { libc::poll(&mut pfd, 1, (interval as libc::c_int) * 1000) };

    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            return;
        }
        disable_inotify(inotify_fd);
        return;
    } else if ret == 0 {
        return;
    }

    #[repr(align(8))]
    struct InotifyBuf([u8; 4096]);
    let mut buf = InotifyBuf([0u8; 4096]);
    let mut reload_needed = false;
    let mut needs_rewatch = false;
    let hdr = std::mem::size_of::<libc::inotify_event>();

    loop {
        let len = unsafe {
            libc::read(
                inotify_fd,
                buf.0.as_mut_ptr() as *mut libc::c_void,
                buf.0.len(),
            )
        };
        if len <= 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error();
            if errno == Some(libc::EAGAIN)
                || errno == Some(libc::EWOULDBLOCK)
                || errno == Some(libc::EINTR)
            {
                break;
            }
            disable_inotify(inotify_fd);
            return;
        }

        let mut offset = 0;
        while offset + hdr <= len as usize {
            let event = unsafe { &*(buf.0.as_ptr().add(offset) as *const libc::inotify_event) };
            if event.mask & (libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0
            {
                reload_needed = true;
                *last_mtime = -1;
                if event.mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
                    needs_rewatch = true;
                }
            }
            offset += hdr + event.len as usize;
        }
    }

    if needs_rewatch {
        thread::sleep(Duration::from_secs(interval));
        if !inotify_rewatch(inotify_fd) {
            return;
        }
    }

    if reload_needed {
        config_reload(last_mtime);
    }
}

fn inotify_rewatch(inotify_fd: i32) -> bool {
    let inotify_wd = INOTIFY_WD.load(Ordering::Acquire);
    unsafe {
        libc::inotify_rm_watch(inotify_fd, inotify_wd as u32);
    }
    let cfg_cstr = match CString::new(lock_ignore_poison(&CONFIG_FILE).clone()) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("错误: 配置文件路径包含非法字符，降级为轮询模式");
            disable_inotify(inotify_fd);
            return false;
        }
    };
    let new_wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            cfg_cstr.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF,
        )
    };

    if new_wd < 0 {
        disable_inotify(inotify_fd);
        return false;
    }
    INOTIFY_WD.store(new_wd, Ordering::Release);
    true
}
