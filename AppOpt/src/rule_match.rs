use std::ffi::CString;

use crate::MAX_THREAD_LEN;
use crate::config::AppConfig;
use crate::cpuset::{CpuSet, ensure_cpuset_dir};

/// 线程亲和性计算结果
pub struct AffinityResult {
    pub cpus: CpuSet,
    pub cpuset_dir: String,
    pub is_thread_rule: bool,
}

/// 线程规则 CPU 累加，无线程匹配走包级 fallback，仍无则返回 None
pub fn thread_affinity(pkg: &str, thread: &str, cfg: &AppConfig) -> Option<AffinityResult> {
    let mut cpus = CpuSet::new();
    let mut cpuset_dir = String::new();
    let mut matched = false;

    // === 线程规则匹配（不变） ===
    if !thread.is_empty() {
        for rule in &cfg.rules {
            if rule.pkg != pkg || rule.thread.is_empty() {
                continue;
            }
            if fnmatch_c(&rule.thread_pattern, thread) {
                cpus.or(&rule.cpus);
                matched = true;
            }
        }
        if matched {
            cpuset_dir = ensure_cpuset_dir(&cpus, &cfg.topo);
        }
    }

    // === 包级兜底（修改为两级查找） ===
    if !matched {
        let mut fallback_seen = false;
        let mut found = false;

        // 第一遍：精确匹配包名
        for rule in &cfg.rules {
            if rule.pkg != pkg || !rule.thread.is_empty() {
                continue;
            }
            cpus.or(&rule.cpus);
            if !fallback_seen {
                cpuset_dir = rule.cpuset_dir.clone();
                fallback_seen = true;
            } else {
                cpuset_dir.clear();
            }
            found = true;
        }

        // 第二遍：如果没找到，去掉 : 后缀再找（如 xxx:push → xxx）
        if !found {
            if let Some(base) = pkg.split(':').next() {
                if base != pkg {
                    // 避免死循环
                    for rule in &cfg.rules {
                        if rule.pkg != base || !rule.thread.is_empty() {
                            continue;
                        }
                        cpus.or(&rule.cpus);
                        if !fallback_seen {
                            cpuset_dir = rule.cpuset_dir.clone();
                            fallback_seen = true;
                        } else {
                            cpuset_dir.clear();
                        }
                        found = true;
                    }
                }
            }
        }
    }

    // === 后续处理（不变） ===
    if cpus.count() == 0 {
        if cfg.has_thread_rules.contains(pkg) {
            return Some(AffinityResult {
                cpus: cfg.topo.present_cpus,
                cpuset_dir: String::new(),
                is_thread_rule: false,
            });
        }
        // 也检查基础包名的 has_thread_rules
        if let Some(base) = pkg.split(':').next() {
            if base != pkg && cfg.has_thread_rules.contains(base) {
                return Some(AffinityResult {
                    cpus: cfg.topo.present_cpus,
                    cpuset_dir: String::new(),
                    is_thread_rule: false,
                });
            }
        }
        None
    } else {
        Some(AffinityResult {
            cpus,
            cpuset_dir,
            is_thread_rule: matched,
        })
    }
}

/// POSIX fnmatch 封装，需预转换为 CString
fn fnmatch_c(pattern: &CString, string: &str) -> bool {
    if string.len() >= MAX_THREAD_LEN {
        return false;
    }
    let mut buf = [0u8; MAX_THREAD_LEN];
    buf[..string.len()].copy_from_slice(string.as_bytes());
    unsafe {
        libc::fnmatch(
            pattern.as_ptr(),
            buf.as_ptr() as *const _,
            libc::FNM_NOESCAPE,
        ) == 0
    }
}

/// 通过内核 comm 匹配配置包名
pub fn comm_to_pkg(comm: &str, cfg: &AppConfig) -> Option<String> {
    if cfg.pkgs.contains(comm) {
        return Some(comm.to_string());
    }

    // 如果精确匹配不到，去掉 : 后缀再试
    if let Some(base) = comm.split(':').next() {
        if base != comm && cfg.pkgs.contains(base) {
            return Some(base.to_string());
        }
    }

    if comm.len() >= 15 {
        for pkg in &cfg.pkgs {
            if pkg.starts_with(comm) {
                return Some(pkg.clone());
            }
        }
        for pkg in &cfg.pkgs {
            if pkg.ends_with(comm) {
                return Some(pkg.clone());
            }
        }
    }
    None
}
