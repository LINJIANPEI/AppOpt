#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>
#include "uthash.h"

#define VERSION "1.6.3"
#define BASE_CPUSET "/dev/cpuset/Linlin"
#define MAX_PKG_LEN 128
#define MAX_THREAD_LEN 32
#define DENT_BUF_SIZE (128 * 1024)

// ============ 日志系统 ============
#define LOG(fmt, ...) do { \
    time_t t = time(NULL); \
    struct tm *tm = localtime(&t); \
    fprintf(stderr, "[%02d:%02d:%02d] " fmt, tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
    fflush(stderr); \
} while(0)

// ============ 数据结构 ============
typedef struct {
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
    bool is_wildcard;
    int priority;
} AffinityRule;

typedef struct {
    pid_t tid;
    char name[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
} ThreadInfo;

typedef struct {
    pid_t pid;
    char pkg[MAX_PKG_LEN];
    char base_cpuset[128];
    cpu_set_t base_cpus;
    ThreadInfo* threads;
    size_t num_threads;
    size_t threads_cap;
    AffinityRule** thread_rules;
    size_t num_thread_rules;
    size_t thread_rules_cap;
} ProcessInfo;

typedef struct {
    cpu_set_t present_cpus;
    char present_str[128];
    char mems_str[32];
    bool cpuset_enabled;
    int base_cpuset_fd;
} CpuTopology;

typedef struct {
    atomic_int ref_count;
    AffinityRule* rules;
    size_t num_rules;
    AffinityRule** wildcard_rules;
    size_t num_wildcard_rules;
    time_t mtime;
    CpuTopology topo;
    char** pkgs;
    size_t num_pkgs;
    struct PackageEntry* pkg_table;
    char config_file[4096];
} AppConfig;

typedef struct PackageEntry {
    char pkg[MAX_PKG_LEN];
    UT_hash_handle hh;
} PackageEntry;

typedef struct {
    ProcessInfo* procs;
    size_t num_procs;
    size_t procs_cap;
    int last_proc_total;
    bool scan_all;
    pid_t* tracked_pids;
    size_t num_tracked;
    size_t tracked_cap;
} ProcCache;

// ============ 工具函数 ============
static bool read_file(int fd, const char* name, char* buf, size_t size) {
    int f = openat(fd, name, O_RDONLY | O_CLOEXEC);
    if (f < 0) return false;
    ssize_t n = read(f, buf, size - 1);
    close(f);
    if (n <= 0) return false;
    buf[n] = '\0';
    return true;
}

static bool write_file(int fd, const char* name, const char* content) {
    int f = openat(fd, name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (f < 0) return false;
    ssize_t n = write(f, content, strlen(content));
    close(f);
    return n == (ssize_t)strlen(content);
}

static void trim(char* s) {
    if (!s) return;
    char* start = s;
    while (isspace(*start)) start++;
    if (start != s) memmove(s, start, strlen(start) + 1);
    char* end = s + strlen(s) - 1;
    while (end > s && isspace(*end)) end--;
    end[1] = '\0';
}

static bool parse_cpu_ranges(const char* spec, cpu_set_t* set, const cpu_set_t* present, char* invalid, size_t invalid_size) {
    if (!spec) return true;
    char* copy = strdup(spec);
    if (!copy) return false;
    char* s = copy;
    bool valid = true;
    
    while (*s) {
        char* end;
        unsigned long a = strtoul(s, &end, 10);
        if (end == s) { s++; continue; }
        unsigned long b = a;
        if (*end == '-') {
            s = end + 1;
            b = strtoul(s, &end, 10);
            if (end == s) b = a;
        }
        
        if (a > b) {
            if (invalid && invalid_size > 0) {
                snprintf(invalid, invalid_size, "%lu-%lu", a, b);
            }
            valid = false;
            s = (*end == ',') ? end + 1 : end;
            continue;
        }
        
        for (unsigned long i = a; i <= b && i < CPU_SETSIZE; i++) {
            if (present && !CPU_ISSET(i, present)) {
                if (invalid && invalid_size > 0) {
                    snprintf(invalid, invalid_size, "%lu", i);
                }
                valid = false;
                break;
            }
            CPU_SET(i, set);
        }
        s = (*end == ',') ? end + 1 : end;
    }
    free(copy);
    return valid;
}

static char* cpu_set_to_str(const cpu_set_t* set, char* buf, size_t size) {
    if (!buf || size == 0) return NULL;
    char* p = buf;
    bool first = true;
    size_t remain = size - 1;
    
    for (int i = 0; i < CPU_SETSIZE && remain > 0; i++) {
        if (CPU_ISSET(i, set)) {
            int start = i;
            while (i + 1 < CPU_SETSIZE && CPU_ISSET(i + 1, set)) i++;
            int needed;
            if (start == i) {
                needed = snprintf(p, remain + 1, "%s%d", first ? "" : ",", start);
            } else {
                needed = snprintf(p, remain + 1, "%s%d-%d", first ? "" : ",", start, i);
            }
            if (needed < 0 || (size_t)needed > remain) break;
            p += needed;
            remain -= needed;
            first = false;
        }
    }
    *p = '\0';
    return buf;
}

static int calc_priority(const char* pattern) {
    if (!pattern || !*pattern) return 200;
    if (strchr(pattern, '*') || strchr(pattern, '?') || strchr(pattern, '['))
        return 100 + strlen(pattern);
    return 1000 + strlen(pattern);
}

static bool create_cpuset_dir(const char* path, const char* cpus, const char* mems) {
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return false;
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s/cpus", path);
    if (!write_file(AT_FDCWD, tmp, cpus)) return false;
    snprintf(tmp, sizeof(tmp), "%s/mems", path);
    if (!write_file(AT_FDCWD, tmp, mems)) return false;
    return true;
}

// ============ 进程资源清理 ============
static void free_process_info(ProcessInfo* proc) {
    if (!proc) return;
    if (proc->threads) {
        free(proc->threads);
        proc->threads = NULL;
    }
    if (proc->thread_rules) {
        free(proc->thread_rules);
        proc->thread_rules = NULL;
    }
    proc->num_threads = 0;
    proc->num_thread_rules = 0;
    proc->threads_cap = 0;
    proc->thread_rules_cap = 0;
}

static void free_proc_cache(ProcCache* cache) {
    if (!cache) return;
    for (size_t i = 0; i < cache->num_procs; i++) {
        free_process_info(&cache->procs[i]);
    }
    if (cache->procs) {
        free(cache->procs);
        cache->procs = NULL;
    }
    if (cache->tracked_pids) {
        free(cache->tracked_pids);
        cache->tracked_pids = NULL;
    }
    cache->num_procs = 0;
    cache->num_tracked = 0;
    cache->procs_cap = 0;
    cache->tracked_cap = 0;
}

// ============ 配置加载 ============
static AppConfig* load_config(const char* file, const CpuTopology* topo, time_t* last_mtime) {
    struct stat st;
    if (stat(file, &st) != 0) {
        const char* default_content = "# AppOpt config\n# Format: pkg{thread}=cpu_range\n\n";
        write_file(AT_FDCWD, file, default_content);
        LOG("创建默认配置文件: %s\n", file);
        return NULL;
    }
    
    if (last_mtime && *last_mtime == st.st_mtime && *last_mtime != -1)
        return NULL;

    int fd = open(file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG("无法打开配置: %s\n", file);
        return NULL;
    }

    char* data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) {
        LOG("无法映射配置文件: %s\n", file);
        return NULL;
    }

    AppConfig* cfg = calloc(1, sizeof(AppConfig));
    if (!cfg) {
        munmap(data, st.st_size);
        LOG("内存分配失败\n");
        return NULL;
    }
    
    cfg->ref_count = 1;
    cfg->topo = *topo;
    strncpy(cfg->config_file, file, sizeof(cfg->config_file) - 1);
    cfg->config_file[sizeof(cfg->config_file) - 1] = '\0';
    
    cfg->rules = malloc(256 * sizeof(AffinityRule));
    cfg->wildcard_rules = malloc(128 * sizeof(AffinityRule*));
    if (!cfg->rules || !cfg->wildcard_rules) {
        free(cfg->rules);
        free(cfg->wildcard_rules);
        free(cfg);
        munmap(data, st.st_size);
        LOG("内存分配失败\n");
        return NULL;
    }
    
    PackageEntry* pkg_table = NULL;
    char line[256];
    char* p = data;
    char* end = data + st.st_size;
    size_t num_rules = 0;
    size_t num_wild = 0;
    size_t rules_cap = 256;
    size_t wild_cap = 128;

    while (p < end) {
        char* nl = memchr(p, '\n', end - p);
        if (!nl) nl = end;
        size_t len = nl - p;
        
        if (len > 0 && len < sizeof(line)) {
            memcpy(line, p, len);
            line[len] = '\0';
            trim(line);
            
            if (line[0] && line[0] != '#') {
                char* eq = strchr(line, '=');
                if (eq) {
                    *eq++ = '\0';
                    char* key = trim(line);
                    char* val = trim(eq);
                    
                    if (!key || !*key || !val || !*val) {
                        p = nl + 1;
                        continue;
                    }
                    
                    // 解析包名{线程名}
                    char* br = strchr(key, '{');
                    char* thread = "";
                    if (br) {
                        *br++ = '\0';
                        char* eb = strchr(br, '}');
                        if (eb) {
                            *eb = '\0';
                            thread = trim(br);
                        }
                    }
                    char* pkg = trim(key);
                    
                    if (strlen(pkg) >= MAX_PKG_LEN || strlen(thread) >= MAX_THREAD_LEN) {
                        LOG("包名或线程名过长: %s\n", pkg);
                        p = nl + 1;
                        continue;
                    }
                    
                    // 检查重复规则
                    bool duplicate = false;
                    for (size_t i = 0; i < num_rules; i++) {
                        if (strcmp(cfg->rules[i].pkg, pkg) == 0 &&
                            strcmp(cfg->rules[i].thread, thread) == 0) {
                            LOG("重复规则: %s{%s}\n", pkg, thread);
                            duplicate = true;
                            break;
                        }
                    }
                    if (duplicate) {
                        p = nl + 1;
                        continue;
                    }
                    
                    // 扩展规则数组
                    if (num_rules >= rules_cap) {
                        rules_cap *= 2;
                        AffinityRule* new_rules = realloc(cfg->rules, rules_cap * sizeof(AffinityRule));
                        if (!new_rules) {
                            LOG("内存分配失败\n");
                            goto load_error;
                        }
                        cfg->rules = new_rules;
                    }
                    
                    // 创建规则
                    AffinityRule* r = &cfg->rules[num_rules];
                    strncpy(r->pkg, pkg, MAX_PKG_LEN - 1);
                    r->pkg[MAX_PKG_LEN - 1] = '\0';
                    strncpy(r->thread, thread, MAX_THREAD_LEN - 1);
                    r->thread[MAX_THREAD_LEN - 1] = '\0';
                    CPU_ZERO(&r->cpus);
                    
                    char invalid_range[64] = {0};
                    if (!parse_cpu_ranges(val, &r->cpus, &cfg->topo.present_cpus, 
                                         invalid_range, sizeof(invalid_range))) {
                        LOG("无效CPU范围: %s 在规则 %s{%s}\n", invalid_range, pkg, thread);
                        p = nl + 1;
                        continue;
                    }
                    
                    if (CPU_COUNT(&r->cpus) == 0) {
                        LOG("CPU范围无效: %s\n", val);
                        p = nl + 1;
                        continue;
                    }
                    
                    // 判断是否是默认规则
                    bool is_default = (strcmp(pkg, "*") == 0 && !thread[0]);
                    r->priority = is_default ? -1 : calc_priority(thread[0] ? thread : pkg);
                    r->is_wildcard = is_default || strchr(pkg, '*') || strchr(pkg, '?') || 
                                    strchr(thread, '*') || strchr(thread, '?');
                    
                    // 创建cpuset目录
                    char path[256];
                    snprintf(path, sizeof(path), "%s/%s", BASE_CPUSET, val);
                    if (!create_cpuset_dir(path, val, topo->mems_str)) {
                        LOG("无法创建cpuset目录: %s\n", path);
                        p = nl + 1;
                        continue;
                    }
                    strncpy(r->cpuset_dir, val, sizeof(r->cpuset_dir) - 1);
                    r->cpuset_dir[sizeof(r->cpuset_dir) - 1] = '\0';
                    
                    // 存储规则
                    if (!r->is_wildcard) {
                        PackageEntry* pe;
                        HASH_FIND_STR(pkg_table, pkg, pe);
                        if (!pe) {
                            pe = malloc(sizeof(PackageEntry));
                            if (!pe) {
                                LOG("内存分配失败\n");
                                goto load_error;
                            }
                            strncpy(pe->pkg, pkg, MAX_PKG_LEN - 1);
                            pe->pkg[MAX_PKG_LEN - 1] = '\0';
                            HASH_ADD_STR(pkg_table, pkg, pe);
                        }
                    } else {
                        if (num_wild >= wild_cap) {
                            wild_cap *= 2;
                            AffinityRule** new_wild = realloc(cfg->wildcard_rules, 
                                                             wild_cap * sizeof(AffinityRule*));
                            if (!new_wild) {
                                LOG("内存分配失败\n");
                                goto load_error;
                            }
                            cfg->wildcard_rules = new_wild;
                        }
                        cfg->wildcard_rules[num_wild++] = r;
                    }
                    num_rules++;
                }
            }
        }
        p = nl + 1;
    }

    munmap(data, st.st_size);
    
    if (num_rules == 0) {
        LOG("未加载有效规则\n");
        free(cfg->rules);
        free(cfg->wildcard_rules);
        free(cfg);
        return NULL;
    }

    // 构建包列表
    cfg->num_pkgs = HASH_COUNT(pkg_table);
    cfg->pkgs = malloc((cfg->num_pkgs + 1) * sizeof(char*));
    if (!cfg->pkgs) {
        LOG("内存分配失败\n");
        goto load_error;
    }
    
    size_t idx = 0;
    PackageEntry *pe, *tmp;
    HASH_ITER(hh, pkg_table, pe, tmp) {
        cfg->pkgs[idx] = strdup(pe->pkg);
        if (!cfg->pkgs[idx]) {
            LOG("内存分配失败\n");
            for (size_t j = 0; j < idx; j++) free(cfg->pkgs[j]);
            free(cfg->pkgs);
            goto load_error;
        }
        idx++;
        HASH_DEL(pkg_table, pe);
        free(pe);
    }
    cfg->pkgs[idx] = NULL;
    
    // 重新分配精确大小
    AffinityRule* new_rules = realloc(cfg->rules, num_rules * sizeof(AffinityRule));
    if (new_rules) cfg->rules = new_rules;
    cfg->num_rules = num_rules;
    
    AffinityRule** new_wild = realloc(cfg->wildcard_rules, num_wild * sizeof(AffinityRule*));
    if (new_wild) cfg->wildcard_rules = new_wild;
    cfg->num_wildcard_rules = num_wild;
    
    cfg->mtime = st.st_mtime;
    if (last_mtime) *last_mtime = st.st_mtime;
    
    LOG("加载 %zu 条规则，%zu 条通配符规则，%zu 个应用包\n", num_rules, num_wild, cfg->num_pkgs);
    return cfg;

load_error:
    munmap(data, st.st_size);
    if (cfg) {
        free(cfg->rules);
        free(cfg->wildcard_rules);
        free(cfg);
    }
    PackageEntry *e, *t;
    HASH_ITER(hh, pkg_table, e, t) {
        HASH_DEL(pkg_table, e);
        free(e);
    }
    return NULL;
}

// ============ 规则匹配 ============
static int compare_rules(const void* a, const void* b) {
    AffinityRule* ra = *(AffinityRule**)a;
    AffinityRule* rb = *(AffinityRule**)b;
    return rb->priority - ra->priority;
}

static bool match_rules_for_process(ProcessInfo* proc, const AppConfig* cfg) {
    if (!proc || !cfg) return false;
    
    // 清理旧规则
    if (proc->thread_rules) {
        free(proc->thread_rules);
        proc->thread_rules = NULL;
        proc->thread_rules_cap = 0;
        proc->num_thread_rules = 0;
    }
    
    proc->thread_rules = malloc(8 * sizeof(AffinityRule*));
    if (!proc->thread_rules) return false;
    proc->thread_rules_cap = 8;
    proc->num_thread_rules = 0;
    
    AffinityRule* default_rule = NULL;
    
    // 1. 精确匹配
    PackageEntry* pe;
    HASH_FIND_STR(cfg->pkg_table, proc->pkg, pe);
    if (pe) {
        for (size_t i = 0; i < cfg->num_rules; i++) {
            AffinityRule* r = &cfg->rules[i];
            if (strcmp(r->pkg, proc->pkg) == 0) {
                if (r->priority == -1) {
                    default_rule = r;
                } else {
                    if (proc->num_thread_rules >= proc->thread_rules_cap) {
                        size_t new_cap = proc->thread_rules_cap * 2;
                        AffinityRule** new_rules = realloc(proc->thread_rules, 
                                                          new_cap * sizeof(AffinityRule*));
                        if (!new_rules) {
                            free(proc->thread_rules);
                            proc->thread_rules = NULL;
                            return false;
                        }
                        proc->thread_rules = new_rules;
                        proc->thread_rules_cap = new_cap;
                    }
                    proc->thread_rules[proc->num_thread_rules++] = r;
                }
            }
        }
    }
    
    // 2. 通配符匹配（如果没有精确匹配）
    if (proc->num_thread_rules == 0) {
        for (size_t i = 0; i < cfg->num_wildcard_rules; i++) {
            AffinityRule* r = cfg->wildcard_rules[i];
            if (r->priority == -1) {
                default_rule = r;
                continue;
            }
            if (fnmatch(r->pkg, proc->pkg, 0) == 0) {
                if (proc->num_thread_rules >= proc->thread_rules_cap) {
                    size_t new_cap = proc->thread_rules_cap * 2;
                    AffinityRule** new_rules = realloc(proc->thread_rules, 
                                                      new_cap * sizeof(AffinityRule*));
                    if (!new_rules) {
                        free(proc->thread_rules);
                        proc->thread_rules = NULL;
                        return false;
                    }
                    proc->thread_rules = new_rules;
                    proc->thread_rules_cap = new_cap;
                }
                proc->thread_rules[proc->num_thread_rules++] = r;
            }
        }
    }
    
    // 3. 如果没有匹配，使用默认规则
    if (proc->num_thread_rules == 0 && default_rule) {
        if (proc->thread_rules_cap < 1) {
            proc->thread_rules = malloc(sizeof(AffinityRule*));
            if (!proc->thread_rules) return false;
            proc->thread_rules_cap = 1;
        }
        proc->thread_rules[proc->num_thread_rules++] = default_rule;
    }
    
    if (proc->num_thread_rules == 0) {
        free(proc->thread_rules);
        proc->thread_rules = NULL;
        return false;
    }
    
    // 按优先级排序
    if (proc->num_thread_rules > 1) {
        qsort(proc->thread_rules, proc->num_thread_rules, sizeof(AffinityRule*), compare_rules);
    }
    
    // 设置基础CPU
    CPU_ZERO(&proc->base_cpus);
    for (size_t i = 0; i < proc->num_thread_rules; i++) {
        if (proc->thread_rules[i]->priority != -1) {
            CPU_OR(&proc->base_cpus, &proc->base_cpus, &proc->thread_rules[i]->cpus);
            strncpy(proc->base_cpuset, proc->thread_rules[i]->cpuset_dir, sizeof(proc->base_cpuset) - 1);
            proc->base_cpuset[sizeof(proc->base_cpuset) - 1] = '\0';
            break;
        }
    }
    
    if (CPU_COUNT(&proc->base_cpus) == 0 && proc->num_thread_rules > 0) {
        CPU_OR(&proc->base_cpus, &proc->base_cpus, &proc->thread_rules[0]->cpus);
        strncpy(proc->base_cpuset, proc->thread_rules[0]->cpuset_dir, sizeof(proc->base_cpuset) - 1);
        proc->base_cpuset[sizeof(proc->base_cpuset) - 1] = '\0';
    }
    
    return CPU_COUNT(&proc->base_cpus) > 0;
}

// ============ 进程收集 ============
static void collect_procs(const AppConfig* cfg, ProcCache* cache) {
    if (!cfg || !cache) return;
    
    // 清理旧数据
    for (size_t i = 0; i < cache->num_procs; i++) {
        free_process_info(&cache->procs[i]);
    }
    cache->num_procs = 0;
    
    char buf[DENT_BUF_SIZE];
    int fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        LOG("无法打开/proc目录\n");
        return;
    }

    time_t now = time(NULL);
    
    while (1) {
        int n = syscall(__NR_getdents64, fd, (struct linux_dirent64*)buf, DENT_BUF_SIZE);
        if (n <= 0) break;
        
        for (int pos = 0; pos < n; ) {
            struct linux_dirent64* e = (struct linux_dirent64*)(buf + pos);
            bool is_dir = (e->d_type == DT_DIR);
            bool is_digit = isdigit(e->d_name[0]);
            
            if (is_dir && is_digit) {
                pid_t pid = atoi(e->d_name);
                if (pid <= 0) goto next_entry;
                
                // 检查是否需要扫描
                bool tracked = false;
                for (size_t i = 0; i < cache->num_tracked && i < cache->tracked_cap; i++) {
                    if (cache->tracked_pids[i] == pid) {
                        tracked = true;
                        break;
                    }
                }
                
                if (!tracked && !cache->scan_all) {
                    struct stat st;
                    if (fstatat(fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
                        if (now - st.st_mtime > 60) goto next_entry;
                    }
                }
                
                int pfd = openat(fd, e->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (pfd < 0) goto next_entry;
                
                char cmd[MAX_PKG_LEN] = {0};
                if (!read_file(pfd, "cmdline", cmd, sizeof(cmd))) {
                    close(pfd);
                    goto next_entry;
                }
                
                // 确保有足够容量
                if (cache->num_procs >= cache->procs_cap) {
                    size_t new_cap = cache->procs_cap ? cache->procs_cap * 2 : 1024;
                    ProcessInfo* new_procs = realloc(cache->procs, new_cap * sizeof(ProcessInfo));
                    if (!new_procs) {
                        close(pfd);
                        LOG("内存分配失败\n");
                        goto next_entry;
                    }
                    cache->procs = new_procs;
                    cache->procs_cap = new_cap;
                    // 初始化新分配的内存
                    memset(cache->procs + cache->num_procs, 0, 
                           (new_cap - cache->num_procs) * sizeof(ProcessInfo));
                }
                
                ProcessInfo* proc = &cache->procs[cache->num_procs];
                memset(proc, 0, sizeof(ProcessInfo));
                proc->pid = pid;
                
                char* name = strrchr(cmd, '/');
                if (name) name++; else name = cmd;
                strncpy(proc->pkg, name, MAX_PKG_LEN - 1);
                proc->pkg[MAX_PKG_LEN - 1] = '\0';
                
                // 匹配规则
                if (!match_rules_for_process(proc, cfg)) {
                    close(pfd);
                    goto next_entry;
                }
                
                // 收集线程
                int tf = openat(pfd, "task", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                close(pfd);
                if (tf < 0) {
                    free_process_info(proc);
                    goto next_entry;
                }
                
                DIR* d = fdopendir(tf);
                if (!d) {
                    close(tf);
                    free_process_info(proc);
                    goto next_entry;
                }
                
                proc->threads = malloc(32 * sizeof(ThreadInfo));
                if (!proc->threads) {
                    closedir(d);
                    free_process_info(proc);
                    LOG("内存分配失败\n");
                    goto next_entry;
                }
                proc->threads_cap = 32;
                proc->num_threads = 0;
                
                struct dirent* de;
                while ((de = readdir(d))) {
                    pid_t tid = atoi(de->d_name);
                    if (tid <= 0) continue;
                    
                    char tname[MAX_THREAD_LEN] = {0};
                    int tf2 = openat(tf, de->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                    if (tf2 >= 0) {
                        read_file(tf2, "comm", tname, sizeof(tname));
                        close(tf2);
                    }
                    trim(tname);
                    
                    if (proc->num_threads >= proc->threads_cap) {
                        size_t new_cap = proc->threads_cap * 2;
                        ThreadInfo* new_threads = realloc(proc->threads, new_cap * sizeof(ThreadInfo));
                        if (!new_threads) {
                            LOG("内存分配失败\n");
                            break;
                        }
                        proc->threads = new_threads;
                        proc->threads_cap = new_cap;
                    }
                    
                    ThreadInfo* ti = &proc->threads[proc->num_threads];
                    memset(ti, 0, sizeof(ThreadInfo));
                    ti->tid = tid;
                    strncpy(ti->name, tname, MAX_THREAD_LEN - 1);
                    ti->name[MAX_THREAD_LEN - 1] = '\0';
                    
                    // 线程规则匹配（分离默认规则）
                    bool matched = false;
                    AffinityRule* default_thread_rule = NULL;
                    
                    for (size_t i = 0; i < proc->num_thread_rules; i++) {
                        AffinityRule* r = proc->thread_rules[i];
                        if (r->priority == -1) {
                            default_thread_rule = r;
                            continue;
                        }
                        if (fnmatch(r->thread, tname, 0) == 0) {
                            ti->cpus = r->cpus;
                            strncpy(ti->cpuset_dir, r->cpuset_dir, sizeof(ti->cpuset_dir) - 1);
                            ti->cpuset_dir[sizeof(ti->cpuset_dir) - 1] = '\0';
                            matched = true;
                            break;
                        }
                    }
                    
                    if (!matched && default_thread_rule) {
                        ti->cpus = default_thread_rule->cpus;
                        strncpy(ti->cpuset_dir, default_thread_rule->cpuset_dir, 
                                sizeof(ti->cpuset_dir) - 1);
                        ti->cpuset_dir[sizeof(ti->cpuset_dir) - 1] = '\0';
                        matched = true;
                    }
                    
                    if (!matched) {
                        ti->cpus = proc->base_cpus;
                        strncpy(ti->cpuset_dir, proc->base_cpuset, sizeof(ti->cpuset_dir) - 1);
                        ti->cpuset_dir[sizeof(ti->cpuset_dir) - 1] = '\0';
                    }
                    
                    proc->num_threads++;
                }
                closedir(d);
                cache->num_procs++;
                
            next_entry:
                pos += e->d_reclen;
            } else {
                pos += e->d_reclen;
            }
        }
    }
    close(fd);
    
    // 更新跟踪列表
    if (cache->num_procs > cache->tracked_cap) {
        size_t new_cap = cache->num_procs * 2;
        pid_t* new_pids = realloc(cache->tracked_pids, new_cap * sizeof(pid_t));
        if (new_pids) {
            cache->tracked_pids = new_pids;
            cache->tracked_cap = new_cap;
        }
    }
    
    cache->num_tracked = 0;
    for (size_t i = 0; i < cache->num_procs && cache->num_tracked < cache->tracked_cap; i++) {
        cache->tracked_pids[cache->num_tracked++] = cache->procs[i].pid;
    }
    cache->scan_all = false;
}

// ============ 应用亲和性 ============
static void apply_affinity(const ProcCache* cache, const CpuTopology* topo) {
    if (!cache || !topo) return;
    
    for (size_t i = 0; i < cache->num_procs; i++) {
        const ProcessInfo* p = &cache->procs[i];
        for (size_t j = 0; j < p->num_threads; j++) {
            const ThreadInfo* t = &p->threads[j];
            
            // 检查当前亲和性
            cpu_set_t curr;
            if (sched_getaffinity(t->tid, sizeof(curr), &curr) == 0) {
                if (CPU_EQUAL(&t->cpus, &curr)) continue;
            }
            
            // 设置CPU亲和性
            if (sched_setaffinity(t->tid, sizeof(t->cpus), &t->cpus) == 0) {
                // 如果cpuset可用，也设置cpuset
                if (topo->cpuset_enabled && topo->base_cpuset_fd >= 0 && t->cpuset_dir[0]) {
                    char tid_str[32];
                    snprintf(tid_str, sizeof(tid_str), "%d\n", t->tid);
                    int cfd = openat(topo->base_cpuset_fd, t->cpuset_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                    if (cfd >= 0) {
                        write_file(cfd, "tasks", tid_str);
                        close(cfd);
                    }
                }
            } else if (errno == ESRCH) {
                // 线程已退出，标记需要重新扫描
                // 这里可以通过全局变量通知主循环
            }
        }
    }
}

// ============ 配置管理 ============
static atomic_int config_updated = ATOMIC_VAR_INIT(0);
static _Atomic(AppConfig*) current_config = NULL;
static int inotify_fd = -1;
static int inotify_wd = -1;
static int inotify_supported = 0;

static void config_release(AppConfig* cfg) {
    if (!cfg) return;
    if (atomic_fetch_sub_explicit(&cfg->ref_count, 1, memory_order_acq_rel) == 1) {
        if (cfg->rules) free(cfg->rules);
        if