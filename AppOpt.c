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
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <signal.h>

#define VERSION            "1.8.0"
#define BASE_CPUSET        "/dev/cpuset/Linlin"
#define MAX_PKG_LEN        128
#define MAX_THREAD_LEN     32

typedef struct {
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
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
    AffinityRule** wildcard_thread_rules;
    size_t wildcard_thread_rule_count;
    time_t mtime;
    CpuTopology topo;
    char** pkgs;
    size_t num_pkgs;
    char config_file[4096];
} AppConfig;

typedef struct {
    ProcessInfo* procs;
    size_t num_procs;
    size_t procs_cap;
    int last_proc_count;
    bool scan_all_proc;
    pid_t* tracked_pids;
    size_t num_tracked_pids;
    size_t tracked_pids_cap;
    int last_proc_total;
} ProcCache;

static atomic_int config_updated = ATOMIC_VAR_INIT(0);
static int inotify_fd = -1;
static int inotify_supported = 0;
static _Atomic(AppConfig*) current_config = NULL;
static char** config_files = NULL;
static size_t num_config_files = 0;

typedef struct {
    int wd;
    char dir_path[PATH_MAX];
    char file_name[PATH_MAX];
} WatchEntry;
static WatchEntry* watches = NULL;
static size_t watch_count = 0;

/* ----- 辅助函数 ----- */
static char* strtrim(char* s) {
    while (isspace(*s)) s++;
    if (*s == 0) return s;
    char* end = s + strlen(s) - 1;
    while (end > s && isspace(*end)) end--;
    *(end + 1) = 0;
    return s;
}

static bool read_file(int dir_fd, const char* filename, char* buf, size_t buf_size) {
    int fd = openat(dir_fd, filename, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return false;
    ssize_t n = read(fd, buf, buf_size - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    return true;
}

static bool write_file(int dir_fd, const char* filename, const char* content, int flags) {
    int fd = openat(dir_fd, filename, flags | O_CLOEXEC, 0644);
    if (fd == -1) return false;
    ssize_t n = write(fd, content, strlen(content));
    close(fd);
    return (n == (ssize_t)strlen(content));
}

static int build_str(char *dest, size_t dest_size, ...) {
    va_list args;
    const char *segment;
    char *p = dest;
    size_t remaining = dest_size - 1;
    va_start(args, dest_size);
    while ((segment = va_arg(args, const char *)) != NULL) {
        size_t len = strlen(segment);
        if (len > remaining) {
            va_end(args);
            return 0;
        }
        memcpy(p, segment, len);
        p += len;
        remaining -= len;
    }
    *p = '\0';
    va_end(args);
    return 1;
}

static void parse_cpu_ranges(const char* spec, cpu_set_t* set, const cpu_set_t* present) {
    if (!spec) return;
    char* copy = strdup(spec);
    if (!copy) return;
    char* s = copy;
    while (*s) {
        char* end;
        unsigned long a = strtoul(s, &end, 10);
        if (end == s) {
            s++;
            continue;
        }
        unsigned long b = a;
        if (*end == '-') {
            s = end + 1;
            b = strtoul(s, &end, 10);
            if (end == s) b = a;
        }
        if (a > b) { unsigned long t = a; a = b; b = t; }
        for (unsigned long i = a; i <= b && i < CPU_SETSIZE; i++) {
            if (present && !CPU_ISSET(i, present)) continue;
            CPU_SET(i, set);
        }
        s = (*end == ',') ? end + 1 : end;
    }
    free(copy);
}

static char* cpu_set_to_str(const cpu_set_t *set) {
    size_t buf_size = 8 * CPU_SETSIZE;
    char *buf = malloc(buf_size);
    if (!buf) return NULL;
    int start = -1, end = -1;
    char *p = buf;
    size_t remain = buf_size - 1;
    bool first = true;
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, set)) {
            if (start == -1) {
                start = end = i;
            } else if (i == end + 1) {
                end = i;
            } else {
                int needed;
                if (start == end) {
                    needed = snprintf(p, remain + 1, "%s%d", first ? "" : ",", start);
                } else {
                    needed = snprintf(p, remain + 1, "%s%d-%d", first ? "" : ",", start, end);
                }
                if (needed < 0 || (size_t)needed > remain) {
                    free(buf);
                    return NULL;
                }
                p += needed;
                remain -= needed;
                start = end = i;
                first = false;
            }
        }
    }
    if (start != -1) {
        int needed;
        if (start == end) {
            needed = snprintf(p, remain + 1, "%s%d", first ? "" : ",", start);
        } else {
            needed = snprintf(p, remain + 1, "%s%d-%d", first ? "" : ",", start, end);
        }
        if (needed < 0 || (size_t)needed > remain) {
            free(buf);
            return NULL;
        }
        p += needed;
    }
    *p = '\0';
    return buf;
}

static int mkdir_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    char *p = NULL;
    struct stat st;
    size_t len;
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/') tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

static bool create_cpuset_dir(const char *path, const char *cpus, const char *mems) {
    if (mkdir_p(path, 0755) != 0 && errno != EEXIST) return false;
    if (chmod(path, 0755) != 0) return false;
    if (chown(path, 0, 0) != 0) return false;

    char cpus_path[256];
    build_str(cpus_path, sizeof(cpus_path), path, "/cpus", NULL);
    if (!write_file(AT_FDCWD, cpus_path, cpus, O_WRONLY | O_CREAT | O_TRUNC)) return false;

    char mems_path[256];
    build_str(mems_path, sizeof(mems_path), path, "/mems", NULL);
    return write_file(AT_FDCWD, mems_path, mems, O_WRONLY | O_CREAT | O_TRUNC);
}

static CpuTopology init_cpu_topo(void) {
    CpuTopology topo = { .cpuset_enabled = false, .base_cpuset_fd = -1 };
    CPU_ZERO(&topo.present_cpus);
    if (read_file(AT_FDCWD, "/sys/devices/system/cpu/present", topo.present_str, sizeof(topo.present_str))) {
        strtrim(topo.present_str);
    }
    parse_cpu_ranges(topo.present_str, &topo.present_cpus, NULL);
    if (access("/dev/cpuset", F_OK) != 0) return topo;
    if (create_cpuset_dir(BASE_CPUSET, topo.present_str, "0")) {
        topo.base_cpuset_fd = open(BASE_CPUSET, O_RDONLY | O_DIRECTORY);
        if (topo.base_cpuset_fd != -1) topo.cpuset_enabled = true;
    }
    char mems_path[256];
    build_str(mems_path, sizeof(mems_path), BASE_CPUSET, "/mems", NULL);
    if (!read_file(AT_FDCWD, mems_path, topo.mems_str, sizeof(topo.mems_str))) {
        build_str(topo.mems_str, sizeof(topo.mems_str), "0", NULL);
    } else {
        strtrim(topo.mems_str);
    }
    return topo;
}

static void free_proc_resources(ProcessInfo* proc) {
    if (proc->threads) free(proc->threads);
    if (proc->thread_rules) free(proc->thread_rules);
    memset(proc, 0, sizeof(*proc));
}

static AppConfig* merge_configs(const CpuTopology* topo, const char** files, size_t num_files) {
    AppConfig* merged = calloc(1, sizeof(AppConfig));
    if (!merged) return NULL;
    merged->ref_count = 1;
    merged->topo = *topo;
    merged->rules = NULL;
    merged->num_rules = 0;
    merged->pkgs = NULL;
    merged->num_pkgs = 0;
    merged->wildcard_thread_rules = NULL;
    merged->wildcard_thread_rule_count = 0;

    AffinityRule* tmp_rules = NULL;
    size_t tmp_cap = 0, tmp_cnt = 0;

    for (size_t fi = 0; fi < num_files; fi++) {
        FILE* fp = fopen(files[fi], "r");
        if (!fp) {
            fprintf(stderr, "警告: 无法打开配置文件 %s\n", files[fi]);
            continue;
        }
        char line[256];
        int line_num = 0;
        while (fgets(line, sizeof(line), fp)) {
            line_num++;
            char* p = strtrim(line);
            if (*p == '#' || !*p) continue;
            char* eq = strchr(p, '=');
            if (!eq) continue;
            *eq++ = 0;
            char* br = strchr(p, '{');
            char* thread = "";
            if (br) {
                *br++ = 0;
                char* eb = strchr(br, '}');
                if (!eb) continue;
                *eb = 0;
                thread = strtrim(br);
            }
            char* pkg = strtrim(p);
            char* cpus = strtrim(eq);
            if (strlen(pkg) >= MAX_PKG_LEN || strlen(thread) >= MAX_THREAD_LEN) {
                fprintf(stderr, "%s:%d: 规则校验失败: 包名或线程名过长 (%s{%s})\n", files[fi], line_num, pkg, thread);
                continue;
            }
            cpu_set_t set;
            CPU_ZERO(&set);
            parse_cpu_ranges(cpus, &set, &merged->topo.present_cpus);
            if (CPU_COUNT(&set) == 0) {
                fprintf(stderr, "%s:%d: 规则校验失败: CPU 范围无效或不包含任何在线 CPU (%s=%s)\n", files[fi], line_num, pkg, cpus);
                continue;
            }
            char* dir_name = cpu_set_to_str(&set);
            if (!dir_name) {
                fprintf(stderr, "%s:%d: 规则校验失败: 无法生成 cpuset 目录名\n", files[fi], line_num);
                continue;
            }
            char path[256];
            build_str(path, sizeof(path), BASE_CPUSET, "/", dir_name, NULL);
            if (!create_cpuset_dir(path, dir_name, merged->topo.mems_str)) {
                fprintf(stderr, "%s:%d: 规则校验失败: 无法创建 cpuset 目录 %s\n", files[fi], line_num, path);
                free(dir_name);
                continue;
            }
            AffinityRule rule = {0};
            build_str(rule.pkg, sizeof(rule.pkg), pkg, NULL);
            build_str(rule.thread, sizeof(rule.thread), thread, NULL);
            build_str(rule.cpuset_dir, sizeof(rule.cpuset_dir), dir_name, NULL);
            rule.cpus = set;
            free(dir_name);

            if (tmp_cnt >= tmp_cap) {
                size_t new_cap = tmp_cap ? tmp_cap * 2 : 64;
                AffinityRule* tmp = realloc(tmp_rules, new_cap * sizeof(AffinityRule));
                if (!tmp) {
                    fprintf(stderr, "内存不足，跳过规则 %s{%s}\n", pkg, thread);
                    continue;
                }
                tmp_rules = tmp;
                tmp_cap = new_cap;
            }
            tmp_rules[tmp_cnt++] = rule;

            if (strcmp(pkg, "*") != 0) {
                bool pkg_exists = false;
                for (size_t i = 0; i < merged->num_pkgs; i++) {
                    if (strcmp(merged->pkgs[i], pkg) == 0) {
                        pkg_exists = true;
                        break;
                    }
                }
                if (!pkg_exists) {
                    char** tmp = realloc(merged->pkgs, (merged->num_pkgs + 1) * sizeof(char*));
                    if (tmp) {
                        merged->pkgs = tmp;
                        merged->pkgs[merged->num_pkgs] = strdup(pkg);
                        if (merged->pkgs[merged->num_pkgs]) merged->num_pkgs++;
                    }
                }
            }
        }
        fclose(fp);
    }

    if (tmp_cnt) {
        merged->rules = malloc(tmp_cnt * sizeof(AffinityRule));
        if (merged->rules) {
            memcpy(merged->rules, tmp_rules, tmp_cnt * sizeof(AffinityRule));
            merged->num_rules = tmp_cnt;
        }
    }
    free(tmp_rules);

    size_t wcnt = 0;
    for (size_t i = 0; i < merged->num_rules; i++) {
        AffinityRule* r = &merged->rules[i];
        if (strcmp(r->pkg, "*") == 0 && r->thread[0]) wcnt++;
    }
    if (wcnt > 0) {
        merged->wildcard_thread_rules = malloc(wcnt * sizeof(AffinityRule*));
        if (merged->wildcard_thread_rules) {
            size_t idx = 0;
            for (size_t i = 0; i < merged->num_rules; i++) {
                AffinityRule* r = &merged->rules[i];
                if (strcmp(r->pkg, "*") == 0 && r->thread[0]) {
                    merged->wildcard_thread_rules[idx++] = r;
                }
            }
            merged->wildcard_thread_rule_count = wcnt;
        }
    }

    printf("配置合并完成，共加载 %zu 条规则，%zu 个包名，%zu 条通配线程规则\n",
           merged->num_rules, merged->num_pkgs, merged->wildcard_thread_rule_count);
    return merged;
}

static AppConfig* load_configs(const char** files, size_t num_files, const CpuTopology* topo) {
    return merge_configs(topo, files, num_files);
}

static void config_release(AppConfig* cfg) {
    if (!cfg) return;
    if (atomic_fetch_sub(&cfg->ref_count, 1) == 1) {
        if (cfg->rules) free(cfg->rules);
        if (cfg->wildcard_thread_rules) free(cfg->wildcard_thread_rules);
        if (cfg->pkgs) {
            for (size_t i = 0; i < cfg->num_pkgs; i++) free(cfg->pkgs[i]);
            free(cfg->pkgs);
        }
        free(cfg);
    }
}

static AppConfig* get_config(void) {
    AppConfig* cfg = atomic_load_explicit(&current_config, memory_order_acquire);
    if (!cfg) return NULL;
    int old_ref = atomic_fetch_add_explicit(&cfg->ref_count, 1, memory_order_acq_rel);
    if (old_ref <= 0) {
        atomic_fetch_sub_explicit(&cfg->ref_count, 1, memory_order_release);
        return NULL;
    }
    if (atomic_load_explicit(&current_config, memory_order_acquire) != cfg) {
        atomic_fetch_sub_explicit(&cfg->ref_count, 1, memory_order_release);
        return NULL;
    }
    return cfg;
}

static void add_watch_for_config(const char* config_path) {
    if (!inotify_supported || inotify_fd == -1) return;
    char dir_path[PATH_MAX];
    char file_name[PATH_MAX];
    char* last_slash = strrchr(config_path, '/');
    if (last_slash) {
        size_t dirlen = last_slash - config_path;
        if (dirlen >= PATH_MAX) return;
        memcpy(dir_path, config_path, dirlen);
        dir_path[dirlen] = '\0';
        strcpy(file_name, last_slash + 1);
    } else {
        strcpy(dir_path, ".");
        strcpy(file_name, config_path);
    }
    int wd = inotify_add_watch(inotify_fd, dir_path, IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVE);
    if (wd < 0) {
        fprintf(stderr, "警告: 无法监控目录 %s\n", dir_path);
        return;
    }
    WatchEntry* tmp = realloc(watches, (watch_count + 1) * sizeof(WatchEntry));
    if (!tmp) return;
    watches = tmp;
    watches[watch_count].wd = wd;
    strcpy(watches[watch_count].dir_path, dir_path);
    strcpy(watches[watch_count].file_name, file_name);
    watch_count++;
}

static void handle_inotify_events(void) {
    char buf[4096] __attribute__((aligned(8)));
    ssize_t len = read(inotify_fd, buf, sizeof(buf));
    if (len <= 0) return;
    for (char* p = buf; p < buf + len; ) {
        struct inotify_event* ev = (struct inotify_event*)p;
        if (ev->len) {
            for (size_t i = 0; i < watch_count; i++) {
                if (watches[i].wd == ev->wd && strcmp(ev->name, watches[i].file_name) == 0) {
                    if (ev->mask & (IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO)) {
                        atomic_store(&config_updated, 1);
                    }
                }
            }
        }
        p += sizeof(struct inotify_event) + ev->len;
    }
}

static void* config_loader_thread(void* arg) {
    int interval = *(int*)arg;
    free(arg);
    pthread_setname_np(pthread_self(), "ConfigLoader");
    time_t last_reload = 0;
    if (inotify_supported && inotify_fd != -1) {
        for (size_t i = 0; i < num_config_files; i++) {
            add_watch_for_config(config_files[i]);
        }
    }
    while (1) {
        int need_reload = 0;
        if (inotify_supported && inotify_fd != -1) {
            fd_set rfds;
            struct timeval tv;
            FD_ZERO(&rfds);
            FD_SET(inotify_fd, &rfds);
            tv.tv_sec = interval;
            tv.tv_usec = 0;
            int ret = select(inotify_fd + 1, &rfds, NULL, NULL, &tv);
            if (ret < 0) continue;
            if (ret > 0) {
                handle_inotify_events();
                need_reload = atomic_load(&config_updated);
            }
        } else {
            time_t now = time(NULL);
            if (now - last_reload >= interval) {
                need_reload = 1;
                last_reload = now;
            }
        }
        if (need_reload) {
            AppConfig* cfg = get_config();
            CpuTopology topo = cfg ? cfg->topo : init_cpu_topo();
            if (cfg) config_release(cfg);
            AppConfig* new_config = load_configs((const char**)config_files, num_config_files, &topo);
            if (new_config) {
                AppConfig* old = atomic_exchange(&current_config, new_config);
                atomic_store(&config_updated, 1);
                if (old) config_release(old);
            }
            need_reload = 0;
        }
        if (!inotify_supported) sleep(interval);
        else usleep(100000);
    }
    return NULL;
}

static bool is_pid_tracked(ProcCache* cache, pid_t pid) {
    for (size_t i = 0; i < cache->num_tracked_pids; i++) {
        if (cache->tracked_pids[i] == pid) return true;
    }
    return false;
}

static void add_tracked_pid(ProcCache* cache, pid_t pid) {
    if (cache->num_tracked_pids >= cache->tracked_pids_cap) {
        size_t new_cap = cache->tracked_pids_cap ? cache->tracked_pids_cap * 2 : 64;
        pid_t* tmp = realloc(cache->tracked_pids, new_cap * sizeof(pid_t));
        if (!tmp) return;
        cache->tracked_pids = tmp;
        cache->tracked_pids_cap = new_cap;
    }
    cache->tracked_pids[cache->num_tracked_pids++] = pid;
}

static void process_thread_rules(ProcessInfo* proc, const AppConfig* cfg, size_t* out_idx) {
    bool base_rule_set = false;
    for (size_t i = 0; i < cfg->num_rules; i++) {
        const AffinityRule* rule = &cfg->rules[i];
        if (strcmp(rule->pkg, proc->pkg) != 0) continue;
        if (rule->thread[0]) {
            if (proc->num_thread_rules >= proc->thread_rules_cap) {
                size_t new_cap = proc->thread_rules_cap ? proc->thread_rules_cap * 2 : 8;
                AffinityRule** tmp = realloc(proc->thread_rules, new_cap * sizeof(AffinityRule*));
                if (!tmp) return;
                proc->thread_rules = tmp;
                proc->thread_rules_cap = new_cap;
            }
            proc->thread_rules[proc->num_thread_rules++] = (AffinityRule*)rule;
        } else {
            if (!base_rule_set) {
                CPU_OR(&proc->base_cpus, &proc->base_cpus, &rule->cpus);
                build_str(proc->base_cpuset, sizeof(proc->base_cpuset), rule->cpuset_dir, NULL);
                base_rule_set = true;
            } else {
                fprintf(stderr, "警告: 进程 %s (PID %d) 匹配多个进程级规则，仅第一个生效\n", proc->pkg, proc->pid);
            }
        }
    }
    if (!base_rule_set && CPU_COUNT(&proc->base_cpus) == 0 && cfg->wildcard_thread_rule_count > 0) {
        for (size_t i = 0; i < cfg->num_rules; i++) {
            const AffinityRule* rule = &cfg->rules[i];
            if (!(rule->pkg[0] == '*' && rule->pkg[1] == '\0')) continue;
            if (!rule->thread[0]) {
                CPU_OR(&proc->base_cpus, &proc->base_cpus, &rule->cpus);
                build_str(proc->base_cpuset, sizeof(proc->base_cpuset), rule->cpuset_dir, NULL);
                base_rule_set = true;
                break;
            }
        }
    }
    if (CPU_COUNT(&proc->base_cpus) == 0 && proc->num_thread_rules == 0 && cfg->wildcard_thread_rule_count == 0) {
        *out_idx = (size_t)-1;
        return;
    }
    *out_idx = 0;
}

static void collect_threads(ProcessInfo* proc, int task_fd, const AppConfig* cfg) {
    DIR* task_dir = fdopendir(task_fd);
    if (!task_dir) return;
    struct dirent* tent;
    while ((tent = readdir(task_dir))) {
        char* end;
        long tid = strtol(tent->d_name, &end, 10);
        if (*end != '\0') continue;
        char tname[MAX_THREAD_LEN] = {0};
        int tid_fd = openat(task_fd, tent->d_name, O_RDONLY | O_DIRECTORY);
        if (tid_fd == -1) continue;
        if (!read_file(tid_fd, "comm", tname, sizeof(tname))) {
            close(tid_fd);
            continue;
        }
        close(tid_fd);
        strtrim(tname);

        if (proc->num_threads >= proc->threads_cap) {
            size_t new_cap = proc->threads_cap ? proc->threads_cap * 2 : 64;
            ThreadInfo* tmp = realloc(proc->threads, new_cap * sizeof(ThreadInfo));
            if (!tmp) continue;
            proc->threads = tmp;
            proc->threads_cap = new_cap;
        }
        ThreadInfo* ti = &proc->threads[proc->num_threads];
        ti->tid = tid;
        build_str(ti->name, sizeof(ti->name), tname, NULL);
        CPU_ZERO(&ti->cpus);
        const char* matched = NULL;

        const AffinityRule* best_rule = NULL;
        size_t best_len = 0;
        for (size_t i = 0; i < proc->num_thread_rules; i++) {
            const AffinityRule* rule = proc->thread_rules[i];
            if (fnmatch(rule->thread, ti->name, FNM_NOESCAPE) == 0) {
                size_t len = strlen(rule->thread);
                if (!best_rule || len > best_len) {
                    best_rule = rule;
                    best_len = len;
                }
            }
        }
        if (best_rule) {
            ti->cpus = best_rule->cpus;
            matched = best_rule->cpuset_dir;
        }
        if (CPU_COUNT(&ti->cpus) == 0 && cfg->wildcard_thread_rule_count > 0) {
            const AffinityRule* best_wild = NULL;
            size_t best_wild_len = 0;
            for (size_t i = 0; i < cfg->wildcard_thread_rule_count; i++) {
                const AffinityRule* rule = cfg->wildcard_thread_rules[i];
                if (fnmatch(rule->thread, ti->name, FNM_NOESCAPE) == 0) {
                    size_t len = strlen(rule->thread);
                    if (!best_wild || len > best_wild_len) {
                        best_wild = rule;
                        best_wild_len = len;
                    }
                }
            }
            if (best_wild) {
                ti->cpus = best_wild->cpus;
                matched = best_wild->cpuset_dir;
            }
        }
        if (matched) {
            build_str(ti->cpuset_dir, sizeof(ti->cpuset_dir), matched, NULL);
        } else if (CPU_COUNT(&proc->base_cpus) > 0) {
            ti->cpus = proc->base_cpus;
            build_str(ti->cpuset_dir, sizeof(ti->cpuset_dir), proc->base_cpuset, NULL);
        }
        proc->num_threads++;
    }
    closedir(task_dir);
}

static void proc_collect(const AppConfig* cfg, ProcCache* cache, size_t* count) {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return;
    int proc_fd = dirfd(proc_dir);
    *count = 0;

    if (cache->procs) {
        for (size_t i = 0; i < cache->num_procs; i++) {
            free_proc_resources(&cache->procs[i]);
        }
    }
    cache->num_procs = 0;
    if (cache->procs_cap == 0) {
        cache->procs_cap = 2048;
        cache->procs = calloc(cache->procs_cap, sizeof(ProcessInfo));
        if (!cache->procs) {
            closedir(proc_dir);
            return;
        }
    }

    bool has_wildcard_pkg = (cfg->wildcard_thread_rule_count > 0);
    for (size_t i = 0; i < cfg->num_rules; i++) {
        if (strcmp(cfg->rules[i].pkg, "*") == 0) {
            has_wildcard_pkg = true;
            break;
        }
    }

    struct dirent* ent;
    time_t current_time = time(NULL);
    int current_proc_total = 0;
    while ((ent = readdir(proc_dir))) {
        char *end;
        long pid = strtol(ent->d_name, &end, 10);
        if (*end != '\0') continue;
        current_proc_total++;

        if (!cache->scan_all_proc && !is_pid_tracked(cache, pid)) {
            struct stat statbuf;
            if (fstatat(proc_fd, ent->d_name, &statbuf, AT_SYMLINK_NOFOLLOW) != 0) continue;
            if (current_time - statbuf.st_mtime > 60) continue;
        }

        int pid_fd = openat(proc_fd, ent->d_name, O_RDONLY | O_DIRECTORY);
        if (pid_fd == -1) continue;

        char cmd[MAX_PKG_LEN] = {0};
        if (!read_file(pid_fd, "cmdline", cmd, sizeof(cmd))) {
            close(pid_fd);
            continue;
        }
        char* name = strrchr(cmd, '/');
        name = name ? name + 1 : cmd;

        bool found = false;
        for (size_t j = 0; j < cfg->num_pkgs; j++) {
            if (strcmp(name, cfg->pkgs[j]) == 0) {
                found = true;
                break;
            }
        }
        if (!found && !has_wildcard_pkg) {
            close(pid_fd);
            continue;
        }

        if (*count >= cache->procs_cap) {
            size_t new_cap = cache->procs_cap * 2;
            ProcessInfo* new_procs = realloc(cache->procs, new_cap * sizeof(ProcessInfo));
            if (!new_procs) {
                close(pid_fd);
                continue;
            }
            memset(new_procs + cache->procs_cap, 0, (new_cap - cache->procs_cap) * sizeof(ProcessInfo));
            cache->procs = new_procs;
            cache->procs_cap = new_cap;
        }

        ProcessInfo* proc = &cache->procs[*count];
        proc->pid = pid;
        build_str(proc->pkg, sizeof(proc->pkg), name, NULL);
        CPU_ZERO(&proc->base_cpus);
        proc->base_cpuset[0] = '\0';
        proc->num_threads = 0;
        proc->num_thread_rules = 0;
        proc->threads_cap = 0;
        proc->thread_rules_cap = 0;
        proc->threads = NULL;
        proc->thread_rules = NULL;

        size_t valid_flag = 0;
        process_thread_rules(proc, cfg, &valid_flag);
        if (valid_flag == (size_t)-1) {
            close(pid_fd);
            continue;
        }

        int task_fd = openat(pid_fd, "task", O_RDONLY | O_DIRECTORY);
        close(pid_fd);
        if (task_fd == -1) continue;

        collect_threads(proc, task_fd, cfg);
        close(task_fd);

        if (proc->num_threads == 0) {
            free_proc_resources(proc);
            continue;
        }
        (*count)++;
        add_tracked_pid(cache, pid);
    }
    closedir(proc_dir);
    if (current_proc_total > cache->last_proc_total) {
        cache->scan_all_proc = true;
    } else {
        cache->scan_all_proc = false;
    }
    cache->last_proc_total = current_proc_total;
}

static void update_cache(ProcCache* cache, const AppConfig* cfg, int* affinity_counter) {
    bool need_reload = false;
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        need_reload = true;
    } else {
        int current_proc_count = info.procs;
        if (current_proc_count > cache->last_proc_count + 11) {
            need_reload = true;
        } else if (current_proc_count > cache->last_proc_count) {
            *affinity_counter = 0;
        }
        cache->last_proc_count = current_proc_count;
    }
    if (cache->procs != NULL && !need_reload) {
        for (size_t i = 0; i < cache->num_procs; i++) {
            if (kill(cache->procs[i].pid, 0) != 0) {
                need_reload = true;
                break;
            }
        }
    }
    if (need_reload) {
        size_t new_count = 0;
        proc_collect(cfg, cache, &new_count);
        cache->num_procs = new_count;
        *affinity_counter = 0;
    }
}

static void apply_affinity(ProcCache* cache, const CpuTopology* topo) {
    for (size_t i = 0; i < cache->num_procs; i++) {
        const ProcessInfo* proc = &cache->procs[i];
        for (size_t j = 0; j < proc->num_threads; j++) {
            const ThreadInfo* ti = &proc->threads[j];
            if (topo->cpuset_enabled && topo->base_cpuset_fd != -1) {
                char tid_str[32];
                snprintf(tid_str, sizeof(tid_str), "%d\n", ti->tid);
                if (CPU_COUNT(&ti->cpus) == 0) {
                    cpu_set_t curr;
                    if (sched_getaffinity(ti->tid, sizeof(curr), &curr) == -1) continue;
                    if (CPU_EQUAL(&topo->present_cpus, &curr)) continue;
                    if (!write_file(topo->base_cpuset_fd, "tasks", tid_str, O_WRONLY | O_APPEND)) {
                        fprintf(stderr, "警告: 无法将线程 %d 移入 base cpuset\n", ti->tid);
                    }
                } else {
                    cpu_set_t curr;
                    if (sched_getaffinity(ti->tid, sizeof(curr), &curr) == -1) continue;
                    if (CPU_EQUAL(&ti->cpus, &curr)) continue;
                    if (ti->cpuset_dir[0]) {
                        int fd = openat(topo->base_cpuset_fd, ti->cpuset_dir, O_RDONLY | O_DIRECTORY);
                        if (fd != -1) {
                            if (!write_file(fd, "tasks", tid_str, O_WRONLY | O_APPEND)) {
                                fprintf(stderr, "警告: 无法将线程 %d 移入 cpuset %s\n", ti->tid, ti->cpuset_dir);
                            }
                            close(fd);
                        }
                    }
                }
            }
            if (CPU_COUNT(&ti->cpus) == 0) continue;
            if (sched_setaffinity(ti->tid, sizeof(ti->cpus), &ti->cpus) == -1) {
                if (errno == ESRCH) {
                    cache->last_proc_count = 0;
                } else {
                    fprintf(stderr, "警告: 设置线程 %d (%.15s) 亲和性失败: %s\n", ti->tid, ti->name, strerror(errno));
                }
            }
        }
    }
}

static void print_help(const char* prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -c <config_file>   指定配置文件 (可多次使用，合并所有配置)\n");
    printf("  -s <interval>      设置检查间隔(秒) (必须>=1, 默认: 2)\n");
    printf("  -v                 显示程序版本\n");
    printf("  -h                 显示帮助信息\n");
    printf("\n示例:\n");
    printf("  %s -c /data/app1.conf -c /data/app2.conf -s 3\n", prog_name);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    CpuTopology topo = init_cpu_topo();
    int sleep_interval = 2;
    int opt;
    while ((opt = getopt(argc, argv, "c:s:hv")) != -1) {
        switch (opt) {
            case 'c': {
                char** tmp = realloc(config_files, (num_config_files + 1) * sizeof(char*));
                if (!tmp) {
                    perror("realloc config_files");
                    exit(EXIT_FAILURE);
                }
                config_files = tmp;
                config_files[num_config_files] = strdup(optarg);
                num_config_files++;
                break;
            }
            case 's': {
                char *endptr;
                long val = strtol(optarg, &endptr, 10);
                if (endptr == optarg || *endptr != '\0' || val < 1) {
                    fprintf(stderr, "无效的时间间隔: %s\n", optarg);
                    fprintf(stderr, "间隔必须是 >=1 的整数\n");
                    exit(EXIT_FAILURE);
                }
                sleep_interval = (int)val;
                printf("检查间隔: %d 秒\n", sleep_interval);
                break;
            }
            case 'v':
                printf("AppOpt 版本 %s\n", VERSION);
                exit(EXIT_SUCCESS);
            case 'h':
                print_help(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                print_help(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (num_config_files == 0) {
        config_files = malloc(sizeof(char*));
        config_files[0] = strdup("./applist.conf");
        num_config_files = 1;
    }

    for (size_t i = 0; i < num_config_files; i++) {
        struct stat st;
        if (stat(config_files[i], &st) != 0) {
            const char* initial_content = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n";
            if (write_file(AT_FDCWD, config_files[i], initial_content, O_WRONLY | O_CREAT | O_TRUNC)) {
                printf("配置文件 %s 不存在，已创建空配置文件\n", config_files[i]);
            }
        }
    }

    AppConfig* initial_config = load_configs((const char**)config_files, num_config_files, &topo);
    if (!initial_config) {
        fprintf(stderr, "初始配置加载失败\n");
        exit(EXIT_FAILURE);
    }
    atomic_store(&current_config, initial_config);
    atomic_store(&config_updated, 1);

    inotify_fd = inotify_init1(IN_CLOEXEC);
    if (inotify_fd >= 0) {
        int flags = fcntl(inotify_fd, F_GETFL);
        if (flags >= 0) fcntl(inotify_fd, F_SETFL, flags | O_NONBLOCK);
        inotify_supported = 1;
        printf("启用 inotify 监控配置文件变更\n");
    } else {
        inotify_supported = 0;
        printf("inotify 初始化失败，使用轮询模式\n");
    }

    pthread_t loader_thread;
    int* interval_ptr = malloc(sizeof(int));
    if (!interval_ptr) {
        config_release(initial_config);
        if (inotify_fd >= 0) close(inotify_fd);
        exit(EXIT_FAILURE);
    }
    *interval_ptr = sleep_interval;
    if (pthread_create(&loader_thread, NULL, config_loader_thread, interval_ptr) != 0) {
        perror("配置加载器线程创建失败");
        free(interval_ptr);
        config_release(initial_config);
        if (inotify_fd >= 0) close(inotify_fd);
        exit(EXIT_FAILURE);
    }
    pthread_detach(loader_thread);

    ProcCache cache = {0};
    int affinity_counter = 0;
    printf("启动 AppOpt 服务 v%s\n", VERSION);

    for (;;) {
        if (atomic_exchange(&config_updated, 0)) {
            cache.scan_all_proc = true;
            cache.last_proc_count = 0;
        }
        AppConfig* cfg = get_config();
        if (cfg) {
            update_cache(&cache, cfg, &affinity_counter);
            affinity_counter--;
            if (affinity_counter < 1) {
                apply_affinity(&cache, &cfg->topo);
                affinity_counter = 5;
            }
            config_release(cfg);
        }
        sleep(sleep_interval);
    }
    return 0;
}