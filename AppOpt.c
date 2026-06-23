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
    int last_proc_count;
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
    while (isspace(*s)) s++;
    char* end = s + strlen(s) - 1;
    while (end > s && isspace(*end)) end--;
    end[1] = '\0';
}

static bool parse_cpu_ranges(const char* spec, cpu_set_t* set) {
    if (!spec) return true;
    char* copy = strdup(spec);
    if (!copy) return false;
    char* s = copy;
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
        for (unsigned long i = a; i <= b && i < CPU_SETSIZE; i++)
            CPU_SET(i, set);
        s = (*end == ',') ? end + 1 : end;
    }
    free(copy);
    return true;
}

static char* cpu_set_to_str(const cpu_set_t* set) {
    static char buf[512];
    char* p = buf;
    bool first = true;
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, set)) {
            int start = i;
            while (i + 1 < CPU_SETSIZE && CPU_ISSET(i + 1, set)) i++;
            p += sprintf(p, "%s%d%s", first ? "" : ",", start, start == i ? "" : "-");
            if (start != i) p += sprintf(p, "%d", i);
            first = false;
        }
    }
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
    sprintf(tmp, "%s/cpus", path);
    write_file(AT_FDCWD, tmp, cpus);
    sprintf(tmp, "%s/mems", path);
    write_file(AT_FDCWD, tmp, mems);
    return true;
}

// ============ 配置加载（保留所有功能） ============
static AppConfig* load_config(const char* file, const CpuTopology* topo, time_t* last_mtime) {
    struct stat st;
    if (stat(file, &st) != 0) {
        write_file(AT_FDCWD, file, "# AppOpt config\n");
        return NULL;
    }
    
    if (last_mtime && *last_mtime == st.st_mtime && *last_mtime != -1)
        return NULL;

    int fd = open(file, O_RDONLY);
    if (fd < 0) { LOG("无法打开配置: %s\n", file); return NULL; }

    char* data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) return NULL;

    AppConfig* cfg = calloc(1, sizeof(AppConfig));
    if (!cfg) { munmap(data, st.st_size); return NULL; }
    
    cfg->ref_count = 1;
    cfg->topo = *topo;
    strncpy(cfg->config_file, file, sizeof(cfg->config_file) - 1);
    cfg->rules = malloc(256 * sizeof(AffinityRule));
    cfg->wildcard_rules = malloc(128 * sizeof(AffinityRule*));
    PackageEntry* pkg_table = NULL;

    char line[256], *p = data, *end = data + st.st_size;
    size_t num_rules = 0, num_wild = 0;

    while (p < end) {
        char* nl = memchr(p, '\n', end - p);
        if (!nl) nl = end;
        size_t len = nl - p;
        if (len < sizeof(line)) {
            memcpy(line, p, len);
            line[len] = '\0';
            trim(line);
            
            if (line[0] && line[0] != '#') {
                char* eq = strchr(line, '=');
                if (eq) {
                    *eq++ = '\0';
                    char* key = trim(line);
                    char* val = trim(eq);
                    
                    // 解析包名{线程名}
                    char* br = strchr(key, '{');
                    char* thread = "";
                    if (br) {
                        *br++ = '\0';
                        char* eb = strchr(br, '}');
                        if (eb) { *eb = '\0'; thread = trim(br); }
                    }
                    char* pkg = trim(key);
                    
                    // 创建规则
                    AffinityRule* r = &cfg->rules[num_rules];
                    strncpy(r->pkg, pkg, MAX_PKG_LEN - 1);
                    strncpy(r->thread, thread, MAX_THREAD_LEN - 1);
                    CPU_ZERO(&r->cpus);
                    parse_cpu_ranges(val, &r->cpus);
                    
                    // 判断是否是默认规则
                    bool is_default = (strcmp(pkg, "*") == 0 && !thread[0]);
                    r->priority = is_default ? -1 : calc_priority(thread[0] ? thread : pkg);
                    r->is_wildcard = is_default || strchr(pkg, '*') || strchr(pkg, '?') || 
                                    strchr(thread, '*') || strchr(thread, '?');
                    
                    // 创建cpuset目录
                    char path[256];
                    sprintf(path, "%s/%s", BASE_CPUSET, val);
                    create_cpuset_dir(path, val, topo->mems_str);
                    strncpy(r->cpuset_dir, val, sizeof(r->cpuset_dir) - 1);
                    
                    // 存储规则
                    if (!r->is_wildcard) {
                        PackageEntry* pe;
                        HASH_FIND_STR(pkg_table, pkg, pe);
                        if (!pe) {
                            pe = malloc(sizeof(PackageEntry));
                            strcpy(pe->pkg, pkg);
                            HASH_ADD_STR(pkg_table, pkg, pe);
                        }
                    } else {
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
        free(cfg->rules);
        free(cfg->wildcard_rules);
        free(cfg);
        return NULL;
    }

    // 构建包列表
    cfg->num_pkgs = HASH_COUNT(pkg_table);
    cfg->pkgs = malloc(cfg->num_pkgs * sizeof(char*));
    size_t idx = 0;
    PackageEntry *pe, *tmp;
    HASH_ITER(hh, pkg_table, pe, tmp) {
        cfg->pkgs[idx++] = strdup(pe->pkg);
        HASH_DEL(pkg_table, pe);
        free(pe);
    }
    
    cfg->rules = realloc(cfg->rules, num_rules * sizeof(AffinityRule));
    cfg->num_rules = num_rules;
    cfg->wildcard_rules = realloc(cfg->wildcard_rules, num_wild * sizeof(AffinityRule*));
    cfg->num_wildcard_rules = num_wild;
    cfg->mtime = st.st_mtime;
    if (last_mtime) *last_mtime = st.st_mtime;
    
    LOG("加载 %zu 条规则，%zu 条通配符规则\n", num_rules, num_wild);
    return cfg;
}

// ============ 规则匹配（保留优先级和通配符） ============
static int compare_rules(const void* a, const void* b) {
    AffinityRule* ra = *(AffinityRule**)a;
    AffinityRule* rb = *(AffinityRule**)b;
    return rb->priority - ra->priority;
}

static void match_rules_for_process(ProcessInfo* proc, const AppConfig* cfg) {
    // 查找精确匹配
    PackageEntry* pe;
    HASH_FIND_STR(cfg->pkg_table, proc->pkg, pe);
    
    proc->thread_rules = malloc(8 * sizeof(AffinityRule*));
    proc->thread_rules_cap = 8;
    proc->num_thread_rules = 0;
    
    // 默认规则（最低优先级）
    AffinityRule* default_rule = NULL;
    
    // 1. 精确匹配
    if (pe) {
        for (size_t i = 0; i < cfg->num_rules; i++) {
            AffinityRule* r = &cfg->rules[i];
            if (strcmp(r->pkg, proc->pkg) == 0) {
                if (r->priority == -1) {
                    default_rule = r;
                } else if (proc->num_thread_rules < proc->thread_rules_cap) {
                    proc->thread_rules[proc->num_thread_rules++] = r;
                }
            }
        }
    }
    
    // 2. 通配符匹配
    if (proc->num_thread_rules == 0) {
        for (size_t i = 0; i < cfg->num_wildcard_rules; i++) {
            AffinityRule* r = cfg->wildcard_rules[i];
            if (r->priority == -1) {
                default_rule = r;
                continue;
            }
            if (fnmatch(r->pkg, proc->pkg, 0) == 0) {
                if (proc->num_thread_rules < proc->thread_rules_cap) {
                    proc->thread_rules[proc->num_thread_rules++] = r;
                }
            }
        }
    }
    
    // 3. 应用默认规则
    if (proc->num_thread_rules == 0 && default_rule) {
        proc->thread_rules[proc->num_thread_rules++] = default_rule;
    }
    
    // 按优先级排序
    if (proc->num_thread_rules > 1) {
        qsort(proc->thread_rules, proc->num_thread_rules, sizeof(AffinityRule*), compare_rules);
    }
    
    // 设置基础CPU
    if (proc->num_thread_rules > 0) {
        CPU_ZERO(&proc->base_cpus);
        for (size_t i = 0; i < proc->num_thread_rules; i++) {
            if (proc->thread_rules[i]->priority != -1) {
                CPU_OR(&proc->base_cpus, &proc->base_cpus, &proc->thread_rules[i]->cpus);
                strcpy(proc->base_cpuset, proc->thread_rules[i]->cpuset_dir);
                break;
            }
        }
        // 如果没有非默认规则，使用默认规则
        if (CPU_COUNT(&proc->base_cpus) == 0) {
            CPU_OR(&proc->base_cpus, &proc->base_cpus, &proc->thread_rules[0]->cpus);
            strcpy(proc->base_cpuset, proc->thread_rules[0]->cpuset_dir);
        }
    }
}

// ============ 进程收集 ============
static void collect_procs(const AppConfig* cfg, ProcCache* cache) {
    char buf[DENT_BUF_SIZE];
    int fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return;

    cache->num_procs = 0;
    if (!cache->procs) {
        cache->procs_cap = 1024;
        cache->procs = calloc(cache->procs_cap, sizeof(ProcessInfo));
    }

    time_t now = time(NULL);
    while (1) {
        int n = syscall(__NR_getdents64, fd, buf, DENT_BUF_SIZE);
        if (n <= 0) break;
        
        for (int pos = 0; pos < n; ) {
            struct linux_dirent64* e = (struct linux_dirent64*)(buf + pos);
            if (e->d_type == DT_DIR && isdigit(e->d_name[0])) {
                pid_t pid = atoi(e->d_name);
                
                // 检查是否需要扫描
                bool tracked = false;
                for (size_t i = 0; i < cache->num_tracked; i++) {
                    if (cache->tracked_pids[i] == pid) { tracked = true; break; }
                }
                
                if (!tracked && !cache->scan_all) {
                    struct stat st;
                    if (fstatat(fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
                        if (now - st.st_mtime > 60) goto skip;
                    }
                }
                
                int pfd = openat(fd, e->d_name, O_RDONLY | O_DIRECTORY);
                if (pfd < 0) goto skip;
                
                char cmd[MAX_PKG_LEN] = {0};
                if (!read_file(pfd, "cmdline", cmd, sizeof(cmd))) {
                    close(pfd); goto skip;
                }
                
                // 确保有足够的容量
                if (cache->num_procs >= cache->procs_cap) {
                    cache->procs_cap *= 2;
                    cache->procs = realloc(cache->procs, cache->procs_cap * sizeof(ProcessInfo));
                }
                
                ProcessInfo* proc = &cache->procs[cache->num_procs];
                proc->pid = pid;
                char* name = strrchr(cmd, '/');
                strncpy(proc->pkg, name ? name + 1 : cmd, MAX_PKG_LEN - 1);
                proc->threads = NULL;
                proc->num_threads = 0;
                proc->threads_cap = 0;
                
                // 匹配规则
                match_rules_for_process(proc, cfg);
                if (proc->num_thread_rules == 0) {
                    close(pfd);
                    goto skip;
                }
                
                // 收集线程
                int tf = openat(pfd, "task", O_RDONLY | O_DIRECTORY);
                close(pfd);
                if (tf < 0) goto skip;
                
                DIR* d = fdopendir(tf);
                if (!d) { close(tf); goto skip; }
                
                proc->threads = malloc(32 * sizeof(ThreadInfo));
                proc->threads_cap = 32;
                proc->num_threads = 0;
                
                struct dirent* de;
                while ((de = readdir(d))) {
                    pid_t tid = atoi(de->d_name);
                    if (tid == 0) continue;
                    
                    char tname[MAX_THREAD_LEN] = {0};
                    int tf2 = openat(tf, de->d_name, O_RDONLY | O_DIRECTORY);
                    if (tf2 >= 0) {
                        read_file(tf2, "comm", tname, sizeof(tname));
                        close(tf2);
                    }
                    trim(tname);
                    
                    if (proc->num_threads >= proc->threads_cap) {
                        proc->threads_cap *= 2;
                        proc->threads = realloc(proc->threads, proc->threads_cap * sizeof(ThreadInfo));
                    }
                    
                    ThreadInfo* ti = &proc->threads[proc->num_threads];
                    ti->tid = tid;
                    strncpy(ti->name, tname, MAX_THREAD_LEN - 1);
                    
                    // 线程规则匹配（保留优先级）
                    bool matched = false;
                    for (size_t i = 0; i < proc->num_thread_rules; i++) {
                        AffinityRule* r = proc->thread_rules[i];
                        if (r->priority == -1) {
                            // 默认规则：匹配所有
                            if (!matched) {
                                ti->cpus = r->cpus;
                                strcpy(ti->cpuset_dir, r->cpuset_dir);
                                matched = true;
                            }
                            continue;
                        }
                        if (fnmatch(r->thread, tname, 0) == 0) {
                            ti->cpus = r->cpus;
                            strcpy(ti->cpuset_dir, r->cpuset_dir);
                            matched = true;
                            break;
                        }
                    }
                    
                    if (!matched) {
                        ti->cpus = proc->base_cpus;
                        strcpy(ti->cpuset_dir, proc->base_cpuset);
                    }
                    
                    proc->num_threads++;
                }
                closedir(d);
                cache->num_procs++;
                
            skip:
                pos += e->d_reclen;
            } else {
                pos += e->d_reclen;
            }
        }
    }
    close(fd);
}

// ============ 应用亲和性 ============
static void apply_affinity(const ProcCache* cache, const CpuTopology* topo) {
    for (size_t i = 0; i < cache->num_procs; i++) {
        const ProcessInfo* p = &cache->procs[i];
        for (size_t j = 0; j < p->num_threads; j++) {
            const ThreadInfo* t = &p->threads[j];
            
            cpu_set_t curr;
            if (sched_getaffinity(t->tid, sizeof(curr), &curr) == 0) {
                if (CPU_EQUAL(&t->cpus, &curr)) continue;
            }
            
            if (sched_setaffinity(t->tid, sizeof(t->cpus), &t->cpus) == 0) {
                if (topo->cpuset_enabled && t->cpuset_dir[0]) {
                    char tid_str[32];
                    sprintf(tid_str, "%d\n", t->tid);
                    int cfd = openat(topo->base_cpuset_fd, t->cpuset_dir, O_RDONLY | O_DIRECTORY);
                    if (cfd >= 0) {
                        write_file(cfd, "tasks", tid_str);
                        close(cfd);
                    }
                }
            }
        }
    }
}

// ============ 配置管理（保留inotify） ============
static atomic_int config_updated = ATOMIC_VAR_INIT(0);
static _Atomic(AppConfig*) current_config = NULL;
static int inotify_fd = -1;
static int inotify_wd = -1;
static int inotify_supported = 0;

static void config_release(AppConfig* cfg) {
    if (!cfg) return;
    if (atomic_fetch_sub(&cfg->ref_count, 1) == 1) {
        free(cfg->rules);
        free(cfg->wildcard_rules);
        for (size_t i = 0; i < cfg->num_pkgs; i++) free(cfg->pkgs[i]);
        free(cfg->pkgs);
        free(cfg);
    }
}

static AppConfig* get_config(void) {
    AppConfig* cfg = atomic_load(&current_config);
    if (cfg) atomic_fetch_add(&cfg->ref_count, 1);
    return cfg;
}

static void* config_loader_thread(void* arg) {
    int interval = *(int*)arg;
    free(arg);
    time_t last_mtime = -1;
    
    while (1) {
        if (inotify_supported) {
            fd_set rfds;
            struct timeval tv = {.tv_sec = interval, .tv_usec = 0};
            FD_ZERO(&rfds);
            FD_SET(inotify_fd, &rfds);
            
            int ret = select(inotify_fd + 1, &rfds, NULL, NULL, &tv);
            if (ret > 0) {
                char buf[4096];
                read(inotify_fd, buf, sizeof(buf));
                
                AppConfig* cfg = get_config();
                if (cfg) {
                    AppConfig* newcfg = load_config(cfg->config_file, &cfg->topo, &last_mtime);
                    if (newcfg) {
                        AppConfig* old = atomic_exchange(&current_config, newcfg);
                        atomic_store(&config_updated, 1);
                        if (old) {
                            usleep(10000);
                            config_release(old);
                        }
                    }
                    config_release(cfg);
                }
            }
        } else {
            AppConfig* cfg = get_config();
            if (cfg) {
                AppConfig* newcfg = load_config(cfg->config_file, &cfg->topo, &last_mtime);
                if (newcfg) {
                    AppConfig* old = atomic_exchange(&current_config, newcfg);
                    atomic_store(&config_updated, 1);
                    if (old) {
                        usleep(10000);
                        config_release(old);
                    }
                }
                config_release(cfg);
            }
            sleep(interval);
        }
    }
    return NULL;
}

// ============ 缓存更新 ============
static void update_cache(ProcCache* cache, const AppConfig* cfg, int* counter) {
    bool need_reload = atomic_load(&config_updated);
    
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        if (info.procs > cache->last_proc_total + 10) need_reload = true;
        cache->last_proc_total = info.procs;
    }
    
    if (!need_reload && cache->procs) {
        for (size_t i = 0; i < cache->num_procs; i++) {
            if (kill(cache->procs[i].pid, 0) != 0) {
                need_reload = true;
                break;
            }
        }
    }
    
    if (need_reload || cache->scan_all || *counter % 10 == 0) {
        collect_procs(cfg, cache);
        cache->scan_all = false;
        
        // 更新跟踪列表
        if (cache->num_procs > cache->tracked_cap) {
            cache->tracked_cap = cache->num_procs * 2;
            cache->tracked_pids = realloc(cache->tracked_pids, cache->tracked_cap * sizeof(pid_t));
        }
        cache->num_tracked = 0;
        for (size_t i = 0; i < cache->num_procs; i++) {
            if (cache->num_tracked < cache->tracked_cap) {
                cache->tracked_pids[cache->num_tracked++] = cache->procs[i].pid;
            }
        }
        *counter = 0;
    }
}

// ============ 主函数 ============
int main(int argc, char** argv) {
    char config_file[4096] = "./applist.conf";
    int interval = 2;
    
    // 解析参数
    int opt;
    while ((opt = getopt(argc, argv, "c:s:hv")) != -1) {
        switch (opt) {
            case 'c': strncpy(config_file, optarg, sizeof(config_file) - 1); break;
            case 's': interval = atoi(optarg); if (interval < 1) interval = 1; break;
            case 'v': printf("AppOpt %s\n", VERSION); exit(0);
            case 'h': printf("Usage: %s [-c config] [-s seconds]\n", argv[0]); exit(0);
        }
    }
    
    // 初始化CPU拓扑
    CpuTopology topo = {0};
    read_file(AT_FDCWD, "/sys/devices/system/cpu/present", topo.present_str, sizeof(topo.present_str));
    parse_cpu_ranges(topo.present_str, &topo.present_cpus);
    strcpy(topo.mems_str, "0");
    if (access("/dev/cpuset", F_OK) == 0) {
        mkdir(BASE_CPUSET, 0755);
        topo.base_cpuset_fd = open(BASE_CPUSET, O_RDONLY | O_DIRECTORY);
        if (topo.base_cpuset_fd >= 0) topo.cpuset_enabled = true;
    }
    
    // 加载初始配置
    AppConfig* cfg = load_config(config_file, &topo, NULL);
    if (!cfg) { LOG("配置加载失败\n"); exit(1); }
    atomic_store(&current_config, cfg);
    atomic_store(&config_updated, 1);
    
    // 初始化inotify
    inotify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (inotify_fd >= 0) {
        inotify_wd = inotify_add_watch(inotify_fd, config_file, IN_CLOSE_WRITE | IN_DELETE_SELF);
        if (inotify_wd >= 0) {
            inotify_supported = 1;
            LOG("启用inotify监控\n");
        } else {
            close(inotify_fd);
            inotify_fd = -1;
        }
    }
    
    // 启动配置加载线程
    int* interval_ptr = malloc(sizeof(int));
    *interval_ptr = interval;
    pthread_t loader;
    pthread_create(&loader, NULL, config_loader_thread, interval_ptr);
    pthread_detach(loader);
    
    // 初始化缓存
    ProcCache cache = {0};
    int counter = 0;
    
    LOG("AppOpt v%s 启动, PID: %d\n", VERSION, getpid());
    
    // 主循环
    while (1) {
        AppConfig* cfg_ptr = get_config();
        if (cfg_ptr) {
            update_cache(&cache, cfg_ptr, &counter);
            counter++;
            if (counter % 5 == 0) {
                apply_affinity(&cache, &cfg_ptr->topo);
            }
            config_release(cfg_ptr);
        }
        sleep(interval);
    }
    
    return 0;
}