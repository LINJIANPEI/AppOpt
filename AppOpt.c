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
#include <time.h>

/* =========================
 * 基础定义
 * ========================= */

#define VERSION "1.5.8"
#define BASE_CPUSET "/dev/cpuset/Linlin"
#define MAX_PKG_LEN 128
#define MAX_THREAD_LEN 32

/* =========================
 * forward declare（关键修复）
 * ========================= */

typedef struct CpuTopology CpuTopology;
typedef struct AppConfig AppConfig;
typedef struct ProcCache ProcCache;
typedef struct ProcessInfo ProcessInfo;
typedef struct ThreadInfo ThreadInfo;

/* =========================
 * 数据结构
 * ========================= */

typedef struct {
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
} AffinityRule;

struct ThreadInfo {
    pid_t tid;
    char name[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
};

struct ProcessInfo {
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
};

struct CpuTopology {
    cpu_set_t present_cpus;
    char present_str[128];
    char mems_str[32];
    bool cpuset_enabled;
    int base_cpuset_fd;
};

struct AppConfig {
    atomic_int ref_count;

    AffinityRule* rules;
    size_t num_rules;

    char** pkgs;
    size_t num_pkgs;

    CpuTopology topo;

    char config_file[4096];
    time_t mtime;
};

struct ProcCache {
    ProcessInfo* procs;
    size_t num_procs;
    size_t procs_cap;

    int last_proc_count;
    bool scan_all_proc;

    pid_t* tracked_pids;
    size_t num_tracked_pids;
    size_t tracked_pids_cap;
};

/* =========================
 * 工具函数
 * ========================= */

static char* strtrim(char* s) {
    while (isspace(*s)) s++;
    if (*s == 0) return s;
    char* end = s + strlen(s) - 1;
    while (end > s && isspace(*end)) end--;
    *(end + 1) = 0;
    return s;
}

/* =========================
 * CPU 解析（简化保留）
 * ========================= */

static void parse_cpu_ranges(const char* spec, cpu_set_t* set, const cpu_set_t* present) {
    if (!spec) return;
    char* copy = strdup(spec);
    char* s = copy;

    while (*s) {
        char* end;
        unsigned long a = strtoul(s, &end, 10);
        if (end == s) { s++; continue; }

        unsigned long b = a;
        if (*end == '-') {
            s = end + 1;
            b = strtoul(s, &end, 10);
        }

        for (unsigned long i = a; i <= b && i < CPU_SETSIZE; i++) {
            if (!present || CPU_ISSET(i, present))
                CPU_SET(i, set);
        }

        s = (*end == ',') ? end + 1 : end;
    }

    free(copy);
}

/* =========================
 * config
 * ========================= */

static AppConfig* load_config(const char* file, const CpuTopology* topo, time_t* mtime);

/* =========================
 * merge config
 * ========================= */

static void merge_config(AppConfig* base, AppConfig* add) {

    base->rules = realloc(base->rules,
        (base->num_rules + add->num_rules) * sizeof(AffinityRule));

    memcpy(base->rules + base->num_rules,
           add->rules,
           add->num_rules * sizeof(AffinityRule));

    base->num_rules += add->num_rules;

    for (size_t i = 0; i < add->num_pkgs; i++) {
        bool exists = false;

        for (size_t j = 0; j < base->num_pkgs; j++) {
            if (!strcmp(base->pkgs[j], add->pkgs[i])) {
                exists = true;
                break;
            }
        }

        if (!exists) {
            base->pkgs = realloc(base->pkgs,
                (base->num_pkgs + 1) * sizeof(char*));

            base->pkgs[base->num_pkgs++] = strdup(add->pkgs[i]);
        }
    }
}

/* =========================
 * 多配置加载（-c 支持）
 * ========================= */

static AppConfig* load_config_files(char** files,
                                    size_t n,
                                    const CpuTopology* topo,
                                    time_t* mt)
{
    AppConfig* base = calloc(1, sizeof(AppConfig));
    base->ref_count = 1;
    base->topo = *topo;

    for (size_t i = 0; i < n; i++) {
        AppConfig* cfg = load_config(files[i], topo, mt);
        if (!cfg) continue;

        merge_config(base, cfg);
        atomic_fetch_sub(&cfg->ref_count, 1);
        free(cfg);
    }

    return base;
}

/* =========================
 * proc collect（核心优先级修复）
 * ========================= */

static void proc_collect(const AppConfig* cfg, ProcCache* cache, size_t* count) {

    DIR* d = opendir("/proc");
    if (!d) return;

    int fd = dirfd(d);
    *count = 0;

    if (!cache->procs) {
        cache->procs_cap = 1024;
        cache->procs = calloc(cache->procs_cap, sizeof(ProcessInfo));
    }

    struct dirent* e;

    while ((e = readdir(d))) {

        long pid = atoi(e->d_name);
        if (pid <= 0) continue;

        int pfd = openat(fd, e->d_name, O_RDONLY | O_DIRECTORY);
        if (pfd == -1) continue;

        char cmd[128] = {0};
        read(pfd, cmd, sizeof(cmd));

        char* name = strrchr(cmd, '/');
        name = name ? name + 1 : cmd;

        ProcessInfo* p = &cache->procs[*count];
        p->pid = pid;
        strncpy(p->pkg, name, MAX_PKG_LEN);

        CPU_ZERO(&p->base_cpus);

        /* =========================
         * ⭐ 优先级匹配
         * ========================= */

        const AffinityRule* best_thread = NULL;
        const AffinityRule* best_exact = NULL;
        const AffinityRule* best_wild = NULL;

        for (size_t i = 0; i < cfg->num_rules; i++) {

            const AffinityRule* r = &cfg->rules[i];

            if (r->thread[0]) {
                if (fnmatch(r->pkg, p->pkg, 0) == 0)
                    best_thread = r;
                continue;
            }

            if (!strcmp(r->pkg, p->pkg))
                best_exact = r;

            if (fnmatch(r->pkg, p->pkg, 0) == 0)
                best_wild = r;
        }

        const AffinityRule* sel =
            best_thread ? best_thread :
            best_exact  ? best_exact  :
                          best_wild;

        if (!sel) {
            close(pfd);
            continue;
        }

        CPU_OR(&p->base_cpus, &p->base_cpus, &sel->cpus);

        close(pfd);
        (*count)++;
    }

    closedir(d);
}

/* =========================
 * main（多 -c）
 * ========================= */

int main(int argc, char** argv) {

    CpuTopology topo = {0};

    char** files = NULL;
    size_t file_n = 0;

    int opt;
    while ((opt = getopt(argc, argv, "c:")) != -1) {
        if (opt == 'c') {
            files = realloc(files, (file_n + 1) * sizeof(char*));
            files[file_n++] = strdup(optarg);
        }
    }

    if (!file_n) {
        files = malloc(sizeof(char*));
        files[0] = strdup("./applist.conf");
        file_n = 1;
    }

    AppConfig* cfg =
        load_config_files(files, file_n, &topo, NULL);

    ProcCache cache = {0};
    int interval = 2;

    printf("AppOpt v%s start\n", VERSION);

    while (1) {

        size_t cnt = 0;
        proc_collect(cfg, &cache, &cnt);

        sleep(interval);
    }
}