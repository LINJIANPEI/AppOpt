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

#define VERSION "1.5.8"
#define BASE_CPUSET "/dev/cpuset/Linlin"
#define MAX_PKG_LEN 128
#define MAX_THREAD_LEN 32

/* =========================
 * 数据结构
 * ========================= */

typedef struct {
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
} AffinityRule;

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

/* =========================
 * 多配置支持
 * ========================= */

typedef struct {
    char** config_files;
    size_t num_config_files;
} ConfigList;

/* =========================
 * 工具函数（略保留你原来的）
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
 * CPU 解析（保留）
 * ========================= */

static void parse_cpu_ranges(const char* spec, cpu_set_t* set, const cpu_set_t* present);

/* =========================
 * 规则合并
 * ========================= */

static void merge_config(AppConfig* base, AppConfig* add) {
    size_t new_rules = base->num_rules + add->num_rules;

    AffinityRule* tmp = realloc(base->rules, new_rules * sizeof(AffinityRule));
    if (!tmp) return;

    base->rules = tmp;
    memcpy(base->rules + base->num_rules,
           add->rules,
           add->num_rules * sizeof(AffinityRule));

    base->num_rules += add->num_rules;

    /* pkg 合并 */
    for (size_t i = 0; i < add->num_pkgs; i++) {
        bool exists = false;
        for (size_t j = 0; j < base->num_pkgs; j++) {
            if (strcmp(base->pkgs[j], add->pkgs[i]) == 0) {
                exists = true;
                break;
            }
        }

        if (!exists) {
            char** pk = realloc(base->pkgs,
                        (base->num_pkgs + 1) * sizeof(char*));
            if (!pk) continue;

            base->pkgs = pk;
            base->pkgs[base->num_pkgs++] = strdup(add->pkgs[i]);
        }
    }
}

/* =========================
 * 单文件加载（你原来的 load_config）
 * ========================= */

static AppConfig* load_config(const char* file, const CpuTopology* topo, time_t* mtime);

/* =========================
 * 多文件加载
 * ========================= */

static AppConfig* load_config_files(char** files,
                                     size_t count,
                                     const CpuTopology* topo,
                                     time_t* last_mtime)
{
    AppConfig* base = calloc(1, sizeof(AppConfig));
    if (!base) return NULL;

    base->ref_count = 1;
    base->topo = *topo;

    for (size_t i = 0; i < count; i++) {

        AppConfig* cfg = load_config(files[i], topo, last_mtime);
        if (!cfg) continue;

        merge_config(base, cfg);
        config_release(cfg);
    }

    return base;
}

/* =========================
 * proc_collect（核心改造）
 * ========================= */

static void proc_collect(const AppConfig* cfg, ProcCache* cache, size_t* count)
{
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return;

    int proc_fd = dirfd(proc_dir);
    *count = 0;

    if (!cache->procs) {
        cache->procs_cap = 2048;
        cache->procs = calloc(cache->procs_cap, sizeof(ProcessInfo));
    }

    struct dirent* ent;

    while ((ent = readdir(proc_dir))) {

        long pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        int pid_fd = openat(proc_fd, ent->d_name, O_RDONLY | O_DIRECTORY);
        if (pid_fd == -1) continue;

        char cmd[MAX_PKG_LEN] = {0};
        read_file(pid_fd, "cmdline", cmd, sizeof(cmd));

        char* name = strrchr(cmd, '/');
        name = name ? name + 1 : cmd;

        ProcessInfo* proc = &cache->procs[*count];
        proc->pid = pid;
        strncpy(proc->pkg, name, MAX_PKG_LEN);

        CPU_ZERO(&proc->base_cpus);

        /* =========================
         * ⭐ 优先级匹配
         * ========================= */

        const AffinityRule* best_thread = NULL;
        const AffinityRule* best_exact  = NULL;
        const AffinityRule* best_wild   = NULL;

        for (size_t i = 0; i < cfg->num_rules; i++) {

            const AffinityRule* r = &cfg->rules[i];

            if (r->thread[0]) {
                if (fnmatch(r->pkg, proc->pkg, FNM_NOESCAPE) == 0)
                    best_thread = r;
                continue;
            }

            if (strcmp(r->pkg, proc->pkg) == 0)
                best_exact = r;

            if (fnmatch(r->pkg, proc->pkg, FNM_NOESCAPE) == 0)
                best_wild = r;
        }

        const AffinityRule* sel = best_thread ? best_thread :
                                   best_exact  ? best_exact  :
                                   best_wild;

        if (!sel) {
            close(pid_fd);
            continue;
        }

        CPU_OR(&proc->base_cpus, &proc->base_cpus, &sel->cpus);
        strncpy(proc->base_cpuset, sel->cpuset_dir, sizeof(proc->base_cpuset));

        close(pid_fd);
        (*count)++;
    }

    closedir(proc_dir);
}

/* =========================
 * main 改造：多 -c
 * ========================= */

int main(int argc, char** argv)
{
    CpuTopology topo = init_cpu_topo();

    ConfigList cfg = {0};

    int opt;
    while ((opt = getopt(argc, argv, "c:vhs:")) != -1) {
        switch (opt) {

        case 'c': {
            cfg.config_files = realloc(cfg.config_files,
                (cfg.num_config_files + 1) * sizeof(char*));

            cfg.config_files[cfg.num_config_files++] = strdup(optarg);
            printf("加载配置: %s\n", optarg);
            break;
        }

        case 'v':
            printf("AppOpt %s\n", VERSION);
            exit(0);

        case 'h':
            printf("usage: -c file.conf (multi supported)\n");
            exit(0);
        }
    }

    if (cfg.num_config_files == 0) {
        cfg.config_files = malloc(sizeof(char*));
        cfg.config_files[0] = strdup("./applist.conf");
        cfg.num_config_files = 1;
    }

    AppConfig* config =
        load_config_files(cfg.config_files,
                          cfg.num_config_files,
                          &topo,
                          NULL);

    atomic_store(&current_config, config);

    ProcCache cache = {0};
    int interval = 2;

    printf("AppOpt start v%s\n", VERSION);

    while (1) {
        AppConfig* cfg = get_config();
        if (cfg) {
            size_t cnt = 0;
            proc_collect(cfg, &cache, &cnt);
            apply_affinity(&cache, &cfg->topo);
            config_release(cfg);
        }

        sleep(interval);
    }
}