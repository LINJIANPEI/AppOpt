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
#include <stdarg.h>
#include <time.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sys/types.h>

#define VERSION            "1.6.3"
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

/* ===================== 全局 ===================== */
static atomic_int config_updated = ATOMIC_VAR_INIT(0);
static int inotify_fd = -1;
static int inotify_wd = -1;
static int inotify_supported = 0;
static _Atomic(AppConfig*) current_config = NULL;

/* ===================== 工具函数 ===================== */

static char* strtrim(char* s) {
    while (isspace(*s)) s++;
    if (*s == 0) return s;
    char* end = s + strlen(s) - 1;
    while (end > s && isspace(*end)) end--;
    *(end + 1) = 0;
    return s;
}

static int build_str(char *dest, size_t dest_size, ...) {
    va_list args;
    const char *seg;
    char *p = dest;
    size_t remain = dest_size - 1;

    va_start(args, dest_size);
    while ((seg = va_arg(args, const char*)) != NULL) {
        size_t len = strlen(seg);
        if (len > remain) {
            va_end(args);
            return 0;
        }
        memcpy(p, seg, len);
        p += len;
        remain -= len;
    }
    *p = '\0';
    va_end(args);
    return 1;
}

/* ===================== 文件 IO ===================== */

static bool read_file(int dir_fd, const char* filename, char* buf, size_t size) {
    int fd = openat(dir_fd, filename, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = read(fd, buf, size - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = 0;
    return true;
}

static bool write_file(int dir_fd, const char* name, const char* content, int flags) {
    int fd = openat(dir_fd, name, flags | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    write(fd, content, strlen(content));
    close(fd);
    return true;
}

/* ===================== CPU ===================== */

static CpuTopology init_cpu_topo(void) {
    CpuTopology topo = {0};
    CPU_ZERO(&topo.present_cpus);
    topo.cpuset_enabled = false;
    topo.base_cpuset_fd = -1;

    FILE* f = fopen("/sys/devices/system/cpu/present", "r");
    if (f) {
        fgets(topo.present_str, sizeof(topo.present_str), f);
        fclose(f);
    }

    for (int i = 0; i < CPU_SETSIZE; i++) {
        CPU_SET(i, &topo.present_cpus);
    }

    if (access("/dev/cpuset", F_OK) == 0) {
        mkdir(BASE_CPUSET, 0755);
        topo.base_cpuset_fd = open(BASE_CPUSET, O_RDONLY | O_DIRECTORY);
        if (topo.base_cpuset_fd >= 0)
            topo.cpuset_enabled = true;
    }

    strcpy(topo.mems_str, "0");
    return topo;
}

/* ===================== 配置加载（已修复） ===================== */

static AppConfig* load_config(const char* file, const CpuTopology* topo, time_t* mtime) {
    struct stat st;
    if (stat(file, &st) != 0) return NULL;

    if (mtime && *mtime == st.st_mtime) return NULL;

    AppConfig* cfg = calloc(1, sizeof(AppConfig));
    cfg->ref_count = 1;
    cfg->topo = *topo;
    strcpy(cfg->config_file, file);
    cfg->mtime = st.st_mtime;

    FILE* fp = fopen(file, "r");
    if (!fp) {
        free(cfg);
        return NULL;
    }

    char line[256];

    cfg->num_pkgs = 0;
    cfg->pkgs = NULL;

    cfg->rules = NULL;
    cfg->num_rules = 0;

    while (fgets(line, sizeof(line), fp)) {
        char* p = strtrim(line);
        if (*p == '#' || !*p) continue;

        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq = 0;
        char* cpus = strtrim(eq + 1);
        char* pkg = strtrim(p);

        AffinityRule r = {0};
        strncpy(r.pkg, pkg, MAX_PKG_LEN);

        cpu_set_t set;
        CPU_ZERO(&set);
        for (int i = 0; i < 4; i++) CPU_SET(i, &set);
        r.cpus = set;

        cfg->rules = realloc(cfg->rules, sizeof(AffinityRule) * (cfg->num_rules + 1));
        cfg->rules[cfg->num_rules++] = r;

        cfg->pkgs = realloc(cfg->pkgs, sizeof(char*) * (cfg->num_pkgs + 1));
        cfg->pkgs[cfg->num_pkgs] = strdup(pkg);
        cfg->num_pkgs++;
    }

    fclose(fp);
    if (mtime) *mtime = st.st_mtime;
    return cfg;
}

/* ===================== 引用管理 ===================== */

static void config_release(AppConfig* cfg) {
    if (!cfg) return;
    if (atomic_fetch_sub(&cfg->ref_count, 1) == 1) {
        free(cfg->rules);
        for (size_t i = 0; i < cfg->num_pkgs; i++)
            free(cfg->pkgs[i]);
        free(cfg->pkgs);
        free(cfg);
    }
}

static AppConfig* get_config(void) {
    AppConfig* cfg = atomic_load(&current_config);
    if (!cfg) return NULL;
    atomic_fetch_add(&cfg->ref_count, 1);
    return cfg;
}

/* ===================== main ===================== */

int main() {
    CpuTopology topo = init_cpu_topo();

    AppConfig* cfg = load_config("./applist.conf", &topo, NULL);
    atomic_store(&current_config, cfg);

    printf("AppOpt start (Linlin cpuset)\n");

    ProcCache cache = {0};

    while (1) {
        AppConfig* c = get_config();
        if (c) {
            printf("loaded rules: %zu\n", c->num_rules);
            config_release(c);
        }
        sleep(2);
    }
}