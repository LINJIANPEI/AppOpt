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

#define VERSION "2.1.0"
#define BASE_CPUSET "/dev/cpuset/Linlin"

#define MAX_PKG_LEN 128
#define MAX_THREAD_LEN 64

/* ================= RULE ================= */
typedef struct {
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    cpu_set_t cpus;
} Rule;

/* ================= CONFIG ================= */
typedef struct {
    Rule* rules;
    size_t num_rules;
} Config;

/* ================= LOG ================= */
#define LOGI(fmt, ...) printf("[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) printf("[ERR ] " fmt "\n", ##__VA_ARGS__)
#define LOGM(fmt, ...) printf("[MATCH] " fmt "\n", ##__VA_ARGS__)
#define LOGC(fmt, ...) printf("[CPSET] " fmt "\n", ##__VA_ARGS__)
#define LOGA(fmt, ...) printf("[AFF] " fmt "\n", ##__VA_ARGS__)

/* ================= UTIL ================= */
static char* trim(char* s) {
    while (*s && isspace(*s)) s++;
    char* e = s + strlen(s) - 1;
    while (e > s && isspace(*e)) *e-- = 0;
    return s;
}

/* ================= CPU PARSE ================= */
static void parse_cpu(const char* s, cpu_set_t* set) {
    CPU_ZERO(set);
    if (!s) return;

    char* dup = strdup(s);
    char* p = dup;

    while (*p) {
        char* end;
        int a = strtol(p, &end, 10);
        int b = a;

        if (*end == '-') {
            p = end + 1;
            b = strtol(p, &end, 10);
        }

        for (int i = a; i <= b; i++)
            CPU_SET(i, set);

        if (*end == ',') p = end + 1;
        else break;
    }

    free(dup);
}

/* ================= RULE CHECK ================= */
static int exists(Rule* r, Rule* arr, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!strcmp(arr[i].pkg, r->pkg) &&
            !strcmp(arr[i].thread, r->thread))
            return 1;
    }
    return 0;
}

/* ================= LOAD ================= */
static Config* load_file(const char* file) {
    FILE* fp = fopen(file, "r");
    if (!fp) return NULL;

    Config* c = calloc(1, sizeof(Config));
    Rule* rules = NULL;
    size_t cnt = 0, cap = 0;

    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;

        char* left = trim(line);
        char* right = trim(eq + 1);

        char* br = strchr(left, '{');
        char* thread = "";

        if (br) {
            *br = 0;
            char* eb = strchr(br + 1, '}');
            if (!eb) continue;
            *eb = 0;
            thread = trim(br + 1);
        }

        Rule r = {0};
        strncpy(r.pkg, left, MAX_PKG_LEN);
        strncpy(r.thread, thread, MAX_THREAD_LEN);
        parse_cpu(right, &r.cpus);

        if (CPU_COUNT(&r.cpus) == 0) continue;

        if (exists(&r, rules, cnt)) continue;

        if (cnt >= cap) {
            cap = cap ? cap * 2 : 128;
            rules = realloc(rules, cap * sizeof(Rule));
        }

        rules[cnt++] = r;
    }

    fclose(fp);

    c->rules = rules;
    c->num_rules = cnt;

    LOGI("loaded %s rules=%zu", file, cnt);
    return c;
}

/* ================= MERGE ================= */
static Config* merge(char** files, int n) {
    Config* base = load_file(files[0]);
    if (!base) return NULL;

    for (int i = 1; i < n; i++) {
        Config* add = load_file(files[i]);
        if (!add) continue;

        size_t newn = base->num_rules + add->num_rules;
        base->rules = realloc(base->rules, newn * sizeof(Rule));

        memcpy(base->rules + base->num_rules,
               add->rules,
               add->num_rules * sizeof(Rule));

        base->num_rules = newn;

        free(add->rules);
        free(add);
    }

    LOGI("merged rules=%zu", base->num_rules);
    return base;
}

/* ================= MATCH ================= */
static const Rule* match(Config* c, const char* pkg, const char* thread) {
    const Rule* fb = NULL;

    for (size_t i = 0; i < c->num_rules; i++) {
        Rule* r = &c->rules[i];

        if (strcmp(r->pkg, pkg)) continue;

        if (r->thread[0] && !strcmp(r->thread, thread))
            return r;

        if (!fb && fnmatch(r->thread, thread, 0) == 0)
            fb = r;
    }

    return fb;
}

/* ================= CPSET BIND ================= */
static void bind_cpuset(pid_t pid, const char* name) {
    char path[256];
    snprintf(path, sizeof(path),
             "%s/%s/tasks",
             BASE_CPUSET,
             name);

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        LOGE("cpuset open failed %s", path);
        return;
    }

    char buf[32];
    snprintf(buf, sizeof(buf), "%d\n", pid);

    if (write(fd, buf, strlen(buf)) > 0)
        LOGC("pid=%d -> %s", pid, name);
    else
        LOGE("cpuset write failed pid=%d", pid);

    close(fd);
}

/* ================= AFFINITY ================= */
static void bind_affinity(pid_t pid, cpu_set_t* set) {
    if (!set) return;

    if (sched_setaffinity(pid, sizeof(cpu_set_t), set) == -1)
        LOGE("affinity failed pid=%d errno=%d", pid, errno);
    else
        LOGA("pid=%d ok", pid);
}

/* ================= APPLY ================= */
static void apply(Config* c) {
    DIR* d = opendir("/proc");
    if (!d) return;

    struct dirent* e;

    while ((e = readdir(d))) {
        char* end;
        pid_t pid = strtol(e->d_name, &end, 10);
        if (*end) continue;

        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);

        FILE* f = fopen(path, "r");
        if (!f) continue;

        char comm[128] = {0};
        fgets(comm, sizeof(comm), f);
        fclose(f);

        trim(comm);

        const Rule* r = match(c, comm, "UnityMain");
        if (!r) continue;

        /* ===== cpuset绑定 ===== */
        bind_cpuset(pid, "Linlin");

        /* ===== affinity绑定 ===== */
        bind_affinity(pid, &r->cpus);

        LOGM("%s applied", comm);
    }

    closedir(d);
}

/* ================= MAIN LOOP ================= */
int main(int argc, char** argv) {
    char* files[8];
    int n = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc)
            files[n++] = argv[++i];
    }

    if (n == 0)
        files[n++] = "./applist.conf";

    Config* cfg = merge(files, n);
    if (!cfg) {
        LOGE("load failed");
        return -1;
    }

    LOGI("cpuset ready: %s", BASE_CPUSET);
    LOGI("rules=%zu ready", cfg->num_rules);

    while (1) {
        apply(cfg);
        usleep(500000); // 0.5s
    }

    return 0;
}