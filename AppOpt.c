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

#define VERSION "2.0.0"
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
    atomic_int ref;
} Config;

static _Atomic(Config*) g_cfg = NULL;

/* ================= LOG ================= */
#define LOGI(fmt, ...) printf("[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) printf("[ERR ] " fmt "\n", ##__VA_ARGS__)
#define LOGM(fmt, ...) printf("[MATCH] " fmt "\n", ##__VA_ARGS__)

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

/* ================= DUP CHECK ================= */
static int rule_exists(Rule* r, Rule* arr, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (strcmp(arr[i].pkg, r->pkg) == 0 &&
            strcmp(arr[i].thread, r->thread) == 0)
            return 1;
    }
    return 0;
}

/* ================= LOAD CONFIG ================= */
static Config* load_one(const char* file) {
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

        if (cap == 0) {
            cap = 128;
            rules = malloc(cap * sizeof(Rule));
        }

        if (rule_exists(&r, rules, cnt)) continue;

        if (cnt >= cap) {
            cap *= 2;
            rules = realloc(rules, cap * sizeof(Rule));
        }

        rules[cnt++] = r;
    }

    fclose(fp);

    c->rules = rules;
    c->num_rules = cnt;
    atomic_store(&c->ref, 1);

    LOGI("loaded %s rules=%zu", file, cnt);
    return c;
}

/* ================= MERGE ================= */
static Config* merge_all(char** files, int n) {
    Config* base = load_one(files[0]);
    if (!base) return NULL;

    for (int i = 1; i < n; i++) {
        Config* add = load_one(files[i]);
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
    const Rule* fallback = NULL;

    for (size_t i = 0; i < c->num_rules; i++) {
        Rule* r = &c->rules[i];

        if (strcmp(r->pkg, pkg)) continue;

        if (r->thread[0] && strcmp(r->thread, thread) == 0)
            return r;

        if (!fallback && fnmatch(r->thread, thread, 0) == 0)
            fallback = r;
    }

    return fallback;
}

/* ================= APPLY ================= */
static void apply(Config* c) {
    DIR* d = opendir("/proc");
    if (!d) return;

    struct dirent* e;

    while ((e = readdir(d))) {
        char* end;
        int pid = strtol(e->d_name, &end, 10);
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

        if (r) {
            sched_setaffinity(pid, sizeof(r->cpus), &r->cpus);
            LOGM("%s %s", comm, "applied");
        }
    }

    closedir(d);
}

/* ================= LOOP ================= */
int main(int argc, char** argv) {
    char* files[8];
    int n = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc)
            files[n++] = argv[++i];
    }

    if (n == 0)
        files[n++] = "./applist.conf";

    Config* cfg = merge_all(files, n);
    if (!cfg) {
        LOGE("config load failed");
        return -1;
    }

    atomic_store(&g_cfg, cfg);

    LOGI("cpuset ready: %s", BASE_CPUSET);
    LOGI("rules=%zu ready", cfg->num_rules);

    while (1) {
        apply(cfg);
        sleep(1);
    }

    return 0;
}