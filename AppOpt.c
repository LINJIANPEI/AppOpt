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
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
} MergeRule;

typedef struct {
    atomic_int ref_count;
    AffinityRule* rules;
    size_t num_rules;
    time_t mtime;
    cpu_set_t present_cpus;
    char present_str[128];
    char mems_str[32];
} AppConfig;

static _Atomic(AppConfig*) current_config = NULL;

/* ================= CPU PARSE ================= */
static void parse_cpu_ranges(const char* spec, cpu_set_t* set) {
    CPU_ZERO(set);
    if (!spec) return;

    char* copy = strdup(spec);
    char* s = copy;

    while (*s) {
        char* end;
        int a = strtol(s, &end, 10);
        int b = a;

        if (*end == '-') {
            s = end + 1;
            b = strtol(s, &end, 10);
        }

        for (int i = a; i <= b; i++)
            CPU_SET(i, set);

        if (*end == ',') s = end + 1;
        else break;
    }

    free(copy);
}

/* ================= CONFIG LOAD ================= */
static AppConfig* load_config(const char* file) {
    FILE* fp = fopen(file, "r");
    if (!fp) return NULL;

    AppConfig* cfg = calloc(1, sizeof(AppConfig));
    cfg->ref_count = 1;

    AffinityRule* rules = NULL;
    size_t count = 0, cap = 0;

    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;

        char* left = line;
        char* right = eq + 1;

        char* br = strchr(left, '{');
        char* thread = "";

        if (br) {
            *br = 0;
            char* eb = strchr(br + 1, '}');
            if (!eb) continue;
            *eb = 0;
            thread = br + 1;
        }

        if (count >= cap) {
            cap = cap ? cap * 2 : 128;
            rules = realloc(rules, cap * sizeof(AffinityRule));
        }

        AffinityRule r = {0};
        strncpy(r.pkg, left, MAX_PKG_LEN);
        strncpy(r.thread, thread, MAX_THREAD_LEN);
        parse_cpu_ranges(right, &r.cpus);

        rules[count++] = r;
    }

    fclose(fp);

    cfg->rules = rules;
    cfg->num_rules = count;

    return cfg;
}

/* ================= RULE MERGE ================= */
static void merge_config(AppConfig* base, AppConfig* add) {
    if (!base || !add) return;

    size_t new_count = base->num_rules + add->num_rules;
    base->rules = realloc(base->rules, new_count * sizeof(AffinityRule));

    memcpy(base->rules + base->num_rules,
           add->rules,
           add->num_rules * sizeof(AffinityRule));

    base->num_rules = new_count;

    free(add->rules);
    free(add);
}

/* ================= MATCH ================= */
static const AffinityRule* match_rule(AppConfig* cfg, const char* pkg, const char* thread) {
    const AffinityRule* fallback = NULL;

    for (size_t i = 0; i < cfg->num_rules; i++) {
        AffinityRule* r = &cfg->rules[i];
        if (strcmp(r->pkg, pkg) != 0) continue;

        /* 精确优先 */
        if (r->thread[0] && strcmp(r->thread, thread) == 0)
            return r;

        /* 通配 */
        if (!fallback && fnmatch(r->thread, thread, 0) == 0)
            fallback = r;
    }

    return fallback;
}

/* ================= MAIN ================= */
int main(int argc, char** argv) {

    char* cfg_files[8];
    int cfg_count = 0;

    int opt;
    while ((opt = getopt(argc, argv, "c:")) != -1) {
        if (opt == 'c' && cfg_count < 8)
            cfg_files[cfg_count++] = strdup(optarg);
    }

    if (cfg_count == 0) {
        cfg_files[cfg_count++] = strdup("./applist.conf");
    }

    AppConfig* cfg = load_config(cfg_files[0]);

    for (int i = 1; i < cfg_count; i++) {
        AppConfig* tmp = load_config(cfg_files[i]);
        merge_config(cfg, tmp);
    }

    atomic_store(&current_config, cfg);

    printf("规则总数: %zu\n", cfg->num_rules);

    /* demo */
    const AffinityRule* r =
        match_rule(cfg, "com.tencent.tmgp.sgame", "UnityMain");

    if (r)
        printf("match: %s %s\n", r->pkg, r->thread);

    return 0;
}