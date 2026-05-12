#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define VERSION        "1.6.3-stable"
#define BASE_CPUSET    "/dev/cpuset/Linlin"
#define MAX_PKG_LEN    128
#define MAX_THREAD_LEN 64

/* ================= RULE ================= */

typedef struct {
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    cpu_set_t cpus;
} AffinityRule;

typedef struct {
    AffinityRule* rules;
    size_t num_rules;
} AppConfig;

/* ================= GLOBAL CONFIG (STABLE ATOMIC) ================= */

static AppConfig* current_config = NULL;

/* ================= SAFE ATOMIC ================= */

static void set_config(AppConfig* cfg) {
    __atomic_store_n(&current_config, cfg, __ATOMIC_SEQ_CST);
}

static AppConfig* get_config() {
    return __atomic_load_n(&current_config, __ATOMIC_SEQ_CST);
}

/* ================= UTIL ================= */

static char* trim(char* s) {
    while (isspace(*s)) s++;
    char* e = s + strlen(s);
    while (e > s && isspace(*(e - 1))) *(--e) = 0;
    return s;
}

static bool valid_cpu(cpu_set_t* set) {
    return CPU_COUNT(set) > 0;
}

/* ================= CPU PARSER ================= */

static void parse_cpu_ranges(const char* spec, cpu_set_t* set) {
    CPU_ZERO(set);
    if (!spec) return;

    char* copy = strdup(spec);
    char* s = copy;

    while (*s) {
        char* end;
        long a = strtol(s, &end, 10);
        if (end == s) break;

        long b = a;

        if (*end == '-') {
            s = end + 1;
            b = strtol(s, &end, 10);
        }

        if (a > b) {
            long t = a; a = b; b = t;
        }

        for (long i = a; i <= b && i < CPU_SETSIZE; i++) {
            CPU_SET(i, set);
        }

        if (*end == ',') s = end + 1;
        else break;
    }

    free(copy);
}

/* ================= DUP CHECK ================= */

static bool is_duplicate(AffinityRule* rules, size_t count, AffinityRule* r) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rules[i].pkg, r->pkg) == 0 &&
            strcmp(rules[i].thread, r->thread) == 0 &&
            CPU_EQUAL(&rules[i].cpus, &r->cpus)) {
            return true;
        }
    }
    return false;
}

/* ================= LOAD CONFIG ================= */

static AppConfig* load_config(const char* file) {
    FILE* fp = fopen(file, "r");
    if (!fp) return NULL;

    AppConfig* cfg = calloc(1, sizeof(AppConfig));

    AffinityRule* rules = NULL;
    size_t count = 0, cap = 0;

    char line[512];

    while (fgets(line, sizeof(line), fp)) {

        char* p = trim(line);
        if (*p == '#' || *p == 0) continue;

        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq = 0;

        char* left = trim(p);
        char* right = trim(eq + 1);

        char* br = strchr(left, '{');
        char thread[MAX_THREAD_LEN] = "";

        if (br) {
            *br = 0;
            char* eb = strchr(br + 1, '}');
            if (!eb) continue;
            *eb = 0;
            strncpy(thread, trim(br + 1), MAX_THREAD_LEN);
        }

        char pkg[MAX_PKG_LEN];
        strncpy(pkg, trim(left), MAX_PKG_LEN);

        AffinityRule r = {0};
        strncpy(r.pkg, pkg, MAX_PKG_LEN);
        strncpy(r.thread, thread, MAX_THREAD_LEN);

        parse_cpu_ranges(right, &r.cpus);

        if (!valid_cpu(&r.cpus)) continue;
        if (is_duplicate(rules, count, &r)) continue;

        if (count >= cap) {
            cap = cap ? cap * 2 : 128;
            rules = realloc(rules, cap * sizeof(AffinityRule));
        }

        rules[count++] = r;
    }

    fclose(fp);

    cfg->rules = rules;
    cfg->num_rules = count;

    printf("[INFO] loaded %zu rules from %s\n", count, file);

    return cfg;
}

/* ================= MERGE ================= */

static void merge_config(AppConfig* base, AppConfig* add) {
    if (!base || !add) return;

    for (size_t i = 0; i < add->num_rules; i++) {
        if (!is_duplicate(base->rules, base->num_rules, &add->rules[i])) {
            base->rules = realloc(base->rules,
                                  (base->num_rules + 1) * sizeof(AffinityRule));
            base->rules[base->num_rules++] = add->rules[i];
        }
    }

    free(add->rules);
    free(add);
}

/* ================= MATCH ================= */

static const AffinityRule* match_rule(AppConfig* cfg,
                                      const char* pkg,
                                      const char* thread) {
    const AffinityRule* fallback = NULL;

    for (size_t i = 0; i < cfg->num_rules; i++) {
        AffinityRule* r = &cfg->rules[i];

        if (strcmp(r->pkg, pkg) != 0)
            continue;

        if (r->thread[0] && strcmp(r->thread, thread) == 0)
            return r;

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
        if (opt == 'c' && cfg_count < 8) {
            cfg_files[cfg_count++] = strdup(optarg);
            printf("[INFO] add config: %s\n", optarg);
        }
    }

    if (cfg_count == 0) {
        cfg_files[cfg_count++] = strdup("./applist.conf");
    }

    AppConfig* cfg = load_config(cfg_files[0]);

    for (int i = 1; i < cfg_count; i++) {
        AppConfig* tmp = load_config(cfg_files[i]);
        merge_config(cfg, tmp);
    }

    set_config(cfg);

    printf("[OK] total rules: %zu\n", cfg->num_rules);

    const AffinityRule* r =
        match_rule(cfg, "com.tencent.tmgp.sgame", "UnityMain");

    if (r)
        printf("[MATCH] %s %s\n", r->pkg, r->thread);

    return 0;
}