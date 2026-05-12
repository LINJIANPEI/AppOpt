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
#include <sys/stat.h>
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
} AffinityRule;

/* ================= CONFIG ================= */
typedef struct {
    AffinityRule* rules;
    size_t num_rules;
} AppConfig;

/* ================= GLOBAL ================= */
static _Atomic(AppConfig*) current_config = NULL;

/* ================= UTIL ================= */
static char* trim(char* s) {
    while (isspace(*s)) s++;
    char* end = s + strlen(s) - 1;
    while (end > s && isspace(*end)) end--;
    *(end + 1) = '\0';
    return s;
}

/* ================= CPU PARSE ================= */
static void parse_cpu(const char* spec, cpu_set_t* set) {
    CPU_ZERO(set);
    if (!spec) return;

    char* tmp = strdup(spec);
    char* p = tmp;

    while (*p) {
        char* end;
        int a = strtol(p, &end, 10);
        int b = a;

        if (*end == '-') {
            p = end + 1;
            b = strtol(p, &end, 10);
        }

        for (int i = a; i <= b; i++) {
            CPU_SET(i, set);
        }

        if (*end == ',') p = end + 1;
        else break;
    }

    free(tmp);
}

/* ================= LOAD ================= */
static AppConfig* load_config(const char* file) {
    FILE* fp = fopen(file, "r");
    if (!fp) {
        printf("[WARN] cannot open %s\n", file);
        return NULL;
    }

    AppConfig* cfg = calloc(1, sizeof(AppConfig));
    AffinityRule* rules = NULL;
    size_t count = 0, cap = 0;

    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        char* p = trim(line);
        if (*p == '#' || !*p) continue;

        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq = 0;

        char* left = trim(p);
        char* right = trim(eq + 1);

        char* br = strchr(left, '{');
        char* thread = "";

        if (br) {
            *br = 0;
            char* rb = strchr(br + 1, '}');
            if (!rb) continue;
            *rb = 0;
            thread = trim(br + 1);
        }

        if (count >= cap) {
            cap = cap ? cap * 2 : 128;
            rules = realloc(rules, cap * sizeof(AffinityRule));
        }

        AffinityRule r = {0};
        strncpy(r.pkg, left, MAX_PKG_LEN);
        strncpy(r.thread, thread, MAX_THREAD_LEN);
        parse_cpu(right, &r.cpus);

        rules[count++] = r;
    }

    fclose(fp);

    cfg->rules = rules;
    cfg->num_rules = count;

    printf("[INFO] loaded %s rules=%zu\n", file, count);
    return cfg;
}

/* ================= MERGE + DEDUP ================= */
static int rule_equal(AffinityRule* a, AffinityRule* b) {
    return strcmp(a->pkg, b->pkg) == 0 &&
           strcmp(a->thread, b->thread) == 0 &&
           CPU_EQUAL(&a->cpus, &b->cpus);
}

static AppConfig* merge_configs(AppConfig** list, int n) {
    AppConfig* out = calloc(1, sizeof(AppConfig));

    size_t cap = 256;
    out->rules = malloc(cap * sizeof(AffinityRule));

    for (int i = 0; i < n; i++) {
        AppConfig* c = list[i];
        if (!c) continue;

        for (size_t j = 0; j < c->num_rules; j++) {
            AffinityRule* r = &c->rules[j];

            if (strlen(r->pkg) == 0) continue;
            if (CPU_COUNT(&r->cpus) == 0) continue;

            int dup = 0;
            for (size_t k = 0; k < out->num_rules; k++) {
                if (rule_equal(&out->rules[k], r)) {
                    dup = 1;
                    break;
                }
            }

            if (dup) continue;

            if (out->num_rules >= cap) {
                cap *= 2;
                out->rules = realloc(out->rules, cap * sizeof(AffinityRule));
            }

            out->rules[out->num_rules++] = *r;
        }
    }

    printf("[INFO] merged rules=%zu\n", out->num_rules);
    return out;
}

/* ================= CPSET INIT（关键保留 Linlin） ================= */
static void init_cpuset(void) {
    if (access("/dev/cpuset", F_OK) != 0) return;

    mkdir(BASE_CPUSET, 0755);

    FILE* f = fopen("/sys/devices/system/cpu/present", "r");
    if (!f) return;

    char buf[128] = {0};
    fgets(buf, sizeof(buf), f);
    fclose(f);

    char path[256];

    snprintf(path, sizeof(path), "%s/cpus", BASE_CPUSET);
    FILE* fc = fopen(path, "w");
    if (fc) {
        fprintf(fc, "%s", buf);
        fclose(fc);
    }

    snprintf(path, sizeof(path), "%s/mems", BASE_CPUSET);
    FILE* fm = fopen(path, "w");
    if (fm) {
        fprintf(fm, "0");
        fclose(fm);
    }

    printf("[INFO] cpuset ready: %s\n", BASE_CPUSET);
}

/* ================= MATCH DEMO ================= */
static void test_match(AppConfig* cfg) {
    const char* pkg = "com.tencent.tmgp.sgame";
    const char* thread = "UnityMain";

    for (size_t i = 0; i < cfg->num_rules; i++) {
        AffinityRule* r = &cfg->rules[i];

        if (strcmp(r->pkg, pkg) != 0) continue;

        if (r->thread[0] && strcmp(r->thread, thread) == 0) {
            printf("[MATCH] %s %s\n", r->pkg, r->thread);
            return;
        }
    }

    printf("[MATCH] none\n");
}

/* ================= MAIN ================= */
int main(int argc, char** argv) {

    char* files[16];
    int cnt = 0;

    int opt;
    while ((opt = getopt(argc, argv, "c:v")) != -1) {
        if (opt == 'c' && cnt < 16) {
            files[cnt++] = strdup(optarg);
        }
        if (opt == 'v') {
            printf("AppOpt %s\n", VERSION);
            return 0;
        }
    }

    if (cnt == 0) {
        files[cnt++] = strdup("./applist.conf");
    }

    AppConfig* tmp[16];

    for (int i = 0; i < cnt; i++) {
        tmp[i] = load_config(files[i]);
    }

    /* 先合并，再初始化 cpuset（关键优化点） */
    AppConfig* cfg = merge_configs(tmp, cnt);

    init_cpuset();

    atomic_store(&current_config, cfg);

    printf("[OK] rules=%zu ready\n", cfg->num_rules);

    test_match(cfg);

    return 0;
}