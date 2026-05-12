// AppOpt.c —— v5（真实线程扫描 + 自动调度引擎）

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

#define MAX_LINE 1024
#define MAX_RULES 4096
#define MAX_FILES 16

// ===================== 规则结构 =====================
typedef struct {
    char pkg[256];
    char thread[256];
    char range[32];

    int priority;
    int score;

    int line_no;
    char file[128];
} Rule;

static Rule rules[MAX_RULES];
static int rule_count = 0;

static char config_files[MAX_FILES][256];
static int file_count = 0;

// ===================== debug =====================
static int DEBUG = 1;

void logi(const char *msg) {
    printf("[INFO] %s\n", msg);
}

void logd(const char *msg) {
    if (DEBUG) printf("[DEBUG] %s\n", msg);
}

// ===================== match =====================
int match(const char *pattern, const char *text) {
    const char *p = pattern;
    const char *t = text;
    const char *star = NULL;
    const char *backup = NULL;

    while (*t) {
        if (*p == '*') {
            star = p++;
            backup = t;
            continue;
        }
        if (*p == *t) {
            p++; t++;
            continue;
        }
        if (star) {
            p = star + 1;
            t = ++backup;
            continue;
        }
        return 0;
    }

    while (*p == '*') p++;
    return *p == '\0';
}

// ===================== score =====================
int calc_score(const char *pkg, const char *thread) {
    int score = 0;
    score += strlen(pkg) * 10;

    if (strcmp(thread, "*") == 0) score += 1;
    else if (strchr(thread, '*')) score += 5;
    else score += 20;

    return score;
}

// ===================== range 校验 =====================
int validate_range(const char *r) {
    for (int i = 0; r[i]; i++) {
        char c = r[i];
        if (!((c >= '0' && c <= '9') || c=='-' || c==',')) return 0;
    }
    return 1;
}

// ===================== parse rule =====================
int parse_rule(const char *line, Rule *r, int line_no, const char *file) {

    const char *eq = strchr(line, '=');
    if (!eq) return 0;

    memset(r, 0, sizeof(Rule));

    r->line_no = line_no;
    strcpy(r->file, file);

    const char *p1 = strchr(line, '{');
    const char *p2 = strchr(line, '}');

    if (p1 && p2 && p2 < eq) {

        strncpy(r->pkg, line, p1 - line);
        r->pkg[p1 - line] = 0;

        strncpy(r->thread, p1 + 1, p2 - p1 - 1);
        r->thread[p2 - p1 - 1] = 0;

    } else {
        strncpy(r->pkg, line, eq - line);
        r->pkg[eq - line] = 0;
        strcpy(r->thread, "*");
    }

    strcpy(r->range, eq + 1);

    if (!validate_range(r->range)) return 0;

    r->priority = 1;
    r->score = calc_score(r->pkg, r->thread);

    return 1;
}

// ===================== load =====================
int load_file(const char *file) {

    FILE *fp = fopen(file, "r");
    if (!fp) return 0;

    char line[MAX_LINE];
    int line_no = 0;
    int loaded = 0;

    while (fgets(line, sizeof(line), fp)) {

        line_no++;
        line[strcspn(line, "\r\n")] = 0;

        if (line[0] == '#' || line[0] == 0)
            continue;

        Rule r;

        if (parse_rule(line, &r, line_no, file)) {

            if (rule_count < MAX_RULES) {
                rules[rule_count++] = r;
                loaded++;
            }
        }
    }

    fclose(fp);

    printf("[文件] %s -> %d 条规则\n", file, loaded);
    return loaded;
}

// ===================== load all =====================
void load_all() {
    rule_count = 0;

    int total = 0;
    for (int i = 0; i < file_count; i++) {
        total += load_file(config_files[i]);
    }

    printf("[总计] %d 条规则\n", total);
}

// ===================== best match =====================
Rule* find_best(const char *pkg, const char *thread) {

    Rule *best = NULL;
    int best_score = -1;

    for (int i = 0; i < rule_count; i++) {

        if (!match(rules[i].pkg, pkg)) continue;
        if (!match(rules[i].thread, thread)) continue;

        if (rules[i].score > best_score) {
            best = &rules[i];
            best_score = rules[i].score;
        }
    }

    return best;
}

// ===================== 真正调度入口 =====================
void schedule(const char *pkg, const char *thread) {

    Rule *r = find_best(pkg, thread);

    if (r) {
        printf("[命中] %s{%s} <- %s:%d (score=%d)\n",
            r->pkg, r->thread, r->file, r->line_no, r->score);
    } else {
        printf("[未命中] %s{%s}\n", pkg, thread);
    }
}

// ===================== 真实线程扫描（核心替换点） =====================
void scan_threads(const char *pkg, int pid) {

    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);

    DIR *dir = opendir(path);
    if (!dir) return;

    struct dirent *ent;

    while ((ent = readdir(dir))) {

        if (ent->d_name[0] == '.')
            continue;

        char comm_path[256];
        snprintf(comm_path, sizeof(comm_path),
                 "/proc/%d/task/%s/comm",
                 pid, ent->d_name);

        FILE *fp = fopen(comm_path, "r");
        if (!fp) continue;

        char thread[128] = {0};
        fgets(thread, sizeof(thread), fp);
        fclose(fp);

        thread[strcspn(thread, "\r\n")] = 0;

        schedule(pkg, thread);
    }

    closedir(dir);
}

// ===================== 模拟进程发现（可替换成真实 AMS） =====================
void scan_processes() {

    DIR *dir = opendir("/proc");
    if (!dir) return;

    struct dirent *ent;

    while ((ent = readdir(dir))) {

        if (!isdigit(ent->d_name[0]))
            continue;

        char cmd_path[256];
        snprintf(cmd_path, sizeof(cmd_path),
                 "/proc/%s/cmdline",
                 ent->d_name);

        FILE *fp = fopen(cmd_path, "r");
        if (!fp) continue;

        char pkg[256] = {0};
        fgets(pkg, sizeof(pkg), fp);
        fclose(fp);

        if (strlen(pkg) == 0)
            continue;

        int pid = atoi(ent->d_name);

        scan_threads(pkg, pid);
    }

    closedir(dir);
}

// ===================== args =====================
void parse_args(int argc, char *argv[]) {

    for (int i = 1; i < argc; i++) {

        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {

            if (file_count < MAX_FILES) {
                strncpy(config_files[file_count++],
                        argv[i+1],
                        sizeof(config_files[0]) - 1);
            }
        }
    }

    if (file_count == 0) {
        strcpy(config_files[file_count++], "./applist.prop");
    }
}

// ===================== main =====================
int main(int argc, char *argv[]) {

    printf("=================================\n");
    printf(" AppOpt v5 真实线程调度引擎\n");
    printf("=================================\n");

    parse_args(argc, argv);

    for (int i = 0; i < file_count; i++) {
        printf("[输入文件] %s\n", config_files[i]);
    }

    load_all();

    // 🔥 核心：不再模拟，直接扫描真实系统线程
    scan_processes();

    return 0;
}