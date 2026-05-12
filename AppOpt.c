// AppOpt.c —— v4.2（多配置文件 + 统计 + 行号 + 热加载）

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>

#define MAX_LINE 1024
#define MAX_RULES 4096
#define MAX_FILES 16
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))

// ===================== 规则结构 =====================
typedef struct {
    char pkg[256];
    char thread[256];
    char range[32];
    int priority;
    int line_no;
    char file[128];
} Rule;

static Rule rules[MAX_RULES];
static int rule_count = 0;

// ===================== 多文件支持 =====================
static char config_files[MAX_FILES][256];
static int file_count = 0;

// ===================== 日志 =====================
void log_info(const char *msg) {
    printf("[信息] %s\n", msg);
}

void log_error(const char *msg) {
    printf("[错误] %s\n", msg);
}

// ===================== glob匹配 =====================
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

// ===================== 优先级 =====================
int calc_priority(const char *pattern) {
    if (strcmp(pattern, "*") == 0) return 4;
    if (!strchr(pattern, '*')) return 1;
    if (pattern[strlen(pattern)-1] == '*') return 2;
    return 3;
}

// ===================== 校验 =====================
int validate_range(const char *r) {
    for (int i = 0; r[i]; i++) {
        char c = r[i];
        if (!((c >= '0' && c <= '9') || c=='-' || c==',')) return 0;
    }
    return 1;
}

// ===================== 解析 =====================
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

    r->priority = calc_priority(r->pkg);

    return 1;
}

// ===================== 去重 =====================
int exists_rule(Rule *r) {
    for (int i = 0; i < rule_count; i++) {
        if (strcmp(rules[i].pkg, r->pkg) == 0 &&
            strcmp(rules[i].thread, r->thread) == 0 &&
            strcmp(rules[i].range, r->range) == 0)
            return 1;
    }
    return 0;
}

// ===================== 加载单文件 =====================
int load_file(const char *file) {

    FILE *fp = fopen(file, "r");
    if (!fp) {
        printf("[错误] 无法打开文件: %s\n", file);
        return 0;
    }

    char line[MAX_LINE];
    int line_no = 0;
    int loaded = 0;

    while (fgets(line, sizeof(line), fp)) {

        line_no++;
        line[strcspn(line, "\r\n")] = 0;

        if (line[0] == '#' || line[0] == 0)
            continue;

        Rule r;

        if (!parse_rule(line, &r, line_no, file)) {
            printf("[错误] %s:%d 非法规则\n", file, line_no);
            continue;
        }

        if (!exists_rule(&r) && rule_count < MAX_RULES) {
            rules[rule_count++] = r;
            loaded++;
        }
    }

    fclose(fp);

    printf("[文件] %s -> %d 条规则\n", file, loaded);

    return loaded;
}

// ===================== 加载全部 =====================
void load_all() {

    rule_count = 0;

    int total = 0;

    for (int i = 0; i < file_count; i++) {
        total += load_file(config_files[i]);
    }

    printf("[总计] %d 条规则\n", total);
}

// ===================== 匹配 =====================
Rule* find_best(const char *pkg, const char *thread) {

    Rule *best = NULL;

    for (int i = 0; i < rule_count; i++) {

        if (!match(rules[i].pkg, pkg)) continue;
        if (!match(rules[i].thread, thread)) continue;

        if (!best || rules[i].priority < best->priority)
            best = &rules[i];
    }

    return best;
}

// ===================== 调度 =====================
void schedule(const char *pkg, const char *thread) {

    Rule *r = find_best(pkg, thread);

    if (r) {
        printf("[命中] %s{%s} <- %s:%d\n",
            r->pkg, r->thread, r->file, r->line_no);
    } else {
        printf("[未命中] %s{%s}\n", pkg, thread);
    }
}

// ===================== 参数解析 =====================
void parse_args(int argc, char *argv[]) {

    for (int i = 1; i < argc; i++) {

        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {

            if (file_count < MAX_FILES) {
                strncpy(config_files[file_count++],
                        argv[i+1],
                        sizeof(config_files[0])-1);
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
    printf(" AppOpt v4.2 多文件规则引擎\n");
    printf("=================================\n");

    parse_args(argc, argv);

    for (int i = 0; i < file_count; i++) {
        printf("[输入文件] %s\n", config_files[i]);
    }

    load_all();

    schedule("com.android.systemui", "RenderThread");
    schedule("com.android.systemui", "pool-worker-1");
    schedule("com.tencent.mm", "GLThread");

    return 0;
}