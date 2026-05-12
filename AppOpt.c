// AppOpt.c —— 规则引擎 v5（极简错误日志版）

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>

#define MAX_LINE 1024
#define MAX_RULES 4096
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))

// ===================== 规则 =====================
typedef struct {
    char pkg[256];
    char thread[256];
    char range[32];
    int priority;
    int line_no;
} Rule;

static Rule rules[MAX_RULES];
static int rule_count = 0;

static char config_path[512] = "./applist.prop";

// ===================== 错误日志（只保留错误） =====================
void log_error(const char *file, int line, const char *msg) {
    printf("[ERROR] %s:%d -> %s\n", file, line, msg);
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
int priority(const char *p) {
    if (strcmp(p, "*") == 0) return 4;
    if (!strchr(p, '*')) return 1;
    if (p[strlen(p)-1] == '*') return 2;
    return 3;
}

// ===================== 校验 =====================
int valid_range(const char *r) {
    if (!r || !*r) return 0;

    for (int i = 0; r[i]; i++) {
        char c = r[i];
        if (!((c >= '0' && c <= '9') || c=='-' || c==',')) {
            return 0;
        }
    }
    return 1;
}

// ===================== 解析规则 =====================
int parse_rule(const char *line, Rule *r, int line_no, const char *file) {

    const char *eq = strchr(line, '=');
    if (!eq) {
        log_error(file, line_no, "missing '='");
        return 0;
    }

    memset(r, 0, sizeof(Rule));
    r->line_no = line_no;

    const char *l = strchr(line, '{');
    const char *rr = strchr(line, '}');

    // ================= pkg + thread =================
    if (l && rr && rr < eq) {

        strncpy(r->pkg, line, l - line);
        r->pkg[l - line] = '\0';

        strncpy(r->thread, l + 1, rr - l - 1);
        r->thread[rr - l - 1] = '\0';

    } else {
        // ⭐关键：支持 com.xxx=0-5 => com.xxx{*}=0-5
        strncpy(r->pkg, line, eq - line);
        r->pkg[eq - line] = '\0';
        strcpy(r->thread, "*");
    }

    // ================= range =================
    strcpy(r->range, eq + 1);

    if (!valid_range(r->range)) {
        log_error(file, line_no, "illegal range");
        return 0;
    }

    r->priority = priority(r->pkg);
    return 1;
}

// ===================== 去重 =====================
int exists(Rule *r) {
    for (int i = 0; i < rule_count; i++) {
        if (!strcmp(rules[i].pkg, r->pkg) &&
            !strcmp(rules[i].thread, r->thread) &&
            !strcmp(rules[i].range, r->range)) {
            return 1;
        }
    }
    return 0;
}

// ===================== 加载配置 =====================
void load_config() {

    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        log_error(config_path, 0, "cannot open file");
        return;
    }

    rule_count = 0;

    char line[MAX_LINE];
    int ln = 0, ok = 0;

    while (fgets(line, sizeof(line), fp)) {

        ln++;
        line[strcspn(line, "\r\n")] = 0;

        if (!line[0] || line[0] == '#')
            continue;

        Rule r;

        if (!parse_rule(line, &r, ln, config_path))
            continue;

        if (!exists(&r)) {
            rules[rule_count++] = r;
            ok++;
        }
    }

    fclose(fp);

    printf("[INFO] loaded rules: %d (%s)\n", ok, config_path);
}

// ===================== 匹配 =====================
Rule* best(const char *pkg, const char *th) {

    Rule *b = NULL;

    for (int i = 0; i < rule_count; i++) {

        if (!match(rules[i].pkg, pkg)) continue;
        if (!match(rules[i].thread, th)) continue;

        if (!b || rules[i].priority < b->priority)
            b = &rules[i];
    }

    return b;
}

// ===================== 应用 =====================
void apply(const char *range) {
    printf("[CPU] %s\n", range);
}

// ===================== 调度 =====================
void schedule(const char *pkg, const char *th) {

    Rule *r = best(pkg, th);

    if (r) {
        printf("[HIT] %s{%s} line=%d\n",
            r->pkg, r->thread, r->line_no);
        apply(r->range);
    } else {
        printf("[MISS] %s{%s}\n", pkg, th);
    }
}

// ===================== 热加载 =====================
void watch() {

    int fd = inotify_init();
    int wd = inotify_add_watch(fd, config_path, IN_MODIFY);

    char buf[EVENT_BUF_LEN];

    while (1) {

        int len = read(fd, buf, sizeof(buf));
        if (len <= 0) continue;

        for (int i = 0; i < len;) {

            struct inotify_event *ev =
                (struct inotify_event*)&buf[i];

            if (ev->mask & IN_MODIFY) {
                printf("[INFO] config changed -> reload\n");
                load_config();
            }

            i += sizeof(struct inotify_event) + ev->len;
        }
    }
}

// ===================== main =====================
int main(int argc, char *argv[]) {

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc)
            strncpy(config_path, argv[i+1], sizeof(config_path));
    }

    printf("==== AppOpt v5 ====\n");

    load_config();

    // test
    schedule("com.android.systemui", "RenderThread");
    schedule("com.android.systemui", "pool-worker");
    schedule("com.tencent.mm", "GLThread");

    watch();

    return 0;
}