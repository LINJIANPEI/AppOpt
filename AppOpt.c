// AppOpt.c —— 完整规则引擎 v4.1（默认*语义 + 校验 + 热加载）

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>

#define MAX_LINE 1024
#define MAX_RULES 4096
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))

// ===================== 规则结构 =====================
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

// ===================== 日志 =====================
void log_info(const char *msg) {
    printf("[信息] %s\n", msg);
}

void log_error(const char *msg) {
    printf("[错误] %s\n", msg);
}

// ===================== glob 匹配 =====================
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

    if (strcmp(pattern, "*") == 0)
        return 4;

    if (strchr(pattern, '*') == NULL)
        return 1;

    if (pattern[strlen(pattern) - 1] == '*')
        return 2;

    return 3;
}

// ===================== 校验 =====================
int validate_line(const char *line) {
    if (!line || strlen(line) < 3) return 0;
    if (!strchr(line, '=')) return 0;
    return 1;
}

int validate_pkg(const char *pkg) {
    return pkg && strlen(pkg) > 0;
}

int validate_thread(const char *t) {
    return t && strlen(t) > 0;
}

int validate_range(const char *r) {
    if (!r || strlen(r) == 0) return 0;

    for (int i = 0; r[i]; i++) {
        char c = r[i];
        if (!((c >= '0' && c <= '9') || c=='-' || c==',')) {
            return 0;
        }
    }
    return 1;
}

// ===================== 解析规则（核心修复） =====================
int parse_rule(const char *line, Rule *r, int line_no) {

    if (!validate_line(line))
        return 0;

    const char *eq = strchr(line, '=');
    if (!eq) return 0;

    memset(r, 0, sizeof(Rule));
    r->line_no = line_no;

    const char *p1 = strchr(line, '{');
    const char *p2 = strchr(line, '}');

    // ================= pkg =================
    if (p1 && p2 && p2 < eq) {

        strncpy(r->pkg, line, p1 - line);
        r->pkg[p1 - line] = '\0';

        // thread
        if (p2 - p1 - 1 <= 0) {
            strcpy(r->thread, "*");
        } else {
            strncpy(r->thread, p1 + 1, p2 - p1 - 1);
            r->thread[p2 - p1 - 1] = '\0';
        }

    } else {
        // ⭐关键：没有 {} → 默认 *
        strncpy(r->pkg, line, eq - line);
        r->pkg[eq - line] = '\0';
        strcpy(r->thread, "*");
    }

    // ================= range =================
    strcpy(r->range, eq + 1);

    // ================= 校验 =================
    if (!validate_pkg(r->pkg)) return 0;
    if (!validate_thread(r->thread)) return 0;
    if (!validate_range(r->range)) return 0;

    r->priority = calc_priority(r->pkg);

    return 1;
}

// ===================== 去重 =====================
int exists_rule(Rule *r) {
    for (int i = 0; i < rule_count; i++) {
        if (strcmp(rules[i].pkg, r->pkg) == 0 &&
            strcmp(rules[i].thread, r->thread) == 0 &&
            strcmp(rules[i].range, r->range) == 0) {
            return 1;
        }
    }
    return 0;
}

// ===================== 加载配置 =====================
void load_config() {

    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        log_error("无法打开配置文件");
        return;
    }

    char line[MAX_LINE];
    int line_no = 0;
    int loaded = 0;

    rule_count = 0;

    while (fgets(line, sizeof(line), fp)) {

        line_no++;

        line[strcspn(line, "\r\n")] = 0;

        if (line[0] == '#' || line[0] == '\0')
            continue;

        Rule r;

        if (!parse_rule(line, &r, line_no)) {
            printf("[错误] 第 %d 行非法规则: %s\n", line_no, line);
            continue;
        }

        if (!exists_rule(&r) && rule_count < MAX_RULES) {
            rules[rule_count++] = r;
            loaded++;
        }
    }

    fclose(fp);

    printf("[信息] 加载完成：%d 条规则\n", loaded);
}

// ===================== 匹配 =====================
Rule* find_best_rule(const char *pkg, const char *thread) {

    Rule *best = NULL;

    for (int i = 0; i < rule_count; i++) {

        if (!match(rules[i].pkg, pkg))
            continue;

        if (!match(rules[i].thread, thread))
            continue;

        if (!best || rules[i].priority < best->priority)
            best = &rules[i];
    }

    return best;
}

// ===================== 应用 =====================
void apply_cpu(const char *range) {
    printf("[调度] CPU范围: %s\n", range);
}

// ===================== 调度 =====================
void schedule(const char *pkg, const char *thread) {

    Rule *r = find_best_rule(pkg, thread);

    if (r) {
        printf("[命中] %s{%s} (line %d)\n",
            r->pkg, r->thread, r->line_no);
        apply_cpu(r->range);
    } else {
        printf("[未命中] %s{%s}\n", pkg, thread);
    }
}

// ===================== 监听 =====================
void watch_config() {

    int fd = inotify_init();
    int wd = inotify_add_watch(fd, config_path, IN_MODIFY);

    if (wd < 0) {
        log_error("监听失败");
        return;
    }

    log_info("监听配置中...");

    char buffer[EVENT_BUF_LEN];

    while (1) {

        int len = read(fd, buffer, EVENT_BUF_LEN);
        if (len <= 0) continue;

        for (int i = 0; i < len;) {

            struct inotify_event *ev =
                (struct inotify_event*)&buffer[i];

            if (ev->mask & IN_MODIFY) {
                log_info("配置变更，重新加载");
                load_config();
            }

            i += sizeof(struct inotify_event) + ev->len;
        }
    }
}

// ===================== main =====================
int main(int argc, char *argv[]) {

    printf("=================================\n");
    printf(" AppOpt v4.1 规则引擎（强化版）\n");
    printf("=================================\n");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            strncpy(config_path, argv[i+1], sizeof(config_path)-1);
        }
    }

    printf("[配置] %s\n", config_path);

    load_config();

    // 测试
    schedule("com.android.systemui", "RenderThread");
    schedule("com.android.systemui", "pool-worker-1");
    schedule("com.tencent.mm", "GLThread");

    watch_config();

    return 0;
}