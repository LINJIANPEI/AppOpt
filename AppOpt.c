// AppOpt.c —— 完整规则引擎 v4（多配置 + 校验 + 优先级 + 热更新）

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>

#define MAX_LINE 1024
#define MAX_RULES 4096
#define MAX_CONFIGS 16
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))

// ===================== 规则结构 =====================
typedef struct {
    char pkg[256];
    char thread[256];
    char range[32];
    int priority;
} Rule;

static Rule rules[MAX_RULES];
static int rule_count = 0;

static char config_paths[MAX_CONFIGS][512];
static int config_count = 0;

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
        return 1; // 精确匹配最高

    if (pattern[strlen(pattern) - 1] == '*')
        return 2;

    return 3;
}

// ===================== 校验系统 =====================
int validate_rule_line(const char *line) {
    if (!line || strlen(line) < 5) return 0;
    if (!strchr(line, '=')) return 0;
    if (line[0] == '=') return 0;
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

// ===================== 解析规则 =====================
int parse_rule(const char *line, Rule *r) {

    if (!validate_rule_line(line))
        return 0;

    const char *p1 = strchr(line, '{');
    const char *p2 = strchr(line, '}');
    const char *eq = strchr(line, '=');

    memset(r, 0, sizeof(Rule));

    if (!(p1 && p2 && eq && p2 > p1 && eq > p2))
        return 0;

    strncpy(r->pkg, line, p1 - line);
    r->pkg[p1 - line] = '\0';

    strncpy(r->thread, p1 + 1, p2 - p1 - 1);
    r->thread[p2 - p1 - 1] = '\0';

    strcpy(r->range, eq + 1);

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
            strcmp(rules[i].range, r->range) == 0)
            return 1;
    }
    return 0;
}

// ===================== 加载所有配置 =====================
void load_all_configs() {

    rule_count = 0;

    for (int c = 0; c < config_count; c++) {

        FILE *fp = fopen(config_paths[c], "r");
        if (!fp) {
            printf("[错误] 无法打开: %s\n", config_paths[c]);
            continue;
        }

        char line[MAX_LINE];
        int loaded = 0;

        while (fgets(line, sizeof(line), fp)) {

            line[strcspn(line, "\r\n")] = 0;

            if (line[0] == '#' || line[0] == '\0')
                continue;

            Rule r;

            if (!parse_rule(line, &r)) {
                log_error("非法规则跳过");
                continue;
            }

            if (!exists_rule(&r) && rule_count < MAX_RULES) {
                rules[rule_count++] = r;
                loaded++;
            }
        }

        fclose(fp);

        printf("[信息] %s 加载 %d 条规则\n",
               config_paths[c], loaded);
    }

    printf("[信息] 总规则数: %d\n", rule_count);
}

// ===================== 匹配引擎 =====================
Rule* find_best_rule(const char *pkg, const char *thread) {

    Rule *best = NULL;

    for (int i = 0; i < rule_count; i++) {

        if (!match(rules[i].pkg, pkg)) continue;
        if (!match(rules[i].thread, thread)) continue;

        if (!best || rules[i].priority < best->priority)
            best = &rules[i];
    }

    return best;
}

// ===================== 应用 =====================
void apply_cpu(const char *range) {
    printf("[调度] CPU范围: %s\n", range);
}

// ===================== 调度入口 =====================
void schedule(const char *pkg, const char *thread) {

    Rule *r = find_best_rule(pkg, thread);

    if (r) {
        apply_cpu(r->range);
    } else {
        printf("[调度] 未命中: %s{%s}\n", pkg, thread);
    }
}

// ===================== 监听配置 =====================
void watch_config() {

    int fd = inotify_init();
    if (fd < 0) {
        log_error("inotify失败");
        return;
    }

    for (int i = 0; i < config_count; i++) {
        inotify_add_watch(fd, config_paths[i], IN_MODIFY);
    }

    log_info("开始监听多配置文件...");

    char buffer[EVENT_BUF_LEN];

    while (1) {

        int len = read(fd, buffer, EVENT_BUF_LEN);
        if (len <= 0) continue;

        for (int i = 0; i < len;) {

            struct inotify_event *ev =
                (struct inotify_event*)&buffer[i];

            if (ev->mask & IN_MODIFY) {
                log_info("配置变化，重新加载");
                load_all_configs();
            }

            i += sizeof(struct inotify_event) + ev->len;
        }
    }
}

// ===================== main =====================
int main(int argc, char *argv[]) {

    printf("=================================\n");
    printf("   AppOpt v4 Final Rule Engine\n");
    printf("=================================\n");

    for (int i = 1; i < argc; i++) {

        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {

            if (config_count < MAX_CONFIGS) {
                strncpy(config_paths[config_count],
                        argv[i + 1],
                        sizeof(config_paths[0]) - 1);
                config_count++;
            }
        }
    }

    if (config_count == 0) {
        strcpy(config_paths[0], "./applist.prop");
        config_count = 1;
    }

    printf("[配置文件数] %d\n", config_count);

    load_all_configs();

    // 测试
    schedule("com.tencent.mm", "RenderThread");
    schedule("com.tencent.mm", "pool-worker-1");
    schedule("com.xxx.app", "GLThread");

    watch_config();

    return 0;
}