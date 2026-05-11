// AppOpt.c —— 完整规则引擎版本（v3）

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/inotify.h>

#define MAX_LINE 1024
#define MAX_RULES 4096
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))

// ===================== 规则结构 =====================
typedef struct {
    char pkg[256];     // 包名 pattern
    char thread[256];  // 线程 pattern
    char range[32];    // CPU range
    int priority;      // 优先级（越小越优先）
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
            p++;
            t++;
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

// ===================== 优先级计算 =====================
int calc_priority(const char *pattern) {
    if (strcmp(pattern, "*") == 0)
        return 4; // 全局最低

    if (strchr(pattern, '*') == NULL)
        return 1; // 完全精确

    int len = strlen(pattern);
    if (pattern[len - 1] == '*')
        return 2; // 前缀

    return 3; // 模糊
}

// ===================== 解析规则 =====================
void parse_rule(const char *line, Rule *r) {
    const char *p1 = strchr(line, '{');
    const char *p2 = strchr(line, '}');
    const char *p3 = strchr(line, '=');

    memset(r, 0, sizeof(Rule));

    if (p1 && p2 && p3 && p2 > p1 && p3 > p2) {

        strncpy(r->pkg, line, p1 - line);
        r->pkg[p1 - line] = '\0';

        strncpy(r->thread, p1 + 1, p2 - p1 - 1);
        r->thread[p2 - p1 - 1] = '\0';

        strcpy(r->range, p3 + 1);

        r->priority = calc_priority(r->pkg);
    }
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
    int loaded = 0;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;

        if (line[0] == '\0' || line[0] == '#')
            continue;

        Rule r;
        parse_rule(line, &r);

        if (!exists_rule(&r) && rule_count < MAX_RULES) {
            rules[rule_count++] = r;
            loaded++;
        }
    }

    fclose(fp);

    char buf[128];
    snprintf(buf, sizeof(buf), "加载规则完成：%d 条", loaded);
    log_info(buf);
}

// ===================== 最优匹配引擎 =====================
Rule* find_best_rule(const char *pkg, const char *thread) {
    Rule *best = NULL;

    for (int i = 0; i < rule_count; i++) {

        if (!match(rules[i].pkg, pkg))
            continue;

        if (!match(rules[i].thread, thread))
            continue;

        if (best == NULL || rules[i].priority < best->priority) {
            best = &rules[i];
        }
    }

    return best;
}

// ===================== 应用 CPU（示例） =====================
void apply_cpu_range(const char *range) {
    printf("[调度] 应用CPU范围: %s\n", range);
}

// ===================== 调度入口 =====================
void schedule(const char *pkg, const char *thread) {
    Rule *r = find_best_rule(pkg, thread);

    if (r) {
        apply_cpu_range(r->range);
    } else {
        printf("[调度] 无匹配规则: %s{%s}\n", pkg, thread);
    }
}

// ===================== 监听配置 =====================
void watch_config() {
    int fd = inotify_init();
    if (fd < 0) {
        log_error("inotify初始化失败");
        return;
    }

    int wd = inotify_add_watch(fd, config_path, IN_MODIFY);

    if (wd < 0) {
        log_error("监听失败");
        return;
    }

    log_info("开始监听配置变化...");

    char buffer[EVENT_BUF_LEN];

    while (1) {
        int len = read(fd, buffer, EVENT_BUF_LEN);

        if (len <= 0)
            continue;

        for (int i = 0; i < len;) {
            struct inotify_event *event =
                (struct inotify_event*)&buffer[i];

            if (event->mask & IN_MODIFY) {
                log_info("配置变化，重新加载");
                load_config();
            }

            i += sizeof(struct inotify_event) + event->len;
        }
    }
}

// ===================== main =====================
int main(int argc, char *argv[]) {

    printf("=================================\n");
    printf("   AppOpt v3 规则引擎启动\n");
    printf("=================================\n");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            strncpy(config_path, argv[i + 1], sizeof(config_path)-1);
        }
    }

    printf("[配置] %s\n", config_path);

    load_config();

    // 模拟调度测试
    schedule("com.tencent.mm", "RenderThread");
    schedule("com.tencent.mm", "pool-worker-1");
    schedule("com.xxx.app", "GLThread");

    watch_config();

    return 0;
}