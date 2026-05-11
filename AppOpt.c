// AppOpt.c  —— 纯C版守护配置热更新工具

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <errno.h>

#define MAX_LINE 1024
#define MAX_RULES 4096
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))

static char *rules[MAX_RULES];
static int rule_count = 0;

static char config_path[512] = "./applist.prop";

/* =========================
 * 中文日志
 * ========================= */
void log_info(const char *msg) {
    printf("[信息] %s\n", msg);
    fflush(stdout);
}

void log_error(const char *msg) {
    printf("[错误] %s\n", msg);
    fflush(stdout);
}

/* =========================
 * 去重
 * ========================= */
int exists_rule(const char *line) {
    for (int i = 0; i < rule_count; i++) {
        if (strcmp(rules[i], line) == 0) {
            return 1;
        }
    }
    return 0;
}

/* =========================
 * 加载配置
 * ========================= */
void load_config() {
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        log_error("无法打开配置文件");
        return;
    }

    char line[MAX_LINE];
    int loaded = 0;

    while (fgets(line, sizeof(line), fp)) {
        // 去换行
        line[strcspn(line, "\r\n")] = 0;

        // 跳过空行和注释
        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (!exists_rule(line) && rule_count < MAX_RULES) {
            rules[rule_count] = strdup(line);
            rule_count++;
            loaded++;
        }
    }

    fclose(fp);

    char buf[128];
    snprintf(buf, sizeof(buf), "加载配置完成，新增规则: %d，总规则: %d", loaded, rule_count);
    log_info(buf);
}

/* =========================
 * 打印所有规则（调试）
 * ========================= */
void dump_rules() {
    log_info("当前规则列表:");
    for (int i = 0; i < rule_count; i++) {
        printf("  - %s\n", rules[i]);
    }
}

/* =========================
 * inotify 监听
 * ========================= */
void watch_config() {
    int fd = inotify_init();
    if (fd < 0) {
        log_error("inotify初始化失败");
        return;
    }

    int wd = inotify_add_watch(fd, config_path,
        IN_MODIFY | IN_CREATE | IN_DELETE);

    if (wd < 0) {
        log_error("添加inotify监听失败");
        return;
    }

    log_info("开始监听配置文件变化...");

    char buffer[EVENT_BUF_LEN];

    while (1) {
        int length = read(fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            log_error("读取inotify失败");
            continue;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event =
                (struct inotify_event *)&buffer[i];

            if (event->len) {
                if (event->mask & (IN_MODIFY | IN_CREATE | IN_DELETE)) {
                    log_info("检测到配置文件变化，重新加载...");
                    load_config();
                }
            }

            i += sizeof(struct inotify_event) + event->len;
        }
    }
}

/* =========================
 * main
 * ========================= */
int main(int argc, char *argv[]) {

    printf("=================================\n");
    printf("      AppOpt 纯C守护启动\n");
    printf("=================================\n");

    // 参数解析 -c
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            strncpy(config_path, argv[i + 1], sizeof(config_path) - 1);
        }
    }

    char buf[256];
    snprintf(buf, sizeof(buf), "配置文件: %s", config_path);
    log_info(buf);

    // 初次加载
    load_config();

    // 打印规则（可选）
    // dump_rules();

    // 进入监听
    watch_config();

    return 0;
}