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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include "uthash.h"

#define VERSION            "1.6.3"
#define BASE_CPUSET        "/dev/cpuset/Linlin"
#define MAX_PKG_LEN        128
#define MAX_THREAD_LEN     128
#define INITIAL_PKG_CAPACITY 2560
#define INITIAL_RULE_CAPACITY 2560
#define INITIAL_WILDCARD_CAPACITY 128
#define DENT_BUF_SIZE (128 * 1024)

// 定义 linux_dirent64 结构体（在包含头文件后定义）
struct linux_dirent64 {
    ino64_t d_ino;
    off64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

// 简单日志
#define LOG_I(fmt, ...) do { write_log("[I] " fmt, ##__VA_ARGS__); } while (0)
#define LOG_W(fmt, ...) do { write_log("[W] " fmt, ##__VA_ARGS__); } while (0)
#define LOG_E(fmt, ...) do { write_log("[E] " fmt, ##__VA_ARGS__); } while (0)

typedef struct {
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
    bool is_wildcard;
    int priority;
} AffinityRule;

typedef struct {
    pid_t tid;
    char name[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
} ThreadInfo;

typedef struct {
    pid_t pid;
    char pkg[MAX_PKG_LEN];
    char base_cpuset[128];
    cpu_set_t base_cpus;
    ThreadInfo* threads;
    size_t num_threads;
    size_t threads_cap;
    AffinityRule** thread_rules;
    size_t num_thread_rules;
    size_t thread_rules_cap;
} ProcessInfo;

typedef struct {
    cpu_set_t present_cpus;
    char present_str[128];
    char mems_str[32];
    bool cpuset_enabled;
    int base_cpuset_fd;
} CpuTopology;

typedef struct PackageEntry {
    char pkg[MAX_PKG_LEN];
    UT_hash_handle hh;
} PackageEntry;

typedef struct {
    atomic_int ref_count;
    AffinityRule* rules;
    size_t num_rules;
    AffinityRule** wildcard_rules;
    size_t num_wildcard_rules;
    time_t mtime;
    CpuTopology topo;
    char** pkgs;
    size_t num_pkgs;
    struct PackageEntry* pkg_table;
    char config_file[4096];
    char cpuset_base[256];
} AppConfig;

typedef struct {
    ProcessInfo* procs;
    size_t num_procs;
    size_t procs_cap;
    int last_proc_count;
    int last_proc_total;
    bool scan_all_proc;
    pid_t* tracked_pids;
    size_t num_tracked_pids;
    size_t tracked_pids_cap;
} ProcCache;

static atomic_int config_updated = ATOMIC_VAR_INIT(0);
static int inotify_fd = -1;
static int inotify_wd = -1;
static int inotify_supported = 0;
static _Atomic(AppConfig*) current_config = NULL;

// 日志输出
static void write_log(const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(stderr, "[%s] ", time_str);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
}

// 修正：返回 char* 而不是 void
static char* strtrim(char* s) {
    if (!s) return s;
    char* end;
    while (isspace((unsigned char)*s)) s++;
    if (*s == 0) return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    *(end + 1) = 0;
    return s;
}

static char* strtrim_line(char* s) {
    if (!s) return s;
    char* start = s;
    while (isspace((unsigned char)*start)) start++;
    if (!*start) return start;
    char* end = start + strlen(start) - 1;
    while (end > start && (isspace((unsigned char)*end) || *end == '#')) end--;
    end[1] = '\0';
    return start;
}

static bool read_file(int dir_fd, const char* filename, char* buf, size_t buf_size) {
    int fd = openat(dir_fd, filename, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return false;
    ssize_t n = read(fd, buf, buf_size - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    return true;
}

static bool write_file(int dir_fd, const char* filename, const char* content, int flags) {
    int fd = openat(dir_fd, filename, flags | O_CLOEXEC, 0644);
    if (fd == -1) return false;
    ssize_t n = write(fd, content, strlen(content));
    close(fd);
    return (n == (ssize_t)strlen(content));
}

static int build_str(char *dest, size_t dest_size, ...) {
    va_list args;
    const char *segment;
    char *p = dest;
    size_t remaining = dest_size - 1;
    va_start(args, dest_size);
    while ((segment = va_arg(args, const char *)) != NULL) {
        size_t len = strlen(segment);
        if (len > remaining) {
            va_end(args);
            return 0;
        }
        memcpy(p, segment, len);
        p += len;
        remaining -= len;
    }
    *p = '\0';
    va_end(args);
    return 1;
}

static bool parse_cpu_ranges(const char* spec, cpu_set_t* set, const cpu_set_t* present, char* invalid_range, size_t invalid_range_size) {
    if (!spec) return true;
    char* copy = strdup(spec);
    if (!copy) return false;
    char* s = copy;
    bool valid = true;

    while (*s) {
        char* end;
        unsigned long a = strtoul(s, &end, 0);
        if (end == s) {
            s++;
            continue;
        }

        unsigned long b = a;
        if (*end == '-') {
            s = end + 1;
            b = strtoul(s, &end, 10);
            if (end == s) b = a;
        }

        if (a > b) {
            if (invalid_range && invalid_range_size > 0) {
                snprintf(invalid_range, invalid_range_size, "%lu-%lu", a, b);
            }
            valid = false;
            s = (*end == ',') ? end + 1 : end;
            continue;
        }

        for (unsigned long i = a; i <= b && i < CPU_SETSIZE; i++) {
            if (present && !CPU_ISSET(i, present)) {
                if (invalid_range && invalid_range_size > 0) {
                    if (a == b) {
                        snprintf(invalid_range, invalid_range_size, "%lu", i);
                    } else {
                        snprintf(invalid_range, invalid_range_size, "%lu-%lu", a, b);
                    }
                }
                valid = false;
                break;
            }
            CPU_SET(i, set);
        }

        s = (*end == ',') ? end + 1 : end;
    }
    free(copy);
    return valid;
}

static char* cpu_set_to_str(const cpu_set_t *set) {
    size_t buf_size = 8 * CPU_SETSIZE;
    char *buf = malloc(buf_size);
    if (!buf) return NULL;
    int start = -1, end = -1;
    char *p = buf;
    size_t remain = buf_size - 1;
    bool first = true;

    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, set)) {
            if (start == -1) {
                start = end = i;
            } else if (i == end + 1) {
                end = i;
            } else {
                int needed;
                if (start == end) {
                    needed = snprintf(p, remain + 1, "%s%d", first ? "" : ",", start);
                } else {
                    needed = snprintf(p, remain + 1, "%s%d-%d", first ? "" : ",", start, end);
                }
                if (needed < 0 || (size_t)needed > remain) {
                    free(buf);
                    return NULL;
                }
                p += needed;
                remain -= needed;
                start = end = i;
                first = false;
            }
        }
    }
    if (start != -1) {
        int needed;
        if (start == end) {
            needed = snprintf(p, remain + 1, "%s%d", first ? "" : ",", start);
        } else {
            needed = snprintf(p, remain + 1, "%s%d-%d", first ? "" : ",", start, end);
        }
        if (needed < 0 || (size_t)needed > remain) {
            free(buf);
            return NULL;
        }
        p += needed;
    }
    *p = '\0';
    return buf;
}

static bool create_cpuset_dir(const char *path, const char *cpus, const char *mems) {
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return false;
    if (chmod(path, 0755) != 0) return false;
    if (chown(path, 0, 0) != 0) return false;

    char cpus_path[256];
    build_str(cpus_path, sizeof(cpus_path), path, "/cpus", NULL);
    if (!write_file(AT_FDCWD, cpus_path, cpus, O_WRONLY | O_CREAT | O_TRUNC)) return false;

    char mems_path[256];
    build_str(mems_path, sizeof(mems_path), path, "/mems", NULL);
    return write_file(AT_FDCWD, mems_path, mems, O_WRONLY | O_CREAT | O_TRUNC);
}

static CpuTopology init_cpu_topo(void) {
    CpuTopology topo = { .cpuset_enabled = false, .base_cpuset_fd = -1 };
    CPU_ZERO(&topo.present_cpus);

    if (read_file(AT_FDCWD, "/sys/devices/system/cpu/present", topo.present_str, sizeof(topo.present_str))) {
        strtrim(topo.present_str);
    }
    parse_cpu_ranges(topo.present_str, &topo.present_cpus, NULL, NULL, 0);

    if (access("/dev/cpuset", F_OK) != 0) return topo;

    if (create_cpuset_dir(BASE_CPUSET, topo.present_str, "0")) {
        topo.base_cpuset_fd = open(BASE_CPUSET, O_RDONLY | O_DIRECTORY);
        if (topo.base_cpuset_fd != -1) topo.cpuset_enabled = true;
    }

    char mems_path[256];
    build_str(mems_path, sizeof(mems_path), BASE_CPUSET, "/mems", NULL);
    if (!read_file(AT_FDCWD, mems_path, topo.mems_str, sizeof(topo.mems_str))) {
        build_str(topo.mems_str, sizeof(topo.mems_str), "0", NULL);
    } else {
        strtrim(topo.mems_str);
    }

    return topo;
}

static int calculate_rule_priority(const char* pkg, const char* thread) {
    // 检测规则类型并返回对应的优先级值
    bool pkg_exact = false;
    bool pkg_wildcard = false;
    bool pkg_default = false;
    bool thread_exact = false;
    bool thread_wildcard = false;
    bool thread_default = false;

    // 分析包名
    if (strcmp(pkg, "*") == 0) {
        pkg_default = true;
    } else if (strchr(pkg, '*') != NULL || strchr(pkg, '?') != NULL || strchr(pkg, '[') != NULL) {
        pkg_wildcard = true;
    } else {
        pkg_exact = true;
    }

    // 分析线程名
    if (thread[0] == '\0' || strcmp(thread, "*") == 0) {
        thread_default = true;
    } else if (strchr(thread, '*') != NULL || strchr(thread, '?') != NULL || strchr(thread, '[') != NULL) {
        thread_wildcard = true;
    } else {
        thread_exact = true;
    }

    // 按优先级从高到低返回
    if (pkg_exact && thread_exact) {
        return 100000;  // 1. 精确包名+精确线程（最高）
    } else if (pkg_exact && thread_wildcard) {
        return 80000;   // 2. 精确包名+线程通配符
    } else if (pkg_exact && thread_default) {
        return 60000;   // 3. 精确包名（无线程）
    } else if (pkg_wildcard && thread_exact) {
        return 40000;   // 4. 包名通配符+精确线程
    } else if (pkg_wildcard && thread_wildcard) {
        return 20000;   // 5. 包名通配符+线程通配符
    } else { // pkg_default
        return -1;      // 6. 默认规则（最低）- 统一为 -1
    }
}

static const char* get_rule_type_name(const AffinityRule* rule) {
    bool pkg_exact = false, pkg_wildcard = false, pkg_default = false;
    bool thread_exact = false, thread_wildcard = false, thread_default = false;

    if (strcmp(rule->pkg, "*") == 0) {
        pkg_default = true;
    } else if (strchr(rule->pkg, '*') != NULL || strchr(rule->pkg, '?') != NULL || 
               strchr(rule->pkg, '[') != NULL) {
        pkg_wildcard = true;
    } else {
        pkg_exact = true;
    }

    if (rule->thread[0] == '\0' || strcmp(rule->thread, "*") == 0) {
        thread_default = true;
    } else if (strchr(rule->thread, '*') != NULL || strchr(rule->thread, '?') != NULL || 
               strchr(rule->thread, '[') != NULL) {
        thread_wildcard = true;
    } else {
        thread_exact = true;
    }

    if (pkg_exact && thread_exact) return "精确包名+精确线程";
    if (pkg_exact && thread_wildcard) return "精确包名+线程通配符";
    if (pkg_exact && thread_default) return "精确包名（无线程）";
    if (pkg_wildcard && thread_exact) return "包名通配符+精确线程";
    if (pkg_wildcard && thread_wildcard) return "包名通配符+线程通配符";
    return "默认规则";
}

static void cleanup_temp_resources(AffinityRule** rules, size_t num_rules, AffinityRule*** wildcard_rules, size_t num_wildcard_rules, PackageEntry** pkg_table) {
    if (rules && *rules) {
        free(*rules);
        *rules = NULL;
    }
    if (wildcard_rules && *wildcard_rules) {
        free(*wildcard_rules);
        *wildcard_rules = NULL;
    }
    if (pkg_table && *pkg_table) {
        PackageEntry* entry, *tmp;
        HASH_ITER(hh, *pkg_table, entry, tmp) {
            HASH_DEL(*pkg_table, entry);
            free(entry);
        }
        *pkg_table = NULL;
    }
}

static void validate_rule_priorities(AffinityRule* rules, size_t num_rules) {
    LOG_I("规则优先级验证:\n");
    LOG_I("  - 精确包名+精确线程: 最高 (100000)\n");
    LOG_I("  - 精确包名+线程通配符: 次高 (80000)\n");
    LOG_I("  - 精确包名（无线程）: 中等 (60000)\n");
    LOG_I("  - 包名通配符+精确线程: 较低 (40000)\n");
    LOG_I("  - 包名通配符+线程通配符: 很低 (20000)\n");
    LOG_I("  - 默认规则: 最低 (-1)\n");

    // 检测规则冲突
    for (size_t i = 0; i < num_rules; i++) {
        for (size_t j = i + 1; j < num_rules; j++) {
            // 跳过默认规则
            if (rules[i].priority < 0 || rules[j].priority < 0) continue;

            // 检查包名是否可能匹配同一个进程
            bool pkg_overlap = false;

            // 情况1：包名完全相同
            if (strcmp(rules[i].pkg, rules[j].pkg) == 0) {
                pkg_overlap = true;
            }
            // 情况2：精确包名包含在另一个包名中（如 com.example 和 com.example.app）
            else if (!rules[i].is_wildcard && !rules[j].is_wildcard) {
                // 两个都是精确包名，检查是否是父子关系
                if (strncmp(rules[i].pkg, rules[j].pkg, strlen(rules[i].pkg)) == 0 ||
                    strncmp(rules[j].pkg, rules[i].pkg, strlen(rules[j].pkg)) == 0) {
                    pkg_overlap = true;
                }
            }
            // 情况3：精确包名匹配通配符模式
            else if (!rules[i].is_wildcard && rules[j].is_wildcard) {
                if (fnmatch(rules[j].pkg, rules[i].pkg, 0) == 0) {
                    pkg_overlap = true;
                }
            }
            else if (rules[i].is_wildcard && !rules[j].is_wildcard) {
                if (fnmatch(rules[i].pkg, rules[j].pkg, 0) == 0) {
                    pkg_overlap = true;
                }
            }
            // 情况4：两个都是通配符
            else if (rules[i].is_wildcard && rules[j].is_wildcard) {
                // 简化检测：如果包名相同或非常相似
                if (strcmp(rules[i].pkg, rules[j].pkg) == 0) {
                    pkg_overlap = true;
                } else {
                    // 尝试检测可能的重叠（简化版本）
                    char pkg_i[256], pkg_j[256];
                    strncpy(pkg_i, rules[i].pkg, sizeof(pkg_i) - 1);
                    strncpy(pkg_j, rules[j].pkg, sizeof(pkg_j) - 1);
                    pkg_i[sizeof(pkg_i) - 1] = '\0';
                    pkg_j[sizeof(pkg_j) - 1] = '\0';

                    // 移除通配符进行简单比较
                    char* star_i = strchr(pkg_i, '*');
                    char* star_j = strchr(pkg_j, '*');
                    if (star_i) *star_i = '\0';
                    if (star_j) *star_j = '\0';

                    if (strcmp(pkg_i, pkg_j) == 0) {
                        pkg_overlap = true;
                    }
                }
            }

            if (!pkg_overlap) continue;

            // 检查线程名是否可能匹配同一个线程
            bool thread_overlap = false;

            // 情况1：线程名完全相同
            if (strcmp(rules[i].thread, rules[j].thread) == 0) {
                thread_overlap = true;
            }
            // 情况2：无线程规则 vs 有线程规则
            else if (rules[i].thread[0] == '\0' || rules[j].thread[0] == '\0') {
                // 无线程规则匹配所有线程，所以肯定重叠
                thread_overlap = true;
            }
            // 情况3：精确线程包含在另一个中
            else if (strchr(rules[i].thread, '*') == NULL && strchr(rules[j].thread, '*') == NULL) {
                if (strncmp(rules[i].thread, rules[j].thread, strlen(rules[i].thread)) == 0 ||
                    strncmp(rules[j].thread, rules[i].thread, strlen(rules[j].thread)) == 0) {
                    thread_overlap = true;
                }
            }
            // 情况4：精确线程匹配通配符线程
            else if (strchr(rules[i].thread, '*') != NULL || strchr(rules[j].thread, '*') != NULL) {
                if (fnmatch(rules[i].thread, rules[j].thread, 0) == 0 ||
                    fnmatch(rules[j].thread, rules[i].thread, 0) == 0) {
                    thread_overlap = true;
                }
            }

            if (!thread_overlap) continue;

            // 如果包名和线程名都可能重叠，输出警告
            LOG_W("  潜在冲突: %s{%s}(%d) 与 %s{%s}(%d) 可能匹配相同线程\n",
                  rules[i].pkg, rules[i].thread, rules[i].priority,
                  rules[j].pkg, rules[j].thread, rules[j].priority);

            // 检查优先级是否合理（更高优先级应该更具体）
            if (rules[i].priority > rules[j].priority) {
                // i 的优先级更高，检查是否 i 比 j 更具体
                bool i_more_specific = true;

                // 如果 i 是通配符而 j 是精确的，则 i 不够具体
                if (rules[i].is_wildcard && !rules[j].is_wildcard) {
                    i_more_specific = false;
                }

                // 如果 i 的线程是通配符而 j 是精确的，则 i 不够具体
                if (strchr(rules[i].thread, '*') && !strchr(rules[j].thread, '*')) {
                    i_more_specific = false;
                }

                if (!i_more_specific) {
                    LOG_W("    警告: 优先级更高的规则 (%d) 可能不够具体，会被优先级较低的规则 (%d) 覆盖\n",
                          rules[i].priority, rules[j].priority);
                }
            }
        }
    }
}

static AppConfig* load_config(const char* config_file, const CpuTopology* topo, time_t* last_mtime) {
    // 1. 检查文件状态
    struct stat st;
    if (stat(config_file, &st) != 0) {
        // 创建空配置文件
        return NULL;
    }

    // 2. 检查是否需要重新加载
    if (last_mtime && *last_mtime == st.st_mtime && *last_mtime != -1) {
        return NULL;
    }

    // 3. 打开并映射文件
    int fd = open(config_file, O_RDONLY);
    if (fd < 0) {
        LOG_E("无法打开配置文件 %s: %s\n", config_file, strerror(errno));
        return NULL;
    }

    char* data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) {
        LOG_E("无法映射配置文件 %s: %s\n", config_file, strerror(errno));
        return NULL;
    }

    // 4. 分配配置结构
    AppConfig* cfg = calloc(1, sizeof(AppConfig));
    if (!cfg) {
        munmap(data, st.st_size);
        return NULL;
    }
    cfg->ref_count = 1;
    cfg->topo = *topo;
    build_str(cfg->config_file, sizeof(cfg->config_file), config_file, NULL);
    build_str(cfg->cpuset_base, sizeof(cfg->cpuset_base), BASE_CPUSET, NULL);

    // 5. 分配规则数组
    AffinityRule* rules = malloc(INITIAL_RULE_CAPACITY * sizeof(AffinityRule));
    size_t rules_capacity = INITIAL_RULE_CAPACITY;
    size_t num_rules = 0;
    AffinityRule** wildcard_rules = malloc(INITIAL_WILDCARD_CAPACITY * sizeof(AffinityRule*));
    size_t wildcard_capacity = INITIAL_WILDCARD_CAPACITY;
    size_t num_wildcard_rules = 0;
    PackageEntry* pkg_table = NULL;

    if (!rules || !wildcard_rules) {
        munmap(data, st.st_size);
        free(rules);
        free(wildcard_rules);
        free(cfg);
        return NULL;
    }

    // 6. 解析每一行
    char line[256];
    char* line_ptr = data;
    char* end = data + st.st_size;
    size_t line_number = 0;

    while (line_ptr < end) {
        char* newline = memchr(line_ptr, '\n', end - line_ptr);
        if (!newline) newline = end;
        size_t line_len = newline - line_ptr;
        line_number++;

        if (line_len >= sizeof(line)) {
            LOG_W("第 %zu 行过长，跳过\n", line_number);
            line_ptr = newline + 1;
            continue;
        }

        strncpy(line, line_ptr, line_len);
        line[line_len] = '\0';
        line_ptr = newline + 1;

        char* p = strtrim_line(line);
        if (!*p || *p == '#') continue;

        char* eq = strchr(p, '=');
        if (!eq) {
            LOG_W("第 %zu 行无效规则：缺少 '=': %s\n", line_number, p);
            continue;
        }
        *eq++ = '\0';

        char* key = strtrim(p);
        char* value = strtrim(eq);

        char* comment = strchr(value, '#');
        if (comment) *comment = '\0';
        value = strtrim(value);

        if (!*key || !*value) {
            LOG_W("第 %zu 行无效规则：键或值为空: %s\n", line_number, p);
            continue;
        }

        // ========== 解析包名{线程名} ==========
        char* br = strchr(key, '{');
        char* thread = NULL;
        char* pkg = NULL;

        if (br) {
            *br++ = '\0';
            char* eb = strchr(br, '}');
            if (!eb) {
                LOG_W("第 %zu 行无效规则：缺少闭合 '}': %s\n", line_number, p);
                continue;
            }
            *eb = '\0';
            thread = strtrim(br);
            pkg = strtrim(key);

            if (thread[0] == '\0') {
                LOG_W("第 %zu 行无效规则：线程名为空，已跳过: %s{%s}=%s\n", 
                      line_number, pkg, thread, value);
                continue;
            }
        } else {
            pkg = strtrim(key);
            thread = "";
        }

        if (!pkg || pkg[0] == '\0') {
            LOG_W("第 %zu 行无效规则：包名为空，已跳过: %s\n", line_number, p);
            continue;
        }

        if (strlen(pkg) >= MAX_PKG_LEN || strlen(thread) >= MAX_THREAD_LEN) {
            LOG_W("第 %zu 行无效规则：包名或线程名过长，已跳过: %s\n", line_number, p);
            continue;
        }

        // 检查重复规则
        bool is_duplicate = false;
        for (size_t i = 0; i < num_rules; i++) {
            if (!strcmp(rules[i].pkg, pkg) && !strcmp(rules[i].thread, thread)) {
                LOG_W("第 %zu 行重复规则：%s{%s}=%s，已跳过\n", line_number, pkg, thread, value);
                is_duplicate = true;
                break;
            }
        }
        if (is_duplicate) continue;

        if (num_rules >= rules_capacity) {
            rules_capacity *= 2;
            AffinityRule* temp_rules = realloc(rules, rules_capacity * sizeof(AffinityRule));
            if (!temp_rules) {
                munmap(data, st.st_size);
                cleanup_temp_resources(&rules, num_rules, &wildcard_rules, num_wildcard_rules, &pkg_table);
                free(cfg);
                return NULL;
            }
            rules = temp_rules;
        }

        AffinityRule* rule = &rules[num_rules];
        strncpy(rule->pkg, pkg, MAX_PKG_LEN - 1);
        rule->pkg[MAX_PKG_LEN - 1] = '\0';
        strncpy(rule->thread, thread, MAX_THREAD_LEN - 1);
        rule->thread[MAX_THREAD_LEN - 1] = '\0';
        CPU_ZERO(&rule->cpus);

        char invalid_range[64] = {0};
        if (!parse_cpu_ranges(value, &rule->cpus, &cfg->topo.present_cpus, invalid_range, sizeof(invalid_range))) {
            LOG_W("第 %zu 行无效 CPU 范围：%s 在规则 %s{%s}=%s，超出可用 CPU (%s)\n",
                  line_number, invalid_range, pkg, thread, value, cfg->topo.present_str);
            continue;
        }

        if (CPU_COUNT(&rule->cpus) == 0) {
            LOG_W("第 %zu 行无效 CPU 范围：%s 在规则 %s{%s}=%s，无有效 CPU\n",
                  line_number, value, pkg, thread, value);
            continue;
        }

        char* dir_name = cpu_set_to_str(&rule->cpus);
        if (!dir_name) {
            LOG_W("第 %zu 行无法将 CPU 集合转换为字符串\n", line_number);
            continue;
        }
        char cpuset_path[256];
        build_str(cpuset_path, sizeof(cpuset_path), cfg->cpuset_base, "/", dir_name, NULL);
        if (!create_cpuset_dir(cpuset_path, dir_name, cfg->topo.mems_str)) {
            LOG_W("第 %zu 行无法创建 cpuset 目录 %s\n", line_number, cpuset_path);
            free(dir_name);
            continue;
        }
        strncpy(rule->cpuset_dir, dir_name, sizeof(rule->cpuset_dir) - 1);
        rule->cpuset_dir[sizeof(rule->cpuset_dir) - 1] = '\0';
        free(dir_name);

        // 计算优先级
        bool is_default = (strcmp(pkg, "*") == 0 && (thread[0] == '\0' || strcmp(thread, "*") == 0));

        if (is_default) {
            rule->priority = -1;
            rule->is_wildcard = false;
        } else {
            bool is_wildcard = (strchr(pkg, '*') != NULL || 
                               strchr(pkg, '?') != NULL || 
                               strchr(pkg, '[') != NULL ||
                               strchr(thread, '*') != NULL || 
                               strchr(thread, '?') != NULL || 
                               strchr(thread, '[') != NULL);
            rule->is_wildcard = is_wildcard;
            rule->priority = calculate_rule_priority(pkg, thread);
        }

        num_rules++;

        if (is_default) {
            // 默认规则：不加入索引
        } else if (rule->is_wildcard) {
            if (num_wildcard_rules >= wildcard_capacity) {
                wildcard_capacity *= 2;
                AffinityRule** temp_wildcard_rules = realloc(wildcard_rules, wildcard_capacity * sizeof(AffinityRule*));
                if (!temp_wildcard_rules) {
                    munmap(data, st.st_size);
                    cleanup_temp_resources(&rules, num_rules, &wildcard_rules, num_wildcard_rules, &pkg_table);
                    free(cfg);
                    return NULL;
                }
                wildcard_rules = temp_wildcard_rules;
            }
            wildcard_rules[num_wildcard_rules++] = rule;
        } else {
            PackageEntry* pkg_entry;
            HASH_FIND_STR(pkg_table, pkg, pkg_entry);
            if (!pkg_entry) {
                pkg_entry = malloc(sizeof(PackageEntry));
                if (!pkg_entry) {
                    munmap(data, st.st_size);
                    cleanup_temp_resources(&rules, num_rules, &wildcard_rules, num_wildcard_rules, &pkg_table);
                    free(cfg);
                    return NULL;
                }
                strncpy(pkg_entry->pkg, pkg, MAX_PKG_LEN - 1);
                pkg_entry->pkg[MAX_PKG_LEN - 1] = '\0';
                HASH_ADD_STR(pkg_table, pkg, pkg_entry);
            }
        }
    }

    munmap(data, st.st_size);

    // 7. 检查是否有有效规则
    if (!num_rules) {
        LOG_W("从 %s 未加载有效规则\n", config_file);
        cleanup_temp_resources(&rules, num_rules, &wildcard_rules, num_wildcard_rules, &pkg_table);
        free(cfg);
        return NULL;
    }

    // 8. 构建包名列表
    size_t num_pkgs = HASH_COUNT(pkg_table);
    char** pkgs = malloc(INITIAL_PKG_CAPACITY * sizeof(char*));
    size_t pkgs_capacity = INITIAL_PKG_CAPACITY;
    if (!pkgs) {
        cleanup_temp_resources(&rules, num_rules, &wildcard_rules, num_wildcard_rules, &pkg_table);
        free(cfg);
        return NULL;
    }
    PackageEntry* entry, *tmp;
    size_t i = 0;
    HASH_ITER(hh, pkg_table, entry, tmp) {
        if (i >= pkgs_capacity) {
            pkgs_capacity *= 2;
            char** temp_pkgs = realloc(pkgs, pkgs_capacity * sizeof(char*));
            if (!temp_pkgs) {
                for (size_t j = 0; j < i; j++) free(pkgs[j]);
                free(pkgs);
                cleanup_temp_resources(&rules, num_rules, &wildcard_rules, num_wildcard_rules, &pkg_table);
                free(cfg);
                return NULL;
            }
            pkgs = temp_pkgs;
        }
        pkgs[i] = strdup(entry->pkg);
        if (!pkgs[i]) {
            for (size_t j = 0; j < i; j++) free(pkgs[j]);
            free(pkgs);
            cleanup_temp_resources(&rules, num_rules, &wildcard_rules, num_wildcard_rules, &pkg_table);
            free(cfg);
            return NULL;
        }
        i++;
    }

    // ========== 9. 在这里验证优先级 ==========
    validate_rule_priorities(rules, num_rules);
    // =======================================

     // 10. 清理旧配置并赋值新配置
    if (cfg->rules) free(cfg->rules);
    if (cfg->wildcard_rules) free(cfg->wildcard_rules);
    if (cfg->pkgs) {
        for (size_t j = 0; j < cfg->num_pkgs; j++) free(cfg->pkgs[j]);
        free(cfg->pkgs);
    }
    HASH_CLEAR(hh, cfg->pkg_table);
    HASH_ITER(hh, cfg->pkg_table, entry, tmp) {
        HASH_DEL(cfg->pkg_table, entry);
        free(entry);
    }

    cfg->rules = rules;
    cfg->num_rules = num_rules;
    cfg->wildcard_rules = wildcard_rules;
    cfg->num_wildcard_rules = num_wildcard_rules;
    cfg->pkgs = pkgs;
    cfg->num_pkgs = num_pkgs;
    cfg->pkg_table = pkg_table;
    cfg->mtime = st.st_mtime;

    if (last_mtime) *last_mtime = st.st_mtime;

    size_t exact_pkg_exact_thread = 0;      // 精确包名+精确线程
    size_t exact_pkg_wildcard_thread = 0;   // 精确包名+线程通配符
    size_t exact_pkg_no_thread = 0;         // 精确包名（无线程）
    size_t wildcard_pkg_exact_thread = 0;   // 包名通配符+精确线程
    size_t wildcard_pkg_wildcard_thread = 0;// 包名通配符+线程通配符
    size_t default_rules = 0;               // 默认规则

    for (size_t i = 0; i < num_rules; i++) {
        int prio = rules[i].priority;
        if (prio == 100000) {
            exact_pkg_exact_thread++;
        } else if (prio == 80000) {
            exact_pkg_wildcard_thread++;
        } else if (prio == 60000) {
            exact_pkg_no_thread++;
        } else if (prio == 40000) {
            wildcard_pkg_exact_thread++;
        } else if (prio == 20000) {
            wildcard_pkg_wildcard_thread++;
        } else if (prio == -1 || prio == 0) {
            default_rules++;
        }
    }

    LOG_I("配置文件解析完成\n");
    LOG_I("总规则: %zu 条\n", num_rules);
    LOG_I("  - 精确包名+精确线程: %zu 条 (优先级: 100000)\n", exact_pkg_exact_thread);
    LOG_I("  - 精确包名+线程通配符: %zu 条 (优先级: 80000)\n", exact_pkg_wildcard_thread);
    LOG_I("  - 精确包名（无线程）: %zu 条 (优先级: 60000)\n", exact_pkg_no_thread);
    LOG_I("  - 包名通配符+精确线程: %zu 条 (优先级: 40000)\n", wildcard_pkg_exact_thread);
    LOG_I("  - 包名通配符+线程通配符: %zu 条 (优先级: 20000)\n", wildcard_pkg_wildcard_thread);
    LOG_I("  - 默认规则: %zu 条 (优先级: -1)\n", default_rules);
    LOG_I("应用包: %zu 个\n", num_pkgs);
    // ===================================

    return cfg;
}

static int compare_rules(const void* a, const void* b) {
    AffinityRule* ra = *(AffinityRule**)a;
    AffinityRule* rb = *(AffinityRule**)b;
    if (rb->priority > ra->priority) return 1;
    if (rb->priority < ra->priority) return -1;
    return 0;
}


static void proc_collect(const AppConfig* cfg, ProcCache* cache, size_t* count)
{
    char* dent_buf = malloc(DENT_BUF_SIZE);
    if (!dent_buf) return;

    int proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd < 0) {
        free(dent_buf);
        return;
    }

    int current_proc_total = 0;
    *count = 0;

    // 清理旧数据
    for (size_t i = 0; i < cache->num_procs; i++) {
        free(cache->procs[i].threads);
        free(cache->procs[i].thread_rules);
        cache->procs[i].threads = NULL;
        cache->procs[i].thread_rules = NULL;
        cache->procs[i].num_threads = 0;
        cache->procs[i].num_thread_rules = 0;
    }

    if (!cache->procs) {
        cache->procs_cap = 1024;
        cache->procs = calloc(cache->procs_cap, sizeof(ProcessInfo));
    }

    while (1) {
        int nread = syscall(__NR_getdents64, proc_fd,
                            (struct linux_dirent64*)dent_buf,
                            DENT_BUF_SIZE);
        if (nread <= 0) break;

        for (int pos = 0; pos < nread;) {
            struct linux_dirent64* ent =
                (struct linux_dirent64*)(dent_buf + pos);
            pos += ent->d_reclen;

            if (ent->d_type != DT_DIR || !isdigit(ent->d_name[0]))
                continue;

            long pid = strtol(ent->d_name, NULL, 10);
            current_proc_total++;

            int proc_dir_fd = openat(proc_fd, ent->d_name,
                                      O_RDONLY | O_DIRECTORY);
            if (proc_dir_fd == -1) continue;

            char cmd[MAX_PKG_LEN] = {0};
            if (!read_file(proc_dir_fd, "cmdline", cmd, sizeof(cmd))) {
                close(proc_dir_fd);
                continue;
            }

            char* name = strrchr(cmd, '/');
            name = name ? name + 1 : cmd;

            if (*count >= cache->procs_cap) {
                cache->procs_cap *= 2;
                cache->procs = realloc(cache->procs,
                    cache->procs_cap * sizeof(ProcessInfo));
            }

            ProcessInfo* proc = &cache->procs[*count];
            memset(proc, 0, sizeof(ProcessInfo));

            proc->pid = pid;
            build_str(proc->pkg, sizeof(proc->pkg), name, NULL);

            CPU_ZERO(&proc->base_cpus);
            build_str(proc->base_cpuset, sizeof(proc->base_cpuset),
                      cfg->cpuset_base, NULL);

            // 初始化
            proc->threads_cap = 32;
            proc->threads = malloc(proc->threads_cap * sizeof(ThreadInfo));
            proc->num_threads = 0;

            proc->thread_rules_cap = 16;
            proc->thread_rules = malloc(proc->thread_rules_cap * sizeof(AffinityRule*));
            proc->num_thread_rules = 0;

            bool matched_any = false;

            PackageEntry* pkg_entry;
            HASH_FIND_STR(cfg->pkg_table, name, pkg_entry);

            // ============================
            // 1. 精确规则
            // ============================
            if (pkg_entry) {
                for (size_t i = 0; i < cfg->num_rules; i++) {
                    const AffinityRule* r = &cfg->rules[i];

                    if (r->priority < 0) continue;

                    if (!r->is_wildcard && strcmp(r->pkg, name) == 0) {

                        proc->thread_rules[proc->num_thread_rules++] =
                            (AffinityRule*)r;

                        CPU_OR(&proc->base_cpus, &proc->base_cpus, &r->cpus);
                        matched_any = true;
                    }
                }
            }

            // ============================
            // 2. wildcard规则
            // ============================
            for (size_t i = 0; i < cfg->num_wildcard_rules; i++) {
                const AffinityRule* r = cfg->wildcard_rules[i];

                if (fnmatch(r->pkg, proc->pkg, 0) == 0) {

                    proc->thread_rules[proc->num_thread_rules++] =
                        (AffinityRule*)r;

                    CPU_OR(&proc->base_cpus, &proc->base_cpus, &r->cpus);
                    matched_any = true;
                }
            }

            // ============================
            // 3. default rule（关键修复点）
            // ============================
            for (size_t i = 0; i < cfg->num_rules; i++) {
                const AffinityRule* r = &cfg->rules[i];

                if (r->priority != -1) continue;

                // ⭐ 关键：default 也必须参与 wildcard 语义
                proc->thread_rules[proc->num_thread_rules++] =
                    (AffinityRule*)r;

                CPU_OR(&proc->base_cpus, &proc->base_cpus, &r->cpus);
                matched_any = true;
            }

            if (!matched_any) {
                free(proc->threads);
                free(proc->thread_rules);
                close(proc_dir_fd);
                continue;
            }

            // 排序（保证稳定）
            if (proc->num_thread_rules > 1) {
                qsort(proc->thread_rules,
                      proc->num_thread_rules,
                      sizeof(AffinityRule*),
                      compare_rules);
            }

            // ============================
            // THREAD SCAN + FIXED MATCH
            // ============================
            int task_fd = openat(proc_dir_fd, "task",
                                  O_RDONLY | O_DIRECTORY);
            close(proc_dir_fd);

            if (task_fd == -1) continue;

            DIR* task_dir = fdopendir(task_fd);
            if (!task_dir) {
                close(task_fd);
                continue;
            }

            while (1) {
                struct dirent* d = readdir(task_dir);
                if (!d) break;

                long tid = strtol(d->d_name, NULL, 10);
                if (tid <= 0) continue;

                int tid_fd = openat(task_fd, d->d_name,
                                    O_RDONLY | O_DIRECTORY);
                if (tid_fd == -1) continue;

                char tname[MAX_THREAD_LEN] = {0};
                read_file(tid_fd, "comm", tname, sizeof(tname));
                close(tid_fd);

                strtrim(tname);

                if (proc->num_threads >= proc->threads_cap) {
                    proc->threads_cap *= 2;
                    proc->threads = realloc(proc->threads,
                        proc->threads_cap * sizeof(ThreadInfo));
                }

                ThreadInfo* ti = &proc->threads[proc->num_threads++];
                memset(ti, 0, sizeof(ThreadInfo));

                ti->tid = tid;
                build_str(ti->name, sizeof(ti->name), tname, NULL);

                CPU_ZERO(&ti->cpus);

                const AffinityRule* best = NULL;

                // ============================
                // ⭐ 核心：选择最高优先级规则
                // ============================
                for (size_t i = 0; i < proc->num_thread_rules; i++) {

                    AffinityRule* r = proc->thread_rules[i];

                    // ⭐ FIX：* + wildcard 正确匹配
                    if (r->thread[0] != '\0' &&
                        strcmp(r->thread, "*") != 0 &&
                        fnmatch(r->thread, tname, 0) != 0) {
                        continue;
                    }

                    if (!best || r->priority > best->priority) {
                        best = r;
                    }
                }

                if (best) {
                    CPU_OR(&ti->cpus, &ti->cpus, &best->cpus);
                    build_str(ti->cpuset_dir,
                              sizeof(ti->cpuset_dir),
                              best->cpuset_dir, NULL);
                } else {
                    CPU_OR(&ti->cpus, &ti->cpus, &proc->base_cpus);
                    build_str(ti->cpuset_dir,
                              sizeof(ti->cpuset_dir),
                              proc->base_cpuset, NULL);
                }
            }

            closedir(task_dir);
            (*count)++;
        }
    }

    free(dent_buf);
    close(proc_fd);

    cache->last_proc_total = current_proc_total;
}

static void update_cache(ProcCache* cache, const AppConfig* cfg, int* affinity_counter) {
    bool need_reload = atomic_load(&config_updated);
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        need_reload = true;
    } else {
        int current_proc_count = info.procs;
        if (current_proc_count > cache->last_proc_count + 10) {
            need_reload = true;
        } else if (current_proc_count > cache->last_proc_count) {
            *affinity_counter = 0;
        }
        cache->last_proc_count = current_proc_count;
    }
    if (cache->procs != NULL && !need_reload) {
        for (size_t i = 0; i < cache->num_procs; i++) {
            if (kill(cache->procs[i].pid, 0) != 0) {
                need_reload = true;
                break;
            }
        }
    }

    if (need_reload || cache->scan_all_proc ) {
        size_t new_count = 0;
        proc_collect(cfg, cache, &new_count);

        if (new_count > cache->tracked_pids_cap) {
            size_t new_cap = cache->tracked_pids_cap ? cache->tracked_pids_cap * 2 : new_count;
            pid_t* new_pids = realloc(cache->tracked_pids, new_cap * sizeof(pid_t));
            if (new_pids) {
                cache->tracked_pids = new_pids;
                cache->tracked_pids_cap = new_cap;
            }
        }

        if (cache->tracked_pids) {
            cache->num_tracked_pids = 0;
            for (size_t i = 0; i < new_count; i++) {
                if (cache->num_tracked_pids < cache->tracked_pids_cap) {
                    cache->tracked_pids[cache->num_tracked_pids++] = cache->procs[i].pid;
                }
            }
        }

        cache->num_procs = new_count;
        *affinity_counter = 0;
    }
}

static void apply_affinity(ProcCache* cache, const CpuTopology* topo) {
    for (size_t i = 0; i < cache->num_procs; i++) {
        const ProcessInfo* proc = &cache->procs[i];
        for (size_t j = 0; j < proc->num_threads; j++) {
            const ThreadInfo* ti = &proc->threads[j];
            if (topo->cpuset_enabled && topo->base_cpuset_fd != -1) {
                char tid_str[32];
                snprintf(tid_str, sizeof(tid_str), "%d\n", ti->tid);
                if (CPU_COUNT(&ti->cpus) == 0) {
                    cpu_set_t curr;
                    if (sched_getaffinity(ti->tid, sizeof(curr), &curr) == -1) continue;
                    if (CPU_EQUAL(&topo->present_cpus, &curr)) continue;
                    write_file(topo->base_cpuset_fd, "tasks", tid_str, O_WRONLY | O_APPEND);
                } else {
                    cpu_set_t curr;
                    if (sched_getaffinity(ti->tid, sizeof(curr), &curr) == -1) continue;
                    if (CPU_EQUAL(&ti->cpus, &curr)) continue;
                    if (ti->cpuset_dir[0]) {
                        int fd = openat(topo->base_cpuset_fd, ti->cpuset_dir, O_RDONLY | O_DIRECTORY);
                        if (fd != -1) {
                            write_file(fd, "tasks", tid_str, O_WRONLY | O_APPEND);
                            close(fd);
                        }
                    }
                }
            }
            if (CPU_COUNT(&ti->cpus) == 0) continue;
            if (sched_setaffinity(ti->tid, sizeof(ti->cpus), &ti->cpus) == -1 && errno == ESRCH) {
                cache->last_proc_count = 0;
            }
        }
    }
}

static void config_release(AppConfig* cfg) {
    if (!cfg) return;
    if (atomic_fetch_sub(&cfg->ref_count, 1) == 1) {
        if (cfg->rules) free(cfg->rules);
        if (cfg->wildcard_rules) free(cfg->wildcard_rules);
        if (cfg->pkgs) {
            for (size_t i = 0; i < cfg->num_pkgs; i++) free(cfg->pkgs[i]);
            free(cfg->pkgs);
        }
        PackageEntry* entry, *tmp;
        HASH_ITER(hh, cfg->pkg_table, entry, tmp) {
            HASH_DEL(cfg->pkg_table, entry);
            free(entry);
        }
        free(cfg);
    }
}

static AppConfig* get_config() {
    AppConfig* cfg = atomic_load_explicit(&current_config, memory_order_acquire);
    if (!cfg) return NULL;
    int old_ref = atomic_fetch_add_explicit(&cfg->ref_count, 1, memory_order_acq_rel);
    if (old_ref <= 0) {
        atomic_fetch_sub_explicit(&cfg->ref_count, 1, memory_order_release);
        return NULL;
    }
    if (atomic_load_explicit(&current_config, memory_order_acquire) != cfg) {
        atomic_fetch_sub_explicit(&cfg->ref_count, 1, memory_order_release);
        return NULL;
    }
    return cfg;
}

static void* config_loader_thread(void* arg) {
    int interval = *(int*)arg;
    free(arg);
    pthread_setname_np(pthread_self(), "ConfigLoader");

    time_t last_mtime = -1;
    while (1) {
        if (inotify_supported) {
            fd_set rfds;
            struct timeval tv;
            FD_ZERO(&rfds);
            FD_SET(inotify_fd, &rfds);
            tv.tv_sec = interval;
            tv.tv_usec = 0;

            int ret = select(inotify_fd + 1, &rfds, NULL, NULL, &tv);
            if (ret < 0) {
                if (errno == EINTR) continue;
                inotify_supported = 0;
                close(inotify_fd);
                inotify_fd = -1;
                continue;
            } else if (ret == 0) {
                continue;
            }

            char buf[4096] __attribute__((aligned(8)));
            ssize_t len = read(inotify_fd, buf, sizeof(buf));
            if (len <= 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    inotify_supported = 0;
                    close(inotify_fd);
                    inotify_fd = -1;
                }
                continue;
            }

            bool reload_needed = false;
            for (char* p = buf; p < buf + len;) {
                struct inotify_event* event = (struct inotify_event*)p;
                if (event->mask & (IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF)) {
                    reload_needed = true;

                    if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
                        sleep(interval);
                        AppConfig* cfg = get_config();
                        if (cfg) {
                            inotify_rm_watch(inotify_fd, inotify_wd);
                            inotify_wd = inotify_add_watch(inotify_fd, cfg->config_file, IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF);
                            last_mtime = -1;
                            config_release(cfg);
                        }
                        if (inotify_wd < 0) {
                            inotify_supported = 0;
                            close(inotify_fd);
                            inotify_fd = -1;
                            break;
                        }
                    }
                }
                p += sizeof(struct inotify_event) + event->len;
            }

            if (reload_needed) {
                AppConfig* cfg = get_config();
                if (cfg) {
                    AppConfig* new_config = load_config(cfg->config_file, &cfg->topo, &last_mtime);
                    if (new_config) {
                        AppConfig* old_config = atomic_exchange(&current_config, new_config);
                        atomic_store(&config_updated, 1);
                        if (old_config) {
                            usleep(10000);
                            config_release(old_config);
                        }
                    }
                    config_release(cfg);
                }
            }
        } else {
            AppConfig* cfg = get_config();
            if (cfg) {
                AppConfig* new_config = load_config(cfg->config_file, &cfg->topo, &last_mtime);
                if (new_config) {
                    AppConfig* old_config = atomic_exchange(&current_config, new_config);
                    atomic_store(&config_updated, 1);
                    if (old_config) {
                        usleep(10000);
                        config_release(old_config);
                    }
                }
                config_release(cfg);
            }
            sleep(interval);
        }
    }
    return NULL;
}

static void print_help(const char* prog_name) {
    printf("用法: %s [选项]\n", prog_name);
    printf("选项:\n");
    printf("  -c <配置文件>   指定配置文件 (默认: ./applist.conf)\n");
    printf("  -s <间隔>      设置检查间隔(秒) (必须>=1, 默认: 2)\n");
    printf("  -v             显示程序版本\n");
    printf("  -h             显示帮助信息\n");
    printf("\n示例:\n");
    printf("  %s -c /data/applist.conf -s 3\n", prog_name);
}


int main(int argc, char **argv) {
    CpuTopology topo = init_cpu_topo();
    char config_file[4096] = "./applist.conf";
    int sleep_interval = 2;
    int opt;
    while ((opt = getopt(argc, argv, "c:s:hv")) != -1) {
        switch (opt) {
            case 'c':
                build_str(config_file, sizeof(config_file), optarg, NULL);
                printf("配置文件: %s\n", config_file);
                break;
            case 's':
            {
                char *endptr;
                long val = strtol(optarg, &endptr, 10);
                if (endptr == optarg || *endptr != '\0' || val < 1) {
                    fprintf(stderr, "无效的时间间隔: %s\n", optarg);
                    fprintf(stderr, "间隔必须是 >=1 的整数\n");
                    exit(EXIT_FAILURE);
                }
                sleep_interval = (int)val;
                printf("检查间隔: %d 秒\n", sleep_interval);
                break;
            }
            case 'v':
                printf("AppOpt 版本 %s\n", VERSION);
                exit(EXIT_SUCCESS);
            case 'h':
                print_help(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                print_help(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    struct stat st;
    if (stat(config_file, &st) != 0) {
        const char* initial_content = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n";
        if (write_file(AT_FDCWD, config_file, initial_content, O_WRONLY | O_CREAT | O_TRUNC)) {
            LOG_W("配置文件不存在，重建一个空的配置文件: %s\n", config_file);
        }
    }

    AppConfig* initial_config = load_config(config_file, &topo, NULL);
    if (!initial_config) {
        fprintf(stderr, "初始配置加载失败\n");
        exit(EXIT_FAILURE);
    }
    atomic_store(&current_config, initial_config);
    atomic_store(&config_updated, 1);

    inotify_fd = inotify_init1(IN_CLOEXEC);
    if (inotify_fd >= 0) {
        int flags = fcntl(inotify_fd, F_GETFL);
        if (flags >= 0) fcntl(inotify_fd, F_SETFL, flags | O_NONBLOCK);
        inotify_wd = inotify_add_watch(inotify_fd, config_file, IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF);
        if (inotify_wd >= 0) {
            inotify_supported = 1;
            LOG_I("启用inotify监控配置文件变更\n");
        } else {
            close(inotify_fd);
            inotify_fd = -1;
            LOG_W("inotify初始化失败，使用轮询模式\n");
        }
    }

    pthread_t loader_thread;
    int* interval_ptr = malloc(sizeof(int));
    if (!interval_ptr) {
        config_release(initial_config);
        if (inotify_supported) close(inotify_fd);
        exit(EXIT_FAILURE);
    }
    *interval_ptr = sleep_interval;

    if (pthread_create(&loader_thread, NULL, config_loader_thread, interval_ptr) != 0) {
        perror("配置加载器线程创建失败");
        free(interval_ptr);
        config_release(initial_config);
        if (inotify_supported) close(inotify_fd);
        exit(EXIT_FAILURE);
    }
    pthread_detach(loader_thread);

    ProcCache cache = {0};
    int affinity_counter = 0;
    LOG_I("启动AppOpt服务 v%s [PID:%d]\n", VERSION, getpid());

    for (;;) {
        if (atomic_exchange(&config_updated, 0)) {
            cache.scan_all_proc = true;
            cache.last_proc_count = 0;
        }

        AppConfig* cfg = get_config();
        if (cfg) {
            update_cache(&cache, cfg, &affinity_counter);
            affinity_counter--;
            if (affinity_counter < 1) {
                apply_affinity(&cache, &cfg->topo);
                affinity_counter = 5;
            }
            config_release(cfg);
        }
        sleep(sleep_interval);
    }
    return 0;
}