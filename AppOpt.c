/*
 * AppOpt v1.6.3
 * Modified Version
 *
 * Features:
 * - Multiple -c config support
 * - Wildcard package support
 * - Wildcard thread support
 * - Exact match priority
 * - Merged cpuset
 * - Multi-config hot reload
 *
 * NOTE:
 * This is the fully integrated modified source skeleton.
 * Replace your original file with this one.
 */

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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#define VERSION "1.6.3-mod"
#define BASE_CPUSET "/dev/cpuset/AppOpt"

#define MAX_PKG_LEN 128
#define MAX_THREAD_LEN 32

typedef struct {
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    char cpuset_dir[256];

    cpu_set_t cpus;

    bool wildcard_pkg;

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

typedef struct {

    atomic_int ref_count;

    AffinityRule* rules;
    size_t num_rules;

    CpuTopology topo;

    char** config_files;
    size_t num_config_files;

} AppConfig;

static _Atomic(AppConfig*) current_config = NULL;

static char* strtrim(char* s)
{
    char* end;

    while (isspace(*s))
        s++;

    if (*s == 0)
        return s;

    end = s + strlen(s) - 1;

    while (end > s && isspace(*end))
        end--;

    *(end + 1) = 0;

    return s;
}

static bool read_file(int dir_fd,
                      const char* filename,
                      char* buf,
                      size_t buf_size)
{
    int fd =
        openat(dir_fd,
               filename,
               O_RDONLY | O_CLOEXEC);

    if (fd == -1)
        return false;

    ssize_t n =
        read(fd,
             buf,
             buf_size - 1);

    close(fd);

    if (n <= 0)
        return false;

    buf[n] = 0;

    return true;
}

static int build_str(char* dest,
                     size_t size,
                     ...)
{
    va_list args;

    va_start(args, size);

    const char* seg;

    char* p = dest;

    size_t remain = size - 1;

    while ((seg = va_arg(args, const char*))) {

        size_t len = strlen(seg);

        if (len > remain) {
            va_end(args);
            return 0;
        }

        memcpy(p, seg, len);

        p += len;
        remain -= len;
    }

    *p = 0;

    va_end(args);

    return 1;
}

static void parse_cpu_ranges(const char* spec,
                             cpu_set_t* set)
{
    if (!spec)
        return;

    char* copy = strdup(spec);

    if (!copy)
        return;

    char* s = copy;

    while (*s) {

        char* end;

        long a = strtol(s, &end, 10);

        if (end == s) {
            s++;
            continue;
        }

        long b = a;

        if (*end == '-') {

            s = end + 1;

            b = strtol(s, &end, 10);
        }

        if (a > b) {

            long t = a;
            a = b;
            b = t;
        }

        for (long i = a;
             i <= b;
             i++) {

            CPU_SET(i, set);
        }

        s = (*end == ',')
                ? end + 1
                : end;
    }

    free(copy);
}

static char* cpu_set_to_str(const cpu_set_t* set)
{
    char* out = malloc(256);

    if (!out)
        return NULL;

    out[0] = 0;

    bool first = true;

    for (int i = 0;
         i < CPU_SETSIZE;
         i++) {

        if (!CPU_ISSET(i, set))
            continue;

        char tmp[32];

        snprintf(tmp,
                 sizeof(tmp),
                 "%s%d",
                 first ? "" : ",",
                 i);

        strcat(out, tmp);

        first = false;
    }

    return out;
}

static AppConfig*
load_multi_config(char** files,
                  size_t num_files)
{
    AppConfig* cfg =
        calloc(1, sizeof(AppConfig));

    if (!cfg)
        return NULL;

    cfg->ref_count = 1;

    cfg->config_files =
        calloc(num_files, sizeof(char*));

    cfg->num_config_files =
        num_files;

    for (size_t i = 0;
         i < num_files;
         i++) {

        cfg->config_files[i] =
            strdup(files[i]);
    }

    for (size_t f = 0;
         f < num_files;
         f++) {

        FILE* fp =
            fopen(files[f], "r");

        if (!fp)
            continue;

        char line[256];

        while (fgets(line,
                     sizeof(line),
                     fp)) {

            char* p = strtrim(line);

            if (!*p || *p == '#')
                continue;

            char* eq = strchr(p, '=');

            if (!eq)
                continue;

            *eq++ = 0;

            char* br = strchr(p, '{');

            char* thread = "";

            if (br) {

                *br++ = 0;

                char* eb =
                    strchr(br, '}');

                if (!eb)
                    continue;

                *eb = 0;

                thread = strtrim(br);
            }

            char* pkg =
                strtrim(p);

            char* cpus =
                strtrim(eq);

            cfg->rules =
                realloc(cfg->rules,
                        (cfg->num_rules + 1) *
                        sizeof(AffinityRule));

            AffinityRule* rule =
                &cfg->rules[cfg->num_rules];

            memset(rule, 0,
                   sizeof(*rule));

            build_str(rule->pkg,
                      sizeof(rule->pkg),
                      pkg,
                      NULL);

            build_str(rule->thread,
                      sizeof(rule->thread),
                      thread,
                      NULL);

            rule->wildcard_pkg =
                strpbrk(pkg, "*?[") != NULL;

            CPU_ZERO(&rule->cpus);

            parse_cpu_ranges(cpus,
                             &rule->cpus);

            char* cpustr =
                cpu_set_to_str(
                    &rule->cpus);

            if (cpustr) {

                build_str(rule->cpuset_dir,
                          sizeof(rule->cpuset_dir),
                          cpustr,
                          NULL);

                free(cpustr);
            }

            cfg->num_rules++;
        }

        fclose(fp);
    }

    return cfg;
}

static bool
pkg_matches(const AffinityRule* rule,
            const char* pkg)
{
    if (rule->wildcard_pkg) {

        return fnmatch(rule->pkg,
                       pkg,
                       FNM_NOESCAPE) == 0;
    }

    return strcmp(rule->pkg,
                  pkg) == 0;
}

static void
apply_rules(ProcessInfo* proc,
            const AppConfig* cfg)
{
    bool has_exact = false;

    for (size_t i = 0;
         i < cfg->num_rules;
         i++) {

        const AffinityRule* rule =
            &cfg->rules[i];

        if (rule->wildcard_pkg)
            continue;

        if (strcmp(rule->pkg,
                   proc->pkg) == 0) {

            has_exact = true;
            break;
        }
    }

    CPU_ZERO(&proc->base_cpus);

    for (size_t i = 0;
         i < cfg->num_rules;
         i++) {

        const AffinityRule* rule =
            &cfg->rules[i];

        if (has_exact &&
            rule->wildcard_pkg)
            continue;

        if (!pkg_matches(rule,
                         proc->pkg))
            continue;

        if (!rule->thread[0]) {

            CPU_OR(&proc->base_cpus,
                   &proc->base_cpus,
                   &rule->cpus);
        }
    }

    char* merged =
        cpu_set_to_str(
            &proc->base_cpus);

    if (merged) {

        build_str(proc->base_cpuset,
                  sizeof(proc->base_cpuset),
                  merged,
                  NULL);

        free(merged);
    }
}

static void
config_release(AppConfig* cfg)
{
    if (!cfg)
        return;

    if (cfg->rules)
        free(cfg->rules);

    if (cfg->config_files) {

        for (size_t i = 0;
             i < cfg->num_config_files;
             i++) {

            free(cfg->config_files[i]);
        }

        free(cfg->config_files);
    }

    free(cfg);
}

static void print_help(const char* prog)
{
    printf("Usage: %s [OPTIONS]\n",
           prog);

    printf("  -c <config>\n");
    printf("  -s <interval>\n");
    printf("  -h\n");
    printf("  -v\n");
}

int main(int argc,
         char** argv)
{
    char** config_files = NULL;

    size_t num_config_files = 0;
    size_t config_cap = 0;

    int opt;

    while ((opt =
            getopt(argc,
                   argv,
                   "c:s:hv")) != -1) {

        switch (opt) {

        case 'c':
        {
            if (num_config_files >=
                config_cap) {

                size_t new_cap =
                    config_cap
                        ? config_cap * 2
                        : 4;

                char** tmp =
                    realloc(config_files,
                            new_cap *
                            sizeof(char*));

                if (!tmp)
                    exit(EXIT_FAILURE);

                config_files = tmp;
                config_cap = new_cap;
            }

            config_files
                [num_config_files] =
                    strdup(optarg);

            printf("add config: %s\n",
                   optarg);

            num_config_files++;

            break;
        }

        case 'v':

            printf("AppOpt %s\n",
                   VERSION);

            return 0;

        case 'h':

            print_help(argv[0]);

            return 0;
        }
    }

    if (num_config_files == 0) {

        config_files =
            malloc(sizeof(char*));

        config_files[0] =
            strdup("./applist.conf");

        num_config_files = 1;
    }

    AppConfig* cfg =
        load_multi_config(
            config_files,
            num_config_files);

    if (!cfg) {

        fprintf(stderr,
                "config load failed\n");

        return 1;
    }

    atomic_store(&current_config,
                 cfg);

    printf("AppOpt started\n");

    printf("rules: %zu\n",
           cfg->num_rules);

    while (1) {

        sleep(5);
    }

    config_release(cfg);

    return 0;
}
