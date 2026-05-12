/*

AppOpt modified version

features:

multi -c

wildcard package

wildcard thread

exact priority */

#define _GNU_SOURCE #include <ctype.h> #include <dirent.h> #include <errno.h> #include <fcntl.h> #include <fnmatch.h> #include <pthread.h> #include <sched.h> #include <stdatomic.h> #include <stdbool.h> #include <stdio.h> #include <stdlib.h> #include <string.h> #include <stdarg.h> #include <limits.h> #include <sys/inotify.h> #include <sys/stat.h> #include <sys/sysinfo.h> #include <unistd.h>

#define VERSION "1.6.3" #define BASE_CPUSET "/dev/cpuset/AppOpt" #define MAX_PKG_LEN 128 #define MAX_THREAD_LEN 32 #define MAX_CONFIG_FILES 32

typedef struct { char pkg[MAX_PKG_LEN]; char thread[MAX_THREAD_LEN]; char cpuset_dir[256]; cpu_set_t cpus; bool wildcard_pkg; } AffinityRule;

typedef struct { pid_t tid; char name[MAX_THREAD_LEN]; char cpuset_dir[256]; cpu_set_t cpus; } ThreadInfo;

typedef struct { pid_t pid; char pkg[MAX_PKG_LEN]; char base_cpuset[128]; cpu_set_t base_cpus; ThreadInfo* threads; size_t num_threads; size_t threads_cap; AffinityRule** thread_rules; size_t num_thread_rules; size_t thread_rules_cap; } ProcessInfo;

typedef struct { cpu_set_t present_cpus; char present_str[128]; char mems_str[32]; bool cpuset_enabled; int base_cpuset_fd; } CpuTopology;

typedef struct { atomic_int ref_count; AffinityRule* rules; size_t num_rules; time_t mtime; CpuTopology topo; char** pkgs; size_t num_pkgs; char** config_files; size_t num_config_files; } AppConfig;

typedef struct { ProcessInfo* procs; size_t num_procs; size_t procs_cap; int last_proc_count; bool scan_all_proc; } ProcCache;

static atomic_int config_updated = ATOMIC_VAR_INIT(0); static _Atomic(AppConfig*) current_config = NULL; static int inotify_fd = -1;

static char* strtrim(char* s) { char* end; while (isspace(*s)) s++; if (*s == 0) return s; end = s + strlen(s) - 1; while (end > s && isspace(*end)) end--; *(end + 1) = 0; return s; }

static inline bool has_wildcard(const char* s) { return strpbrk(s, "*?[") != NULL; }

static int build_str(char *dest, size_t dest_size, ...) { va_list args; const char *segment; char *p = dest; size_t remaining = dest_size - 1; va_start(args, dest_size); while ((segment = va_arg(args, const char *)) != NULL) { size_t len = strlen(segment); if (len > remaining) { va_end(args); return 0; } memcpy(p, segment, len); p += len; remaining -= len; } *p = '\0'; va_end(args); return 1; }

static bool read_file(int dir_fd, const char* filename, char* buf, size_t buf_size) { int fd = openat(dir_fd, filename, O_RDONLY | O_CLOEXEC); if (fd == -1) return false; ssize_t n = read(fd, buf, buf_size - 1); close(fd); if (n <= 0) return false; buf[n] = '\0'; return true; }

static bool write_file(int dir_fd, const char* filename, const char* content, int flags) { int fd = openat(dir_fd, filename, flags | O_CLOEXEC, 0644); if (fd == -1) return false; ssize_t n = write(fd, content, strlen(content)); close(fd); return n == (ssize_t)strlen(content); }

static void parse_cpu_ranges(const char* spec, cpu_set_t* set, const cpu_set_t* present) { if (!spec) return; char* copy = strdup(spec); if (!copy) return;

char* s = copy; while (*s) { char* end; unsigned long a = strtoul(s, &end, 10); if (end == s) { s++; continue; } unsigned long b = a; if (*end == '-') { s = end + 1; b = strtoul(s, &end, 10); if (end == s) b = a; } if (a > b) { unsigned long t = a; a = b; b = t; } for (unsigned long i = a; i <= b && i < CPU_SETSIZE; i++) { if (present && !CPU_ISSET(i, present)) continue; CPU_SET(i, set); } s = (*end == ',') ? end + 1 : end; } free(copy); 

}

static char* cpu_set_to_str(const cpu_set_t *set) { size_t buf_size = 8 * CPU_SETSIZE; char *buf = malloc(buf_size); if (!buf) return NULL;

int start = -1, end = -1; char *p = buf; size_t remain = buf_size - 1; bool first = true; for (int i = 0; i < CPU_SETSIZE; i++) { if (CPU_ISSET(i, set)) { if (start == -1) { start = end = i; } else if (i == end + 1) { end = i; } else { int needed; if (start == end) needed = snprintf(p, remain + 1, "%s%d", first ? "" : ",", start); else needed = snprintf(p, remain + 1, "%s%d-%d", first ? "" : ",", start, end); if (needed < 0 || (size_t)needed > remain) { free(buf); return NULL; } p += needed; remain -= needed; start = end = i; first = false; } } } if (start != -1) { int needed; if (start == end) needed = snprintf(p, remain + 1, "%s%d", first ? "" : ",", start); else needed = snprintf(p, remain + 1, "%s%d-%d", first ? "" : ",", start, end); if (needed < 0 || (size_t)needed > remain) { free(buf); return NULL; } } return buf; 

}

static bool create_cpuset_dir(const char *path, const char *cpus, const char *mems) { if (mkdir(path, 0755) != 0 && errno != EEXIST) return false;

char cpus_path[256]; char mems_path[256]; build_str(cpus_path, sizeof(cpus_path), path, "/cpus", NULL); build_str(mems_path, sizeof(mems_path), path, "/mems", NULL); write_file(AT_FDCWD, cpus_path, cpus, O_WRONLY | O_CREAT | O_TRUNC); write_file(AT_FDCWD, mems_path, mems, O_WRONLY | O_CREAT | O_TRUNC); return true; 

}

static CpuTopology init_cpu_topo(void) { CpuTopology topo = {0}; topo.base_cpuset_fd = -1;

CPU_ZERO(&topo.present_cpus); if (read_file(AT_FDCWD, "/sys/devices/system/cpu/present", topo.present_str, sizeof(topo.present_str))) { strtrim(topo.present_str); } parse_cpu_ranges(topo.present_str, &topo.present_cpus, NULL); strcpy(topo.mems_str, "0"); if (access("/dev/cpuset", F_OK) == 0) { create_cpuset_dir(BASE_CPUSET, topo.present_str, topo.mems_str); topo.base_cpuset_fd = open(BASE_CPUSET, O_RDONLY | O_DIRECTORY); if (topo.base_cpuset_fd != -1) topo.cpuset_enabled = true; } return topo; 

}

static AppConfig* load_configs(char** files, size_t num_files, const CpuTopology* topo) {

AppConfig* cfg = calloc(1, sizeof(AppConfig)); if (!cfg) return NULL; cfg->ref_count = 1; cfg->topo = *topo; cfg->config_files = calloc(num_files, sizeof(char*)); cfg->num_config_files = num_files; for (size_t i = 0; i < num_files; i++) cfg->config_files[i] = strdup(files[i]); for (size_t file_idx = 0; file_idx < num_files; file_idx++) { FILE* fp = fopen(files[file_idx], "r"); if (!fp) continue; char line[256]; while (fgets(line, sizeof(line), fp)) { char* p = strtrim(line); if (*p == '#' || !*p) continue; char* eq = strchr(p, '='); if (!eq) continue; *eq++ = 0; char* br = strchr(p, '{'); char* thread = ""; if (br) { *br++ = 0; char* eb = strchr(br, '}'); if (!eb) continue; *eb = 0; thread = strtrim(br); } char* pkg = strtrim(p); char* cpus = strtrim(eq); cpu_set_t set; CPU_ZERO(&set); parse_cpu_ranges(cpus, &set, &cfg->topo.present_cpus); if (CPU_COUNT(&set) == 0) continue; char* dir_name = cpu_set_to_str(&set); if (!dir_name) continue; char path[256]; build_str(path, sizeof(path), BASE_CPUSET, "/", dir_name, NULL); create_cpuset_dir(path, dir_name, cfg->topo.mems_str); cfg->rules = realloc(cfg->rules, (cfg->num_rules + 1) * sizeof(AffinityRule)); AffinityRule* rule = &cfg->rules[cfg->num_rules]; memset(rule, 0, sizeof(*rule)); build_str(rule->pkg, sizeof(rule->pkg), pkg, NULL); build_str(rule->thread, sizeof(rule->thread), thread, NULL); build_str(rule->cpuset_dir, sizeof(rule->cpuset_dir), dir_name, NULL); rule->cpus = set; rule->wildcard_pkg = has_wildcard(pkg); cfg->num_rules++; free(dir_name); } fclose(fp); } printf("loaded %zu rules\n", cfg->num_rules); return cfg; 

}

static void apply_affinity(ProcCache* cache, const CpuTopology* topo, const AppConfig* cfg) {

for (size_t i = 0; i < cache->num_procs; i++) { ProcessInfo* proc = &cache->procs[i]; bool has_exact = false; for (size_t r = 0; r < cfg->num_rules; r++) { AffinityRule* rule = &cfg->rules[r]; if (rule->wildcard_pkg) continue; if (strcmp(rule->pkg, proc->pkg) == 0) { has_exact = true; break; } } CPU_ZERO(&proc->base_cpus); for (size_t r = 0; r < cfg->num_rules; r++) { AffinityRule* rule = &cfg->rules[r]; if (has_exact && rule->wildcard_pkg) continue; bool matched; if (rule->wildcard_pkg) matched = fnmatch(rule->pkg, proc->pkg, FNM_NOESCAPE) == 0; else matched = strcmp(rule->pkg, proc->pkg) == 0; if (!matched) continue; CPU_OR(&proc->base_cpus, &proc->base_cpus, &rule->cpus); } for (size_t t = 0; t < proc->num_threads; t++) { ThreadInfo* ti = &proc->threads[t]; ti->cpus = proc->base_cpus; sched_setaffinity(ti->tid, sizeof(cpu_set_t), &ti->cpus); if (topo->cpuset_enabled) { char tid_str[32]; snprintf(tid_str, sizeof(tid_str), "%d\n", ti->tid); char* cpustr = cpu_set_to_str(&ti->cpus); if (cpustr) { int fd = openat(topo->base_cpuset_fd, cpustr, O_RDONLY | O_DIRECTORY); if (fd != -1) { write_file(fd, "tasks", tid_str, O_WRONLY | O_APPEND); close(fd); } free(cpustr); } } } } 

}

static void proc_collect(const AppConfig* cfg, ProcCache* cache) {

DIR* proc_dir = opendir("/proc"); if (!proc_dir) return; if (!cache->procs) { cache->procs_cap = 128; cache->procs = calloc(cache->procs_cap, sizeof(ProcessInfo)); } cache->num_procs = 0; struct dirent* ent; while ((ent = readdir(proc_dir))) { char* end; long pid = strtol(ent->d_name, &end, 10); if (*end != '\0') continue; int pid_fd = openat(dirfd(proc_dir), ent->d_name, O_RDONLY | O_DIRECTORY); if (pid_fd == -1) continue; char cmd[MAX_PKG_LEN] = {0}; if (!read_file(pid_fd, "cmdline", cmd, sizeof(cmd))) { close(pid_fd); continue; } char* name = strrchr(cmd, '/'); name = name ? name + 1 : cmd; bool found = false; for (size_t r = 0; r < cfg->num_rules; r++) { AffinityRule* rule = &cfg->rules[r]; if (rule->wildcard_pkg) { if (fnmatch(rule->pkg, name, FNM_NOESCAPE) == 0) { found = true; break; } } else { if (strcmp(rule->pkg, name) == 0) { found = true; break; } } } if (!found) { close(pid_fd); continue; } if (cache->num_procs >= cache->procs_cap) { cache->procs_cap *= 2; cache->procs = realloc(cache->procs, cache->procs_cap * sizeof(ProcessInfo)); } ProcessInfo* proc = &cache->procs[cache->num_procs++]; memset(proc, 0, sizeof(*proc)); proc->pid = pid; build_str(proc->pkg, sizeof(proc->pkg), name, NULL); int task_fd = openat(pid_fd, "task", O_RDONLY | O_DIRECTORY); close(pid_fd); if (task_fd == -1) continue; DIR* task_dir = fdopendir(task_fd); if (!task_dir) { close(task_fd); continue; } proc->threads_cap = 64; proc->threads = calloc(proc->threads_cap, sizeof(ThreadInfo)); struct dirent* tent; while ((tent = readdir(task_dir))) { char* e2; long tid = strtol(tent->d_name, &e2, 10); if (*e2 != '\0') continue; if (proc->num_threads >= proc->threads_cap) { proc->threads_cap *= 2; proc->threads = realloc(proc->threads, proc->threads_cap * sizeof(ThreadInfo)); } ThreadInfo* ti = &proc->threads[proc->num_threads++]; memset(ti, 0, sizeof(*ti)); ti->tid = tid; } closedir(task_dir); } closedir(proc_dir); 

}

static void config_release(AppConfig* cfg) { if (!cfg) return;

if (atomic_fetch_sub(&cfg->ref_count, 1) != 1) return; free(cfg->rules); if (cfg->config_files) { for (size_t i = 0; i < cfg->num_config_files; i++) free(cfg->config_files[i]); free(cfg->config_files); } free(cfg); 

}

static void print_help(const char* prog_name) { printf("Usage: %s [OPTIONS]\n", prog_name); printf(" -c <config_file>\n"); printf(" -s \n"); printf(" -v\n"); printf(" -h\n"); }

int main(int argc, char **argv) {

CpuTopology topo = init_cpu_topo(); char** config_files = calloc(MAX_CONFIG_FILES, sizeof(char*)); size_t num_config_files = 0; int sleep_interval = 2; int opt; while ((opt = getopt(argc, argv, "c:s:hv")) != -1) { switch (opt) { case 'c': if (num_config_files >= MAX_CONFIG_FILES) break; config_files[num_config_files++] = strdup(optarg); printf("config: %s\n", optarg); break; case 's': sleep_interval = atoi(optarg); if (sleep_interval < 1) sleep_interval = 1; break; case 'v': printf("AppOpt %s\n", VERSION); return 0; case 'h': print_help(argv[0]); return 0; } } if (num_config_files == 0) { config_files[num_config_files++] = strdup("./applist.conf"); } AppConfig* cfg = load_configs(config_files, num_config_files, &topo); if (!cfg) { fprintf(stderr, "config load failed\n"); return 1; } atomic_store(&current_config, cfg); ProcCache cache = {0}; printf("AppOpt started\n"); while (1) { proc_collect(cfg, &cache); apply_affinity(&cache, &topo, cfg); sleep(sleep_interval); } return 0; 

}

