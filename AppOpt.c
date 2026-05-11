#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>

#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

using namespace std;

// ===================== 数据结构 =====================
struct ConfigItem {
    string key;
    string value;
    string file;
    int line;
};

static map<string, ConfigItem> g_config;
static mutex g_mutex;
static atomic<bool> g_running(true);

static vector<string> g_files;

// ===================== 工具函数 =====================

// 去空格
static inline string trim(const string &s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// 通配符匹配
static bool wildcardMatch(const string &pattern, const string &str) {
    regex re;
    string tmp;
    for (char c : pattern) {
        if (c == '*') tmp += ".*";
        else if (c == '?') tmp += ".";
        else if (isalnum(c)) tmp += c;
        else {
            tmp += "\\";
            tmp += c;
        }
    }
    re = regex("^" + tmp + "$");
    return regex_match(str, re);
}

// ===================== 配置解析 =====================
static void loadFile(const string &file) {
    ifstream in(file);
    if (!in.is_open()) {
        cout << "[错误] 无法打开配置文件: " << file << endl;
        return;
    }

    string line;
    int lineno = 0;
    int loaded = 0;
    int dup = 0;
    int err = 0;

    while (getline(in, line)) {
        lineno++;
        line = trim(line);

        if (line.empty() || line[0] == '#')
            continue;

        size_t eq = line.find('=');
        if (eq == string::npos) {
            cout << "[配置错误] " << file << ":" << lineno
                 << " 缺少 '=' -> " << line << endl;
            err++;
            continue;
        }

        string key = trim(line.substr(0, eq));
        string value = trim(line.substr(eq + 1));

        if (key.empty() || value.empty()) {
            cout << "[配置错误] " << file << ":" << lineno
                 << " 空键或空值 -> " << line << endl;
            err++;
            continue;
        }

        lock_guard<mutex> lock(g_mutex);

        if (g_config.count(key)) {
            cout << "[去重] key=" << key
                 << " 原文件=" << g_config[key].file
                 << " -> 新文件=" << file << endl;
            dup++;
        }

        g_config[key] = {key, value, file, lineno};
        loaded++;
    }

    cout << "[加载完成] 文件=" << file
         << " 新增=" << loaded
         << " 去重=" << dup
         << " 错误=" << err << endl;
}

// ===================== 全量加载 =====================
static void reloadAll() {
    lock_guard<mutex> lock(g_mutex);

    g_config.clear();

    cout << "===============================" << endl;
    cout << "[AppOpt] 开始重新加载配置..." << endl;

    for (auto &f : g_files) {
        loadFile(f);
    }

    cout << "[AppOpt] 当前配置总数: " << g_config.size() << endl;
    cout << "===============================" << endl;
}

// ===================== inotify 监听 =====================
static void watchFiles() {
    int fd = inotify_init();
    if (fd < 0) {
        cout << "[警告] inotify不可用，切换轮询模式" << endl;
        return;
    }

    map<int, string> wdMap;

    for (auto &f : g_files) {
        int wd = inotify_add_watch(fd, f.c_str(),
                                   IN_MODIFY | IN_DELETE_SELF | IN_CREATE);
        if (wd < 0) {
            cout << "[警告] 无法监听: " << f << endl;
            continue;
        }
        wdMap[wd] = f;
    }

    char buf[1024];

    while (g_running) {
        int len = read(fd, buf, sizeof(buf));
        if (len <= 0) continue;

        int i = 0;
        while (i < len) {
            struct inotify_event *event = (struct inotify_event *)&buf[i];

            if (event->len == 0 && wdMap.count(event->wd)) {
                cout << "[文件变化] " << wdMap[event->wd]
                     << " 触发重新加载" << endl;
                reloadAll();
            }

            i += sizeof(struct inotify_event) + event->len;
        }
    }

    close(fd);
}

// ===================== 轮询 =====================
static void pollWatch() {
    map<string, time_t> last;

    for (auto &f : g_files) {
        struct stat st;
        if (stat(f.c_str(), &st) == 0)
            last[f] = st.st_mtime;
    }

    while (g_running) {
        this_thread::sleep_for(chrono::seconds(2));

        bool changed = false;

        for (auto &f : g_files) {
            struct stat st;
            if (stat(f.c_str(), &st) != 0) continue;

            if (st.st_mtime != last[f]) {
                last[f] = st.st_mtime;
                cout << "[文件变化] " << f << " 触发重新加载" << endl;
                changed = true;
            }
        }

        if (changed) reloadAll();
    }
}

// ===================== 初始化 =====================
static void printConfig() {
    cout << "\n========== 当前配置 ==========\n";

    for (auto &p : g_config) {
        cout << p.first << " = " << p.second.value
             << "    (来源: " << p.second.file
             << ":" << p.second.line << ")\n";
    }

    cout << "==============================\n";
}

// ===================== main =====================
int main(int argc, char *argv[]) {
    cout << "[AppOpt] 启动中..." << endl;

    if (argc < 3) {
        cout << "用法: AppOpt -c file1 -c file2 ..." << endl;
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "-c" && i + 1 < argc) {
            g_files.push_back(argv[++i]);
        }
    }

    if (g_files.empty()) {
        cout << "[错误] 未指定配置文件" << endl;
        return 0;
    }

    reloadAll();

    thread watcher;

    // 优先 inotify
    int fd = inotify_init();
    if (fd >= 0) {
        close(fd);
        watcher = thread(watchFiles);
        cout << "[AppOpt] 使用 inotify 文件监听" << endl;
    } else {
        watcher = thread(pollWatch);
        cout << "[AppOpt] 使用轮询监听模式" << endl;
    }

    cout << "[AppOpt] 启动成功，配置数量: " << g_config.size() << endl;

    printConfig();

    watcher.join();
    return 0;
}