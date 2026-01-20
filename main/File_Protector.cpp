#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ol_public.h"
#include <atomic>
#include <cstdarg>
#include <dlfcn.h>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

// 兼容老系统宏定义
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif

using namespace ol;
using namespace std;

// 全局配置
vector<string> g_ProtectedFiles;
vector<string> g_WhitelistProcs;
atomic_bool g_bConfigLoaded(false);
clogfile g_log;
const string g_configPath = "/home/mysql/Projects/File_Protector/main/config.xml";
const string g_logPath = "/home/mysql/Projects/File_Protector/main/file_protector.log";

// ================================== <工具函数> ==================================
// 获取当前进程绝对路径
string get_current_proc_path()
{
    char buf[PATH_MAX] = {0};
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len <= 0) return "";
    return string(buf, len);
}

// 转换为绝对路径
string get_absolute_path(const string& path)
{
    char abs_path[PATH_MAX] = {0};
    if (realpath(path.c_str(), abs_path) == nullptr) return path;
    return string(abs_path);
}

// 判断路径是否受保护
bool is_path_protected(const string& path)
{
    string abs_path = get_absolute_path(path);
    for (const auto& protected_item : g_ProtectedFiles)
    {
        string abs_protected = get_absolute_path(protected_item);
        if (abs_path == abs_protected) return true;
        // 目录递归匹配
        struct stat st;
        if (stat(abs_protected.c_str(), &st) == 0 && S_ISDIR(st.st_mode))
        {
            if (abs_path.find(abs_protected) == 0) return true;
        }
    }
    return false;
}

// 判断进程是否在白名单
bool is_proc_whitelisted()
{
    string proc_path = get_current_proc_path().c_str();
    if (proc_path.empty()) return false;

    // 兼容路径简化（/usr/bin → /bin）
    string simplified_proc = proc_path;
    if (simplified_proc.find("/usr/bin/") == 0)
    {
        simplified_proc = simplified_proc.replace(0, 4, "/bin");
    }

    for (const auto& whitelist_proc : g_WhitelistProcs)
    {
        string simplified_white = whitelist_proc;
        if (simplified_white.find("/usr/bin/") == 0)
        {
            simplified_white = simplified_white.replace(0, 4, "/bin");
        }
        if (proc_path == whitelist_proc || simplified_proc == simplified_white)
        {
            return true;
        }
    }
    return false;
}
// ================================== </工具函数> ==================================

// ================================== <配置加载> ==================================
void load_config()
{
    // 原子判断：已加载则直接返回
    bool expected = false;

    if (!g_bConfigLoaded.compare_exchange_strong(expected, true)) return;

    // 初始化日志
    g_log.open(g_logPath, ios::app, false, true);
    g_log.write("========== 开始加载配置 ==========\n");
    g_log.write("配置文件路径：%s\n", g_configPath);

    // 读取XML配置
    cifile ifile;
    if (!ifile.open(g_configPath))
    {
        g_log.write("❌ 配置文件不存在\n");
        g_bConfigLoaded.store(true, memory_order_release);
        return;
    }

    // 逐行解析XML
    string buf;
    size_t prot_count = 0, white_count = 0;
    while (ifile.readline(buf))
    {
        string load;
        // 解析保护文件/目录
        if (getByXml(buf, "ProtectedFile", load))
        {
            string abs_path = get_absolute_path(load);
            g_ProtectedFiles.push_back(abs_path);
            g_log.write("✅ 加载保护文件：%s\n", abs_path);
            ++prot_count;
        }
        // 解析白名单进程
        else if (getByXml(buf, "WhitelistProc", load))
        {
            string abs_path = get_absolute_path(load);
            g_WhitelistProcs.push_back(abs_path);
            g_log.write("✅ 加载白名单进程：%s\n", abs_path);
            ++white_count;
        }
    }

    // 配置加载完成日志
    g_log.write("========== 配置加载完成 ==========\n");
    g_log.write("保护文件总数：%zu\n", prot_count);
    g_log.write("白名单进程总数：%zu\n", white_count);
    g_log.write("==================================\n");
    g_bConfigLoaded.store(true, memory_order_release);
}
// ================================== </配置加载> ==================================

// ================================== <系统调用劫持> ==================================
// 系统调用劫持（open/openat/unlink/write）
// 劫持open函数
typedef int (*orig_open_t)(const char* pathname, int flags, ...);
orig_open_t orig_open = nullptr;

extern "C" int open(const char* pathname, int flags, ...)
{
    // 懒加载配置
    if (!g_bConfigLoaded.load(memory_order_acquire)) load_config();

    // 初始化原函数指针
    if (!orig_open)
    {
        orig_open = (orig_open_t)dlsym(RTLD_NEXT, "open");
        if (!orig_open)
        {
            g_log.write("❌ 获取原open函数失败：%s\n", dlerror());
            errno = EINVAL;
            return -1;
        }
    }

    // 调试日志
    g_log.write("进入open劫持：路径[%s]，进程[%s]\n",
                pathname, get_current_proc_path());

    // 拦截逻辑
    bool protected_flag = is_path_protected(pathname);
    bool whitelist_flag = is_proc_whitelisted();
    g_log.write("路径[%s]受保护：%d，进程[%s]在白名单：%d\n",
                pathname, protected_flag, get_current_proc_path(), whitelist_flag);

    if (protected_flag)
    {
        // 是否是白名单进程
        if (whitelist_flag)
        {
            g_log.write("ℹ️ 放行白名单进程[%s]open访问保护文件[%s]\n",
                        get_current_proc_path(), pathname);
        }
        else
        {
            g_log.write("✅ 拦截非白名单进程[%s]open访问保护文件[%s]\n",
                        get_current_proc_path(), pathname);
            errno = EACCES; // 权限拒绝
            return -1;
        }
    }

    // 调用原open函数
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    va_end(args);
    return orig_open(pathname, flags, mode);
}

// 劫持openat函数
typedef int (*orig_openat_t)(int dirfd, const char* pathname, int flags, ...);
orig_openat_t orig_openat = nullptr;

extern "C" int openat(int dirfd, const char* pathname, int flags, ...)
{
    // 懒加载配置
    if (!g_bConfigLoaded.load(memory_order_acquire)) load_config();

    // 初始化原函数指针
    if (!orig_openat)
    {
        orig_openat = (orig_openat_t)dlsym(RTLD_NEXT, "openat");
        if (!orig_openat)
        {
            g_log.write("❌ 获取原openat函数失败：%s\n", dlerror());
            errno = EINVAL;
            return -1;
        }
    }

    g_log.write("进入openat劫持：dirfd[%d]，路径[%s]，进程[%s]\n",
                dirfd, pathname, get_current_proc_path());

    // 处理绝对路径
    string abs_path = pathname;
    if (dirfd != AT_FDCWD)
    {
        char fd_path[PATH_MAX] = {0};
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", dirfd);
        string dir_abs = get_absolute_path(fd_path);
        abs_path = dir_abs + "/" + pathname;
    }
    else
    {
        abs_path = get_absolute_path(pathname);
    }

    // 拦截逻辑
    bool protected_flag = is_path_protected(abs_path);
    bool whitelist_flag = is_proc_whitelisted();
    if (protected_flag)
    {
        // 是否是白名单进程
        if (whitelist_flag)
        {
            g_log.write("ℹ️ 放行白名单进程[%s]openat访问保护文件[%s]\n",
                        get_current_proc_path(), abs_path);
        }
        else
        {
            g_log.write("✅ 拦截非白名单进程[%s]openat访问保护文件[%s]\n",
                        get_current_proc_path(), abs_path);
            errno = EACCES;
            return -1;
        }
    }

    // 调用原openat函数
    va_list args;
    va_start(args, flags);
    mode_t mode = (flags & O_CREAT) ? va_arg(args, mode_t) : 0;
    va_end(args);
    return orig_openat(dirfd, pathname, flags, mode);
}

// 劫持unlink函数
typedef int (*orig_unlink_t)(const char* pathname);
orig_unlink_t orig_unlink = nullptr;

extern "C" int unlink(const char* pathname)
{
    // 懒加载配置
    if (!g_bConfigLoaded.load(memory_order_acquire)) load_config();

    // 初始化原函数指针
    if (!orig_unlink)
    {
        orig_unlink = (orig_unlink_t)dlsym(RTLD_NEXT, "unlink");
        if (!orig_unlink)
        {
            g_log.write("❌ 获取原unlink函数失败：%s\n", dlerror());
            errno = EINVAL;
            return -1;
        }
    }

    g_log.write("进入unlink劫持：路径[%s]，进程[%s]\n",
                pathname, get_current_proc_path());

    // 拦截逻辑
    bool protected_flag = is_path_protected(pathname);
    bool whitelist_flag = is_proc_whitelisted();
    if (protected_flag)
    {
        // 是否是白名单进程
        if (whitelist_flag)
        {
            g_log.write("ℹ️ 放行白名单进程[%s]unlink访问保护文件[%s]\n",
                        get_current_proc_path(), pathname);
        }
        else
        {
            g_log.write("✅ 拦截非白名单进程[%s]unlink删除保护文件[%s]\n",
                        get_current_proc_path(), pathname);
            errno = EACCES;
            return -1;
        }
    }

    return orig_unlink(pathname);
}

// 劫持write函数
typedef ssize_t (*orig_write_t)(int fd, const void* buf, size_t count);
orig_write_t orig_write = nullptr;

extern "C" ssize_t write(int fd, const void* buf, size_t count)
{
    // 懒加载配置
    if (!g_bConfigLoaded.load(memory_order_acquire)) load_config();

    // 初始化原函数指针
    if (!orig_write)
    {
        orig_write = (orig_write_t)dlsym(RTLD_NEXT, "write");
        if (!orig_write)
        {
            g_log.write("❌ 获取原write函数失败：%s\n", dlerror());
            errno = EINVAL;
            return -1;
        }
    }

    // 通过fd获取文件路径
    char path[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    string file_path = get_absolute_path(path);

    g_log.write("进入write劫持：FD[%d] → 文件[%s]，进程[%s]\n",
                fd, file_path, get_current_proc_path());

    // 拦截逻辑
    bool protected_flag = is_path_protected(file_path);
    bool whitelist_flag = is_proc_whitelisted();
    if (protected_flag)
    {
        // 是否是白名单进程
        if (whitelist_flag)
        {
            g_log.write("ℹ️ 放行白名单进程[%s]write访问保护文件[%s]\n",
                        get_current_proc_path(), file_path);
        }
        else
        {
            g_log.write("✅ 拦截非白名单进程[%s]write写入保护文件[%s]\n",
                        get_current_proc_path(), file_path);
            errno = EACCES;
            return -1;
        }
    }

    return orig_write(fd, buf, count);
}

// 劫持read函数
typedef ssize_t (*orig_read_t)(int fd, void* buf, size_t count);
orig_read_t orig_read = nullptr;

extern "C" ssize_t read(int fd, void* buf, size_t count)
{
    // 懒加载配置
    if (!g_bConfigLoaded.load(memory_order_acquire)) load_config();

    // 初始化原函数指针
    if (!orig_read)
    {
        orig_read = (orig_read_t)dlsym(RTLD_NEXT, "read");
        if (!orig_read)
        {
            g_log.write("❌ 获取原read函数失败：%s\n", dlerror());
            errno = EINVAL;
            return -1;
        }
    }

    // 通过fd获取文件路径
    char path[PATH_MAX] = {0};
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    string file_path = get_absolute_path(path);

    g_log.write("进入read劫持：FD[%d] → 文件[%s]，进程[%s]\n",
                fd, file_path, get_current_proc_path());

    // 拦截逻辑
    bool protected_flag = is_path_protected(file_path);
    bool whitelist_flag = is_proc_whitelisted();
    if (protected_flag)
    {
        // 是否是白名单进程
        if (whitelist_flag)
        {
            g_log.write("ℹ️ 放行白名单进程[%s]read访问保护文件[%s]\n",
                        get_current_proc_path(), file_path);
        }
        else
        {
            g_log.write("✅ 拦截非白名单进程[%s]read写入保护文件[%s]\n",
                        get_current_proc_path(), file_path);
            errno = EACCES;
            return -1;
        }
    }

    return orig_read(fd, buf, count);
}
// ================================== </系统调用劫持> ==================================