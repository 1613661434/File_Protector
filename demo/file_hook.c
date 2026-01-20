#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>

// -------------------------- 全局配置：拦截规则（可自定义）--------------------------
// 拦截规则结构体：操作类型 + 目标文件路径 + 是否拦截
typedef struct {
    const char* op_type;    // 操作类型："open" "read" "write" "unlink"
    const char* file_path;  // 目标文件路径（支持绝对路径，如 "/tmp/protected.txt"）
    int block;              // 1=拦截，0=放行
} BlockRule;

// 自定义拦截规则（可根据需求修改/添加）
BlockRule g_block_rules[] = {
    // 禁止删除 /tmp/protected.txt
    {"unlink", "/tmp/protected.txt", 1},
    // 禁止向 /etc/hosts 写入（系统文件保护）
    {"write", "/etc/hosts", 1},
    // 记录所有对 /tmp/log.txt 的读取操作（不拦截，仅日志）
    {"read", "/tmp/log.txt", 0},
    // 禁止打开 /tmp/forbidden.txt（只读/只写/读写都拦截）
    {"open", "/tmp/forbidden.txt", 1},
};

#define RULE_COUNT (sizeof(g_block_rules) / sizeof(g_block_rules[0]))

// -------------------------- 原函数指针（保存系统原生函数）--------------------------
// open 函数原型：int open(const char *pathname, int flags, mode_t mode)
static int (*original_open)(const char*, int, mode_t) = NULL;
// read 函数原型：ssize_t read(int fd, void *buf, size_t count)
static ssize_t (*original_read)(int, void*, size_t) = NULL;
// write 函数原型：ssize_t write(int fd, const void *buf, size_t count)
static ssize_t (*original_write)(int, const void*, size_t) = NULL;
// unlink 函数原型：int unlink(const char *pathname)
static int (*original_unlink)(const char*) = NULL;

// -------------------------- 辅助函数：获取程序路径/文件路径 --------------------------
/**
 * 获取当前调用程序的绝对路径
 * @param buf：存储路径的缓冲区
 * @param buf_len：缓冲区长度
 * @return：成功返回路径，失败返回 NULL
 */
static char* get_program_path(char* buf, size_t buf_len) {
    if (buf == NULL || buf_len == 0) return NULL;
    // /proc/self/exe 是当前进程的符号链接，指向程序绝对路径
    ssize_t len = readlink("/proc/self/exe", buf, buf_len - 1);
    if (len < 0) {
        fprintf(stderr, "[HOOK] 读取程序路径失败：%s\n", strerror(errno));
        return NULL;
    }
    buf[len] = '\0';  // 手动添加字符串结束符
    return buf;
}

/**
 * 通过文件描述符（fd）获取文件绝对路径
 * @param fd：文件描述符
 * @param buf：存储路径的缓冲区
 * @param buf_len：缓冲区长度
 * @return：成功返回路径，失败返回 NULL
 */
static char* get_file_path_by_fd(int fd, char* buf, size_t buf_len) {
    if (fd < 0 || buf == NULL || buf_len == 0) return NULL;
    char fd_path[PATH_MAX];
    // 拼接 /proc/self/fd/{fd} 路径（进程当前打开的文件描述符列表）
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    // 读取符号链接，获取真实文件路径
    ssize_t len = readlink(fd_path, buf, buf_len - 1);
    if (len < 0) {
        // 部分 fd 可能不是文件（如管道、socket），返回 NULL 不处理
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

/**
 * 判断当前操作是否需要拦截
 * @param op_type：操作类型（"open" "read" "write" "unlink"）
 * @param file_path：文件绝对路径
 * @return：1=拦截，0=放行
 */
static int should_block(const char* op_type, const char* file_path) {
    if (op_type == NULL || file_path == NULL) return 0;

    // 遍历所有规则，匹配操作类型和文件路径
    for (int i = 0; i < RULE_COUNT; i++) {
        BlockRule* rule = &g_block_rules[i];
        if (strcmp(rule->op_type, op_type) == 0 && strstr(file_path, rule->file_path) != NULL) {
            // 打印拦截日志（红色字体，便于区分）
            char prog_path[PATH_MAX];
            get_program_path(prog_path, sizeof(prog_path));
            if (rule->block) {
                fprintf(stderr, "\033[31m[HOOK] 拦截操作：op=%s, prog=%s, file=%s\033[0m\n",
                        op_type, prog_path, file_path);
            } else {
                fprintf(stderr, "\033[33m[HOOK] 记录操作：op=%s, prog=%s, file=%s\033[0m\n",
                        op_type, prog_path, file_path);
            }
            return rule->block;
        }
    }
    return 0;  // 无匹配规则，放行
}

// -------------------------- 自定义拦截函数（覆盖系统原生函数）--------------------------
/**
 * 拦截 open 函数（打开文件）
 * 注意：open 有两个重载，这里用可变参数适配（flags 后可能有 mode 参数）
 */
int open(const char* pathname, int flags, ...) {
    // 第一次调用时，获取系统原生 open 函数地址（只初始化一次）
    if (original_open == NULL) {
        // RTLD_NEXT：跳过当前库，查找下一个同名函数（即系统库的 open）
        original_open = dlsym(RTLD_NEXT, "open");
        if (original_open == NULL) {
            fprintf(stderr, "[HOOK] 找不到系统 open 函数：%s\n", dlerror());
            errno = ENOENT;
            return -1;
        }
    }

    // 检查是否需要拦截（open 操作直接用传入的 pathname 判断）
    if (should_block("open", pathname)) {
        errno = EACCES;  // 返回"权限拒绝"错误，符合系统行为
        return -1;
    }

    // 调用系统原生 open 函数（处理可变参数：mode 是可选参数，仅 O_CREAT 时需要）
    va_list args;
    va_start(args, flags);
    mode_t mode = (flags & O_CREAT) ? va_arg(args, mode_t) : 0;
    va_end(args);
    return original_open(pathname, flags, mode);
}

/**
 * 拦截 read 函数（读取文件）
 */
ssize_t read(int fd, void* buf, size_t count) {
    if (original_read == NULL) {
        original_read = dlsym(RTLD_NEXT, "read");
        if (original_read == NULL) {
            fprintf(stderr, "[HOOK] 找不到系统 read 函数：%s\n", dlerror());
            errno = ENOENT;
            return -1;
        }
    }

    // 通过 fd 获取文件路径，判断是否需要拦截
    char file_path[PATH_MAX];
    if (get_file_path_by_fd(fd, file_path, sizeof(file_path)) != NULL) {
        if (should_block("read", file_path)) {
            errno = EACCES;
            return -1;
        }
    }

    // 放行：调用系统原生 read 函数
    return original_read(fd, buf, count);
}

/**
 * 拦截 write 函数（写入文件）
 */
ssize_t write(int fd, const void* buf, size_t count) {
    if (original_write == NULL) {
        original_write = dlsym(RTLD_NEXT, "write");
        if (original_write == NULL) {
            fprintf(stderr, "[HOOK] 找不到系统 write 函数：%s\n", dlerror());
            errno = ENOENT;
            return -1;
        }
    }

    // 通过 fd 获取文件路径，判断是否需要拦截
    char file_path[PATH_MAX];
    if (get_file_path_by_fd(fd, file_path, sizeof(file_path)) != NULL) {
        if (should_block("write", file_path)) {
            errno = EACCES;
            return -1;
        }
    }

    // 放行：调用系统原生 write 函数
    return original_write(fd, buf, count);
}

/**
 * 拦截 unlink 函数（删除文件）
 */
int unlink(const char* pathname) {
    if (original_unlink == NULL) {
        original_unlink = dlsym(RTLD_NEXT, "unlink");
        if (original_unlink == NULL) {
            fprintf(stderr, "[HOOK] 找不到系统 unlink 函数：%s\n", dlerror());
            errno = ENOENT;
            return -1;
        }
    }

    // 检查是否需要拦截（unlink 直接用 pathname 判断）
    if (should_block("unlink", pathname)) {
        errno = EACCES;
        return -1;
    }

    // 放行：调用系统原生 unlink 函数
    return original_unlink(pathname);
}