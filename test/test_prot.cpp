#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

// 测试文件路径
#define PROT_FILE "/home/ol/MyFiles/Projects/File_Protector/test/prot.txt"

int main()
{
    printf("===== 白名单进程（test_prot）测试 =====\n");

    // 1. 测试open保护文件（应允许）
    printf("\n1. 尝试打开保护文件 %s\n", PROT_FILE);
    int fd = open(PROT_FILE, O_RDWR | O_CREAT, 0644);
    if (fd >= 0)
    {
        printf("✅ 允许：open保护文件成功，FD=%d\n", fd);

        // 2. 测试写入保护文件（应允许）
        const char* msg = "test prot file (whitelist)\n";
        ssize_t ret = write(fd, msg, strlen(msg));
        if (ret > 0)
        {
            printf("✅ 允许：write写入保护文件成功\n");
        }
        else
        {
            perror("❌ 异常：write写入保护文件失败");
        }
        close(fd);
    }
    else
    {
        perror("❌ 异常：open保护文件失败");
    }

    // 2. 测试删除保护文件（演示白名单权限）
    printf("\n2. 尝试删除保护文件 %s（演示白名单权限）\n", PROT_FILE);
    int ret = unlink(PROT_FILE);
    if (ret == 0)
    {
        printf("✅ 允许：unlink删除保护文件成功\n");
        // 重建文件（方便后续测试）
        fd = open(PROT_FILE, O_CREAT, 0644);
        close(fd);
    }
    else
    {
        perror("❌ 异常：unlink删除保护文件失败");
    }

    return 0;
}