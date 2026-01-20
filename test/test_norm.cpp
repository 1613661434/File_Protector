#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

// 测试文件路径
#define PROT_FILE "/home/ol/MyFiles/Projects/File_Protector/test/prot.txt"
#define NORM_FILE "/home/ol/MyFiles/Projects/File_Protector/test/norm.txt"

int main()
{
    printf("===== 非白名单进程（test_norm）测试 =====\n");

    // 1. 测试open保护文件（应被拦截）
    printf("\n1. 尝试打开保护文件 %s\n", PROT_FILE);
    int fd1 = open(PROT_FILE, O_RDWR);
    if (fd1 >= 0)
    {
        printf("❌ 未被拦截：open成功，FD=%d\n", fd1);
        close(fd1);
    }
    else
    {
        perror("✅ 被拦截：open失败");
    }

    // 2. 测试open普通文件（应允许）
    printf("\n2. 尝试打开普通文件 %s\n", NORM_FILE);
    int fd2 = open(NORM_FILE, O_RDWR | O_CREAT, 0644);
    if (fd2 >= 0)
    {
        printf("✅ 允许：open成功，FD=%d\n", fd2);
        // 测试写入普通文件（应允许）
        const char* msg = "test norm file\n";
        ssize_t ret = write(fd2, msg, strlen(msg));
        if (ret > 0)
        {
            printf("✅ 允许：write写入普通文件成功\n");
        }
        else
        {
            perror("❌ 异常：write写入普通文件失败");
        }
        close(fd2);
    }
    else
    {
        perror("❌ 异常：open普通文件失败");
    }

    // 3. 测试删除保护文件（应被拦截）
    printf("\n3. 尝试删除保护文件 %s\n", PROT_FILE);
    int ret = unlink(PROT_FILE);
    if (ret == 0)
    {
        printf("❌ 未被拦截：unlink删除保护文件成功\n");
    }
    else
    {
        perror("✅ 被拦截：unlink删除保护文件失败");
    }

    return 0;
}