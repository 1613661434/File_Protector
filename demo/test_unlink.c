#include <stdio.h>
#include <unistd.h>

int main() {
    // 尝试删除 /tmp/protected.txt（和拦截规则一致）
    int ret = unlink("/tmp/protected.txt");
    if (ret == 0) {
        printf("文件删除成功（未被拦截）\n");
    } else {
        perror("文件删除失败（可能被拦截）");
    }
    return 0;
}