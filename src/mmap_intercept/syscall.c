#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

void __write(int fd, char *str, int size)
{
    asm volatile ("syscall"
            : /* ignore output */
            : "a"(__NR_write), "D"(fd), "S"(str), "d"(size)
            : "cc", "rcx", "r11", "memory"
            );
    return;
}

int __munmap(void *addr, size_t length)
{
    int ret;
    asm volatile ("syscall"
            : "=a" (ret)
            : "a"(__NR_munmap), "D"(addr), "S"(length)
            : "cc", "rcx", "r11", "memory"
            );
    return ret;
}
