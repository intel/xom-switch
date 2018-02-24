#include <sys/syscall.h>
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


