#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "utils.h"
extern void *ldso_mmap(void *addr, size_t len, int prot, int flags, int filedes, off_t off);
extern void ldso_dl_debug_vdprintf(int fd, int tag, const char *fmt, va_list arg);
extern void implement_xom(void *base, size_t len, int prot, int flags, int fd, off_t off);
extern int __syscall(int num, ...);
void simple_printf(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ldso_dl_debug_vdprintf(1, 0, fmt, ap);
    va_end(ap);
    return;
}

void *wrapper_mmap(void *addr, size_t len, int prot, int flags, int filedes,
                   off_t off)
{
    int fd = 1;
    char *info = "allocating an elf file!";
    void *res = ldso_mmap(addr, len, prot, flags, filedes, off);
    if(res != (void *)NULL && !(flags &= MAP_FIXED) &&
       (prot == (PROT_EXEC|PROT_READ)) && filedes > 0) {
        //simple_printf("fd %x is used and %s at address %lx\n", filedes,
        //              info, res);
        implement_xom(res, len, prot, flags, filedes, off);
    }
    return res;
}
int wrapper_syscall_execve(const char *filename, char *const argv[], char *const envp[])
{
	int ret;
    int idx;
    int argc;
    char ** argvptr = (char **)argv;
    char buf[5] = {'\0'};
    for(idx = 0; argvptr[idx] != NULL; idx++);
    argc = idx;
    char *newargv[idx + 2];
    int fd = __syscall(__NR_open, filename, O_CLOEXEC|O_RDONLY);
    __syscall(__NR_read, fd, buf, 4);
    if(strncmp(buf, "\177ELF", 4) == 0) {
        filename = "/home/mingwei/projects/xom_enabling-blackhat18/src/analysis/ld.so";
        for(idx = 0; argv[idx] != NULL; idx++) {
            newargv[idx+1] = argv[idx];
        }
        newargv[0] = (char *)filename;
        newargv[argc+1] = NULL;
        argvptr = (char **)newargv;
    }
	__asm__ volatile ("syscall"
			:"=a" (ret)
			:"a"(59), // syscall number (execve)
			 "D"(filename), // filename
			 "S"(argvptr), // arguments
			 "d"(envp) // env
			:"rcx","r11","cc");
	return ret;
}
