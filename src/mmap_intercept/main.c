#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdarg.h>

extern void *ldso_mmap(void *addr, size_t len, int prot, int flags, int filedes, off_t off);
extern void _dl_debug_vdprintf(int fd, int tag, const char *fmt, va_list arg);
extern void implement_xom(void *base, size_t len, int prot, int flags, int fd, off_t off);

void simple_printf(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _dl_debug_vdprintf(1, 0, fmt, ap);
    va_end(ap);
    return;
}

void *_mymmap(void *addr, size_t len, int prot, int flags, int filedes, off_t off) {
    int fd = 1;
    char *info = "allocating an elf file!";
    void *res = ldso_mmap(addr, len, prot, flags, filedes, off);
    if(res != (void *)NULL && !(flags &= MAP_FIXED) &&
       (prot == (PROT_EXEC|PROT_READ)) && filedes > 0) {
        simple_printf("fd %x is used and %s at address %lx\n", filedes,
                      info, res);
        implement_xom(res, len, prot, flags, filedes, off);
    }
    return res;
}
