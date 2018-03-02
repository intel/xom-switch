#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdarg.h>
#include <elf.h>
#include "utils.h"
extern void *ldso_mmap(void *addr, size_t len, int prot, int flags,
                       int filedes, off_t off);
extern void *ldso_mprotect(void *addr, size_t len, int prot);
extern void simple_printf(char *fmt, ...);
extern int __syscall(int number, ...);

char *get_elf_soname(void *base, Elf64_Ehdr *elfhdr)
{
    int idx = 0;
    int phdrent = elfhdr->e_phnum;
    int soname_offset = -1;
    int dynstr_offset = -1;
    Elf64_Dyn *dynamic = NULL;
    Elf64_Phdr *phdr = base + elfhdr->e_phoff;
    /* Get Dynamic Segment Offset. */
    for (idx = 0; idx < phdrent; idx++) {
        if (phdr->p_type == PT_DYNAMIC) {
            dynamic = (Elf64_Dyn *)(base + phdr->p_offset);
            break;
        }
        phdr++;
    }
    if (dynamic == NULL) {
        //simple_printf("failed to find dynamic segment.\n");
        return NULL;
    }
    /* Traverse Dynamic Segment. */
    while (dynamic->d_tag != DT_NULL) {
        if (dynamic->d_tag == DT_SONAME)
            soname_offset = dynamic->d_un.d_val;
        else if (dynamic->d_tag == DT_STRTAB)
            dynstr_offset = dynamic->d_un.d_val;
        dynamic++;
    }
    if (soname_offset == -1 || dynstr_offset == -1) {
        //simple_printf("failed to find soname or dynstr offset.\n");
        return NULL;
    }
    return base + soname_offset + dynstr_offset;
}

int check_elf_whitelist(void *base, Elf64_Ehdr *elfhdr)
{
    char *whitelist[] =  { "libffi.so.6", "libfreeblpriv3.so", "libavcodec.so.57", "libcrypto.so.1.0.0" };
    int whitelistsize = sizeof(whitelist)/sizeof(char *);
    char *soname = get_elf_soname(base, elfhdr);
    int idx = 0;
    if (soname == NULL) {
        /* Executable does not have SO_NAME. */
        return 0;
    }
    //simple_printf("this elf is ===== :%s\n", soname);
    for (idx = 0; idx < whitelistsize; idx++) {
        if (strcmp(soname , whitelist[idx]) == 0)
            return 1;
    }
    return 0;
}

void implement_xom(void *base, size_t len, int prot, int flags, int fd, off_t off)
{
    void *sectable = NULL;
    void *pgsectable = NULL;
    void *execstart = NULL;
    void *execend = NULL;
    void *pgupexecstart = NULL;
    void *pgdownexecstart = NULL;
    void *pgupexecend = NULL;
    void *pgdownexecend = NULL;
    void *pgupcodesegend = NULL;
    int execsize = 0;
    int sectablesize = 0;
    int pgsectablesize = 0;
    int pgelfmetasize = 0;
    int pgrodatasize = 0;
    int idx = 0;
    if (strncmp(base, ELFMAG, 4) == 0) {
        ;//simple_printf("matched ELF header!\n");
    } else {
        simple_printf("did not match ELF header: %s!\n", base);
        return;
    }
    /* Traverse PHDR table and figure out code segment range. */
    Elf64_Ehdr *elfheader = (Elf64_Ehdr *)base;
    Elf64_Phdr *phdr = base + elfheader->e_phoff;
    int phdrent = elfheader->e_phnum;
    for (idx = 0; idx < phdrent; idx++) {
        if (phdr->p_type == PT_LOAD && phdr->p_flags == (PF_X|PF_R)) {
            pgupcodesegend = (void *)(base + round_up_pgsize(phdr->p_memsz));
            break;
        }
        phdr++;
    }
    if (pgupcodesegend == NULL) {
        simple_printf("code segment does not exist, return");
        return;
    }
    /* Figure out section table location and mmap it into memmory. */
    if (check_elf_whitelist(base, elfheader) == 1) {
        /* Whitelisted library make skip xom. */
        return;
    }
    sectablesize = elfheader->e_shnum * elfheader->e_shentsize;
    pgsectablesize = round_up_pgsize(elfheader->e_shoff + sectablesize) -
                     round_down_pgsize(elfheader->e_shoff);
    pgsectable = ldso_mmap(NULL, pgsectablesize, PROT_READ,
                           MAP_PRIVATE|MAP_DENYWRITE, fd,
                           round_down_pgsize(elfheader->e_shoff));
    sectable = pgsectable + (elfheader->e_shoff -
                             round_down_pgsize(elfheader->e_shoff));
    Elf64_Shdr *sectionheader = (Elf64_Shdr *)sectable;

    /* Traverse section table and figure out true executable region. */
    for (idx = 0; idx < elfheader->e_shnum; idx++) {
        if (sectionheader->sh_flags & SHF_EXECINSTR) {
            if (execstart == NULL)
                execstart = (void *)sectionheader->sh_addr;
            //simple_printf("executable section idx: %x\n", idx);
        } else if (!(sectionheader->sh_flags & SHF_EXECINSTR) &&
                   execstart != NULL && execend == NULL) {
            execend = (void *)sectionheader->sh_addr;
            break;
        }
        sectionheader++;
    }
    pgdownexecstart = (void *)((size_t)base + (size_t)round_down_pgsize((size_t)execstart));
    pgupexecstart = (void *)((size_t)base + (size_t)round_up_pgsize((size_t)execstart));
    pgdownexecend = (void *)((size_t)base + (size_t)round_down_pgsize((size_t)execend));
    pgupexecend = (void *)((size_t)base + (size_t)round_up_pgsize((size_t)execend));
    execsize  = (size_t)pgdownexecend - (size_t)pgupexecstart;
    if (execsize > 0) {
        ldso_mprotect(pgupexecstart, execsize, PROT_EXEC);
    }
    /* TODO: Mark elf metadata as read-only. */
    pgelfmetasize = (int)((size_t)pgdownexecstart - (size_t)base);
    if (pgelfmetasize > 0)
        ldso_mprotect((void *)base, pgelfmetasize, PROT_READ);
    /* TODO: Mark read-only section in code segment as read-only. */
    pgrodatasize = (int)((size_t)pgupcodesegend - (size_t)pgupexecend);
    if(pgrodatasize > 0)
        ldso_mprotect((void *)pgupexecend, pgrodatasize, PROT_READ);

    out:
    __syscall(__NR_munmap, (void *)pgsectable, pgsectablesize);
    return;
}
