#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdarg.h>
#include <elf.h>
#include <string.h>
extern void *ldso_mmap(void *addr, size_t len, int prot, int flags,
                       int filedes, off_t off);
extern void *ldso_mprotect(void *addr, size_t len, int prot);
extern void simple_printf(char *fmt, ...);

int strcmp(const char *s1, const char *s2)
{
    unsigned char uc1, uc2;
    while (*s1 != '\0' && *s1 == *s2) {
        s1++;
        s2++;
    }
    uc1 = (*(unsigned char *) s1);
    uc2 = (*(unsigned char *) s2);
    return ((uc1 < uc2) ? -1 : (uc1 > uc2));
}

int strncmp(const char *s1, const char *s2, size_t n)
{
    unsigned char uc1, uc2;
    /* Nothing to compare?  Return zero.  */
    if (n == 0)
        return 0;
    /* Loop, comparing bytes.  */
    while (n-- > 0 && *s1 == *s2) {
        /* If we've run out of bytes or hit a null, return zero
           since we already know *s1 == *s2.  */
        if (n == 0 || *s1 == '\0')
            return 0;
        s1++;
        s2++;
    }
    uc1 = (*(unsigned char *) s1);
    uc2 = (*(unsigned char *) s2);
    return ((uc1 < uc2) ? -1 : (uc1 > uc2));
}

int round_up_pgsize(int size)
{
    if (size % 0x1000 == 0)
        return size;
    return size - (size % 0x1000) + 0x1000;
}

int round_down_pgsize(int size)
{
    if (size % 0x1000 == 0)
        return size;
    return size - (size % 0x1000);
}
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
        if(phdr->p_type == PT_DYNAMIC) {
            dynamic = (Elf64_Dyn *)(base + phdr->p_offset);
            break;
        }
        phdr++;
    }
    if(dynamic == NULL) {
        simple_printf("failed to find dynamic segment.\n");
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
    if(soname_offset == -1 || dynstr_offset == -1) {
        simple_printf("failed to find soname or dynstr offset.\n");
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
    simple_printf("this elf is ===== :%s\n", soname);
    for (idx = 0; idx < whitelistsize; idx++) {
        if(strcmp(soname , whitelist[idx]) == 0)
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
    int execsize = 0;
    int sectablesize = 0;
    int pgsectablesize = 0;

    int idx = 0;
    if (strncmp(base, ELFMAG, 4) == 0) {
        ;//simple_printf("matched ELF header!\n");
    } else {
        simple_printf("did not match ELF header: %s!\n", base);
        return;
    }
    /* Figure out section table location and mmap it into memmory. */
    Elf64_Ehdr *elfheader = (Elf64_Ehdr *)base;
    if(check_elf_whitelist(base, elfheader) == 1) {
        /* Whitelisted library make skip xom. */
        return;
    }
    //simple_printf("section table offset: %x\n", elfheader->e_shoff);
    sectablesize = elfheader->e_shnum * elfheader->e_shentsize;
    pgsectablesize = round_up_pgsize(elfheader->e_shoff + sectablesize) -
                     round_down_pgsize(elfheader->e_shoff);
    //simple_printf("section table size: %x\n", sectablesize);
    pgsectable = ldso_mmap(NULL, pgsectablesize, PROT_READ,
                           MAP_PRIVATE|MAP_DENYWRITE, fd,
                           round_down_pgsize(elfheader->e_shoff));
    //simple_printf("section table mmaped at address: %lx\n", pgsectable);
    sectable = pgsectable + (elfheader->e_shoff -
                             round_down_pgsize(elfheader->e_shoff));
    //simple_printf("section table is at address: %lx\n", sectable);
    Elf64_Shdr *sectionheader = (Elf64_Shdr *)sectable;
    //simple_printf("section table entry number: %x\n", elfheader->e_shnum);

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
    //simple_printf("executable execstart (offset): %lx\n", execstart);
    //simple_printf("executable execend (offset): %lx\n", execend);
    execstart = (void *)((size_t)base + (size_t)round_up_pgsize((size_t)execstart));
    execend   = (void *)((size_t)base + (size_t)round_down_pgsize((size_t)execend));
    if ((size_t)execstart >= (size_t)execend) {
        //simple_printf("executable only region is 0\n");
        return;
    }
    execsize  = (size_t)execend - (size_t)execstart;
    ldso_mprotect(execstart, execsize, PROT_EXEC);
    //simple_printf("executable execstart: %lx\n", execstart);
    //simple_printf("executable execend: %lx\n", execend);

    /* TODO: Mark elf metadata as read-only. */


    /* TODO: Mark read-only section in code segment as read-only. */
}
