#include "utils.h"

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

