#ifndef _UTILS_H_
#define _UTILS_H_
#include <sys/types.h>

int strcmp(const char *s1, const char *s2);

int strncmp(const char *s1, const char *s2, size_t n);

int round_up_pgsize(int size);

int round_down_pgsize(int size);
#endif
