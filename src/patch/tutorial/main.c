#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
/* This function represents an auto-generated stub code that contains a jump to
 * the original function 'printf'. */
extern int original_pltcall___printf_chk(int flag, const char *fmt, ...);
extern int original_pltcall_fwrite_unlocked(const void *ptr, size_t size,
                                             size_t n, FILE *stream);

/* Interception function name should **always** be like the following format:
 *
 * ##hook-type##_##calltype##_##original-function-name-or-address##
 *
 * hook-type right now supports only "intercept". "Intercept" means that your
 * instrumentation function will be like this in runtime:
 *
 * (orig code) ... call intercept_funcA ->
 * (your code) ... call original_funcA  ->
 * (orig code) ... ret
 *
 * Note: only "direct call sites" are patched to your interception function.
 * "indirect call sites" are currently not hooked.
 *
 * calltype could be:
 *   - syscall : system call wrapper function entry address.
 *   - pltcall : plt call stub code entry address.
 *   - dynsym  : exported function entry address.
 *   - symbol  : function entry address specified in static symbol table.
 *   - addr    : address (in hex without '0x') of a function.
 *
 * Note: calltype and original-function-name-or-address together help identify
 * the location of original function to hook.
 */

/* intercepting calls to fwrite_unlocked */
int intercept_pltcall_fwrite_unlocked(const void *ptr, size_t size, size_t n,
                      FILE *stream)
{
    original_pltcall___printf_chk(1, "\n**hacker** fwrite is hooked\n");
    return original_pltcall_fwrite_unlocked(ptr, size, n, stream);
}
