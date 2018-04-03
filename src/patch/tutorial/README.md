## Instrumentation Tutorial

This tutorial tells you how to write your instrumentation code in C. We demonstrate the instrumentation steps as follows:

#### Write your instrumentation
The following is a short sample:
```C
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>

/* intercepting calls to fwrite_unlocked */
int intercept_pltcall_fwrite_unlocked(const void *ptr, size_t size, size_t n,
                                      FILE *stream)
{
    original_pltcall___printf_chk(1, "\n**hacker** fwrite is hooked\n");
    return original_pltcall_fwrite_unlocked(ptr, size, n, stream);
}
```
You may put your code logic in your instrumentation function `intercept_pltcall_fwrite_unlocked`. Please note the function naming format. `intercept` means a method of interception. Basically `intercept` works by modifying all call sites to target your interception function  where you decide when to call the original function.  `pltcall` indicates that the function to be intercepted is a PLT code stub calling the actual library function. `fwrite_unlocked` means the function to intercept.

#### Define usage of original functions
```C
/* This function represents an auto-generated stub code that contains a jump to
 * the original function 'printf'. */
extern int original_pltcall___printf_chk(int flag, const char *fmt, ...);
extern int original_pltcall_fwrite_unlocked(const void *ptr, size_t size,
                                             size_t n, FILE *stream);
```
The functions starting with `original_` represent code stubs that target original functions in your target binaries. For instance, `original_pltcall_fwrite_unlocked` is the stub code that jump to the location of original function. Note that if your target binary does not contain such a function, it will be an *empty* stub call that does nothing but returns. Code stubs are auto-generated so users do not have to care about where they are.

#### Complete instrumentation code
```C
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
/* This function represents an auto-generated stub code that contains a jump to
 * the original function 'printf'. */
extern int original_pltcall___printf_chk(int flag, const char *fmt, ...);
extern int original_pltcall_fwrite_unlocked(const void *ptr, size_t size,
                                             size_t n, FILE *stream);

/* intercepting calls to fwrite_unlocked */
int intercept_pltcall_fwrite_unlocked(const void *ptr, size_t size, size_t n,
                                      FILE *stream)
{
    original_pltcall___printf_chk(1, "\n**hacker** fwrite is hooked\n");
    return original_pltcall_fwrite_unlocked(ptr, size, n, stream);
}
```
#### Compile your code
Go to src/patch/tutorial and run `make` and you will see a binary `tutorial` in path `src/patch/tutorial`.

#### Instrument your binary
Run the following command to patch `tutorial` into `/bin/ls`:
```Bash
src/analysis/patch-binary.sh /bin/ls src/patch/tutorial/tutorial ./my_ls
```
#### Run and see result
You may run `my_ls` and see the result as follows:
```
**hacker** fwrite is hooked
check_cpuinfo.sh  
**hacker** fwrite is hooked
libc-xom.so.6  
**hacker** fwrite is hooked
patch-binary.sh  
**hacker** fwrite is hooked
patch-loader.sh  
**hacker** fwrite is hooked
scripts

**hacker** fwrite is hooked
ld-xom.so	  
**hacker** fwrite is hooked
newls		 
**hacker** fwrite is hooked
patch-libc.sh	  
**hacker** fwrite is hooked
README.md	   
**hacker** fwrite is hooked
tests
```
As you can see that every time your `newls` prints something to standard output, it will print an extra line that you inserted!


