/*****************************************************************************
 *
 * The code in this file contains trampoline functions of injected binary that
 * help redirecting control flows in target binary (binary that is
 * instrumented). The following are the naming conventions being used in this
 * file.
 *
 * Any function starting with "_wrapper" means a proxy code stub that targeting
 * it real wrapper function in the target binary
 *
 * Any function name like "_wrapper_FUNCTION" means that calls in target binary
 * (binary to be instrumented) targeting FUNCTION should be redirected to
 * _wrapper_FUNCTION.
 *
 * Any function name like "_wrapper_syscall_FUNCTION" means that we intercept
 * the syscall instruction in the original function and redirect control here.
 * Since syscall has only two bytes, patching such an instruction would clobber
 * the next function. This is a TODO for developer. In this future, the next
 * instruction should be automatically identified and copied into the
 * "_wrapper" proxy code.
 *
 * Any function name like "LIBNAME_FUNCTION" (e.g, ldso_mmap) means a code stub
 * that should target the mmap function in ld.so (after instrumentation).
 * Similarly, libc_mmap means a code stub that should target mmap function in
 * libc. This type of function is to help forwarding the control flow from its
 * corresponding wrapper function.
 *
 *****************************************************************************/

.text
.globl _start
.type _start, @function
_start:
hlt
.size _start, .-_start

.text
.globl __syscall
.type __syscall, @function
__syscall:
mov    %rdi,%rax
mov    %rsi,%rdi
mov    %rdx,%rsi
mov    %rcx,%rdx
mov    %r8,%r10
mov    %r9,%r8
mov    0x8(%rsp),%r9
syscall
cmp    $0xfffffffffffff001,%rax
jae    __syscall_error
retq
__syscall_error:
neg %rax
orq $0xffffffffffffffff, %rax
retq
.size __syscall, .-__syscall

.text
.globl _wrapper_mmap
.type _wrapper_mmap, @function
_wrapper_mmap:
call wrapper_mmap
ret
.size _wrapper_mmap, .-_wrapper_mmap

.text
.globl ldso_mmap
.type ldso_mmap, @function
ldso_mmap:
.byte 0xe9,0x0,0x0,0x0,0x0
.size ldso_mmap, .-ldso_mmap

.text
.globl ldso_mprotect
.type ldso_mprotect, @function
ldso_mprotect:
.byte 0xe9,0x0,0x0,0x0,0x0
.size ldso_mprotect, .-ldso_mprotect

.text
.globl ldso_dl_debug_vdprintf
.type ldso_dl_debug_vdprintf, @function
ldso_dl_debug_vdprintf:
.byte 0xe9,0x0,0x0,0x0,0x0
.size ldso_dl_debug_vdprintf, .-ldso_dl_debug_vdprintf

#TODO: supporting any instruction after syscall in general.
.text
.globl _wrapper_syscall_execve
.type _wrapper_syscall_execve, @function
_wrapper_syscall_execve:
pushq %rcx
popq %r10
call wrapper_syscall_execve
cmpq $0xfffffffffffff001,%rax
post_syscall_execve:
.byte 0xe9,0x0,0x0,0x0,0x0
.size _wrapper_syscall_execve, .-_wrapper_syscall_execve

