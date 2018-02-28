.text
.globl _start
.type _start, @function
_start:
call wrapper_mmap
ret
.size _start, .-_start

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
.globl _dl_debug_vdprintf
.type _dl_debug_vdprintf, @function
_dl_debug_vdprintf:
.byte 0xe9,0x0,0x0,0x0,0x0
.size _dl_debug_vdprintf, .-_dl_debug_vdprintf

.text
.globl _wrapper_syscall_execve
.type _wrapper_syscall_execve, @function
_wrapper_syscall_execve:
call wrapper_syscall_execve
cmpq $0xfffffffffffff001,%rax
post_syscall_execve:
.byte 0xe9,0x0,0x0,0x0,0x0
.size _wrapper_syscall_execve, .-_wrapper_syscall_execve

