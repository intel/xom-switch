.text
.globl FUNCNAME
.type FUNCNAME, @function
FUNCNAME:
.byte 0xe9,0x00, 0x00, 0x00, 0x00
FUNCNAME_ret:
ret
.size FUNCNAME, .-FUNCNAME

