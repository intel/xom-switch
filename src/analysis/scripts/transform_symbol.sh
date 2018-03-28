#!/bin/bash
# *****************************************************************************
#
# THis program transform a symbol in injected binary to the location 
# in original binary. 
#
# For instance, symbol, "original_pltcall_printf", will need to be transformed
# into one address in original binary that is the location of the pltcall stub
# of printf.
#
# *****************************************************************************
#
# Note: symbol name should **always** be like the following format:
# 
# ##hook-type##_##calltype##_##original-function-name-or-address##
# 
# This program will ignore the hook-type, but take a look of all the remaining
# fields. For instance,
#
# calltype could be:
#   - syscall : system call wrapper function entry address.
#   - pltcall : plt call stub code entry address.
#   - dynsym  : exported function entry address.
#   - symbol  : function entry address specified in static symbol table.
#   - addr    : address (in hex without '0x') of a function.
# 
# calltype and original-function-name-or-address together help identify the
# location of original function to hook.
#
# *****************************************************************************

symbol=$1
exe=$2
progdir=$(readlink -f $(dirname $0))
cname=$(echo $symbol|sed  's/^[^_]\+_//g')
ftype=$(echo $cname|awk -F"_" '{print $1}')
fname=$(echo $cname|sed  "s/^${ftype}//g; s/^_//g")
if [ "$fname" == "" ]; then
    echo "  [ERROR] invalid function name."
    exit 1
fi
origfuncaddr=0
if [ "$ftype" == "syscall" ]; then
    origfuncaddr=$($progdir/analyze_syscall.sh $fname $exe)
elif [ "$ftype" == "pltcall" ]; then
    origfuncaddr=$($progdir/analyze_pltcall.sh $fname $exe)
elif [ "$ftype" == "dynsym" ]; then
    echo "  [ERROR] function type not supported yet."
    exit 1
elif [ "$ftype" == "symbol" ]; then
    echo "  [ERROR] function type not supported yet."
    exit 1
elif [ "$ftype" == "addr" ]; then
    echo "  [ERROR] function type not supported yet."
    exit 1
else
    echo "  [ERROR] invalid  function type"
    exit 1
fi
echo $origfuncaddr
