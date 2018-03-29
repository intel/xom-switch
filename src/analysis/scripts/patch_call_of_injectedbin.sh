#!/bin/bash
if [ $# -lt 5 ]; then
    echo ""
    echo "  [USAGE] <program> <symbol name> <corresponding syscall in ld.so>"\
         "<binary to patch> <injected binary> <original binary>"\
         "[offset to symbol]"
    echo ""
    echo "  [NOTE]: this program patches symbols in injected binary to target"\
         "its corresponding syscall wrapper in ld.so."
    echo "  e.g.: the wrapper of mmap is mmap; the wrapper of writev in ld.so"\
         "is actually _dl_debug_vdprintf (simple version of printf)."
    echo ""
    exit 1
fi
callname=$1
syscall=$2
exe=$3
injectexe=$4
origexe=$5
offset2symbol=$6
if [ "$offset2symbol" == "" ]; then
    offsetsymbol=0
fi
progdir=$(readlink -f $(dirname $0))
ftype=$(echo $syscall|awk -F":" '{print $1}')
fname=$(echo $syscall|sed  "s/^${ftype}//g; s/^://g")
if [ "$fname" == "" ]; then
    echo "  [ERROR] invalid function name."
    exit 1
fi
syscalladdr=0
if [ "$ftype" == "syscall" ]; then
    syscalladdr=$($progdir/analyze_syscall.sh $fname $origexe)
    syscalladdr=$((syscalladdr+offsetsymbol))
elif [ "$ftype" == "pltcall" ]; then
    syscalladdr=$($progdir/analyze_pltcall.sh $fname $origexe)
    syscalladdr=$((syscalladdr+offsetsymbol))
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
if [ "$syscalladdr" == "" ] || [ "$syscalladdr" == "0" ]; then
    echo "  [ERROR] cannot find function $syscall"
    exit 1
fi
echo "$fname"
echo "$syscall wrapper function address: $syscalladdr"
textoffset=$(r2 -qc "iS~.text[1]" $injectexe)
echo "textoffset: $textoffset"
textoffset4BC=$(printf "%X" $textoffset)
#we preserve the offset within page
offsetinpage=$(echo "obase=10; ibase=16; $textoffset4BC % 1000" | bc)
echo "offset in page: $offsetinpage"
offsetinpageHEX=$(printf "0x%x" $offsetinpage)
echo "offset in page (hex): $offsetinpageHEX"
echo "callname: $callname"
topatchoffset=$(r2 -qc "is~$callname$" $injectexe|head -1|awk '{print $2}')
echo "topatchoffset: $topatchoffset"
echo "textoffset: $textoffset"
echo "callname: $callname"
offset=$((topatchoffset - textoffset))
base=$(r2 -qc "iS~.instrumented_code[3]" $exe)
echo "base: $base"

patchaddr=$((base + offset + offsetinpage))
echo "address to patch: $patchaddr"
r2 -Aw -qc "s $patchaddr; wa jmp $syscalladdr; save; quit" $exe

