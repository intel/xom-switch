#!/bin/bash
if [ $# -ne 2 ]; then
    echo "[USAGE] <program> <binary to patch> <injected binary>"
    exit 1
fi
exe=$1
injectexe=$2
progdir=$(readlink -f $(dirname $0))
mmap=$($progdir/analyze_mmap_syscall.sh $1)
echo "mmap function address: $mmap"
textoffset=$(r2 -A -qc "iS~.text[1]" $injectexe)
echo $textoffset
topatchoffset=$(r2 -A -qc "is~ldso_mmap[1]" $injectexe)
echo $topatchoffset
offset=$((topatchoffset - textoffset))
base=$(r2 -A -qc "iS~.instrumented_code[3]" $exe)
echo $base

patchaddr=$((base + offset))
echo "address to patch: $patchaddr"
r2 -Aw -qc "s $patchaddr; wa jmp $mmap; save; quit" $exe

