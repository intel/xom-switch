#!/bin/bash

progdir=$(readlink -f $(dirname $0))
rewriterpath=$progdir/../rewriter/examples
scriptdir=$progdir/scripts

if [ $# -lt 1 ]; then
    echo ""
    echo "[USAGE] <program> <binary to be patched> <your instrumentation binary> [final binary]"
    echo ""
    exit 1
fi
exe=$1
if [ ! -e $exe ]; then
    echo "[Error] binary $exe does not exists, please specify a valid binary."
    exit 1
fi
iself=$(file $(readlink -f $exe)|grep -o "ELF")
if [ "$iself" == "" ]; then
    echo "[Error] file $exe is not an ELF executable."
    exit 1
fi
elf2inject=$2
if [ ! -e $elf2inject ]; then
    echo "[Error] binary $elf2inject does not exists, please specify a valid one."
    exit 1
fi
targetexe=$3
if [ "$targetexe" == "" ]; then
    targetexe=$(mktemp)
    echo "final binary name: $targetexe"
fi
r2path=$(command -v r2)
if [ "$r2path" == "" ]; then
    echo "[Error] Please ensure that Radare2 is properly installed."
    exit 1
fi

$rewriterpath/inject_instrumentation.py -i $elf2inject -f $exe -o $targetexe
$scriptdir/patch_calls2origcode_in_injected_code.sh $targetexe $elf2inject $exe
$scriptdir/patch_calls2injectedcode_in_original_code.sh $targetexe $elf2inject $exe

echo "injected executable has been saved as $targetexe"
