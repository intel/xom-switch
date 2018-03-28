#!/bin/bash
if [ $# -ne 2 ]; then
    echo "[USAGE] <program> <pltcall name> <ELF binary>"
    exit 0
fi
pltcall=$1
exe=$2
a=$(r2 -qc "aa; afl~sym.imp.$pltcall[0]" $exe)
if [ "$a" == "" ]; then
    #echo "cannot find address of pltcall $pltcall, abort"
    exit 1
fi
echo $a
