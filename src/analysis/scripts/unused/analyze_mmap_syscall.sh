#!/bin/bash
if [ $# -ne 1 ]; then
    echo "[USAGE] <program> <ELF binary>"
    exit 0
fi
exe=$1
a=$(r2 -A -qc '/s | grep mmap |sed -n "1p"' $exe | awk '{print $1}')
if [ "$a" == "" ]; then
    echo "cannot find mmap syscall address, abort"
    exit 1
fi
#echo $a
func=$(r2 -qc "aaa; s $a; sf.; s" $exe)
echo $func
