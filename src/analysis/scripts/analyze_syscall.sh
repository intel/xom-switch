#!/bin/bash
if [ $# -ne 2 ]; then
    echo "[USAGE] <program> <syscall name> <ELF binary>"
    exit 0
fi
syscall=$1
exe=$2
a=$(r2 -qc "/s~$syscall[:0]" $exe | awk '{print $1}')
if [ "$a" == "" ]; then
    echo "cannot find address of syscall $syscall, abort"
    exit 1
fi
#echo $a
func=$(r2 -A -qc "s $a; sf.; s" $exe)
echo $func
