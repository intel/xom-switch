#!/bin/bash
if [ $# -ne 2 ]; then
    echo "[USAGE] <program> <syscall> <ELF binary>"
    exit 0
fi
syscall=$1
exe=$2
progdir=$(readlink -f $(dirname $0))
func=$($progdir/analyze_syscall.sh $syscall $exe)
r2 -qc "aaa; /r $func" $exe 2>/dev/null |awk '{print $2}'
