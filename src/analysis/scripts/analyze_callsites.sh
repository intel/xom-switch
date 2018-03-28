#!/bin/bash
if [ $# -ne 2 ]; then
    echo "[USAGE] <program> <address> <ELF binary>"
    exit 0
fi
address=$1
exe=$2
progdir=$(readlink -f $(dirname $0))
r2 -qc "aaa; /r $address~[1,2]" $exe 2>/dev/null
