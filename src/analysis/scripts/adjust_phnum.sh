#!/bin/bash
if [ $# -ne 2 ]; then
    echo "[USAGE] <program> <increase|decrease> <elf binary>"
    exit 1
fi

option=$1
exe=$2
if [ $option != "increase" ] && [ "$option" != "decrease" ]; then
    echo "invalid option"
    exit 1
fi
phnum=$(r2 -nn -qc 'pf.elf_header.phnum~[3]' $exe)
offset=$(r2 -nn -qc 'pf.elf_header.phnum~[2]' $exe)
echo $phnum
echo $offset
if [ $option == "increase" ]; then
    phnum=$(echo $(($phnum + 4)))
    echo $phnum
else
    phnum=$(echo $(($phnum - 4)))
    echo $phnum
fi
phnum=$(printf "%02x" $phnum)
echo $phnum
r2 -nn -w -qc "wx $phnum @ $offset" $exe
