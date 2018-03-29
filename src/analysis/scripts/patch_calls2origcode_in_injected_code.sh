#!/bin/bash
if [ $# -ne 3 ]; then
    echo ""
    echo "  [USAGE] <program> <binary to patch> <injected binary>"\
         "<original binary>"
    echo ""
    echo "  [NOTE]: this program patches symbols in injected binary to target"\
         "its corresponding function wrapper in binary to patch."
    echo ""
    exit 1
fi
exe=$1
injectexe=$2
origexe=$3
progdir=$(readlink -f $(dirname $0))
readelf -W -s $injectexe |grep FUNC |awk '{print $8}' | grep "^original_"|\
while read callname; do
    cname=$(echo $callname|sed  's/^original_//g')
    ftype=$(echo $cname|awk -F"_" '{print $1}')
    fname=$(echo $cname|sed  "s/^${ftype}//g; s/^_//g")
    if [ "$fname" == "" ]; then
        echo "  [ERROR] invalid function name."
        exit 1
    fi
    if [ "$ftype" == "syscall" ]; then
        fname="syscall:$fname"
    elif [ "$ftype" == "pltcall" ]; then
        fname="pltcall:$fname"
    elif [ "$ftype" == "dynsym" ]; then
        fname="dynsym:$fname"
    elif [ "$ftype" == "symbol" ]; then
        fname="symbol:$fname"
    elif [ "$ftype" == "addr" ]; then
        fname="addr:$fname"
    else
        echo "  [ERROR] invalid  function type"
        exit 1
    fi
    echo "[Processing] $callname"
    $progdir/patch_call_of_injectedbin.sh $callname $fname $exe $injectexe \
                                          $origexe
done
