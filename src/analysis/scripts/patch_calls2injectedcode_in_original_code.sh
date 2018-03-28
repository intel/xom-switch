#!/bin/bash
if [ $# -ne 3 ]; then
    echo ""
    echo "  [USAGE] <program> <binary to patch> <injected binary>"\
         "<original binary>"
    echo ""
    echo "  [NOTE]: this program patches calls in binary to patch to target"\
         "its hooking function wrapper in injected code section."
    echo ""
    exit 1
fi
exe=$1
injectexe=$2
origexe=$3
progdir=$(readlink -f $(dirname $0))
readelf -s $injectexe |grep FUNC |grep " intercept_"|awk '{print $8}' |\
while read symbol; do
    addrfile=$(mktemp)
    directcallfile=$(mktemp)
    echo "[Processing] function: $symbol"
    addr=$($progdir/transform_symbol.sh $symbol $origexe)
    if [ "$addr" == "" ]; then
        echo "  [ERROR] cannot find address of $symbol, proceed"
        continue
    fi
    $progdir/analyze_callsites.sh $addr $origexe > $addrfile
    cat $addrfile|grep "\[call\]" |awk '{print $1}' > $directcallfile
    $progdir/patch_calls_of_origbin.sh $directcallfile $symbol \
                                       $exe $injectexe; 
done
