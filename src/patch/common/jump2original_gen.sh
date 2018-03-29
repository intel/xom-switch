#!/bin/bash
bindir=$1
funcname=$1
progdir=$(readlink -f $(dirname $0))
cat $bindir/trampoline.s > $bindir/trampoline_final.s
cat $bindir/*.c |grep "original_.*(" |\
    sed 's/^.*original_\(.*\)*\s*(.*$/\1/g'|sort|uniq|\
    while read f; do
        echo "func: $f"
        cat $progdir/func.s |sed "s/FUNCNAME/original_$f/g" \
            >> $bindir/trampoline_final.s
    done
