#!/bin/bash
binary=$1
progdir=$(readlink -f $(dirname $0))
binfile="$progdir/binfiles"
echo "[Rewriting] loader code"
$progdir/../patch-loader.sh /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
    $progdir/../../patch/xomenable/xomenable $progdir/ld.so \
    >$progdir/.rewritelog 2>&1
if [ $? -ne 0 ]; then
    echo  "[Error] generating ld.so"
    exit 1
fi
if [ "$binary" != "" ]; then
    $progdir/ld.so $binary
    exit 0
fi
echo "[Testing] binaries: "
while read bin;
do
    retval=$(echo $bin | awk '{print $1}')
    biname=$(echo $bin | awk '{print $2}')
    cmdline=$(echo $bin | awk '{$1=""}1')
    timeout 60 $progdir/ld.so $cmdline >$progdir/.runlog 2>&1 
    if [ "$?" == "$retal" ]; then
        echo  "[Error] testing $biname"
        exit 1
    else
        echo "  [Succeed] testing $biname"
    fi
done < $binfile
