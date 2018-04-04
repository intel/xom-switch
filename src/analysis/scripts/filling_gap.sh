#!/bin/bash
if [ $# != 1 ]; then
    exit 1
fi
exe=$1
if [ ! -e $exe ]; then
    exit 1
fi
offsetbss=$(readelf -W -S $exe|sed 's/^ *\[//g'|grep " \.bss "|awk '{print $5}')
offsetnextsec=$(readelf -W -S $exe|sed 's/^ *\[//g'|grep -A 1 " \.bss "|tail -1|awk '{print $5}')
if [ "$offsetbss" == "" ] || [ "$offsetnextsec" == "" ]; then
    exit 1
fi
offsetbss="0x$offsetbss"
offsetnextsec="0x$offsetnextsec"
echo "offsetbss: $offsetbss"
echo "offsetnextsec: $offsetnextsec"
size=$(echo $(($offsetnextsec-$offsetbss)))
dd if=/dev/zero of=$exe bs=1 count=$(echo $(($offsetnextsec - $offsetbss))) \
    seek=$(echo $(($offsetbss))) conv=notrunc
echo "done filling the gap"
