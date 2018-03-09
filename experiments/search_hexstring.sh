#!/bin/bash
tmp=$(mktemp)
xxd -g 1 -p $1 |tr '\n' ' '|sed 's/ //g' |grep -o --byte-offset "0f01ef"| sed 's/:/ /g' >$tmp
while read offset str;
do
    a=$((offset%2))    
    if [ $a -eq 0 ]; then
        realoff=$((offset/2))
        realoff=$(echo "obase=16;ibase=10;$realoff"|bc)
        echo "offset: 0x$realoff";
    fi
done <$tmp
rm $tmp
