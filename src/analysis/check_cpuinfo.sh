#!/bin/bash
pku=$(cat /proc/cpuinfo|grep -o pku)
ospke=$(cat /proc/cpuinfo|grep -o ospke)

if [ "$pku" == "" ] || [ "$ospke" == "" ]; then
    echo "Memory Protection Key is not yet supported in your kernel. Please"\
         "make sure your CPU has MPK support and then upgrade your kernel."
    exit 1
fi
echo "Great! You are ready to use memory protection keys!"
exit 0
