#!/bin/bash

progdir=$(readlink -f $(dirname $0))
rewriterpath=$progdir/../rewriter/examples
scriptdir=$progdir/scripts

if [ $# -lt 1 ]; then
    echo ""
    echo "[USAGE] <program> <binary to patch> [final binary]"
    echo ""
    exit 1
fi
exe=$1
if [ ! -e $exe ]; then
    echo "[Error] binary $exe does not exists, please specify a valid ld.so."
    exit 1
fi
iself=$(file $(readlink -f $exe)|grep -o "ELF")
if [ "$iself" == "" ]; then
    echo "[Error] file $exe is not an ELF executable."
    exit 1
fi
targetexe=$2
if [ "$targetexe" == "" ]; then
    targetexe=$(mktemp)
    echo "final binary name: $targetexe"
fi
r2path=$(command -v r2)
if [ "$r2path" == "" ]; then
    echo "[Error] Please ensure that Radare2 is properly installed."
    exit 1
fi
# Compile to-be-injected binary.
echo "[Generating] xomenable code..."
cd $progdir
make -C ../patch/ clean
make -C ../patch/
if [ $? -ne 0 ]; then
    echo "[Error] compiling xomenable code, please check your gcc setup."
    cd $OLDPWD
    exit 1
fi
cd $OLDPWD
elf2inject=$progdir/../patch/xomenable

addrfile=$(mktemp)
newexe=$(mktemp)

$rewriterpath/inject_instrumentation.py -i $elf2inject -f $exe -o $targetexe

execveaddr=$(r2 $exe -qc "/s~execve:0[:1]")
if [ "$execveaddr" == "" ]; then
    echo "[Error] failed to find execve address, abort"
    exit 1
fi
echo $execveaddr > $addrfile

$scriptdir/patch_calls_of_origbin.sh $addrfile _wrapper_syscall_execve \
                                     $targetexe $elf2inject; 
$scriptdir/patch_call_of_injectedbin.sh post_syscall_execve execve $targetexe \
                                        $elf2inject $exe 13;
rm $newexe
rm $addrfile

echo "injected executable has been saved as $targetexe"
