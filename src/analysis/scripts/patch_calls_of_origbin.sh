#!/bin/bash
if [ $# -ne 4 ]; then
    echo ""
    echo "  [NOTE]: This program is to change callsites specified in <patch"\
         "addr file> of <binary to patch> to targeting the corresponding"\
         "symbol address in <binary to patch>"
    echo ""
    echo "  [NOTE]: This program should be invoked after binary injection."

    echo ""
    echo "  [USAGE] <program> <patch addr file> <binary to patch>"\
         "<injected binary> <symbol in injected binary>"
    echo ""
    exit 1
fi
addrfile=$1
symbol=$2
exe=$3
injectexe=$4
#target address was the entry point of original binary
echo "patching addresses stored in file: $addrfile"

textoffset=$(r2 -qc "iS~.text[1]" $injectexe)
echo $textoffset
textoffset4BC=$(printf "%X" $textoffset)
#we preserve the offset within page
offsetinpage=$(echo "obase=10; ibase=16; $textoffset4BC % 1000" | bc)
echo "offset in page: $offsetinpage"
offsetinpageHEX=$(printf "0x%x" $offsetinpage)

entryoffset=$(r2 -qc "is~ $symbol[1]" $injectexe)
echo "entryoffset: $entryoffset"
offset=$((entryoffset-textoffset))
echo $offset
base=$(r2 -qc "iS~.instrumented_code[3]" $exe)
if [ "$base" == "" ]; then
    echo "  [ERROR] invalid base address, please check if the binary is"\
         "instrumented or not."
    exit 1
fi
target=$((base + offset + offsetinpage))
echo "target value is: $target"

while read addr; do
    echo "patching address: $addr with \"call $target\""
    r2 -w -qc "s $addr; wa call $target; save; quit" $exe  
done <$addrfile
