#!/bin/bash
src=$(readlink -f $1)
dst=$(readlink -f $2)
srcsize=$(stat --printf="%s" $src)
dstsize=$(stat --printf="%s" $dst)
echo $(((dstsize-srcsize)*100/srcsize))
