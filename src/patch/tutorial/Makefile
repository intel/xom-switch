all:
	../common/jump2original_gen.sh .
	gcc -nostdlib -fno-exceptions -fno-stack-protector -fPIC -c main.c
	gcc -Wl,-T,ld.script -nostdlib -o tutorial main.o trampoline_final.s
clean:
	rm -f trampoline_final.s tutorial *.o
