all:
	gcc -nostdlib -fno-exceptions -fno-stack-protector -fPIC -c main.c
	gcc -nostdlib -fno-exceptions -fno-stack-protector -fPIC -c enable_xom.c
	gcc -nostdlib -fno-exceptions -fno-stack-protector -fPIC -c utils.c
	gcc -Wl,-T,ld.script -nostdlib -o xomenable main.o enable_xom.o trampoline.s utils.o
clean:
	rm -f xomenable *.o
