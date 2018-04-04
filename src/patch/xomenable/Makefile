all:
	gcc -Wall -nostdlib -fno-exceptions -fno-stack-protector -fPIC -c main.c
	gcc -Wall -nostdlib -fno-exceptions -fno-stack-protector -fPIC -c enable_xom.c
	gcc -Wall -nostdlib -fno-exceptions -fno-stack-protector -fPIC -c utils.c
	gcc -Wall -Wl,-T,ld.script -nostdlib -o xomenable main.o enable_xom.o trampoline.s utils.o
clean:
	rm -f xomenable *.o
