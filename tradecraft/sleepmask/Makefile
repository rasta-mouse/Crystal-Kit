CC_64=x86_64-w64-mingw32-gcc
CFLAGS=-O1 -fno-jump-tables -shared -Wall -Wno-pointer-arith
 
.PHONY: all x64 clean
 
all: x64

bin:
	mkdir -p bin

x64: bin
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/sleepmask.c       -o bin/sleepmask.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/sleepmask_hooks.c -o bin/sleepmask_hooks.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/sleepmask_setup.c -o bin/sleepmask_setup.x64.o

clean:
	rm -rf bin
