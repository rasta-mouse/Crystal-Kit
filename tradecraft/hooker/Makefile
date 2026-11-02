CC_64=x86_64-w64-mingw32-gcc
CFLAGS=-O1 -fno-jump-tables -shared -Wall -Wno-pointer-arith
 
.PHONY: all x64 clean
 
all: x64

bin:
	mkdir -p bin

x64: bin
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/hooker.c       -o bin/hooker.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/hooker_hooks.c -o bin/hooker_hooks.x64.o

clean:
	rm -rf bin
