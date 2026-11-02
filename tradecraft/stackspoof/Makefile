ASM=nasm
CC_64=x86_64-w64-mingw32-gcc
CFLAGS=-O1 -fno-jump-tables -shared -Wall -Wno-pointer-arith
 
.PHONY: all x64 clean
 
all: x64

bin:
	mkdir -p bin

x64: bin
	$(ASM)                          src/spoof.asm     -o bin/spoof.x64.bin
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/spoof.c       -o bin/spoof.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/spoof_hooks.c -o bin/spoof_hooks.x64.o

clean:
	rm -rf bin
