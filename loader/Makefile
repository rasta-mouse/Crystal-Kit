CC_64=x86_64-w64-mingw32-gcc
CFLAGS=-O1 -fno-jump-tables -shared -Wall -Wno-pointer-arith

.PHONY: all x64 clean

all: x64

bin:
	mkdir -p bin

x64: bin
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/loader.c   -o bin/loader.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/services.c -o bin/services.x64.o
	$(CC_64) -DWIN_X64 $(CFLAGS) -c src/pico.c     -o bin/pico.x64.o

clean:
	rm -rf bin
