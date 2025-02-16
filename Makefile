CC = clang
CFLAGS = -std=c2x -Wall -Wextra $(shell llvm-config --cflags)
LDFLAGS = $(shell llvm-config --ldflags --system-libs --libs core)

gb_emu: gb_main.c
	$(CC) $(CFLAGS) gb_main.c -o gb_emu $(LDFLAGS)

clean:
	rm -f gb_emu