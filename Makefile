LLVM_CONFIG := $(shell for ver in 17 16 15 ''; \
    do which llvm-config$$ver >/dev/null 2>&1 && { echo llvm-config$$ver; break; }; done)

ifeq ($(LLVM_CONFIG),)
    $(error "No llvm-config found. Please install LLVM development packages (version 15 or newer)")
endif

CFLAGS = -std=c2x -Wall
ALL_FLAGS = $(shell $(LLVM_CONFIG) --cflags) $(CFLAGS)
LDFLAGS = $(shell $(LLVM_CONFIG) --ldflags --system-libs --libs core)

gb_emu: gb_main.c
	$(CC) $(ALL_FLAGS) gb_main.c -o gb_emu $(LDFLAGS)

clean:
	rm -f gb_emu