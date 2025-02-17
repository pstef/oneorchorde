# Try different versions of llvm-config (only tested with 15 and 18)
LLVM_CONFIG := $(shell for ver in 18 15 ''; \
    do which llvm-config$$ver >/dev/null 2>&1 && { echo llvm-config$$ver; break; }; done)

ifeq ($(LLVM_CONFIG),)
    $(error "No llvm-config found. Please install LLVM development packages (version 15 or newer)")
endif

# Get LLVM flags and required static libraries
LLVM_CFLAGS := $(shell $(LLVM_CONFIG) --cflags)
LLVM_STATIC := $(shell $(LLVM_CONFIG) --libfiles orcjit core native support)
LLVM_LIBS := $(shell $(LLVM_CONFIG) --system-libs) -lstdc++
LLVM_VERSION := $(shell $(LLVM_CONFIG) --version)

# Default flags
CFLAGS = -std=c2x -O2 -g -Wall -Wno-unused

# All compiler flags combined, with CFLAGS last to allow override
ALL_CFLAGS = -fPIC $(INCLUDES) $(LLVM_CFLAGS) $(CFLAGS)

# Build both emulator and ROM generator
all: llvm_version gb_emu test_rom

llvm_version:
	@echo "Using $(LLVM_CONFIG) version $(LLVM_VERSION)"

gb_emu: gb_main.c
	$(CC) $(ALL_CFLAGS) $^ -o $@ $(LLVM_STATIC) $(LLVM_LIBS)

test_rom: test_rom.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f gb_emu test_rom *.o

.PHONY: clean llvm_version all