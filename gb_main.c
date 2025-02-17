#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <llvm-c/Core.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/Target.h>
#include <llvm-c/Error.h>
#include <llvm-c/LLJIT.h>
#include <llvm-c/Orc.h>

// GameBoy ROM header starts at 0x100
#define ROM_HEADER_START 0x100
#define ROM_HEADER_SIZE 0x50
#define ROM_TITLE_START 0x134
#define ROM_TITLE_SIZE 16

// Memory map definitions
#define ROM_BANK_0_START    0x0000
#define ROM_BANK_0_END      0x3FFF
#define ROM_BANK_N_START    0x4000
#define ROM_BANK_N_END      0x7FFF
#define VRAM_START          0x8000
#define VRAM_END           0x9FFF
#define EXTERNAL_RAM_START  0xA000
#define EXTERNAL_RAM_END    0xBFFF
#define WORK_RAM_START      0xC000
#define WORK_RAM_END        0xDFFF
#define ECHO_RAM_START      0xE000
#define ECHO_RAM_END        0xFDFF
#define OAM_START          0xFE00
#define OAM_END            0xFE9F
#define IO_PORTS_START     0xFF00
#define IO_PORTS_END       0xFF7F
#define HRAM_START         0xFF80
#define HRAM_END           0xFFFE
#define IE_REGISTER        0xFFFF

// CPU state that will be accessed by translated code
struct gb_cpu_state {
    uint8_t a;     // Accumulator
    uint8_t f;     // Flags: Z N H C 0 0 0 0
    uint8_t b, c;  // BC pair
    uint8_t d, e;  // DE pair
    uint8_t h, l;  // HL pair
    uint16_t sp;   // Stack pointer
    uint16_t pc;   // Program counter
};

// Hardware state including memory and CPU
struct gb_hw_state {
    uint8_t *rom_data;      // ROM data (up to 32KB for bank 0)
    size_t rom_size;        // Total ROM size
    uint8_t *rom_banks;     // Additional ROM banks
    uint8_t vram[8192];     // Video RAM (8KB)
    uint8_t wram[8192];     // Work RAM (8KB)
    uint8_t oam[160];       // Object Attribute Memory
    uint8_t io[128];        // I/O registers
    uint8_t hram[127];      // High RAM
    uint8_t ie;             // Interrupt Enable register
    struct gb_cpu_state cpu;
};

// Translation context
struct translation_ctx {
    LLVMContextRef ctx;
    LLVMModuleRef module;
    LLVMBuilderRef builder;
    LLVMTypeRef cpu_state_type;
    LLVMValueRef cpu_state_ptr;
    LLVMValueRef current_function;
    LLVMOrcLLJITBuilderRef jit_builder;
    LLVMOrcLLJITRef jit;
};

static struct gb_hw_state hw_state;

static void hw_init(void) {
    memset(&hw_state, 0, sizeof(hw_state));
}

static void hw_cleanup(void) {
    free(hw_state.rom_data);
    free(hw_state.rom_banks);
}

// Validate ROM header and extract cartridge info
static bool validate_rom(const uint8_t *data, size_t size) {
    if (size < ROM_HEADER_START + ROM_HEADER_SIZE) {
        fprintf(stderr, "ROM file too small\n");
        return false;
    }

    // Nintendo logo check (basic validation)
    static const uint8_t nintendo_logo[] = {
        0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B,
        0x03, 0x73, 0x00, 0x83, 0x00, 0x0C, 0x00, 0x0D
    };
    
    if (memcmp(data + 0x104, nintendo_logo, sizeof(nintendo_logo)) != 0) {
        fprintf(stderr, "Invalid Nintendo logo in ROM header\n");
        return false;
    }

    // Print cartridge title
    char title[ROM_TITLE_SIZE + 1] = {0};
    memcpy(title, data + ROM_TITLE_START, ROM_TITLE_SIZE);
    
    // Trim trailing spaces
    for (int i = ROM_TITLE_SIZE - 1; i >= 0; i--) {
        if (title[i] == ' ') {
            title[i] = '\0';
        } else {
            break;
        }
    }

    printf("ROM Title: %s\n", title);
    printf("ROM Size: %zu bytes\n", size);

    return true;
}

// Load ROM file into memory
static bool load_rom(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("Failed to open ROM file");
        return false;
    }

    // Get file size
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) {
        fprintf(stderr, "Invalid ROM file size\n");
        fclose(f);
        return false;
    }

    // Allocate memory for ROM
    uint8_t *data = malloc(size);
    if (!data) {
        fprintf(stderr, "Failed to allocate memory for ROM\n");
        fclose(f);
        return false;
    }

    // Read ROM data
    if (fread(data, 1, size, f) != size) {
        fprintf(stderr, "Failed to read ROM file\n");
        free(data);
        fclose(f);
        return false;
    }

    fclose(f);

    // Validate ROM
    if (!validate_rom(data, size)) {
        free(data);
        return false;
    }

    // Store ROM data
    hw_state.rom_data = data;
    hw_state.rom_size = size;

    return true;
}

// Memory read callback - will be called by translated code
static uint8_t __attribute__((noinline)) hw_read_memory(uint16_t addr) {
    if (addr <= ROM_BANK_0_END) {
        return hw_state.rom_data[addr];
    }
    if (addr >= VRAM_START && addr <= VRAM_END) {
        return hw_state.vram[addr - VRAM_START];
    }
    if (addr >= WORK_RAM_START && addr <= WORK_RAM_END) {
        return hw_state.wram[addr - WORK_RAM_START];
    }
    if (addr >= OAM_START && addr <= OAM_END) {
        return hw_state.oam[addr - OAM_START];
    }
    if (addr >= IO_PORTS_START && addr <= IO_PORTS_END) {
        return hw_state.io[addr - IO_PORTS_START];
    }
    if (addr >= HRAM_START && addr <= HRAM_END) {
        return hw_state.hram[addr - HRAM_START];
    }
    if (addr == IE_REGISTER) {
        return hw_state.ie;
    }
    return 0xFF; // Unmapped memory returns 0xFF
}

// Memory write callback - will be called by translated code
static void __attribute__((noinline)) hw_write_memory(uint16_t addr, uint8_t value) {
    if (addr >= VRAM_START && addr <= VRAM_END) {
        hw_state.vram[addr - VRAM_START] = value;
    }
    else if (addr >= WORK_RAM_START && addr <= WORK_RAM_END) {
        hw_state.wram[addr - WORK_RAM_START] = value;
    }
    else if (addr >= OAM_START && addr <= OAM_END) {
        hw_state.oam[addr - OAM_START] = value;
    }
    else if (addr >= IO_PORTS_START && addr <= IO_PORTS_END) {
        hw_state.io[addr - IO_PORTS_START] = value;
    }
    else if (addr >= HRAM_START && addr <= HRAM_END) {
        hw_state.hram[addr - HRAM_START] = value;
    }
    else if (addr == IE_REGISTER) {
        hw_state.ie = value;
    }
    // Writes to ROM are ignored
}


// Initialize LLVM and create translation context
static bool init_translation(struct translation_ctx *ctx) {
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    
    // Create JIT builder
    ctx->jit_builder = LLVMOrcCreateLLJITBuilder();
    if (!ctx->jit_builder) {
        fprintf(stderr, "Failed to create LLJIT builder\n");
        return false;
    }

    // Create JIT instance
    LLVMErrorRef err = LLVMOrcCreateLLJIT(&ctx->jit, ctx->jit_builder);
    if (err) {
        char *msg = LLVMGetErrorMessage(err);
        fprintf(stderr, "Failed to create LLJIT: %s\n", msg);
        LLVMDisposeErrorMessage(msg);
        return false;
    }

    // Get the context - will be owned by the JIT
    ctx->ctx = LLVMContextCreate();
    if (!ctx->ctx) {
        fprintf(stderr, "Failed to create LLVM context\n");
        return false;
    }

    // Create module within this context
    ctx->module = LLVMModuleCreateWithNameInContext("gb_code", ctx->ctx);
    if (!ctx->module) {
        fprintf(stderr, "Failed to create LLVM module\n");
        return false;
    }

    // Create IR builder
    ctx->builder = LLVMCreateBuilderInContext(ctx->ctx);
    if (!ctx->builder) {
        fprintf(stderr, "Failed to create LLVM IR builder\n");
        return false;
    }

    return true;
}

static void cleanup_translation(struct translation_ctx *ctx) {
    if (ctx->builder) {
        LLVMDisposeBuilder(ctx->builder);
    }
    if (ctx->jit) {
        LLVMOrcDisposeLLJIT(ctx->jit);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <rom_file>\n", argv[0]);
        return 1;
    }

    hw_init();

    struct translation_ctx ctx = {0};
    if (!init_translation(&ctx)) {
        fprintf(stderr, "Failed to initialize translation\n");
        return 1;
    }

    printf("LLVM initialized successfully\n");

    cleanup_translation(&ctx);
    hw_cleanup();
    return 0;
}