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

// Instruction decoding helpers
struct instruction {
    uint8_t opcode;
    uint8_t length;    // Instruction length in bytes
    const char *name;  // Instruction mnemonic (for debugging)
};

// Translation context with the necessary LLVM types for common operations
struct translation_ctx {
    LLVMContextRef ctx;
    LLVMModuleRef module;
    LLVMBuilderRef builder;
    LLVMTypeRef cpu_state_type;
    LLVMValueRef cpu_state_ptr;
    LLVMValueRef current_function;
    LLVMOrcLLJITBuilderRef jit_builder;
    LLVMOrcLLJITRef jit;
    LLVMOrcThreadSafeContextRef tsctx;  // Add this

    // Common LLVM types we'll need
    LLVMTypeRef i8_type;
    LLVMTypeRef i16_type;
    LLVMTypeRef void_type;
    
    // Memory access function types
    LLVMTypeRef read_memory_type;
    LLVMTypeRef write_memory_type;
    
    // Memory access function declarations
    LLVMValueRef read_memory_fn;
    LLVMValueRef write_memory_fn;
};

// Create LLVM function declarations for memory access
static bool create_memory_interface(struct translation_ctx *ctx) {
    // Create common types
    ctx->i8_type = LLVMInt8TypeInContext(ctx->ctx);
    ctx->i16_type = LLVMInt16TypeInContext(ctx->ctx);
    ctx->void_type = LLVMVoidTypeInContext(ctx->ctx);
    
    // Create read_memory function type: uint8_t(uint16_t)
    LLVMTypeRef read_params[] = { ctx->i16_type };
    ctx->read_memory_type = LLVMFunctionType(ctx->i8_type, read_params, 1, false);
    
    // Create write_memory function type: void(uint16_t, uint8_t)
    LLVMTypeRef write_params[] = { ctx->i16_type, ctx->i8_type };
    ctx->write_memory_type = LLVMFunctionType(ctx->void_type, write_params, 2, false);
    
    // Declare the functions in the module
    ctx->read_memory_fn = LLVMAddFunction(ctx->module, "hw_read_memory", 
                                        ctx->read_memory_type);
    ctx->write_memory_fn = LLVMAddFunction(ctx->module, "hw_write_memory", 
                                         ctx->write_memory_type);
    
    return true;
}

// Simple instruction decoder for initial testing
static struct instruction decode_instruction(const uint8_t *code) {
    struct instruction inst = {0};
    inst.opcode = code[0];
    inst.length = 1;  // Default length, will be adjusted

    switch (code[0]) {
        case 0x00:  // NOP
            inst.name = "NOP";
            break;
        case 0x3E:  // LD A,d8
            inst.name = "LD A,d8";
            inst.length = 2;
            break;
        case 0x06:  // LD B,d8
            inst.name = "LD B,d8";
            inst.length = 2;
            break;
        case 0xFA:  // LD A,(a16)
            inst.name = "LD A,(a16)";
            inst.length = 3;
            break;
        case 0xEA:  // LD (a16),A
            inst.name = "LD (a16),A";
            inst.length = 3;
            break;
        case 0xC3:  // JP a16
            inst.name = "JP a16";
            inst.length = 3;
            break;
        default:
            inst.name = "Unknown";
            break;
    }
    return inst;
}

// Generate LLVM IR for loading a register with an immediate value
static bool translate_ld_r_d8(struct translation_ctx *ctx, uint8_t reg_idx, uint8_t value) {
    // Get pointer to register in CPU state
    LLVMValueRef reg_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type, 
                                              ctx->cpu_state_ptr, reg_idx, "reg_ptr");
    // Store immediate value
    LLVMValueRef imm = LLVMConstInt(ctx->i8_type, value, false);
    LLVMBuildStore(ctx->builder, imm, reg_ptr);
    return true;
}

// Generate LLVM IR for loading A from memory
static bool translate_ld_a_mem(struct translation_ctx *ctx, uint16_t addr) {
    // Create call to read_memory(addr)
    LLVMValueRef args[] = { LLVMConstInt(ctx->i16_type, addr, false) };
    LLVMValueRef value = LLVMBuildCall2(ctx->builder, ctx->read_memory_type,
                                       ctx->read_memory_fn, args, 1, "mem_value");
    
    // Store result in A register
    LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                            ctx->cpu_state_ptr, 0, "a_ptr");
    LLVMBuildStore(ctx->builder, value, a_ptr);
    return true;
}

// Generate LLVM IR for storing A to memory
static bool translate_ld_mem_a(struct translation_ctx *ctx, uint16_t addr) {
    // Load A register value
    LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                            ctx->cpu_state_ptr, 0, "a_ptr");
    LLVMValueRef a_val = LLVMBuildLoad2(ctx->builder, ctx->i8_type, a_ptr, "a_val");
    
    // Create call to write_memory(addr, a_val)
    LLVMValueRef args[] = {
        LLVMConstInt(ctx->i16_type, addr, false),
        a_val
    };
    LLVMBuildCall2(ctx->builder, ctx->write_memory_type, 
                   ctx->write_memory_fn, args, 2, "");
    return true;
}

// Translate a single instruction to LLVM IR
static bool translate_instruction(struct translation_ctx *ctx, 
                                const struct instruction *inst,
                                const uint8_t *code) {
    switch (inst->opcode) {
        case 0x00:  // NOP
            return true;
        
        case 0x3E:  // LD A,d8
            return translate_ld_r_d8(ctx, 0, code[1]);  // A is at index 0
        
        case 0x06:  // LD B,d8
            return translate_ld_r_d8(ctx, 2, code[1]);  // B is at index 2
        
        case 0xFA: { // LD A,(a16)
            uint16_t addr = code[1] | (code[2] << 8);
            return translate_ld_a_mem(ctx, addr);
        }
        
        case 0xEA: { // LD (a16),A
            uint16_t addr = code[1] | (code[2] << 8);
            return translate_ld_mem_a(ctx, addr);
        }
    }
    
    fprintf(stderr, "Unhandled opcode: 0x%02X\n", inst->opcode);
    return false;
}

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

    ctx->ctx = LLVMContextCreate();
    if (!ctx->ctx) {
        fprintf(stderr, "Failed to create LLVM context\n");
        return false;
    }

    ctx->module = LLVMModuleCreateWithNameInContext("gb_code", ctx->ctx);
    if (!ctx->module) {
        fprintf(stderr, "Failed to create LLVM module\n");
        return false;
    }

    ctx->builder = LLVMCreateBuilderInContext(ctx->ctx);
    if (!ctx->builder) {
        fprintf(stderr, "Failed to create LLVM IR builder\n");
        return false;
    }

    // Create memory interface
    if (!create_memory_interface(ctx)) {
        fprintf(stderr, "Failed to create memory interface\n");
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
    if (ctx->tsctx) {
        LLVMOrcDisposeThreadSafeContext(ctx->tsctx);
    }
}
// Function type for our translated code
typedef void (*gb_main_fn)(struct gb_cpu_state*);

// Create main function that we'll translate ROM code into
static bool create_translated_function(struct translation_ctx *ctx) {
    // Create function type: void gb_main(struct gb_cpu_state*)
    LLVMTypeRef param_types[] = { 
        LLVMPointerType(ctx->cpu_state_type, 0) 
    };
    LLVMTypeRef function_type = LLVMFunctionType(ctx->void_type, 
                                                param_types, 1, false);
    
    // Add function to module
    ctx->current_function = LLVMAddFunction(ctx->module, "gb_main", function_type);
    if (!ctx->current_function) {
        return false;
    }
    
    // Create entry block
    LLVMBasicBlockRef entry = LLVMAppendBasicBlock(ctx->current_function, "entry");
    LLVMPositionBuilderAtEnd(ctx->builder, entry);
    
    // Store CPU state pointer
    ctx->cpu_state_ptr = LLVMGetParam(ctx->current_function, 0);
    
    return true;
}

static bool test_translation_and_run(struct translation_ctx *ctx) {
    // Create main function for translated code
    if (!create_translated_function(ctx)) {
        fprintf(stderr, "Failed to create translation function\n");
        return false;
    }
    
    // Translate first few instructions starting at ROM_HEADER_START
    uint16_t pc = ROM_HEADER_START;
    bool success = true;
    
    printf("Starting translation at 0x%04X\n", pc);
    
    // Translate up to 10 instructions or until we hit an unknown one
    for (int i = 0; i < 10 && pc < hw_state.rom_size; i++) {
        struct instruction inst = decode_instruction(&hw_state.rom_data[pc]);
        
        if (strcmp(inst.name, "Unknown") == 0) {
            printf("Stopping at unknown instruction at 0x%04X\n", pc);
            break;
        }
        
        printf("Translating 0x%04X: %s\n", pc, inst.name);
        
        if (!translate_instruction(ctx, &inst, &hw_state.rom_data[pc])) {
            fprintf(stderr, "Failed to translate instruction at 0x%04X\n", pc);
            success = false;
            break;
        }
        
        pc += inst.length;
    }
    
    // Add return instruction
    LLVMBuildRetVoid(ctx->builder);
    
    // Verify the generated code
    char *error = NULL;
    if (LLVMVerifyModule(ctx->module, LLVMPrintMessageAction, &error) != 0) {
        fprintf(stderr, "Module verification failed\n");
        LLVMDisposeMessage(error);
        return false;
    }
    
    // Print generated IR for inspection
    char *ir = LLVMPrintModuleToString(ctx->module);
    printf("\nGenerated LLVM IR:\n%s\n", ir);
    LLVMDisposeMessage(ir);
    
    // Create thread-safe module for JIT
    LLVMOrcThreadSafeContextRef tsctx = LLVMOrcCreateNewThreadSafeContext();
    if (!tsctx) {
        fprintf(stderr, "Failed to create thread-safe context\n");
        return false;
    }
    
    LLVMOrcThreadSafeModuleRef tsm = LLVMOrcCreateNewThreadSafeModule(
        ctx->module, tsctx);
    if (!tsm) {
        fprintf(stderr, "Failed to create thread-safe module\n");
        LLVMOrcDisposeThreadSafeContext(tsctx);
        return false;
    }
    
    // Add module to JIT
    LLVMOrcJITDylibRef main_jd = LLVMOrcLLJITGetMainJITDylib(ctx->jit);
    LLVMErrorRef err = LLVMOrcLLJITAddLLVMIRModule(ctx->jit, main_jd, tsm);
    if (err) {
        char *msg = LLVMGetErrorMessage(err);
        fprintf(stderr, "Failed to add module to JIT: %s\n", msg);
        LLVMDisposeErrorMessage(msg);
        LLVMOrcDisposeThreadSafeModule(tsm);
        LLVMOrcDisposeThreadSafeContext(tsctx);
        return false;
    }
    
    // Look up the generated function
    LLVMOrcJITTargetAddress addr = 0;
    err = LLVMOrcLLJITLookup(ctx->jit, &addr, "gb_main");
    if (err) {
        char *msg = LLVMGetErrorMessage(err);
        fprintf(stderr, "Failed to look up function: %s\n", msg);
        LLVMDisposeErrorMessage(msg);
        return false;
    }
    
    // Cast address to function pointer
    gb_main_fn translated_code = (gb_main_fn)(intptr_t)addr;
    
    // Initialize CPU state for testing
    struct gb_cpu_state cpu_state = {0};
    cpu_state.pc = ROM_HEADER_START;
    
    printf("\nExecuting translated code...\n");
    
    // Execute the translated code
    translated_code(&cpu_state);
    
    // Print resulting CPU state
    printf("\nCPU state after execution:\n");
    printf("A: %02X  F: %02X  BC: %02X%02X  DE: %02X%02X  HL: %02X%02X\n",
           cpu_state.a, cpu_state.f, cpu_state.b, cpu_state.c,
           cpu_state.d, cpu_state.e, cpu_state.h, cpu_state.l);
    printf("PC: %04X  SP: %04X\n", cpu_state.pc, cpu_state.sp);
    
    // Module is now owned by the JIT
    ctx->module = NULL;
    return success;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <rom_file>\n", argv[0]);
        return 1;
    }

    hw_init();

    if (!load_rom(argv[1])) {
        fprintf(stderr, "Failed to load ROM\n");
        hw_cleanup();
        return 1;
    }

    struct translation_ctx ctx = {0};
    if (!init_translation(&ctx)) {
        fprintf(stderr, "Failed to initialize translation\n");
        hw_cleanup();
        return 1;
    }

    printf("Testing instruction translation and execution:\n");
    if (!test_translation_and_run(&ctx)) {
        fprintf(stderr, "Translation/execution test failed\n");
        cleanup_translation(&ctx);
        hw_cleanup();
        return 1;
    }

    cleanup_translation(&ctx);
    hw_cleanup();
    return 0;
}