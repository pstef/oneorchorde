#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <llvm-c/Core.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/Target.h>
#include <llvm-c/Error.h>
#include <llvm-c/LLJIT.h>  // ORC v2 C API
#include <llvm-c/Orc.h>    // Base ORC types

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

// Hardware state including CPU
struct gb_hw_state {
    uint8_t *rom;           // ROM data
    size_t rom_size;        // ROM size
    uint8_t vram[8192];     // Video RAM (8KB)
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
    LLVMOrcLLJITBuilderRef jit_builder;   // ORC v2 JIT builder
    LLVMOrcLLJITRef jit;                  // ORC v2 JIT instance
};

static struct gb_hw_state hw_state;

static void hw_init(void) {
    memset(&hw_state, 0, sizeof(hw_state));
}

static void hw_cleanup(void) {
    free(hw_state.rom);
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