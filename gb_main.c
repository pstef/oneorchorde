/*
OneOrchorde - GameBoy to Native Code Translator

Project Overview:
---------------
This project translates GameBoy ROM dumps to native machine code using LLVM ORC JIT.
Translation happens once at ROM load time. The translated code interacts with
emulated hardware components implemented in C.

Architecture:
-----------
1. Translation Pipeline:
   ROM -> Instruction Decoder -> LLVM IR Generator -> Native Code

2. Hardware Emulation:
   - Memory Map (0x0000-0xFFFF)
   - Basic PPU (enough for simple games)
   - No APU (sound) emulation yet
   - No MBC (Memory Bank Controller) support yet

3. LLVM Integration:
   - Using ORC JIT (not legacy JIT)
   - Static linking with LLVM libraries
   - Single-module design for now
   - No optimization passes yet

Current Implementation Status:
---------------------------
1. CPU Translation
   See comment below

2. Memory Implementation:
   - ROM bank 0 (0x0000-0x3FFF): Read-only
   - VRAM (0x8000-0x9FFF): Read-write
   - WRAM (0xC000-0xDFFF): Read-write
   - OAM (0xFE00-0xFE9F): Read-write
   - I/O registers (0xFF00-0xFF7F): Partial implementation
   - HRAM (0xFF80-0xFFFE): Read-write
   - IE register (0xFFFF): Read-write

3. PPU Implementation:
   - Basic register support (LCDC, STAT, etc.)
   - No actual rendering yet
   - Minimal timing simulation

Translation Process Details:
-------------------------
1. Instruction Translation:
   ROM instruction -> LLVM IR builder calls -> Native code
   Example for "LD A,n":
   - Load immediate from code[]
   - Get A register pointer from cpu_state
   - Generate store instruction

2. Hardware Access:
   Generated code -> hw_read_memory()/hw_write_memory() -> Hardware emulation
   All hardware access goes through these two functions

3. Control Flow:
   - Basic blocks created for each potential jump target
   - Conditional execution using LLVM branch instructions
   - Return addresses handled on emulated stack

Current Limitations:
-----------------
1. ROM Support:
   - No MBC support (32KB ROMs only)
   - No save RAM support
   - No ROM bank switching

2. CPU Limitations:
   - No timing accuracy
   - Limited instruction set
   - No interrupt support yet

3. Graphics:
   - No sprite support
   - No window support
   - No actual pixel processing

Development Milestones:
--------------------
✓ Milestone 1: Basic ROM loading and validation
✓ Milestone 2: Initial instruction translation
✓ Milestone 3: Basic memory read/write support
Current -> Milestone 4: Implement enough instructions for Alleyway
Future  -> Milestone 5: Add interrupt support
Future  -> Milestone 6: Implement basic PPU

Build Requirements:
----------------
- LLVM 16+ (statically linked)
- C23 compiler
- No external dependencies beyond LLVM

Testing Strategy:
---------------
1. ROM header validation
2. Individual instruction translation
3. Basic block formation
4. Memory access patterns
5. Hardware state consistency

File Organization:
----------------
gb_main.c:     Main implementation file
test_rom.c:    Test ROM generation
[Additional files only when needed for sharing definitions]
*/

/*
CPU Translation
--------------------------------

Register Layout in CPU State (struct gb_cpu_state indices):
- 0: A (Accumulator)
- 1: F (Flags: Z N H C 0 0 0 0)
- 2: B
- 3: C
- 4: D
- 5: E
- 6: H
- 7: L
- 8: SP (Stack Pointer)
- 9: PC (Program Counter)

Currently Implemented Instructions:
--------------------------------

Load 8-bit:
- 0x3E: LD A,d8      (Load immediate into A)
- 0x06: LD B,d8      (Load immediate into B)
- 0xFA: LD A,(a16)   (Load from memory into A)
- 0xEA: LD (a16),A   (Store A to memory)
- 0xF0: LDH A,(a8)   (Load from high memory into A)
- 0xE0: LDH (a8),A   (Store A to high memory)
- 0x77: LD (HL),A    (Store A to memory at HL)
- 0x7E: LD A,(HL)    (Load from memory at HL into A)

Load 16-bit:
- 0x21: LD HL,d16    (Load immediate into HL)

Load with increment/decrement:
- 0x2A: LD A,(HL+)   (Load from HL and increment)
- 0x22: LD (HL+),A   (Store to HL and increment)
- 0x32: LD (HL-),A   (Store to HL and decrement)

Stack Operations:
- 0xC5: PUSH BC      (Push BC onto stack)
- 0xD5: PUSH DE      (Push DE onto stack)
- 0xE5: PUSH HL      (Push HL onto stack)
- 0xF5: PUSH AF      (Push AF onto stack)
- 0xC1: POP BC       (Pop into BC from stack)
- 0xD1: POP DE       (Pop into DE from stack)
- 0xE1: POP HL       (Pop into HL from stack)
- 0xF1: POP AF       (Pop into AF from stack)

Arithmetic/Logic:
- 0x80-0x87: ADD A,r    (Add register to A)
- 0xC6: ADD A,d8        (Add immediate to A)
- 0xCE: ADC A,d8        (Add immediate and carry to A)
- 0xAF: XOR A,A         (Clear A register)
- 0x04: INC B           (Increment B)
- 0x0C: INC C           (Increment C)

Compare Instructions:
- 0xBE: CP (HL)      (Compare A with memory at HL)
- 0xFE: CP d8        (Compare A with immediate)
- 0xB8: CP B         (Compare A with B)
- 0xB9: CP C         (Compare A with C)
- 0xBA: CP D         (Compare A with D)
- 0xBB: CP E         (Compare A with E)
- 0xBC: CP H         (Compare A with H)
- 0xBD: CP L         (Compare A with L)
- 0xBF: CP A         (Compare A with itself)

Control Flow:
- 0x00: NOP          (No operation)
- 0xC3: JP a16       (Jump to immediate address)
- 0xC0: RET NZ       (Return if not zero)
- 0xC8: RET Z        (Return if zero)
- 0xC9: RET          (Return unconditionally)
- 0xC4: CALL NZ,a16  (Call if not zero)
- 0xCC: CALL Z,a16   (Call if zero)
- 0xCD: CALL a16     (Call unconditionally)
- RST vectors:
  - 0xC7: RST 00H    (Call 0x0000)
  - 0xCF: RST 08H    (Call 0x0008)
  - 0xD7: RST 10H    (Call 0x0010)
  - 0xDF: RST 18H    (Call 0x0018)
  - 0xE7: RST 20H    (Call 0x0020)
  - 0xEF: RST 28H    (Call 0x0028)
  - 0xF7: RST 30H    (Call 0x0030)
  - 0xFF: RST 38H    (Call 0x0038)

TODO for Alleyway:
-----------------
1. Arithmetic/Logic Instructions:
   - SUB r        (Subtract register from A)
   - SUB (HL)     (Subtract memory from A)
   - AND r        (AND register with A)
   - OR r         (OR register with A)

2. Control Flow Instructions:
   - JR NZ,r8     (Relative jump if not zero)
   - JR Z,r8      (Relative jump if zero)

3. Bit Operations:
   - BIT b,r      (Test bit b in register)
   - BIT b,(HL)   (Test bit b in memory)

Known Limitations:
----------------
1. Timing is not implemented - no cycle counting
2. No interrupt handling yet
3. No PPU timing emulation
4. Limited memory bank switching support

Next Steps:
----------
1. Implement CP instruction for collision detection
2. Add basic timing support for PPU synchronization
3. Implement remaining arithmetic instructions
4. Add support for input handling

Flag Handling (F Register):
-------------------------
Layout (bits 7-4 only, bits 3-0 always zero):
- Bit 7: Z (Zero Flag)
  Set when: Result of operation is zero
  Clear when: Result of operation is non-zero
  Used by: Conditional jumps, calls, returns (Z/NZ conditions)

- Bit 6: N (Subtract Flag)
  Set when: Last operation was a subtraction
  Clear when: Last operation was an addition or logical operation
  Used by: DAA instruction (BCD adjustment, not implemented yet)

- Bit 5: H (Half Carry Flag)
  Set when: Carry from bit 3 to bit 4 in last operation
  Clear when: No carry from bit 3
  For addition: Set if (val1 & 0xF) + (val2 & 0xF) > 0xF
  For subtraction: Set if borrow from bit 4
  Used by: DAA instruction

- Bit 4: C (Carry Flag)
  Set when: Result overflowed 8 bits / borrow was needed
  Clear when: No overflow / no borrow needed
  For addition: Set if result > 0xFF
  For subtraction: Set if borrow needed (val1 < val2)
  Used by: ADC, SBC, conditional jumps (C/NC conditions)

Currently Implemented Flag Operations:
----------------------------------
1. ADD A,r/n updates all flags:
   - Z: Set if result is zero
   - N: Reset (0)
   - H: Set if carry from bit 3
   - C: Set if result exceeded 0xFF
   Note: ADD ignores current carry flag

2. ADC A,d8 updates all flags:
   - Z: Set if result is zero
   - N: Reset (0)
   - H: Set if carry from bit 3 (includes current carry)
   - C: Set if result exceeded 0xFF (includes current carry)
   Note: ADC adds current carry flag to result

3. INC r updates Z, N, H:
   - Z: Set if result is zero
   - N: Reset (0)
   - H: Set if carry from bit 3
   - C: Preserved (unchanged)

4. XOR A updates all flags:
   - Z: Set (A becomes 0)
   - N: Reset (0)
   - H: Reset (0)
   - C: Reset (0)

5. CP updates all flags:
   - Z: Set if A equals operand
   - N: Set (1)
   - H: Set if borrow from bit 4
   - C: Set if A < operand

6. ADC A,d8 updates all flags:
   - Z: Set if result is zero
   - N: Reset (0)
   - H: Set if carry from bit 3 (includes current carry)
   - C: Set if result exceeded 0xFF (includes current carry)

Flag Helper Functions:
-------------------
get_flag_z():
- Returns current Z flag value
- Used by conditional instructions (RET Z/NZ, CALL Z/NZ)

set_flag_z():
- Sets Z flag while preserving others
- Used by arithmetic and logical operations

update_flags_add():
- Updates all flags after addition
- Handles H and C flag computation for 8-bit addition

update_flags_sub():
- Updates all flags for subtraction operations
- Sets N flag to indicate subtraction
- Handles H and C flags for borrow
- Used by CP and SUB instructions

TODO for Flag Handling:
---------------------
1. Add update_flags_logical() for AND/OR operations:
   - Z flag based on result
   - N and C always reset
   - H flag set for AND, reset for OR

2. Add flag handling for:
   - Bit test instructions
   - 16-bit arithmetic

3. Add helper functions for:
   - Individual flag manipulation
   - Flag condition testing (for JP cc,nn etc.)

Important Notes:
--------------
1. Half-carry (H) flag computation:
   - For addition: ((a & 0xF) + (b & 0xF)) & 0x10
   - For subtraction: ((a & 0xF) - (b & 0xF)) & 0x10

2. When implementing CP:
   - Updates flags like SUB but doesn't store result
   - Z set if A == operand
   - N always set (indicates comparison)
   - H set if borrow from bit 4
   - C set if A < operand

3. CP instruction usage in Alleyway:
   - CP d8: Used for boundary checks (screen edges)
   - CP (HL): Used for collision detection with sprites
   - CP r: Used for position comparisons
   - All CP variants update flags without modifying A
*/

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

struct gb_ppu_state {
    uint8_t lcdc;      // LCD Control
    uint8_t stat;      // LCD Status
    uint8_t scy, scx;  // Scroll Y/X
    uint8_t ly;        // LCD Y-Coordinate
    uint8_t lyc;       // LY Compare
    uint8_t bgp;       // BG Palette Data
    uint8_t obp0;      // Object Palette 0 Data
    uint8_t obp1;      // Object Palette 1 Data
    uint8_t wy, wx;    // Window Y/X Position
    uint8_t vram[8192];// Video RAM
    uint8_t oam[160];  // Object Attribute Memory
    uint32_t framebuffer[160 * 144]; // RGB framebuffer
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
    struct gb_ppu_state ppu;
    uint32_t *framebuffer;
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

static void hw_write_ppu_reg(uint16_t addr, uint8_t value) {
    switch (addr) {
        case 0xFF40: hw_state.ppu.lcdc = value; break;  // LCDC
        case 0xFF41: hw_state.ppu.stat = value; break;  // STAT
        case 0xFF42: hw_state.ppu.scy = value; break;   // SCY
        case 0xFF43: hw_state.ppu.scx = value; break;   // SCX
        case 0xFF44: hw_state.ppu.ly = value; break;    // LY
        case 0xFF45: hw_state.ppu.lyc = value; break;   // LYC
        case 0xFF47: hw_state.ppu.bgp = value; break;   // BGP
        case 0xFF48: hw_state.ppu.obp0 = value; break;  // OBP0
        case 0xFF49: hw_state.ppu.obp1 = value; break;  // OBP1
        case 0xFF4A: hw_state.ppu.wy = value; break;    // WY
        case 0xFF4B: hw_state.ppu.wx = value; break;    // WX
    }
}

// Memory write callback - will be called by translated code
static void __attribute__((noinline)) hw_write_memory(uint16_t addr, uint8_t value) {
    if (addr == 0xFF41) {  // STAT
        hw_state.ppu.stat = (hw_state.ppu.stat & 0xFC) | (value & 0x03);
        // Mode bits are read-only
    } else if (addr == 0xFF44) {  // LY
        hw_state.ppu.ly = value;
        // Update STAT mode bits based on LY
        if (value >= 144) {
            // V-Blank period (mode 1)
            hw_state.ppu.stat = (hw_state.ppu.stat & 0xFC) | 0x01;
        }
    }
    if (addr >= 0xFF40 && addr <= 0xFF4B) {
        hw_write_ppu_reg(addr, value);
        return;
    }
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

    // Create CPU state type
    LLVMTypeRef field_types[] = {
        ctx->i8_type,  // a
        ctx->i8_type,  // f
        ctx->i8_type,  // b
        ctx->i8_type,  // c
        ctx->i8_type,  // d
        ctx->i8_type,  // e
        ctx->i8_type,  // h
        ctx->i8_type,  // l
        ctx->i16_type, // sp
        ctx->i16_type  // pc
    };
    ctx->cpu_state_type = LLVMStructCreateNamed(ctx->ctx, "gb_cpu_state");
    LLVMStructSetBody(ctx->cpu_state_type, field_types, 10, false);

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

// Instruction decoder
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
        case 0xAF:  // XOR A,A (A = 0)
            inst.name = "XOR A,A";
            inst.length = 1;
            break;
        case 0x21:  // LD HL,d16
            inst.name = "LD HL,d16";
            inst.length = 3;
            break;
        case 0x32:  // LD (HL-),A
            inst.name = "LD (HL-),A";
            inst.length = 1;
            break;
        case 0x40: // LD B,B
            inst.name = "LD B,B";
            break;
        case 0x41: // LD B,C
            inst.name = "LD B,C";
            break;
        case 0x80: // ADD A,B
            inst.name = "ADD A,B";
            break;
        case 0x81: // ADD A,C
            inst.name = "ADD A,C";
            break;
        case 0x90: // SUB B
            inst.name = "SUB B";
            break;
        case 0xA0: // AND B
            inst.name = "AND B";
            break;
        case 0xB0: // OR B
            inst.name = "OR B";
            break;
        case 0xF0: // LDH A,(a8)
            inst.name = "LDH A,(a8)";
            inst.length = 2;
            break;
        case 0xE0: // LDH (a8),A
            inst.name = "LDH (a8),A";
            inst.length = 2;
            break;
        case 0x2A: // LD A,(HL+)
            inst.name = "LD A,(HL+)";
            break;
        case 0x22: // LD (HL+),A
            inst.name = "LD (HL+),A";
            break;
        // 8-bit loads
        case 0x7E: // LD A,(HL)
            inst.name = "LD A,(HL)";
            break;
        case 0x77: // LD (HL),A
            inst.name = "LD (HL),A";
            break;
        // 16-bit loads
        case 0x11: // LD DE,d16
            inst.name = "LD DE,d16";
            inst.length = 3;
            break;
        // Stack operations
        case 0xC5: // PUSH BC
            inst.name = "PUSH BC";
            break;
        case 0xD5: // PUSH DE
            inst.name = "PUSH DE";
            break;
        case 0xE5: // PUSH HL
            inst.name = "PUSH HL";
            break;
        case 0xF5: // PUSH AF
            inst.name = "PUSH AF";
            break;
        // Conditional jumps
        case 0x20: // JR NZ,r8
            inst.name = "JR NZ,r8";
            inst.length = 2;
            break;
        case 0x28: // JR Z,r8
            inst.name = "JR Z,r8";
            inst.length = 2;
            break;
        case 0xC1: // POP BC
            inst.name = "POP BC";
            break;
        case 0xD1: // POP DE
            inst.name = "POP DE";
            break;
        case 0xE1: // POP HL
            inst.name = "POP HL";
            break;
        case 0xF1: // POP AF
            inst.name = "POP AF";
            break;
        case 0xC0: // RET NZ
            inst.name = "RET NZ";
            break;
        case 0xC8: // RET Z
            inst.name = "RET Z";
            break;
        case 0xC9: // RET
            inst.name = "RET";
            break;
        case 0xC4: // CALL NZ,a16
            inst.name = "CALL NZ,a16";
            inst.length = 3;
            break;
        case 0xCC: // CALL Z,a16
            inst.name = "CALL Z,a16";
            inst.length = 3;
            break;
        case 0xCD: // CALL a16
            inst.name = "CALL a16";
            inst.length = 3;
            break;
        case 0xC7: // RST 00H
            inst.name = "RST 00H";
            break;
        case 0xCF: // RST 08H
            inst.name = "RST 08H";
            break;
        case 0xD7: // RST 10H
            inst.name = "RST 10H";
            break;
        case 0xDF: // RST 18H
            inst.name = "RST 18H";
            break;
        case 0xE7: // RST 20H
            inst.name = "RST 20H";
            break;
        case 0xEF: // RST 28H
            inst.name = "RST 28H";
            break;
        case 0xF7: // RST 30H
            inst.name = "RST 30H";
            break;
        case 0xFF: // RST 38H
            inst.name = "RST 38H";
            break;
        case 0x82: // ADD A,D
            inst.name = "ADD A,D";
            break;
        case 0x83: // ADD A,E
            inst.name = "ADD A,E";
            break;
        case 0x84: // ADD A,H
            inst.name = "ADD A,H";
            break;
        case 0x85: // ADD A,L
            inst.name = "ADD A,L";
            break;
        case 0x86: // ADD A,(HL)
            inst.name = "ADD A,(HL)";
            break;
        case 0x87: // ADD A,A
            inst.name = "ADD A,A";
            break;
        case 0xC6: // ADD A,d8
            inst.name = "ADD A,d8";
            inst.length = 2;
            break;
        case 0x91: // SUB C
            inst.name = "SUB C";
            break;
        case 0x04: // INC B
            inst.name = "INC B";
            break;
        case 0x05: // DEC B
            inst.name = "DEC B";
            break;
        case 0x0C: // INC C
            inst.name = "INC C";
            break;
        case 0x0D: // DEC C
            inst.name = "DEC C";
            break;
        case 0xBE: // CP (HL)
            inst.name = "CP (HL)";
            inst.length = 1;
            break;
        // In decode_instruction, add:
        case 0xFE:  // CP d8
            inst.name = "CP d8";
            inst.length = 2;
            break;
        case 0xB8:  // CP B
            inst.name = "CP B";
            break;
        case 0xB9:  // CP C
            inst.name = "CP C";
            break;
        case 0xBA:  // CP D
            inst.name = "CP D";
            break;
        case 0xBB:  // CP E
            inst.name = "CP E";
            break;
        case 0xBC:  // CP H
            inst.name = "CP H";
            break;
        case 0xBD:  // CP L
            inst.name = "CP L";
            break;
        case 0xBF:  // CP A
            inst.name = "CP A";
            break;
        case 0xCE:  // ADC A,d8
            inst.name = "ADC A,d8";
            inst.length = 2;
            break;
        default:
            inst.name = "Unknown";
            break;
    }
    return inst;
}

static bool translate_xor_a(struct translation_ctx *ctx) {
    // Get pointer to A register
    LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                            ctx->cpu_state_ptr, 0, "a_ptr");
    // Store zero
    LLVMBuildStore(ctx->builder, LLVMConstInt(ctx->i8_type, 0, false), a_ptr);
    return true;
}

static bool translate_ld_hl_d16(struct translation_ctx *ctx, uint16_t value) {
    // Get pointer to HL
    LLVMValueRef hl_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, 3, "hl_ptr");
    // Store 16-bit immediate
    LLVMBuildStore(ctx->builder, LLVMConstInt(ctx->i16_type, value, false), hl_ptr);
    return true;
}

static bool translate_ld_hl_dec_a(struct translation_ctx *ctx) {
    // Load current HL
    LLVMValueRef hl_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, 3, "hl_ptr");
    LLVMValueRef hl = LLVMBuildLoad2(ctx->builder, ctx->i16_type, hl_ptr, "hl");
    
    // Load A value
    LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                            ctx->cpu_state_ptr, 0, "a_ptr");
    LLVMValueRef a = LLVMBuildLoad2(ctx->builder, ctx->i8_type, a_ptr, "a");

    // Store A to memory at (HL)
    LLVMValueRef args[] = { hl, a };
    LLVMBuildCall2(ctx->builder, ctx->write_memory_type, 
                   ctx->write_memory_fn, args, 2, "");

    // Decrement HL
    LLVMValueRef new_hl = LLVMBuildSub(ctx->builder, hl,
        LLVMConstInt(ctx->i16_type, 1, false), "hl_dec");
    LLVMBuildStore(ctx->builder, new_hl, hl_ptr);
    
    return true;
}

static bool translate_jp_a16(struct translation_ctx *ctx, uint16_t addr) {
    // Create a new basic block for the jump target
    char block_name[32];
    snprintf(block_name, sizeof(block_name), "addr_%04X", addr);
    LLVMBasicBlockRef target_block = LLVMAppendBasicBlock(ctx->current_function, block_name);

    // Jump to the target block
    LLVMBuildBr(ctx->builder, target_block);

    // Position builder at the new block
    LLVMPositionBuilderAtEnd(ctx->builder, target_block);

    return true;
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


static LLVMValueRef get_flag_mask(struct translation_ctx *ctx, uint8_t flag) {
    return LLVMConstInt(ctx->i8_type, flag, false);
}

static bool translate_ldh_a8(struct translation_ctx *ctx, uint8_t offset, bool to_a) {
    // High RAM access ($FF00 + offset)
    uint16_t addr = 0xFF00 + offset;
    
    if (to_a) {
        return translate_ld_a_mem(ctx, addr);
    } else {
        return translate_ld_mem_a(ctx, addr);
    }
}

static bool translate_ld_hl_inc_a(struct translation_ctx *ctx, bool to_a) {
    // Load current HL
    LLVMValueRef hl_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                           ctx->cpu_state_ptr, 6, "hl_ptr");
    LLVMValueRef hl = LLVMBuildLoad2(ctx->builder, ctx->i16_type, hl_ptr, "hl");

    if (to_a) {
        // LD A,(HL+)
        // Read from memory
        LLVMValueRef args[] = { hl };
        LLVMValueRef val = LLVMBuildCall2(ctx->builder, ctx->read_memory_type,
                                       ctx->read_memory_fn, args, 1, "mem_val");
        
        // Store to A
        LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                              ctx->cpu_state_ptr, 0, "a_ptr");
        LLVMBuildStore(ctx->builder, val, a_ptr);
    } else {
        // LD (HL+),A
        // Load A
        LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                              ctx->cpu_state_ptr, 0, "a_ptr");
        LLVMValueRef a = LLVMBuildLoad2(ctx->builder, ctx->i8_type, a_ptr, "a");

        // Write to memory
        LLVMValueRef args[] = { hl, a };
        LLVMBuildCall2(ctx->builder, ctx->write_memory_type,
                     ctx->write_memory_fn, args, 2, "");
    }

    // Increment HL
    LLVMValueRef new_hl = LLVMBuildAdd(ctx->builder, hl,
        LLVMConstInt(ctx->i16_type, 1, false), "hl_inc");
    LLVMBuildStore(ctx->builder, new_hl, hl_ptr);

    return true;
}


static LLVMValueRef get_flag_z(struct translation_ctx *ctx) {
    // Get F register
    LLVMValueRef f_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                            ctx->cpu_state_ptr, 1, "f_ptr");
    LLVMValueRef f = LLVMBuildLoad2(ctx->builder, ctx->i8_type, f_ptr, "f");
    
    // Extract Z flag (bit 7)
    return LLVMBuildAnd(ctx->builder, f, 
                        LLVMConstInt(ctx->i8_type, 0x80, false), "z_flag");
}

static void set_flag_z(struct translation_ctx *ctx, LLVMValueRef value) {
    // Get F register
    LLVMValueRef f_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                            ctx->cpu_state_ptr, 1, "f_ptr");
    LLVMValueRef f = LLVMBuildLoad2(ctx->builder, ctx->i8_type, f_ptr, "f");
    
    // Clear Z flag and set new value
    LLVMValueRef new_f = LLVMBuildOr(ctx->builder,
        LLVMBuildAnd(ctx->builder, f, LLVMConstInt(ctx->i8_type, 0x7F, false), "f_cleared"),
        LLVMBuildShl(ctx->builder, value, LLVMConstInt(ctx->i8_type, 7, false), "z_shifted"),
        "f_new");
    
    LLVMBuildStore(ctx->builder, new_f, f_ptr);
}

static bool translate_ld_hl(struct translation_ctx *ctx, bool to_a) {
    // Get HL pointer
    LLVMValueRef h_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                            ctx->cpu_state_ptr, 6, "h_ptr");
    LLVMValueRef l_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                            ctx->cpu_state_ptr, 7, "l_ptr");
    
    // Load H and L
    LLVMValueRef h = LLVMBuildLoad2(ctx->builder, ctx->i8_type, h_ptr, "h");
    LLVMValueRef l = LLVMBuildLoad2(ctx->builder, ctx->i8_type, l_ptr, "l");
    
    // Create 16-bit address
    LLVMValueRef hl = LLVMBuildOr(ctx->builder,
        LLVMBuildShl(ctx->builder, h, LLVMConstInt(ctx->i8_type, 8, false), "h_shifted"),
        l, "hl");
    
    if (to_a) {
        // LD A,(HL)
        LLVMValueRef args[] = { hl };
        LLVMValueRef val = LLVMBuildCall2(ctx->builder, ctx->read_memory_type,
                                         ctx->read_memory_fn, args, 1, "mem_val");
        
        LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                                ctx->cpu_state_ptr, 0, "a_ptr");
        LLVMBuildStore(ctx->builder, val, a_ptr);
    } else {
        // LD (HL),A
        LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                                ctx->cpu_state_ptr, 0, "a_ptr");
        LLVMValueRef a = LLVMBuildLoad2(ctx->builder, ctx->i8_type, a_ptr, "a");
        
        LLVMValueRef args[] = { hl, a };
        LLVMBuildCall2(ctx->builder, ctx->write_memory_type,
                       ctx->write_memory_fn, args, 2, "");
    }
    
    return true;
}

static bool translate_push_rr(struct translation_ctx *ctx, int hi_idx, int lo_idx) {
    // Load SP
    LLVMValueRef sp_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, 8, "sp_ptr");
    LLVMValueRef sp = LLVMBuildLoad2(ctx->builder, ctx->i16_type, sp_ptr, "sp");
    
    // Load high and low bytes
    LLVMValueRef hi_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, hi_idx, "hi_ptr");
    LLVMValueRef lo_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, lo_idx, "lo_ptr");
    
    LLVMValueRef hi = LLVMBuildLoad2(ctx->builder, ctx->i8_type, hi_ptr, "hi");
    LLVMValueRef lo = LLVMBuildLoad2(ctx->builder, ctx->i8_type, lo_ptr, "lo");
    
    // Decrement SP and write high byte
    LLVMValueRef new_sp = LLVMBuildSub(ctx->builder, sp,
        LLVMConstInt(ctx->i16_type, 1, false), "sp_dec");
    LLVMBuildStore(ctx->builder, new_sp, sp_ptr);
    
    LLVMValueRef args1[] = { new_sp, hi };
    LLVMBuildCall2(ctx->builder, ctx->write_memory_type,
                   ctx->write_memory_fn, args1, 2, "");
    
    // Decrement SP and write low byte
    new_sp = LLVMBuildSub(ctx->builder, new_sp,
        LLVMConstInt(ctx->i16_type, 1, false), "sp_dec2");
    LLVMBuildStore(ctx->builder, new_sp, sp_ptr);
    
    LLVMValueRef args2[] = { new_sp, lo };
    LLVMBuildCall2(ctx->builder, ctx->write_memory_type,
                   ctx->write_memory_fn, args2, 2, "");
    
    return true;
}

static bool translate_pop_rr(struct translation_ctx *ctx, int hi_idx, int lo_idx) {
    // Load SP
    LLVMValueRef sp_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, 8, "sp_ptr");
    LLVMValueRef sp = LLVMBuildLoad2(ctx->builder, ctx->i16_type, sp_ptr, "sp");
    
    // Read low byte first
    LLVMValueRef args1[] = { sp };
    LLVMValueRef lo = LLVMBuildCall2(ctx->builder, ctx->read_memory_type,
                                    ctx->read_memory_fn, args1, 1, "lo");
    
    // Increment SP and read high byte
    LLVMValueRef new_sp = LLVMBuildAdd(ctx->builder, sp,
        LLVMConstInt(ctx->i16_type, 1, false), "sp_inc");
    LLVMBuildStore(ctx->builder, new_sp, sp_ptr);
    
    LLVMValueRef args2[] = { new_sp };
    LLVMValueRef hi = LLVMBuildCall2(ctx->builder, ctx->read_memory_type,
                                    ctx->read_memory_fn, args2, 1, "hi");
    
    // Increment SP again
    new_sp = LLVMBuildAdd(ctx->builder, new_sp,
        LLVMConstInt(ctx->i16_type, 1, false), "sp_inc2");
    LLVMBuildStore(ctx->builder, new_sp, sp_ptr);
    
    // Store values in registers
    LLVMValueRef hi_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, hi_idx, "hi_ptr");
    LLVMValueRef lo_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, lo_idx, "lo_ptr");
    
    // For AF pair, mask F register value
    if (hi_idx == 0 && lo_idx == 1) {  // AF pair
        // Only bits 7-4 of F are used
        lo = LLVMBuildAnd(ctx->builder, lo,
            LLVMConstInt(ctx->i8_type, 0xF0, false), "f_masked");
    }
    
    LLVMBuildStore(ctx->builder, hi, hi_ptr);
    LLVMBuildStore(ctx->builder, lo, lo_ptr);
    
    return true;
}

static bool translate_ret(struct translation_ctx *ctx, bool conditional, bool condition) {
    // For conditional RET, we need to check the Z flag
    LLVMBasicBlockRef ret_block = NULL;
    LLVMBasicBlockRef continue_block = NULL;
    
    if (conditional) {
        // Create blocks for the conditional
        ret_block = LLVMAppendBasicBlock(ctx->current_function, "ret");
        continue_block = LLVMAppendBasicBlock(ctx->current_function, "ret_continue");
        
        // Get Z flag
        LLVMValueRef z_flag = get_flag_z(ctx);
        
        // Compare with zero (for NZ) or non-zero (for Z)
        LLVMValueRef cond;
        if (condition) { // RET Z
            cond = LLVMBuildICmp(ctx->builder, LLVMIntNE,
                z_flag, LLVMConstInt(ctx->i8_type, 0, false), "z_check");
        } else { // RET NZ
            cond = LLVMBuildICmp(ctx->builder, LLVMIntEQ,
                z_flag, LLVMConstInt(ctx->i8_type, 0, false), "nz_check");
        }
        
        LLVMBuildCondBr(ctx->builder, cond, ret_block, continue_block);
        
        // Position at ret block
        LLVMPositionBuilderAtEnd(ctx->builder, ret_block);
    }
    
    // Load SP
    LLVMValueRef sp_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, 8, "sp_ptr");
    LLVMValueRef sp = LLVMBuildLoad2(ctx->builder, ctx->i16_type, sp_ptr, "sp");
    
    // Read return address (low byte first)
    LLVMValueRef args1[] = { sp };
    LLVMValueRef pcl = LLVMBuildCall2(ctx->builder, ctx->read_memory_type,
                                     ctx->read_memory_fn, args1, 1, "pcl");
    
    // Increment SP and read high byte
    LLVMValueRef new_sp = LLVMBuildAdd(ctx->builder, sp,
        LLVMConstInt(ctx->i16_type, 1, false), "sp_inc");
    
    LLVMValueRef args2[] = { new_sp };
    LLVMValueRef pch = LLVMBuildCall2(ctx->builder, ctx->read_memory_type,
                                     ctx->read_memory_fn, args2, 1, "pch");
    
    // Increment SP again
    new_sp = LLVMBuildAdd(ctx->builder, new_sp,
        LLVMConstInt(ctx->i16_type, 1, false), "sp_inc2");
    LLVMBuildStore(ctx->builder, new_sp, sp_ptr);
    
    // Combine into 16-bit address
    LLVMValueRef ret_addr = LLVMBuildOr(ctx->builder,
        LLVMBuildShl(ctx->builder, pch, LLVMConstInt(ctx->i16_type, 8, false), "pch_shifted"),
        LLVMBuildZExt(ctx->builder, pcl, ctx->i16_type, "pcl_ext"),
        "ret_addr");
    
    // Create a new basic block for the return target
    char block_name[32];
    snprintf(block_name, sizeof(block_name), "ret_%04X", 0); // We don't know the actual address yet
    LLVMBasicBlockRef target_block = LLVMAppendBasicBlock(ctx->current_function, block_name);
    
    // Branch to the target
    LLVMBuildBr(ctx->builder, target_block);
    
    if (conditional) {
        // Position at continue block and create branch
        LLVMPositionBuilderAtEnd(ctx->builder, continue_block);
        LLVMBuildBr(ctx->builder, target_block);
    }
    
    // Position at new block
    LLVMPositionBuilderAtEnd(ctx->builder, target_block);
    
    return true;
}

static bool translate_call(struct translation_ctx *ctx, const uint8_t *code, bool conditional, bool condition) {
    uint16_t target_addr = code[1] | (code[2] << 8);
    
    // For conditional CALL, we need to check the Z flag
    LLVMBasicBlockRef call_block = NULL;
    LLVMBasicBlockRef continue_block = NULL;
    
    if (conditional) {
        // Create blocks for the conditional
        call_block = LLVMAppendBasicBlock(ctx->current_function, "call");
        continue_block = LLVMAppendBasicBlock(ctx->current_function, "call_continue");
        
        // Get Z flag
        LLVMValueRef z_flag = get_flag_z(ctx);
        
        // Compare with zero (for NZ) or non-zero (for Z)
        LLVMValueRef cond;
        if (condition) { // CALL Z
            cond = LLVMBuildICmp(ctx->builder, LLVMIntNE,
                z_flag, LLVMConstInt(ctx->i8_type, 0, false), "z_check");
        } else { // CALL NZ
            cond = LLVMBuildICmp(ctx->builder, LLVMIntEQ,
                z_flag, LLVMConstInt(ctx->i8_type, 0, false), "nz_check");
        }
        
        LLVMBuildCondBr(ctx->builder, cond, call_block, continue_block);
        
        // Position at call block
        LLVMPositionBuilderAtEnd(ctx->builder, call_block);
    }
    
    // Get SP
    LLVMValueRef sp_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, 8, "sp_ptr");
    LLVMValueRef sp = LLVMBuildLoad2(ctx->builder, ctx->i16_type, sp_ptr, "sp");
    
    // Calculate return address (current PC + instruction length)
    uint16_t return_addr = (uint16_t)(target_addr + 3);  // 3 is the length of CALL instruction
    
    // Push return address (high byte first)
    LLVMValueRef new_sp = LLVMBuildSub(ctx->builder, sp,
        LLVMConstInt(ctx->i16_type, 1, false), "sp_dec");
    
    // Push high byte
    LLVMValueRef args1[] = { 
        new_sp,
        LLVMConstInt(ctx->i8_type, (return_addr >> 8) & 0xFF, false)
    };
    LLVMBuildCall2(ctx->builder, ctx->write_memory_type,
                   ctx->write_memory_fn, args1, 2, "");
    
    // Push low byte
    new_sp = LLVMBuildSub(ctx->builder, new_sp,
        LLVMConstInt(ctx->i16_type, 1, false), "sp_dec2");
    
    LLVMValueRef args2[] = {
        new_sp,
        LLVMConstInt(ctx->i8_type, return_addr & 0xFF, false)
    };
    LLVMBuildCall2(ctx->builder, ctx->write_memory_type,
                   ctx->write_memory_fn, args2, 2, "");
    
    // Update SP
    LLVMBuildStore(ctx->builder, new_sp, sp_ptr);
    
    // Create target block and branch to it
    char block_name[32];
    snprintf(block_name, sizeof(block_name), "addr_%04X", target_addr);
    LLVMBasicBlockRef target_block = LLVMAppendBasicBlock(ctx->current_function, block_name);
    LLVMBuildBr(ctx->builder, target_block);
    
    if (conditional) {
        // Position at continue block and create branch
        LLVMPositionBuilderAtEnd(ctx->builder, continue_block);
        LLVMBuildBr(ctx->builder, target_block);
    }
    
    // Position at new block
    LLVMPositionBuilderAtEnd(ctx->builder, target_block);
    
    return true;
}

static bool translate_rst(struct translation_ctx *ctx, uint8_t vector) {
    // RST pushes current PC and jumps to a fixed address
    uint16_t target_addr = vector;
    
    // Get SP
    LLVMValueRef sp_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, 8, "sp_ptr");
    LLVMValueRef sp = LLVMBuildLoad2(ctx->builder, ctx->i16_type, sp_ptr, "sp");
    
    // For RST, return address is just current PC + 1 (RST is 1 byte)
    uint16_t return_addr = target_addr + 1;
    
    // Push return address (high byte first)
    LLVMValueRef new_sp = LLVMBuildSub(ctx->builder, sp,
        LLVMConstInt(ctx->i16_type, 1, false), "sp_dec");
    
    // Push high byte
    LLVMValueRef args1[] = { 
        new_sp,
        LLVMConstInt(ctx->i8_type, (return_addr >> 8) & 0xFF, false)
    };
    LLVMBuildCall2(ctx->builder, ctx->write_memory_type,
                   ctx->write_memory_fn, args1, 2, "");
    
    // Push low byte
    new_sp = LLVMBuildSub(ctx->builder, new_sp,
        LLVMConstInt(ctx->i16_type, 1, false), "sp_dec2");
    
    LLVMValueRef args2[] = {
        new_sp,
        LLVMConstInt(ctx->i8_type, return_addr & 0xFF, false)
    };
    LLVMBuildCall2(ctx->builder, ctx->write_memory_type,
                   ctx->write_memory_fn, args2, 2, "");
    
    // Update SP
    LLVMBuildStore(ctx->builder, new_sp, sp_ptr);
    
    // Create target block and branch to it
    char block_name[32];
    snprintf(block_name, sizeof(block_name), "rst_%02X", vector);
    LLVMBasicBlockRef target_block = LLVMAppendBasicBlock(ctx->current_function, block_name);
    LLVMBuildBr(ctx->builder, target_block);
    
    // Position at new block
    LLVMPositionBuilderAtEnd(ctx->builder, target_block);
    
    return true;
}

static LLVMValueRef get_flag_c(struct translation_ctx *ctx) {
    // Get F register
    LLVMValueRef f_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                           ctx->cpu_state_ptr, 1, "f_ptr");
    LLVMValueRef f = LLVMBuildLoad2(ctx->builder, ctx->i8_type, f_ptr, "f");
    
    // Extract C flag (bit 4) and shift it to bit 0
    LLVMValueRef c = LLVMBuildLShr(ctx->builder, f,
        LLVMConstInt(ctx->i8_type, 4, false), "c_shifted");
    return LLVMBuildAnd(ctx->builder, c,
        LLVMConstInt(ctx->i8_type, 0x01, false), "c_flag");
}

static void update_flags_add(struct translation_ctx *ctx, LLVMValueRef result, 
                           LLVMValueRef a, LLVMValueRef b, LLVMValueRef carry) {
    // Get F register pointer
    LLVMValueRef f_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                           ctx->cpu_state_ptr, 1, "f_ptr");
    
    // Zero flag (bit 7) - Set if result is zero
    LLVMValueRef zero = LLVMBuildICmp(ctx->builder, LLVMIntEQ,
        result, LLVMConstInt(ctx->i8_type, 0, false), "zero");
    LLVMValueRef z_flag = LLVMBuildZExt(ctx->builder, zero, ctx->i8_type, "z_flag");
    z_flag = LLVMBuildShl(ctx->builder, z_flag, 
        LLVMConstInt(ctx->i8_type, 7, false), "z_flag_shifted");
    
    // Subtract flag (bit 6) - Reset for addition
    LLVMValueRef n_flag = LLVMConstInt(ctx->i8_type, 0, false);
    
    // Half carry flag (bit 5) - Set if carry from bit 3
    // For ADC, need to include the carry in the calculation
    LLVMValueRef h_sum = LLVMBuildAdd(ctx->builder,
        LLVMBuildAdd(ctx->builder,
            LLVMBuildAnd(ctx->builder, a, LLVMConstInt(ctx->i8_type, 0x0F, false), "a_low"),
            LLVMBuildAnd(ctx->builder, b, LLVMConstInt(ctx->i8_type, 0x0F, false), "b_low"),
            "low_sum"),
        carry, "low_sum_c");
    LLVMValueRef h = LLVMBuildICmp(ctx->builder, LLVMIntUGT,
        h_sum, LLVMConstInt(ctx->i8_type, 0x0F, false), "h_carry");
    LLVMValueRef h_flag = LLVMBuildZExt(ctx->builder, h, ctx->i8_type, "h_flag");
    h_flag = LLVMBuildShl(ctx->builder, h_flag,
        LLVMConstInt(ctx->i8_type, 5, false), "h_flag_shifted");
    
    // Carry flag (bit 4) - Set if result overflowed
    // For ADC, need 16 bits to handle the carry
    LLVMValueRef sum = LLVMBuildAdd(ctx->builder,
        LLVMBuildAdd(ctx->builder,
            LLVMBuildZExt(ctx->builder, a, ctx->i16_type, "a_ext"),
            LLVMBuildZExt(ctx->builder, b, ctx->i16_type, "b_ext"),
            "sum"),
        LLVMBuildZExt(ctx->builder, carry, ctx->i16_type, "carry_ext"),
        "sum_c");
    LLVMValueRef c = LLVMBuildICmp(ctx->builder, LLVMIntUGT,
        sum, LLVMConstInt(ctx->i16_type, 0xFF, false), "carry");
    LLVMValueRef c_flag = LLVMBuildZExt(ctx->builder, c, ctx->i8_type, "c_flag");
    c_flag = LLVMBuildShl(ctx->builder, c_flag,
        LLVMConstInt(ctx->i8_type, 4, false), "c_flag_shifted");
    
    // Combine flags
    LLVMValueRef flags = LLVMBuildOr(ctx->builder,
        LLVMBuildOr(ctx->builder,
            LLVMBuildOr(ctx->builder, z_flag, n_flag, "flags_1"),
            h_flag, "flags_2"),
        c_flag, "flags_final");
    
    // Store flags
    LLVMBuildStore(ctx->builder, flags, f_ptr);
}

static bool translate_add_a_r(struct translation_ctx *ctx, int reg_idx) {
    // Get A register
    LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                           ctx->cpu_state_ptr, 0, "a_ptr");
    LLVMValueRef a = LLVMBuildLoad2(ctx->builder, ctx->i8_type, a_ptr, "a");
    
    // Get source register
    LLVMValueRef src_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, reg_idx, "src_ptr");
    LLVMValueRef src = LLVMBuildLoad2(ctx->builder, ctx->i8_type, src_ptr, "src");
    
    // Perform addition
    LLVMValueRef result = LLVMBuildAdd(ctx->builder, a, src, "add_result");
    
    // Update flags with carry=0
    update_flags_add(ctx, result, a, src, LLVMConstInt(ctx->i8_type, 0, false));
    
    // Store result in A
    LLVMBuildStore(ctx->builder, result, a_ptr);
    
    return true;
}

static bool translate_add_a_n(struct translation_ctx *ctx, uint8_t n) {
    // Get A register
    LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                           ctx->cpu_state_ptr, 0, "a_ptr");
    LLVMValueRef a = LLVMBuildLoad2(ctx->builder, ctx->i8_type, a_ptr, "a");
    
    // Create immediate value
    LLVMValueRef imm = LLVMConstInt(ctx->i8_type, n, false);
    
    // Perform addition
    LLVMValueRef result = LLVMBuildAdd(ctx->builder, a, imm, "add_result");
    
    // Update flags with carry=0
    update_flags_add(ctx, result, a, imm, LLVMConstInt(ctx->i8_type, 0, false));
    
    // Store result in A
    LLVMBuildStore(ctx->builder, result, a_ptr);
    
    return true;
}

static bool translate_inc_r(struct translation_ctx *ctx, int reg_idx) {
    // Get register
    LLVMValueRef reg_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                              ctx->cpu_state_ptr, reg_idx, "reg_ptr");
    LLVMValueRef reg = LLVMBuildLoad2(ctx->builder, ctx->i8_type, reg_ptr, "reg");
    
    // Increment
    LLVMValueRef result = LLVMBuildAdd(ctx->builder, reg,
        LLVMConstInt(ctx->i8_type, 1, false), "inc_result");
    
    // Update Z and H flags (N is reset)
    LLVMValueRef f_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                            ctx->cpu_state_ptr, 1, "f_ptr");
    LLVMValueRef f = LLVMBuildLoad2(ctx->builder, ctx->i8_type, f_ptr, "f");
    
    // Zero flag
    LLVMValueRef zero = LLVMBuildICmp(ctx->builder, LLVMIntEQ,
        result, LLVMConstInt(ctx->i8_type, 0, false), "zero");
    LLVMValueRef z_flag = LLVMBuildZExt(ctx->builder, zero, ctx->i8_type, "z_flag");
    z_flag = LLVMBuildShl(ctx->builder, z_flag,
        LLVMConstInt(ctx->i8_type, 7, false), "z_flag_shifted");
    
    // Half carry flag
    LLVMValueRef h = LLVMBuildAnd(ctx->builder,
        result, LLVMConstInt(ctx->i8_type, 0x0F, false), "h_check");
    LLVMValueRef h_flag = LLVMBuildICmp(ctx->builder, LLVMIntEQ,
        h, LLVMConstInt(ctx->i8_type, 0, false), "h_flag");
    h_flag = LLVMBuildZExt(ctx->builder, h_flag, ctx->i8_type, "h_flag_ext");
    h_flag = LLVMBuildShl(ctx->builder, h_flag,
        LLVMConstInt(ctx->i8_type, 5, false), "h_flag_shifted");
    
    // Combine flags (preserve C, reset N, update Z and H)
    LLVMValueRef new_f = LLVMBuildOr(ctx->builder,
        LLVMBuildAnd(ctx->builder, f,
            LLVMConstInt(ctx->i8_type, 0x10, false), "f_mask"), // preserve C
        LLVMBuildOr(ctx->builder, z_flag, h_flag, "flags_combined"),
        "new_f");
    
    LLVMBuildStore(ctx->builder, new_f, f_ptr);
    
    // Store result
    LLVMBuildStore(ctx->builder, result, reg_ptr);
    
    return true;
}

static void update_flags_sub(struct translation_ctx *ctx, LLVMValueRef result, 
                           LLVMValueRef a, LLVMValueRef b, bool store_result) {
    // Get F register pointer
    LLVMValueRef f_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                            ctx->cpu_state_ptr, 1, "f_ptr");
    
    // Zero flag (bit 7) - Set if result is zero
    LLVMValueRef zero = LLVMBuildICmp(ctx->builder, LLVMIntEQ,
        result, LLVMConstInt(ctx->i8_type, 0, false), "zero");
    LLVMValueRef z_flag = LLVMBuildZExt(ctx->builder, zero, ctx->i8_type, "z_flag");
    z_flag = LLVMBuildShl(ctx->builder, z_flag, 
        LLVMConstInt(ctx->i8_type, 7, false), "z_flag_shifted");
    
    // Subtract flag (bit 6) - Set for subtraction
    LLVMValueRef n_flag = LLVMConstInt(ctx->i8_type, 0x40, false);
    
    // Half carry flag (bit 5) - Set if borrow from bit 4
    LLVMValueRef h = LLVMBuildAnd(ctx->builder,
        LLVMBuildXor(ctx->builder,
            LLVMBuildXor(ctx->builder, a, b, "h_xor1"),
            result, "h_xor2"),
        LLVMConstInt(ctx->i8_type, 0x10, false), "h_and");
    LLVMValueRef h_flag = LLVMBuildLShr(ctx->builder, h,
        LLVMConstInt(ctx->i8_type, 1, false), "h_flag_shifted");
    
    // Carry flag (bit 4) - Set if result required borrow
    LLVMValueRef c = LLVMBuildICmp(ctx->builder, LLVMIntULT,
        a, b, "borrow");
    LLVMValueRef c_flag = LLVMBuildZExt(ctx->builder, c, ctx->i8_type, "c_flag");
    c_flag = LLVMBuildShl(ctx->builder, c_flag,
        LLVMConstInt(ctx->i8_type, 4, false), "c_flag_shifted");
    
    // Combine flags
    LLVMValueRef flags = LLVMBuildOr(ctx->builder,
        LLVMBuildOr(ctx->builder,
            LLVMBuildOr(ctx->builder, z_flag, n_flag, "flags_1"),
            h_flag, "flags_2"),
        c_flag, "flags_final");
    
    // Store flags
    LLVMBuildStore(ctx->builder, flags, f_ptr);
    
    // For CP, we don't store the result
    if (store_result) {
        // Get A register pointer and store result
        LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                               ctx->cpu_state_ptr, 0, "a_ptr");
        LLVMBuildStore(ctx->builder, result, a_ptr);
    }
}

static bool translate_cp_hl(struct translation_ctx *ctx) {
    // Get A register
    LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                           ctx->cpu_state_ptr, 0, "a_ptr");
    LLVMValueRef a = LLVMBuildLoad2(ctx->builder, ctx->i8_type, a_ptr, "a");
    
    // Get HL pointer
    LLVMValueRef h_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                           ctx->cpu_state_ptr, 6, "h_ptr");
    LLVMValueRef l_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                           ctx->cpu_state_ptr, 7, "l_ptr");
    
    // Load H and L
    LLVMValueRef h = LLVMBuildLoad2(ctx->builder, ctx->i8_type, h_ptr, "h");
    LLVMValueRef l = LLVMBuildLoad2(ctx->builder, ctx->i8_type, l_ptr, "l");
    
    // Create 16-bit address
    LLVMValueRef hl = LLVMBuildOr(ctx->builder,
        LLVMBuildShl(ctx->builder, h, LLVMConstInt(ctx->i8_type, 8, false), "h_shifted"),
        l, "hl");
    
    // Read memory at (HL)
    LLVMValueRef args[] = { hl };
    LLVMValueRef value = LLVMBuildCall2(ctx->builder, ctx->read_memory_type,
                                      ctx->read_memory_fn, args, 1, "mem_val");
    
    // Perform subtraction
    LLVMValueRef result = LLVMBuildSub(ctx->builder, a, value, "cp_result");
    
    // Update flags but don't store result
    update_flags_sub(ctx, result, a, value, false);
    
    return true;
}

static bool translate_cp_n(struct translation_ctx *ctx, uint8_t n) {
    // Get A register
    LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                           ctx->cpu_state_ptr, 0, "a_ptr");
    LLVMValueRef a = LLVMBuildLoad2(ctx->builder, ctx->i8_type, a_ptr, "a");
    
    // Create immediate value
    LLVMValueRef imm = LLVMConstInt(ctx->i8_type, n, false);
    
    // Perform subtraction
    LLVMValueRef result = LLVMBuildSub(ctx->builder, a, imm, "cp_result");
    
    // Update flags but don't store result
    update_flags_sub(ctx, result, a, imm, false);
    
    return true;
}

static bool translate_cp_r(struct translation_ctx *ctx, int reg_idx) {
    // Get A register
    LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                           ctx->cpu_state_ptr, 0, "a_ptr");
    LLVMValueRef a = LLVMBuildLoad2(ctx->builder, ctx->i8_type, a_ptr, "a");
    
    // Get source register
    LLVMValueRef src_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                             ctx->cpu_state_ptr, reg_idx, "src_ptr");
    LLVMValueRef src = LLVMBuildLoad2(ctx->builder, ctx->i8_type, src_ptr, "src");
    
    // Perform subtraction
    LLVMValueRef result = LLVMBuildSub(ctx->builder, a, src, "cp_result");
    
    // Update flags but don't store result
    update_flags_sub(ctx, result, a, src, false);
    
    return true;
}

static bool translate_adc_n(struct translation_ctx *ctx, uint8_t n) {
    // Get A register
    LLVMValueRef a_ptr = LLVMBuildStructGEP2(ctx->builder, ctx->cpu_state_type,
                                           ctx->cpu_state_ptr, 0, "a_ptr");
    LLVMValueRef a = LLVMBuildLoad2(ctx->builder, ctx->i8_type, a_ptr, "a");
    
    // Get carry flag
    LLVMValueRef carry = get_flag_c(ctx);
    
    // Create immediate value
    LLVMValueRef imm = LLVMConstInt(ctx->i8_type, n, false);
    
    // Add with carry
    LLVMValueRef sum = LLVMBuildAdd(ctx->builder,
        LLVMBuildAdd(ctx->builder, a, imm, "sum"),
        carry, "sum_c");
    
    // Truncate to 8 bits
    LLVMValueRef result = LLVMBuildTrunc(ctx->builder, sum, ctx->i8_type, "result");
    
    // Update flags
    update_flags_add(ctx, result, a, imm, carry);
    
    // Store result in A
    LLVMBuildStore(ctx->builder, result, a_ptr);
    
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

        case 0xC3: { // JP a16
            uint16_t addr = code[1] | (code[2] << 8);
            return translate_jp_a16(ctx, addr);
        }

        case 0xF0:  // LDH A,(a8)
            return translate_ldh_a8(ctx, code[1], true);

        case 0xE0:  // LDH (a8),A
            return translate_ldh_a8(ctx, code[1], false);

        case 0x2A:  // LD A,(HL+)
            return translate_ld_hl_inc_a(ctx, true);

        case 0x22:  // LD (HL+),A
            return translate_ld_hl_inc_a(ctx, false);

        case 0x7E:  // LD A,(HL)
            return translate_ld_hl(ctx, true);
        case 0x77:  // LD (HL),A
            return translate_ld_hl(ctx, false);
        case 0xC5:  // PUSH BC
            return translate_push_rr(ctx, 2, 3);  // B = 2, C = 3
        case 0xD5:  // PUSH DE
            return translate_push_rr(ctx, 4, 5);  // D = 4, E = 5
        case 0xE5:  // PUSH HL
            return translate_push_rr(ctx, 6, 7);  // H = 6, L = 7
        case 0xF5:  // PUSH AF
            return translate_push_rr(ctx, 0, 1);  // A = 0, F = 1
        case 0xC1:  // POP BC
            return translate_pop_rr(ctx, 2, 3);  // B = 2, C = 3
        case 0xD1:  // POP DE
            return translate_pop_rr(ctx, 4, 5);  // D = 4, E = 5
        case 0xE1:  // POP HL
            return translate_pop_rr(ctx, 6, 7);  // H = 6, L = 7
        case 0xF1:  // POP AF
            return translate_pop_rr(ctx, 0, 1);  // A = 0, F = 1
        case 0xC0:  // RET NZ
            return translate_ret(ctx, true, false);
        case 0xC8:  // RET Z
            return translate_ret(ctx, true, true);
        case 0xC9:  // RET
            return translate_ret(ctx, false, false);
        case 0xC4:  // CALL NZ,a16
            return translate_call(ctx, code, true, false);
        case 0xCC:  // CALL Z,a16
            return translate_call(ctx, code, true, true);
        case 0xCD:  // CALL a16
            return translate_call(ctx, code, false, false);
        case 0xC7:  // RST 00H
            return translate_rst(ctx, 0x00);
        case 0xCF:  // RST 08H
            return translate_rst(ctx, 0x08);
        case 0xD7:  // RST 10H
            return translate_rst(ctx, 0x10);
        case 0xDF:  // RST 18H
            return translate_rst(ctx, 0x18);
        case 0xE7:  // RST 20H
            return translate_rst(ctx, 0x20);
        case 0xEF:  // RST 28H
            return translate_rst(ctx, 0x28);
        case 0xF7:  // RST 30H
            return translate_rst(ctx, 0x30);
        case 0xFF:  // RST 38H
            return translate_rst(ctx, 0x38);
        case 0x80: // ADD A,B
            return translate_add_a_r(ctx, 2);  // B = 2
        case 0x81: // ADD A,C
            return translate_add_a_r(ctx, 3);  // C = 3
        case 0x82: // ADD A,D
            return translate_add_a_r(ctx, 4);  // D = 4
        case 0x83: // ADD A,E
            return translate_add_a_r(ctx, 5);  // E = 5
        case 0x84: // ADD A,H
            return translate_add_a_r(ctx, 6);  // H = 6
        case 0x85: // ADD A,L
            return translate_add_a_r(ctx, 7);  // L = 7
        case 0x87: // ADD A,A
            return translate_add_a_r(ctx, 0);  // A = 0
        case 0xC6: // ADD A,d8
            return translate_add_a_n(ctx, code[1]);
        case 0x04: // INC B
            return translate_inc_r(ctx, 2);
        case 0x0C: // INC C
            return translate_inc_r(ctx, 3);
        case 0xBE: // CP (HL)
            return translate_cp_hl(ctx);
        // In translate_instruction, add:
        case 0xFE:  // CP d8
            return translate_cp_n(ctx, code[1]);
        case 0xB8:  // CP B
            return translate_cp_r(ctx, 2);  // B = 2
        case 0xB9:  // CP C
            return translate_cp_r(ctx, 3);  // C = 3
        case 0xBA:  // CP D
            return translate_cp_r(ctx, 4);  // D = 4
        case 0xBB:  // CP E
            return translate_cp_r(ctx, 5);  // E = 5
        case 0xBC:  // CP H
            return translate_cp_r(ctx, 6);  // H = 6
        case 0xBD:  // CP L
            return translate_cp_r(ctx, 7);  // L = 7
        case 0xBF:  // CP A
            return translate_cp_r(ctx, 0);  // A = 0
        case 0xCE:  // ADC A,d8
            return translate_adc_n(ctx, code[1]);
    }

    fprintf(stderr, "Unhandled opcode: 0x%02X\n", inst->opcode);
    return false;
}

// We create a thread-safe context (tsctx) here so we can wrap our module.
static bool init_translation(struct translation_ctx *ctx) {
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    
    // Create the ORC JIT.
    LLVMErrorRef err = LLVMOrcCreateLLJIT(&ctx->jit, NULL);
    if (err) {
        char *msg = LLVMGetErrorMessage(err);
        fprintf(stderr, "Failed to create LLJIT: %s\n", msg);
        LLVMDisposeErrorMessage(msg);
        return false;
    }

    // Create a thread-safe context from the new, plain LLVM context.
    ctx->ctx = LLVMContextCreate();
    if (!ctx->ctx) {
        fprintf(stderr, "Failed to create LLVM context\n");
        return false;
    }

    ctx->tsctx = LLVMOrcCreateNewThreadSafeContext();

    // Create module and builder.
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
    if (ctx->ctx) {
        LLVMContextDispose(ctx->ctx);
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
    
    // For now, generate a simple "return" instruction.
    LLVMBuildRetVoid(ctx->builder);

    return true;
}

// Test translation and run the translated function.
// Note: Even though we don't need full thread safety in our translation,
// LLVM ORC still requires that modules be wrapped as a thread-safe module.
typedef void (*gb_main_fn)(struct gb_cpu_state*);
static gb_main_fn test_translation_and_run(struct translation_ctx *ctx) {
    // Create main function for translated code
    if (!create_translated_function(ctx)) {
        fprintf(stderr, "Failed to create translation function\n");
        return false;
    }
    
    // Translate first few instructions starting at ROM_HEADER_START
    uint16_t pc = ROM_HEADER_START;
    
    printf("Starting translation at 0x%04X\n", pc);
    
    // Translate up to 10 instructions or until we hit an unknown one
    for (int i = 0; i < 10 && pc < hw_state.rom_size; i++) {
        struct instruction inst = decode_instruction(&hw_state.rom_data[pc]);
        
        if (strcmp(inst.name, "Unknown") == 0) {
            printf("Stopping at unknown instruction 0x%02X at 0x%04X\n", inst.opcode, pc);
            break;
        }
        
        printf("Translating 0x%04X: %s\n", pc, inst.name);
        
        if (!translate_instruction(ctx, &inst, &hw_state.rom_data[pc])) {
            fprintf(stderr, "Failed to translate instruction at 0x%04X\n", pc);
            break;
        }
        
        pc += inst.length;
    }
    
    // Verify the generated code
    char *error = NULL;
    if (LLVMVerifyModule(ctx->module, LLVMPrintMessageAction, &error) != 0) {
        fprintf(stderr, "Module verification failed: %s\n", error);
        LLVMDisposeMessage(error);
        return NULL;
    }
    
    // Print generated IR for inspection
    char *ir = LLVMPrintModuleToString(ctx->module);
    printf("\nGenerated LLVM IR:\n%s\n", ir);
    LLVMDisposeMessage(ir);
    
    // Create a thread-safe module from our module and thread-safe context.
    LLVMOrcThreadSafeModuleRef tsm = LLVMOrcCreateNewThreadSafeModule(
        ctx->module, ctx->tsctx);
    if (!tsm) {
        fprintf(stderr, "Failed to create thread-safe module\n");
        LLVMOrcDisposeThreadSafeContext(ctx->tsctx);
        return NULL;
    }
    
    // Add module to JIT
    LLVMOrcJITDylibRef main_jd = LLVMOrcLLJITGetMainJITDylib(ctx->jit);
    LLVMErrorRef err = LLVMOrcLLJITAddLLVMIRModule(ctx->jit, main_jd, tsm);
    if (err) {
        char *msg = LLVMGetErrorMessage(err);
        fprintf(stderr, "Failed to add module to JIT: %s\n", msg);
        LLVMDisposeErrorMessage(msg);
        return NULL;
    }
    
    // Look up the generated function
    LLVMOrcJITTargetAddress addr = 0;
    err = LLVMOrcLLJITLookup(ctx->jit, &addr, "gb_main");
    if (err) {
        char *msg = LLVMGetErrorMessage(err);
        fprintf(stderr, "Failed to look up function: %s\n", msg);
        LLVMDisposeErrorMessage(msg);
        return NULL;
    }
    
    // Cast address to function pointer and return it
    return (gb_main_fn)(intptr_t)addr;
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
    gb_main_fn translated_code = test_translation_and_run(&ctx);
    if (!translated_code) {
        fprintf(stderr, "Translation/execution test failed\n");
        cleanup_translation(&ctx);
        hw_cleanup();
        return 1;
    }

    // Allocate framebuffer
    hw_state.framebuffer = calloc(160 * 144, sizeof(uint32_t));
    if (!hw_state.framebuffer) {
        fprintf(stderr, "Failed to allocate framebuffer\n");
        return 1;
    }

    // Run until first frame
    bool in_vblank = false;
    do {
        // Execute translated code
        translated_code(&hw_state.cpu);
        in_vblank = (hw_state.ppu.ly >= 144) && ((hw_state.ppu.stat & 0x03) == 0x01);
    } while (!in_vblank);

    // Save first frame as PPM
    FILE *f = fopen("frame.ppm", "wb");
    if (f) {
        fprintf(f, "P6\n160 144\n255\n");
        for (int i = 0; i < 160 * 144; i++) {
            uint32_t rgb = hw_state.framebuffer[i];
            uint8_t r = (rgb >> 16) & 0xFF;
            uint8_t g = (rgb >> 8) & 0xFF;
            uint8_t b = rgb & 0xFF;
            fwrite(&r, 1, 1, f);
            fwrite(&g, 1, 1, f);
            fwrite(&b, 1, 1, f);
        }
        fclose(f);
    }

    cleanup_translation(&ctx);
    hw_cleanup();
    return 0;
}