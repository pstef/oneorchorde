#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("test.gb", "wb");
    if (!f) return 1;

    // Minimum ROM size is 32KB (0x8000 bytes)
    unsigned char rom[0x8000] = {0};

    // Entry point at 0x100
    const unsigned char entry[] = {
        0x00,        // NOP
        0xC3, 0x50, 0x01  // JP 0x0150
    };
    memcpy(rom + 0x100, entry, sizeof(entry));

    // Nintendo logo at 0x104-0x133
    const unsigned char nintendo_logo[] = {
        0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B, 0x03, 0x73, 0x00, 0x83,
        0x00, 0x0C, 0x00, 0x0D, 0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E,
        0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99, 0xBB, 0xBB, 0x67, 0x63,
        0x6E, 0x0E, 0xEC, 0xCC, 0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E
    };
    memcpy(rom + 0x104, nintendo_logo, sizeof(nintendo_logo));

    // ROM title at 0x134-0x143
    const char title[] = "TEST ROM";
    memcpy(rom + 0x134, title, strlen(title));

    // Cartridge type at 0x147 (ROM only = 0x00)
    rom[0x147] = 0x00;

    // ROM size at 0x148 (32KB = 0x00)
    rom[0x148] = 0x00;

    // RAM size at 0x149 (None = 0x00)
    rom[0x149] = 0x00;

    // Destination code at 0x14A (0x00 = Japan)
    rom[0x14A] = 0x00;

    // Old licensee code at 0x14B (0x33 = New licensee code will be used)
    rom[0x14B] = 0x33;

    // Mask ROM version at 0x14C (usually 0x00)
    rom[0x14C] = 0x00;

    // Header checksum at 0x14D (calculated for area 0x134-0x14C)
    uint8_t checksum = 0;
    for (int i = 0x134; i <= 0x14C; i++) {
        checksum = checksum - rom[i] - 1;
    }
    rom[0x14D] = checksum;

    // Global checksum at 0x14E-0x14F (not verified by GB)
    rom[0x14E] = 0x00;
    rom[0x14F] = 0x00;

    // Test code at 0x150 (after Nintendo header)
    const unsigned char code[] = {
        0x3E, 0x42,  // LD A,0x42    ; Load 0x42 into A
        0x06, 0x17,  // LD B,0x17    ; Load 0x17 into B
        0x00,        // NOP
        0x18, 0xFD   // JR -3        ; Jump back to NOP (infinite loop)
    };
    memcpy(rom + 0x150, code, sizeof(code));

    // Write complete ROM
    if (fwrite(rom, 1, sizeof(rom), f) != sizeof(rom)) {
        fprintf(stderr, "Failed to write ROM file\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    printf("Created test ROM (32KB)\n");
    printf("Title: TEST ROM\n");
    printf("Header checksum: 0x%02X\n", checksum);
    return 0;
}