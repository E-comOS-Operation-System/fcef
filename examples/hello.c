// examples/hello.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main() {
    // Create a simple FCEF header
    uint8_t fcef_header[16] = {
        0x46, 0x43, 0x45, 0x46,  // "FCEF"
        0x00, 0x01,              // Version 1.0 (0x0100)
        0x41, 0x4C, 0x4C, 0x41,  // "ALLA"
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Reserved
    };
    
    // AArch64 code: write(1, "Hello FCEF!\n", 12) + exit(0)
    uint8_t code[] = {
        // mov x0, #1 (stdout)
        0x20, 0x00, 0x80, 0xD2,
        // adr x1, message
        0x01, 0x00, 0x00, 0x10,
        // mov x2, #12
        0x42, 0x00, 0x80, 0xD2,
        // mov x8, #64 (write syscall)
        0x08, 0x01, 0x80, 0xD2,
        // svc #0
        0x01, 0x00, 0x00, 0xD4,
        // mov x0, #0 (exit code)
        0x00, 0x00, 0x80, 0xD2,
        // mov x8, #93 (exit syscall)
        0x68, 0x00, 0x80, 0xD2,
        // svc #0
        0x01, 0x00, 0x00, 0xD4,
        // message: "Hello FCEF!\n"
        'H', 'e', 'l', 'l', 'o', ' ', 'F', 'C', 'E', 'F', '!', '\n'
    };
    
    FILE *f = fopen("hello.fcef", "wb");
    fwrite(fcef_header, 1, 16, f);
    fwrite(code, 1, sizeof(code), f);
    fclose(f);
    
    printf("Created hello.fcef\n");
    return 0;
}