/**
 * @file test_os_loader.c
 * @brief OS-specific loader integration tests
 * 
 * Tests the loader functionality that would be used by an OS kernel
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../include/fcef.h"

// Mock OS memory management
typedef struct {
    void *base;
    size_t size;
    bool allocated;
} os_memory_chunk_t;

static os_memory_chunk_t mock_memory_pool[10];
static int mock_memory_used = 0;

/**
 * @brief Mock OS memory allocation
 */
static void *os_alloc(size_t size, size_t alignment) {
    if (mock_memory_used >= 10) return NULL;
    
    // Simple aligned allocation
    size_t aligned_size = (size + alignment - 1) & ~(alignment - 1);
    void *memory = aligned_alloc(alignment, aligned_size);
    
    if (!memory) return NULL;
    
    mock_memory_pool[mock_memory_used].base = memory;
    mock_memory_pool[mock_memory_used].size = aligned_size;
    mock_memory_pool[mock_memory_used].allocated = true;
    mock_memory_used++;
    
    return memory;
}

/**
 * @brief Mock OS memory free
 */
static void os_free(void *ptr) {
    for (int i = 0; i < mock_memory_used; i++) {
        if (mock_memory_pool[i].base == ptr) {
            free(ptr);
            mock_memory_pool[i].allocated = false;
            return;
        }
    }
}

/**
 * @brief Test OS loader functionality
 */
static bool test_os_loader(void) {
    printf("Testing OS loader functionality...\n");
    
    // Create a test executable
    fcef_file_t *executable = fcef_create(FCEF_ARCH_X86_64, 1,0);
    if (!executable) return false;
    
    // Set entry point
    fcef_set_entry_point(executable, 0x400000);
    
    // Create text segment with simple "program"
    uint8_t text_segment[] = {
        // Entry point at 0x400000
        0xB8, 0x3C, 0x00, 0x00, 0x00,  // mov eax, 60 (exit)
        0xBF, 0x00, 0x00, 0x00, 0x00,  // mov edi, 0 (exit code)
        0x0F, 0x05,                     // syscall
        0xC3                            // ret
    };
    
    fcef_program_header_t text_phdr = {
        .type = FCEF_PT_LOAD,
        .flags = FCEF_PF_R | FCEF_PF_X,
        .vaddr = 0x400000,
        .paddr = 0x400000,
        .filesz = sizeof(text_segment),
        .memsz = sizeof(text_segment),
        .align = 0x1000
    };
    
    if (!fcef_add_segment(executable, &text_phdr, text_segment, sizeof(text_segment))) {
        fcef_close(executable);
        return false;
    }
    
    // Create data segment
    uint8_t data_segment[] = "Hello from FCEF executable!\n";
    
    fcef_program_header_t data_phdr = {
        .type = FCEF_PT_LOAD,
        .flags = FCEF_PF_R | FCEF_PF_W,
        .vaddr = 0x500000,
        .paddr = 0x500000,
        .filesz = sizeof(data_segment),
        .memsz = sizeof(data_segment),
        .align = 0x1000
    };
    
    if (!fcef_add_segment(executable, &data_phdr, data_segment, sizeof(data_segment))) {
        fcef_close(executable);
        return false;
    }
    
    // Update CRC
    fcef_update_crc32(executable);
    
    // Write to file
    if (!fcef_write_to_file(executable, "test_os_executable.fcef")) {
        fcef_close(executable);
        return false;
    }
    
    // Simulate OS loader
    printf("  Simulating OS loader...\n");
    
    // 1. Open executable
    fcef_file_t *loaded_exec = fcef_open("test_os_executable.fcef");
    if (!loaded_exec) {
        fcef_close(executable);
        return false;
    }
    
    // 2. Validate
    if (!fcef_validate(loaded_exec)) {
        fprintf(stderr, "Executable validation failed\n");
        fcef_close(loaded_exec);
        fcef_close(executable);
        return false;
    }
    
    // 3. Get program headers
    fcef_program_header_t *phdrs = fcef_get_program_headers(loaded_exec);
    if (!phdrs) {
        fcef_close(loaded_exec);
        fcef_close(executable);
        return false;
    }
    
    // 4. Allocate memory for each loadable segment
    void *loaded_segments[10] = {0};
    int segment_count = 0;
    
    for (uint32_t i = 0; i < loaded_exec->header->phnum; i++) {
        if (phdrs[i].type == FCEF_PT_LOAD) {
            // Calculate required memory size with alignment
            size_t total_size = phdrs[i].vaddr + phdrs[i].memsz;
            size_t aligned_size = (total_size + 0xFFF) & ~0xFFF;  // 4KB aligned
            
            // Allocate memory
            void *segment_mem = os_alloc(aligned_size, 0x1000);
            if (!segment_mem) {
                fprintf(stderr, "Failed to allocate memory for segment %u\n", i);
                
                // Cleanup
                for (int j = 0; j < segment_count; j++) {
                    os_free(loaded_segments[j]);
                }
                
                fcef_close(loaded_exec);
                fcef_close(executable);
                remove("test_os_executable.fcef");
                return false;
            }
            
            // Load segment
            if (!fcef_load_segment(loaded_exec, &phdrs[i], segment_mem)) {
                fprintf(stderr, "Failed to load segment %u\n", i);
                os_free(segment_mem);
                
                for (int j = 0; j < segment_count; j++) {
                    os_free(loaded_segments[j]);
                }
                
                fcef_close(loaded_exec);
                fcef_close(executable);
                remove("test_os_executable.fcef");
                return false;
            }
            
            loaded_segments[segment_count++] = segment_mem;
            
            printf("    Loaded segment %u at virtual address 0x%08X\n", 
                   i, phdrs[i].vaddr);
        }
    }
    
    // 5. Get entry point
    void *entry_point = fcef_get_entry_point(loaded_exec);
    printf("    Entry point: 0x%08lX\n", (unsigned long)entry_point);
    
    // 6. Verify loaded data
    printf("  Verifying loaded data...\n");
    
    for (uint32_t i = 0; i < loaded_exec->header->phnum; i++) {
        if (phdrs[i].type == FCEF_PT_LOAD) {
            uint8_t *loaded_data = (uint8_t*)loaded_segments[i] + phdrs[i].vaddr;
            
            // Check first few bytes of each segment
            if (phdrs[i].vaddr == 0x400000) {
                // Should be our text segment
                if (loaded_data[0] != 0xB8 || loaded_data[1] != 0x3C) {
                    fprintf(stderr, "Text segment data mismatch\n");
                    
                    for (int j = 0; j < segment_count; j++) {
                        os_free(loaded_segments[j]);
                    }
                    
                    fcef_close(loaded_exec);
                    fcef_close(executable);
                    remove("test_os_executable.fcef");
                    return false;
                }
            } else if (phdrs[i].vaddr == 0x500000) {
                // Should be our data segment
                if (strncmp((char*)loaded_data, "Hello from FCEF", 15) != 0) {
                    fprintf(stderr, "Data segment mismatch\n");
                    
                    for (int j = 0; j < segment_count; j++) {
                        os_free(loaded_segments[j]);
                    }
                    
                    fcef_close(loaded_exec);
                    fcef_close(executable);
                    remove("test_os_executable.fcef");
                    return false;
                }
            }
        }
    }
    
    // 7. Cleanup
    for (int i = 0; i < segment_count; i++) {
        os_free(loaded_segments[i]);
    }
    
    fcef_close(loaded_exec);
    fcef_close(executable);
    
    // Clean up mock memory
    for (int i = 0; i < mock_memory_used; i++) {
        if (mock_memory_pool[i].allocated) {
            free(mock_memory_pool[i].base);
        }
    }
    mock_memory_used = 0;
    
    remove("test_os_executable.fcef");
    
    printf("OS loader test: PASSED\n");
    return true;
}

/**
 * @brief Test memory protection flags
 */
static bool test_memory_protection(void) {
    printf("\nTesting memory protection flags...\n");
    
    // Create executable with different protection flags
    fcef_file_t *file = fcef_create(FCEF_ARCH_X86_64, 1,0);
    if (!file) return false;
    
    uint8_t dummy_data[64] = {0};
    
    // Segment 1: Read-only
    fcef_program_header_t ro_phdr = {
        .type = FCEF_PT_LOAD,
        .flags = FCEF_PF_R,
        .vaddr = 0x1000,
        .filesz = sizeof(dummy_data),
        .memsz = sizeof(dummy_data)
    };
    
    // Segment 2: Read-Write
    fcef_program_header_t rw_phdr = {
        .type = FCEF_PT_LOAD,
        .flags = FCEF_PF_R | FCEF_PF_W,
        .vaddr = 0x2000,
        .filesz = sizeof(dummy_data),
        .memsz = sizeof(dummy_data)
    };
    
    // Segment 3: Read-Execute
    fcef_program_header_t rx_phdr = {
        .type = FCEF_PT_LOAD,
        .flags = FCEF_PF_R | FCEF_PF_X,
        .vaddr = 0x3000,
        .filesz = sizeof(dummy_data),
        .memsz = sizeof(dummy_data)
    };
    
    // Segment 4: Read-Write-Execute (dangerous!)
    fcef_program_header_t rwx_phdr = {
        .type = FCEF_PT_LOAD,
        .flags = FCEF_PF_R | FCEF_PF_W | FCEF_PF_X,
        .vaddr = 0x4000,
        .filesz = sizeof(dummy_data),
        .memsz = sizeof(dummy_data)
    };
    
    // Add segments
    if (!fcef_add_segment(file, &ro_phdr, dummy_data, sizeof(dummy_data)) ||
        !fcef_add_segment(file, &rw_phdr, dummy_data, sizeof(dummy_data)) ||
        !fcef_add_segment(file, &rx_phdr, dummy_data, sizeof(dummy_data)) ||
        !fcef_add_segment(file, &rwx_phdr, dummy_data, sizeof(dummy_data))) {
        fcef_close(file);
        return false;
    }
    
    // Verify flags
    fcef_program_header_t *phdrs = fcef_get_program_headers(file);
    if (!phdrs) {
        fcef_close(file);
        return false;
    }
    
    bool passed = true;
    
    if ((phdrs[0].flags & FCEF_PF_R) == 0) {
        printf("  ERROR: Segment 0 should be readable\n");
        passed = false;
    }
    if ((phdrs[0].flags & (FCEF_PF_W | FCEF_PF_X)) != 0) {
        printf("  ERROR: Segment 0 should not be writable or executable\n");
        passed = false;
    }
    
    if ((phdrs[1].flags & (FCEF_PF_R | FCEF_PF_W)) != (FCEF_PF_R | FCEF_PF_W)) {
        printf("  ERROR: Segment 1 should be read-write\n");
        passed = false;
    }
    if ((phdrs[1].flags & FCEF_PF_X) != 0) {
        printf("  ERROR: Segment 1 should not be executable\n");
        passed = false;
    }
    
    if ((phdrs[2].flags & (FCEF_PF_R | FCEF_PF_X)) != (FCEF_PF_R | FCEF_PF_X)) {
        printf("  ERROR: Segment 2 should be read-execute\n");
        passed = false;
    }
    if ((phdrs[2].flags & FCEF_PF_W) != 0) {
        printf("  ERROR: Segment 2 should not be writable\n");
        passed = false;
    }
    
    if ((phdrs[3].flags & (FCEF_PF_R | FCEF_PF_W | FCEF_PF_X)) != 
        (FCEF_PF_R | FCEF_PF_W | FCEF_PF_X)) {
        printf("  ERROR: Segment 3 should be read-write-execute\n");
        passed = false;
    }
    
    fcef_close(file);
    
    if (passed) {
        printf("Memory protection test: PASSED\n");
    }
    
    return passed;
}

/**
 * @brief Main function
 */
int main(void) {
    printf("=== OS Loader Integration Tests ===\n\n");
    
    bool test1 = test_os_loader();
    bool test2 = test_memory_protection();
    
    printf("\n=== Results ===\n");
    printf("OS Loader Test: %s\n", test1 ? "PASSED" : "FAILED");
    printf("Memory Protection Test: %s\n", test2 ? "PASSED" : "FAILED");
    
    if (test1 && test2) {
        printf("\nAll OS loader tests PASSED!\n");
        return 0;
    } else {
        printf("\nSome tests FAILED\n");
        return 1;
    }
}