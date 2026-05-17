/**
 * @file fcef_loader.c
 * @brief FCEF file loader and execution implementation
 * 
 * Provides functions for loading, linking, and executing FCEF files.
 */

#include "fcef.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

/**
 * @brief Structure representing a loaded executable
 */
typedef struct {
    void *base_address;        ///< Base address of loaded executable
    size_t memory_size;        ///< Total memory size used
    fcef_file_t *file_handle;  ///< Associated FCEF file handle
    void (*entry_point)();     ///< Entry point function pointer
} fcef_loaded_exec_t;

/**
 * @brief Allocate memory for a segment with proper permissions
 * 
 * @param phdr Program header describing the segment
 * @return void* Pointer to allocated memory, or NULL on failure
 */
static void* allocate_segment_memory(const fcef_program_header_t *phdr) {
    if (!phdr) {
        return NULL;
    }

    // Calculate memory size (aligned to page boundary)
    size_t page_size = getpagesize();
    size_t mem_size = (phdr->memsz + page_size - 1) & ~(page_size - 1);
    
    // Determine memory protection flags
    int prot = 0;
    if (phdr->flags & FCEF_PF_R) prot |= PROT_READ;
    if (phdr->flags & FCEF_PF_W) prot |= PROT_WRITE;
    if (phdr->flags & FCEF_PF_X) prot |= PROT_EXEC;
    
    // Allocate memory with appropriate permissions
    void *mem = mmap(NULL, mem_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "Error: Failed to allocate memory for segment: %s\n", strerror(errno));
        return NULL;
    }
    
    return mem;
}

/**
 * @brief Load an executable into memory
 * 
 * @param file FCEF file handle
 * @return fcef_loaded_exec_t* Loaded executable handle, or NULL on error
 */
fcef_loaded_exec_t* fcef_load_executable(fcef_file_t *file) {
    if (!file || !file->header) {
        fprintf(stderr, "Error: Invalid file handle\n");
        return NULL;
    }
    
    // Validate file before loading
    if (!fcef_validate(file)) {
        fprintf(stderr, "Error: Invalid FCEF file\n");
        return NULL;
    }
    
    // Get program headers
    fcef_program_header_t *phdrs = fcef_get_program_headers(file);
    if (!phdrs) {
        fprintf(stderr, "Error: No program headers found\n");
        return NULL;
    }
    
    // Create loaded executable structure
    fcef_loaded_exec_t *exec = malloc(sizeof(fcef_loaded_exec_t));
    if (!exec) {
        fprintf(stderr, "Error: Failed to allocate executable structure\n");
        return NULL;
    }
    
    exec->file_handle = file;
    exec->base_address = NULL;
    exec->memory_size = 0;
    exec->entry_point = NULL;
    
    // Process each program header
    for (uint32_t i = 0; i < file->header->phnum; i++) {
        if (phdrs[i].type == FCEF_PT_LOAD) {
            // Allocate memory for this segment
            void *segment_memory = allocate_segment_memory(&phdrs[i]);
            if (!segment_memory) {
                // Free previously allocated segments
                fcef_unload_executable(exec);
                return NULL;
            }
            
            // Load segment data into allocated memory
            if (!fcef_load_segment(file, &phdrs[i], segment_memory)) {
                munmap(segment_memory, phdrs[i].memsz);
                fcef_unload_executable(exec);
                return NULL;
            }
            
            // If this is the first loadable segment, set as base address
            if (!exec->base_address) {
                exec->base_address = segment_memory;
            }
            
            // Update total memory size
            size_t page_size = getpagesize();
            size_t segment_size = (phdrs[i].memsz + page_size - 1) & ~(page_size - 1);
            exec->memory_size += segment_size;
        }
    }
    
    // Set entry point if available
    if (file->header->entry_point != 0) {
        exec->entry_point = (void(*)())(exec->base_address + file->header->entry_point);
    }
    
    printf("Successfully loaded executable at base address %p\n", exec->base_address);
    return exec;
}

/**
 * @brief Execute a loaded executable
 * 
 * @param exec Loaded executable handle
 * @return int Exit code of the executed program, or -1 on error
 */
int fcef_execute(fcef_loaded_exec_t *exec) {
    if (!exec || !exec->entry_point) {
        fprintf(stderr, "Error: Invalid executable or no entry point\n");
        return -1;
    }
    
    printf("Executing FCEF file...\n");
    
    // Execute the entry point
    // NOTE: This is potentially dangerous and should only be used in controlled environments
    // In a real OS loader, additional sandboxing and security measures would be required
    int exit_code;
    void (*entry)(void) = exec->entry_point;
    
    // Execute in a safe manner (though still risky)
    entry();
    
    // Note: If the executed code exits properly, we could capture the exit code
    // For now, returning 0 as success
    return 0;
}

/**
 * @brief Unload a loaded executable and free resources
 * 
 * @param exec Loaded executable handle (can be NULL)
 */
void fcef_unload_executable(fcef_loaded_exec_t *exec) {
    if (!exec) return;
    
    // Free allocated memory segments
    if (exec->base_address) {
        size_t page_size = getpagesize();
        size_t total_size = (exec->memory_size + page_size - 1) & ~(page_size - 1);
        munmap(exec->base_address, total_size);
    }
    
    // Free executable structure
    free(exec);
}

/**
 * @brief Load and execute an FCEF file directly from disk
 * 
 * @param filename Path to the FCEF file
 * @return int Exit code of the executed program, or -1 on error
 */
int fcef_load_and_execute_file(const char *filename) {
    if (!filename) {
        fprintf(stderr, "Error: NULL filename provided\n");
        return -1;
    }
    
    // Open the FCEF file
    fcef_file_t *file = fcef_open(filename);
    if (!file) {
        fprintf(stderr, "Error: Failed to open file '%s'\n", filename);
        return -1;
    }
    
    // Validate the file
    if (!fcef_validate(file)) {
        fprintf(stderr, "Error: File '%s' is not a valid FCEF file\n", filename);
        fcef_close(file);
        return -1;
    }
    
    // Load the executable
    fcef_loaded_exec_t *exec = fcef_load_executable(file);
    if (!exec) {
        fprintf(stderr, "Error: Failed to load executable from '%s'\n", filename);
        fcef_close(file);
        return -1;
    }
    
    // Execute the loaded executable
    int result = fcef_execute(exec);
    
    // Cleanup
    fcef_unload_executable(exec);
    fcef_close(file);
    
    return result;
}