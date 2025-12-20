/**
 * @file fcef_reader.c
 * @brief FCEF file reader implementation
 * 
 * Provides functions for reading and parsing FCEF files.
 */

#include "fcef.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/**
 * @brief Open and read an FCEF file from disk
 * 
 * @param filename Path to the FCEF file
 * @return fcef_file_t* File handle, or NULL on error
 */
fcef_file_t* fcef_open(const char *filename) {
    if (!filename) {
        fprintf(stderr, "Error: NULL filename provided\n");
        return NULL;
    }
    
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Failed to open file '%s': %s\n", 
                filename, strerror(errno));
        return NULL;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size < (long)sizeof(fcef_header_t)) {
        fclose(fp);
        fprintf(stderr, "Error: File '%s' is too small to be a valid FCEF file\n", 
                filename);
        return NULL;
    }
    
    // Allocate file buffer
    fcef_file_t *file = malloc(sizeof(fcef_file_t));
    if (!file) {
        fclose(fp);
        fprintf(stderr, "Error: Failed to allocate file structure\n");
        return NULL;
    }
    
    file->data = malloc(file_size);
    if (!file->data) {
        fclose(fp);
        free(file);
        fprintf(stderr, "Error: Failed to allocate file buffer\n");
        return NULL;
    }
    
    // Read file contents
    size_t bytes_read = fread(file->data, 1, file_size, fp);
    fclose(fp);
    
    if (bytes_read != (size_t)file_size) {
        free(file->data);
        free(file);
        fprintf(stderr, "Error: Failed to read entire file\n");
        return NULL;
    }
    
    // Initialize file structure
    file->size = file_size;
    file->header = (fcef_header_t*)file->data;
    file->allocated = true;
    file->base_address = 0;
    
    return file;
}

/**
 * @brief Create an FCEF file handle from memory
 * 
 * @param data Pointer to file data in memory
 * @param size Size of file data
 * @param take_ownership If true, the handle will free the memory when closed
 * @return fcef_file_t* File handle, or NULL on error
 *
fcef_file_t* fcef_create_from_memory(void *data, size_t size, bool take_ownership) {
    if (!data || size < sizeof(fcef_header_t)) {
        fprintf(stderr, "Error: Invalid memory buffer\n");
        return NULL;
    }
    
    fcef_file_t *file = malloc(sizeof(fcef_file_t));
    if (!file) {
        fprintf(stderr, "Error: Failed to allocate file structure\n");
        return NULL;
    }
    
    file->data = (uint8_t*)data;
    file->size = size;
    file->header = (fcef_header_t*)data;
    file->allocated = take_ownership;
    file->base_address = 0;
    
    return file;
}/

/**
 * @brief Get the program headers from a file
 * 
 * @param file FCEF file handle
 * @return fcef_program_header_t* Pointer to program header array, or NULL on error
 */
fcef_program_header_t* fcef_get_program_headers(fcef_file_t *file) {
    if (!file || !file->header || file->header->phnum == 0) {
        return NULL;
    }
    
    // Check bounds
    uint32_t phoff = file->header->phoff;
    uint32_t phsize = file->header->phnum * sizeof(fcef_program_header_t);
    
    if (phoff + phsize > file->size) {
        fprintf(stderr, "Error: Program header table exceeds file bounds\n");
        return NULL;
    }
    
    return (fcef_program_header_t*)(file->data + phoff);
}

/**
 * @brief Get the section headers from a file
 * 
 * @param file FCEF file handle
 * @return fcef_section_header_t* Pointer to section header array, or NULL on error
 */
fcef_section_header_t* fcef_get_section_headers(fcef_file_t *file) {
    if (!file || !file->header || file->header->shnum == 0) {
        return NULL;
    }
    
    // Check bounds
    uint32_t shoff = file->header->shoff;
    uint32_t shsize = file->header->shnum * sizeof(fcef_section_header_t);
    
    if (shoff + shsize > file->size) {
        fprintf(stderr, "Error: Section header table exceeds file bounds\n");
        return NULL;
    }
    
    return (fcef_section_header_t*)(file->data + shoff);
}

/**
 * @brief Get a string from a string table
 * 
 * @param file FCEF file handle
 * @param strtab_offset Offset of the string table in the file
 * @param index Index within the string table
 * @return const char* Pointer to the string, or NULL on error
 */
const char* fcef_get_string(fcef_file_t *file, uint32_t strtab_offset, uint32_t index) {
    if (!file || strtab_offset >= file->size) {
        return NULL;
    }
    
    const char *strtab = (const char*)(file->data + strtab_offset);
    uint32_t strtab_size = file->size - strtab_offset;
    
    // Ensure index is within bounds
    if (index >= strtab_size) {
        return NULL;
    }
    
    // Ensure string is null-terminated within bounds
    const char *str = strtab + index;
    for (uint32_t i = index; i < strtab_size; i++) {
        if (strtab[i] == '\0') {
            return str;
        }
    }
    
    // No null terminator found within bounds
    return NULL;
}

/**
 * @brief Find a symbol by name
 * 
 * @param file FCEF file handle
 * @param name Symbol name to find
 * @return fcef_sym_t* Pointer to symbol, or NULL if not found
 */
fcef_sym_t* fcef_find_symbol(fcef_file_t *file, const char *name) {
    if (!file || !name) {
        return NULL;
    }
    
    fcef_section_header_t *sections = fcef_get_section_headers(file);
    if (!sections) {
        return NULL;
    }
    
    // Search for symbol table sections
    for (uint32_t i = 0; i < file->header->shnum; i++) {
        if (sections[i].type == FCEF_SHT_SYMTAB) {
            // Get the associated string table
            uint32_t strtab_index = sections[i].link;
            if (strtab_index >= file->header->shnum) {
                continue;
            }
            
            fcef_section_header_t *strtab_section = &sections[strtab_index];
            if (strtab_section->type != FCEF_SHT_STRTAB) {
                continue;
            }
            
            // Get string table data
            const char *strtab = (const char*)(file->data + strtab_section->offset);
            
            // Get symbol table
            fcef_sym_t *symbols = (fcef_sym_t*)(file->data + sections[i].offset);
            uint32_t num_symbols = sections[i].size / sizeof(fcef_sym_t);
            
            // Search for the symbol
            for (uint32_t j = 0; j < num_symbols; j++) {
                const char *sym_name = strtab + symbols[j].name;
                if (strcmp(sym_name, name) == 0) {
                    return &symbols[j];
                }
            }
        }
    }
    
    return NULL;
}

/**
 * @brief Get entry point address
 * 
 * @param file FCEF file handle
 * @return void* Entry point address
 */
void* fcef_get_entry_point(fcef_file_t *file) {
    if (!file || !file->header) {
        return NULL;
    }
    
    return (void*)(uintptr_t)file->header->entry_point;
}

/**
 * @brief Get base address for loading
 * 
 * @param file FCEF file handle
 * @return uint32_t Base address
 */
uint32_t fcef_get_base_address(fcef_file_t *file) {
    if (!file) {
        return 0;
    }
    return file->base_address;
}

/**
 * @brief Set base address for loading
 * 
 * @param file FCEF file handle
 * @param base_address Base address
 */
void fcef_set_base_address(fcef_file_t *file, uint32_t base_address) {
    if (file) {
        file->base_address = base_address;
    }
}

/**
 * @brief Get count of program headers
 * 
 * @param file FCEF file handle
 * @return uint32_t Number of program headers
 */
uint32_t fcef_get_program_header_count(fcef_file_t *file) {
    if (!file || !file->header) {
        return 0;
    }
    return file->header->phnum;
}

/**
 * @brief Get count of section headers
 * 
 * @param file FCEF file handle
 * @return uint32_t Number of section headers
 */
uint32_t fcef_get_section_header_count(fcef_file_t *file) {
    if (!file || !file->header) {
        return 0;
    }
    return file->header->shnum;
}

/**
 * @brief Close file handle and free resources
 * 
 * @param file FCEF file handle (can be NULL)
 */
void fcef_close(fcef_file_t *file) {
    if (!file) return;
    
    if (file->allocated && file->data) {
        free(file->data);
    }
    free(file);
}