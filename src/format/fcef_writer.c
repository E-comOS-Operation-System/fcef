/**
 * @file fcef_writer.c
 * @brief FCEF file writer implementation
 * 
 * Provides functions for creating and writing FCEF files.
 */

#include "fcef.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Internal context for writing
typedef struct {
    uint8_t *buffer;      // Current buffer
    size_t capacity;      // Buffer capacity
    size_t size;          // Current size
    size_t position;      // Current write position
} write_context_t;

/**
 * @brief Create a new write context
 * 
 * @param initial_capacity Initial buffer capacity
 * @return write_context_t* New context, or NULL on error
 */
static write_context_t* write_context_create(size_t initial_capacity) {
    write_context_t *ctx = malloc(sizeof(write_context_t));
    if (!ctx) return NULL;
    
    ctx->buffer = malloc(initial_capacity);
    if (!ctx->buffer) {
        free(ctx);
        return NULL;
    }
    
    ctx->capacity = initial_capacity;
    ctx->size = 0;
    ctx->position = 0;
    
    return ctx;
}

/**
 * @brief Destroy a write context
 * 
 * @param ctx Context to destroy
 * @param keep_buffer If true, buffer is not freed (transferred to caller)
 * @return uint8_t* Buffer pointer if keep_buffer is true, NULL otherwise
 */
static uint8_t* write_context_destroy(write_context_t *ctx, bool keep_buffer) {
    if (!ctx) return NULL;
    
    uint8_t *buffer = ctx->buffer;
    
    if (!keep_buffer && buffer) {
        free(buffer);
        buffer = NULL;
    }
    
    free(ctx);
    return buffer;
}

/**
 * @brief Expand buffer if needed
 * 
 * @param ctx Write context
 * @param needed Additional bytes needed
 * @return true Success
 * @return false Out of memory
 */
static bool write_context_ensure_capacity(write_context_t *ctx, size_t needed) {
    if (ctx->position + needed <= ctx->capacity) {
        return true;
    }
    
    // Calculate new capacity
    size_t new_capacity = ctx->capacity * 2;
    while (new_capacity < ctx->position + needed) {
        new_capacity *= 2;
    }
    
    uint8_t *new_buffer = realloc(ctx->buffer, new_capacity);
    if (!new_buffer) {
        return false;
    }
    
    ctx->buffer = new_buffer;
    ctx->capacity = new_capacity;
    return true;
}

/**
 * @brief Write data to buffer
 * 
 * @param ctx Write context
 * @param data Data to write
 * @param size Size of data
 * @return true Success
 * @return false Out of memory
 */
static bool write_context_write(write_context_t *ctx, const void *data, size_t size) {
    if (!write_context_ensure_capacity(ctx, size)) {
        return false;
    }
    
    memcpy(ctx->buffer + ctx->position, data, size);
    ctx->position += size;
    
    if (ctx->position > ctx->size) {
        ctx->size = ctx->position;
    }
    
    return true;
}

/**
 * @brief Align write position
 * 
 * @param ctx Write context
 * @param alignment Alignment (power of two)
 * @return true Success
 * @return false Out of memory
 */
static bool write_context_align(write_context_t *ctx, size_t alignment) {
    size_t padding = (alignment - (ctx->position % alignment)) % alignment;
    if (padding == 0) return true;
    
    if (!write_context_ensure_capacity(ctx, padding)) {
        return false;
    }
    
    // Fill padding with zeros
    memset(ctx->buffer + ctx->position, 0, padding);
    ctx->position += padding;
    
    return true;
}

/**
 * @brief Create a new FCEF file
 * 
 * @param arch Architecture identifier
 * @param version Version number (combined major and minor)
 * @return fcef_file_t* New file handle, or NULL on error
 */
fcef_file_t* fcef_create(uint8_t arch, uint16_t version) {
    // Create write context with initial capacity
    write_context_t *ctx = write_context_create(4096);
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create write context\n");
        return NULL;
    }
    
    // Reserve space for header
    fcef_header_t header = {0};
    if (!write_context_write(ctx, &header, sizeof(header))) {
        write_context_destroy(ctx, false);
        return NULL;
    }
    
    // Align to 8 bytes for program headers
    if (!write_context_align(ctx, 8)) {
        write_context_destroy(ctx, false);
        return NULL;
    }
    
    // Create file structure
    fcef_file_t *file = malloc(sizeof(fcef_file_t));
    if (!file) {
        write_context_destroy(ctx, false);
        return NULL;
    }
    
    // Transfer buffer ownership to file
    file->data = write_context_destroy(ctx, true);
    file->size = ctx->size;
    file->header = (fcef_header_t*)file->data;
    file->allocated = true;
    file->base_address = 0;
    
    // Initialize header
    file->header->magic = FCEF_MAGIC;
    file->header->arch = arch;
    file->header->version = version;
    file->header->version_major = (version >> 8) & 0xFF;
    file->header->version_minor = version & 0xFF;
    file->header->entry_point = 0;
    file->header->phoff = sizeof(fcef_header_t);  // Program headers start after header
    file->header->shoff = 0;  // No section headers yet
    file->header->phnum = 0;
    file->header->shnum = 0;
    file->header->shstrndx = 0;
    file->header->flags = 0;
    file->header->crc32 = 0;  // Will be calculated later
    file->header->file_size = file->size;
    
    // Clean up temporary context
    free(ctx);
    
    return file;
}

/**
 * @brief Add a segment to an FCEF file
 * 
 * @param file FCEF file handle
 * @param phdr Program header describing the segment
 * @param data Segment data (can be NULL for zero-initialized segments)
 * @param data_size Size of segment data
 * @return true Success
 * @return false Error
 */
bool fcef_add_segment(fcef_file_t *file, const fcef_program_header_t *phdr,
                     const void *data, size_t data_size) {
    if (!file || !phdr) {
        return false;
    }
    
    // Calculate the size of the current program header table
    size_t current_phdr_table_size = file->header->phnum * sizeof(fcef_program_header_t);
    size_t new_phdr_table_size = (file->header->phnum + 1) * sizeof(fcef_program_header_t);
    
    // Calculate new total size - header + expanded program header table + new segment data
    size_t new_size = file->size + sizeof(fcef_program_header_t) + data_size;
    
    // Allocate new buffer
    uint8_t *new_data = malloc(new_size);
    if (!new_data) {
        fprintf(stderr, "Error: Failed to allocate new buffer for segment addition\n");
        return false;
    }
    
    // Copy the header
    memcpy(new_data, file->data, sizeof(fcef_header_t));
    
    // Update header values in the new buffer
    fcef_header_t *new_header = (fcef_header_t*)new_data;
    new_header->phnum++;  // Increment program header count
    // The phoff is already set correctly when file is created
    new_header->file_size = new_size;
    
    // Copy existing program headers
    if (current_phdr_table_size > 0) {
        memcpy(new_data + sizeof(fcef_header_t), 
               file->data + sizeof(fcef_header_t), // program headers start right after the file header
               current_phdr_table_size);
    }
    
    // Add the new program header
    fcef_program_header_t *new_phdrs = (fcef_program_header_t*)(new_data + sizeof(fcef_header_t));
    fcef_program_header_t new_phdr = *phdr;  // Copy the input header
    
    // Calculate the offset where this segment's data should be placed in the file
    // It goes after the header + all program headers + all previous segment data
    size_t segment_data_offset = sizeof(fcef_header_t) + new_phdr_table_size;
    
    // Copy all segment data from the original file
    if (current_phdr_table_size > 0) {
        // Find the minimum offset of any existing segment to know where segment data starts
        size_t min_seg_offset = SIZE_MAX;
        fcef_program_header_t *orig_phdrs = (fcef_program_header_t*)(file->data + sizeof(fcef_header_t));
        for (uint32_t i = 0; i < file->header->phnum; i++) {
            if (orig_phdrs[i].offset < min_seg_offset) {
                min_seg_offset = orig_phdrs[i].offset;
            }
        }
        
        // If we had segment data, copy it
        if (min_seg_offset < file->size) {
            size_t seg_data_size = file->size - min_seg_offset;
            memcpy(new_data + segment_data_offset, file->data + min_seg_offset, seg_data_size);
        }
    }
    
    // Add the new segment's data at the end of existing segment data
    if (data && data_size > 0) {
        size_t new_seg_data_offset = segment_data_offset + (file->size - (sizeof(fcef_header_t) + current_phdr_table_size));
        memcpy(new_data + new_seg_data_offset, data, data_size);
        
        // Update the offset in the program header to point to the new location
        new_phdr.offset = new_seg_data_offset;
    } else {
        // If no data is provided, still need to set the offset appropriately
        size_t new_seg_data_offset = segment_data_offset + (file->size - (sizeof(fcef_header_t) + current_phdr_table_size));
        new_phdr.offset = new_seg_data_offset;
    }
    
    // Add the new program header to the table
    new_phdrs[file->header->phnum - 1] = new_phdr;
    
    // Free old data if it was allocated
    if (file->allocated && file->data) {
        free(file->data);
    }
    
    // Update file structure
    file->data = new_data;
    file->size = new_size;
    file->header = (fcef_header_t*)file->data;
    file->allocated = true;
    
    return true;
}

/**
 * @brief Add a section to an FCEF file
 * 
 * @param file FCEF file handle
 * @param shdr Section header describing the section
 * @param data Section data (can be NULL for zero-initialized sections)
 * @param data_size Size of section data
 * @return true Success
 * @return false Error
 */
bool fcef_add_section(fcef_file_t *file, const fcef_section_header_t *shdr,
                     const void *data, size_t data_size) {
    if (!file || !shdr) {
        return false;
    }
    
    // Similar to add_segment, but for sections
    // This is a placeholder implementation
    
    // For now, just update the count
    file->header->shnum++;
    
    return true;
}

/**
 * @brief Set the entry point address
 * 
 * @param file FCEF file handle
 * @param entry_point Entry point address
 */
void fcef_set_entry_point(fcef_file_t *file, uint32_t entry_point) {
    if (file && file->header) {
        file->header->entry_point = entry_point;
    }
}

/**
 * @brief Add a string to string table
 * 
 * @param file FCEF file handle
 * @param str String to add
 * @return uint32_t Offset in string table, or 0 on error
 */
uint32_t fcef_add_string(fcef_file_t *file, const char *str) {
    if (!file || !str) {
        return 0;
    }
    
    // Find or create the string table section
    // Look for an existing string table section
    fcef_section_header_t *sections = fcef_get_section_headers(file);
    fcef_section_header_t *strtab_section = NULL;
    uint32_t strtab_idx = UINT32_MAX;
    
    if (sections) {
        for (uint32_t i = 0; i < file->header->shnum; i++) {
            const char *section_name = fcef_get_string(file, sections[i].name, 0);
            if (section_name && strcmp(section_name, ".strtab") == 0) {
                strtab_section = &sections[i];
                strtab_idx = i;
                break;
            }
        }
    }
    
    // If no string table exists, create one
    if (!strtab_section) {
        // This is a simplified approach - in a real implementation we'd need to add sections properly
        fprintf(stderr, "String table creation not fully implemented in this version\n");
        return 0;
    }
    
    // Find the string in the table to avoid duplicates
    const char *strtab_data = (const char*)(file->data + strtab_section->offset);
    uint32_t current_pos = strtab_section->size; // Start after existing strings including null terminator
    
    // Add string to the table (this is a simplified implementation)
    // In a real implementation, we'd need to expand the section data
    fprintf(stderr, "String table manipulation not fully implemented in this version\n");
    return 0;
}

/**
 * @brief Add a symbol to symbol table
 * 
 * @param file FCEF file handle
 * @param name Symbol name
 * @param value Symbol value (address)
 * @param size Symbol size
 * @param info Symbol type and binding
 * @param shndx Section index
 * @return true Success
 * @return false Error
 */
bool fcef_add_symbol(fcef_file_t *file, const char *name, uint32_t value,
                    uint32_t size, uint8_t info, uint16_t shndx) {
    if (!file || !name) {
        return false;
    }
    
    // Find or create the symbol table section
    fcef_section_header_t *sections = fcef_get_section_headers(file);
    fcef_section_header_t *symtab_section = NULL;
    fcef_section_header_t *strtab_section = NULL;
    uint32_t symtab_idx = UINT32_MAX;
    
    if (sections) {
        for (uint32_t i = 0; i < file->header->shnum; i++) {
            const char *section_name = fcef_get_string(file, sections[i].name, 0);
            if (section_name && strcmp(section_name, ".symtab") == 0) {
                symtab_section = &sections[i];
                symtab_idx = i;
            } else if (section_name && strcmp(section_name, ".strtab") == 0) {
                strtab_section = &sections[i];
            }
        }
    }
    
    // If no symbol table exists, we'd need to create one
    // This requires more complex section management that isn't fully implemented yet
    fprintf(stderr, "Symbol table manipulation not fully implemented in this version\n");
    return false;
}

/**
 * @brief Update CRC32 checksum in file header
 * 
 * @param file FCEF file handle
 * @return true Success
 * @return false Error
 */
bool fcef_update_crc32(fcef_file_t *file) {
    if (!file || !file->header) {
        return false;
    }
    
    // Save current CRC32
    uint32_t saved_crc = file->header->crc32;
    
    // Set CRC32 to 0 for calculation
    file->header->crc32 = 0;
    
    // Calculate CRC32 of entire file
    uint32_t calculated = fcef_calculate_crc32(file->data, file->size);
    file->header->crc32 = calculated;
    
    return true;
}

/**
 * @brief Save FCEF file to disk
 * 
 * @param file FCEF file handle
 * @param filename Output filename
 * @return true Success
 * @return false Error
 */
bool fcef_save(fcef_file_t *file, const char *filename) {
    if (!file || !filename) {
        return false;
    }
    
    // Update CRC32 before saving
    if (!fcef_update_crc32(file)) {
        fprintf(stderr, "Warning: Failed to update CRC32\n");
    }
    
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Failed to open file '%s' for writing\n", filename);
        return false;
    }
    
    size_t bytes_written = fwrite(file->data, 1, file->size, fp);
    fclose(fp);
    
    if (bytes_written != file->size) {
        fprintf(stderr, "Error: Failed to write entire file\n");
        return false;
    }
    
    return true;
}