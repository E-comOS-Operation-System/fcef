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
 * @param version_major Major version
 * @param version_minor Minor version
 * @return fcef_file_t* New file handle, or NULL on error
 */
/*fcef_file_t* fcef_create(uint8_t arch, uint8_t version_minor) {
    write_context_t *ctx = write_context_create(4096);
    if (!ctx) {
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
    
    free(ctx);
    
    // Initialize header
    file->header->magic = FCEF_MAGIC;
    file->header->arch = arch;
    file->header->version_major = version_major;
    file->header->version_minor = version_minor;
    file->header->entry_point = 0;
    file->header->phoff = sizeof(fcef_header_t);  // Program headers start after header
    file->header->shoff = 0;  // No section headers yet
    file->header->phnum = 0;
    file->header->shnum = 0;
    file->header->shstrndx = 0;
    file->header->flags = 0;
    file->header->crc32 = 0;  // Will be calculated later
    file->header->file_size = file->size;
    
    return file;
}*/ // We comment this out to avoid duplicate definition

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
    
    // We need to reallocate the file buffer to add the segment
    // This is a simplified implementation
    
    // Calculate new size
    size_t new_size = file->size + data_size;
    uint8_t *new_data = realloc(file->data, new_size);
    if (!new_data) {
        return false;
    }
    
    // Update file structure
    file->data = new_data;
    file->size = new_size;
    file->header = (fcef_header_t*)file->data;
    
    // Copy segment data
    uint32_t data_offset = file->size - data_size;
    if (data && data_size > 0) {
        memcpy(file->data + data_offset, data, data_size);
    }
    
    // Update program header (we need to write it to the program header table)
    // For now, we'll just update the count
    file->header->phnum++;
    
    // Update file size in header
    file->header->file_size = file->size;
    
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
    
    // This is a simplified implementation
    // In a real implementation, we would manage a string table section
    
    // For now, return a placeholder
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
    
    // This is a placeholder implementation
    // In a real implementation, we would add to a symbol table section
    
    return true;
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