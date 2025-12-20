/**
 * @file fcef.c
 * @brief Core FCEF library implementation
 */

#include "fcef.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// ============================================
// Internal function declarations
// ============================================

static uint32_t crc32_table[256];
static bool crc32_table_initialized = false;

static void init_crc32_table(void);

// ============================================
// CRC32 Implementation
// ============================================

/**
 * @brief Initialize CRC32 lookup table
 */
static void init_crc32_table(void) {
    if (crc32_table_initialized) return;
    
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            if (c & 1) {
                c = 0xEDB88320 ^ (c >> 1);
            } else {
                c = c >> 1;
            }
        }
        crc32_table[i] = c;
    }
    crc32_table_initialized = true;
}

/**
 * @brief Calculate CRC32 checksum for data
 * 
 * @param data Pointer to data
 * @param length Length of data in bytes
 * @return uint32_t CRC32 checksum
 */
uint32_t fcef_calculate_crc32(const uint8_t *data, size_t length) {
    if (!data || length == 0) {
        return 0;
    }
    
    if (!crc32_table_initialized) {
        init_crc32_table();
    }
    
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        uint8_t byte = data[i];
        uint32_t index = (crc ^ byte) & 0xFF;
        crc = crc32_table[index] ^ (crc >> 8);
    }
    
    return crc ^ 0xFFFFFFFF;
}

// ============================================
// File Operations - Fixed function signatures
// ============================================

/**
 * @brief Open and read an FCEF file from disk
 * 
 * @param filename Path to the FCEF file
 * @return fcef_file_t* File handle, or NULL on error
 */
fcef_file_t* fcef_open(const char *filename) {
    if (!filename) {
        return NULL;
    }
    
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file '%s': %s\n", filename, strerror(errno));
        return NULL;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size <= 0) {
        fclose(fp);
        fprintf(stderr, "File '%s' is empty\n", filename);
        return NULL;
    }
    
    // Allocate memory
    fcef_file_t *file = malloc(sizeof(fcef_file_t));
    if (!file) {
        fclose(fp);
        fprintf(stderr, "Failed to allocate file structure\n");
        return NULL;
    }
    
    file->data = malloc(file_size);
    if (!file->data) {
        fclose(fp);
        free(file);
        fprintf(stderr, "Failed to allocate file buffer\n");
        return NULL;
    }
    
    // Read file
    size_t bytes_read = fread(file->data, 1, file_size, fp);
    fclose(fp);
    
    if (bytes_read != (size_t)file_size) {
        free(file->data);
        free(file);
        fprintf(stderr, "Failed to read entire file\n");
        return NULL;
    }
    
    file->size = file_size;
    file->header = (fcef_header_t*)file->data;
    file->allocated = true;
    file->base_address = 0;
    
    return file;
}

/**
 * @brief Create a new FCEF file
 * 
 * @param arch Architecture identifier
 * @param version_major Major version
 * @param version_minor Minor version
 * @return fcef_file_t* New file handle, or NULL on error
 */
fcef_file_t* fcef_create(uint8_t arch, uint16_t version_major) {
    // Allocate file structure
    fcef_file_t *file = malloc(sizeof(fcef_file_t));
    if (!file) {
        return NULL;
    }
    
    // Initial size: header + space for program headers + section headers
    size_t initial_size = sizeof(fcef_header_t) + 
                          sizeof(fcef_program_header_t) * 4 + 
                          sizeof(fcef_section_header_t) * 8;
    
    file->data = calloc(1, initial_size);  // Zero-initialize
    if (!file->data) {
        free(file);
        return NULL;
    }
    
    file->size = initial_size;
    file->allocated = true;
    file->base_address = 0;
    
    // Initialize header
    file->header = (fcef_header_t*)file->data;
    file->header->magic = FCEF_MAGIC;
    file->header->arch = arch;
    file->header->version_major = version_major;

    file->header->entry_point = 0;
    file->header->phoff = sizeof(fcef_header_t);
    file->header->shoff = 0;  // No section headers yet
    file->header->phnum = 0;
    file->header->shnum = 0;
    file->header->shstrndx = 0;
    file->header->flags = 0;
    file->header->crc32 = 0;
    file->header->file_size = initial_size;
    
    return file;
}

/**
 * @brief Create an FCEF file handle from memory
 * 
 * @param data Pointer to file data in memory
 * @param size Size of file data
 * @param take_ownership If true, the handle will free the memory when closed
 * @return fcef_file_t* File handle, or NULL on error
 */
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
    
    // Update CRC32
    if (!fcef_update_crc32(file)) {
        fprintf(stderr, "Warning: Failed to update CRC32\n");
    }
    
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Failed to open file '%s' for writing: %s\n", 
                filename, strerror(errno));
        return false;
    }
    
    size_t bytes_written = fwrite(file->data, 1, file->size, fp);
    fclose(fp);
    
    return bytes_written == file->size;
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

// ============================================
// Validation Functions
// ============================================

/**
 * @brief Validate FCEF file structure
 * 
 * @param file FCEF file handle
 * @return true File is valid
 * @return false File is invalid
 */
bool fcef_validate(fcef_file_t *file) {
    if (!file || !file->header) {
        fprintf(stderr, "Error: NULL file or header\n");
        return false;
    }
    
    // Check magic number
    if (file->header->magic != FCEF_MAGIC) {
        fprintf(stderr, "Invalid magic number: 0x%08X (expected 0x%08X)\n",
                file->header->magic, FCEF_MAGIC);
        return false;
    }
    
    // Check file size
    if (file->header->file_size > file->size) {
        fprintf(stderr, "Header file size (%u) exceeds actual file size (%zu)\n",
                file->header->file_size, file->size);
        return false;
    }
    
    return true;
}

// ============================================
// Program Header Operations - Fixed const modifier
// ============================================

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
    
    if (file->header->phoff >= file->size) {
        return NULL;
    }
    
    return (fcef_program_header_t*)(file->data + file->header->phoff);
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
    
    // Extend file size to accommodate new data
    uint32_t data_offset = file->size;
    size_t new_size = file->size + data_size;
    
    uint8_t *new_data = realloc(file->data, new_size);
    if (!new_data) {
        return false;
    }
    
    file->data = new_data;
    file->size = new_size;
    file->header = (fcef_header_t*)file->data;
    
    // Copy data
    if (data && data_size > 0) {
        memcpy(file->data + data_offset, data, data_size);
    }
    
    // Update program header table (simplified implementation)
    file->header->phnum++;
    
    // Update file size in header
    file->header->file_size = file->size;
    
    return true;
}

// ============================================
// Section Header Operations
// ============================================

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
    
    if (file->header->shoff >= file->size) {
        return NULL;
    }
    
    return (fcef_section_header_t*)(file->data + file->header->shoff);
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

// ============================================
// String Table Operations
// ============================================

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
    if (index >= file->size - strtab_offset) {
        return NULL;
    }
    
    return strtab + index;
}

// ============================================
// Symbol Table Operations
// ============================================

/**
 * @brief Find a symbol by name
 * 
 * @param file FCEF file handle
 * @param name Symbol name to find
 * @return fcef_sym_t* Pointer to symbol, or NULL if not found
 */
fcef_sym_t* fcef_find_symbol(fcef_file_t *file, const char *name) {
    // Simplified implementation - would need to traverse symbol table
    (void)file;
    (void)name;
    return NULL;
}

// ============================================
// Loading and Relocation
// ============================================

/**
 * @brief Load a segment into memory
 * 
 * @param file FCEF file handle
 * @param phdr Program header describing the segment
 * @param memory Base address of memory to load into
 * @return true Success
 * @return false Error
 */
bool fcef_load_segment(fcef_file_t *file, fcef_program_header_t *phdr, void *memory) {
    if (!file || !phdr || !memory) {
        return false;
    }
    
    // Check offset is valid
    if (phdr->offset + phdr->filesz > file->size) {
        return false;
    }
    
    // Copy data
    uint8_t *src = file->data + phdr->offset;
    uint8_t *dst = (uint8_t*)memory + phdr->vaddr;
    
    memcpy(dst, src, phdr->filesz);
    
    // If memory size > file size, zero out remaining
    if (phdr->memsz > phdr->filesz) {
        memset(dst + phdr->filesz, 0, phdr->memsz - phdr->filesz);
    }
    
    return true;
}

// ============================================
// Utility Functions - Fixed return types
// ============================================

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
 * @brief Get entry point address
 * 
 * @param file FCEF file handle
 * @return uint32_t Entry point address
 */
/*uint64_t fcef_get_entry_point(fcef_file_t *file) {
    if (!file || !file->header) {
        return 0;
    }
    return file->header->entry_point;
}*/

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

// ============================================
// CRC32 Update
// ============================================

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
    
    // Calculate CRC32 of entire file
    file->header->crc32 = 0;
    uint32_t calculated = fcef_calculate_crc32(file->data, file->size);
    file->header->crc32 = calculated;
    
    return true;
}

// ============================================
// Debugging and Output - Add missing implementations
// ============================================

/**
 * @brief Dump file header information
 * 
 * @param header File header to dump
 */
void fcef_dump_header(const fcef_header_t *header) {
    if (!header) {
        printf("Header: NULL\n");
        return;
    }
    
    printf("=== FCEF Header ===\n");
    printf("Magic:          0x%08X (%c%c%c%c)\n", 
           header->magic,
           (header->magic >> 24) & 0xFF,
           (header->magic >> 16) & 0xFF,
           (header->magic >> 8) & 0xFF,
           header->magic & 0xFF);
    printf("Architecture:   0x%02X\n", header->arch);
    printf("Version:        %u.%u\n", header->version_major, header->version_minor);
    printf("Entry point:    0x%08X\n", header->entry_point);
    printf("PH offset:      0x%08X\n", header->phoff);
    printf("SH offset:      0x%08X\n", header->shoff);
    printf("PH count:       %u\n", header->phnum);
    printf("SH count:       %u\n", header->shnum);
    printf("SH str idx:     %u\n", header->shstrndx);
    printf("Flags:          0x%08X\n", header->flags);
    printf("CRC32:          0x%08X\n", header->crc32);
    printf("File size:      %u bytes\n", header->file_size);
    printf("==================\n");
}

/**
 * @brief Dump program header information
 * 
 * @param phdr Program header to dump
 */
void fcef_dump_program_header(const fcef_program_header_t *phdr) {
    if (!phdr) {
        printf("Program header: NULL\n");
        return;
    }
    
    printf("  Type:      0x%08X ", phdr->type);
    switch (phdr->type) {
        case FCEF_PT_NULL:    printf("(NULL)\n"); break;
        case FCEF_PT_LOAD:    printf("(LOAD)\n"); break;
        case FCEF_PT_DYNAMIC: printf("(DYNAMIC)\n"); break;
        case FCEF_PT_INTERP:  printf("(INTERP)\n"); break;
        case FCEF_PT_NOTE:    printf("(NOTE)\n"); break;
        case FCEF_PT_PHDR:    printf("(PHDR)\n"); break;
        case FCEF_PT_TLS:     printf("(TLS)\n"); break;
        default:              printf("(UNKNOWN)\n"); break;
    }
    
    printf("  Offset:    0x%08X\n", phdr->offset);
    printf("  VAddr:     0x%08X\n", phdr->vaddr);
    printf("  PAddr:     0x%08X\n", phdr->paddr);
    printf("  FileSz:    0x%08X\n", phdr->filesz);
    printf("  MemSz:     0x%08X\n", phdr->memsz);
    
    printf("  Flags:     0x%08X ", phdr->flags);
    if (phdr->flags & FCEF_PF_R) printf("R");
    if (phdr->flags & FCEF_PF_W) printf("W");
    if (phdr->flags & FCEF_PF_X) printf("X");
    printf("\n");
    
    printf("  Align:     0x%08X\n", phdr->align);
}

/**
 * @brief Dump section header information
 * 
 * @param shdr Section header to dump
 */
void fcef_dump_section_header(const fcef_section_header_t *shdr) {
    if (!shdr) {
        printf("Section header: NULL\n");
        return;
    }
    
    printf("  Name:      0x%08X\n", shdr->name);
    
    printf("  Type:      0x%08X ", shdr->type);
    switch (shdr->type) {
        case FCEF_SHT_NULL:     printf("(NULL)\n"); break;
        case FCEF_SHT_PROGBITS: printf("(PROGBITS)\n"); break;
        case FCEF_SHT_SYMTAB:   printf("(SYMTAB)\n"); break;
        case FCEF_SHT_STRTAB:   printf("(STRTAB)\n"); break;
        case FCEF_SHT_RELA:     printf("(RELA)\n"); break;
        case FCEF_SHT_HASH:     printf("(HASH)\n"); break;
        case FCEF_SHT_DYNAMIC:  printf("(DYNAMIC)\n"); break;
        case FCEF_SHT_NOTE:     printf("(NOTE)\n"); break;
        case FCEF_SHT_NOBITS:   printf("(NOBITS)\n"); break;
        case FCEF_SHT_REL:      printf("(REL)\n"); break;
        case FCEF_SHT_SHLIB:    printf("(SHLIB)\n"); break;
        case FCEF_SHT_DYNSYM:   printf("(DYNSYM)\n"); break;
        default:                printf("(UNKNOWN)\n"); break;
    }
    
    printf("  Flags:     0x%08X\n", shdr->flags);
    printf("  Addr:      0x%08X\n", shdr->addr);
    printf("  Offset:    0x%08X\n", shdr->offset);
    printf("  Size:      0x%08X\n", shdr->size);
    printf("  Link:      0x%08X\n", shdr->link);
    printf("  Info:      0x%08X\n", shdr->info);
    printf("  AddrAlign: 0x%08X\n", shdr->addralign);
    printf("  EntSize:   0x%08X\n", shdr->entsize);
}

void fcef_init_header(fcef_header_t *header) {
    if (!header) return;

    uint8_t *magic_bytes = (uint8_t*)&header->magic;
    magic_bytes[0] = 0x46;  // 'F' 
    magic_bytes[1] = 0x43;  // 'C'
    magic_bytes[2] = 0x45;  // 'E'
    magic_bytes[3] = 0x46;  // 'F' 
    header->version_major = 1;  // Main version
    header->version_minor = 0;  // Sub version
    
    
    header->crc32 = 0;
    
   
    header->file_size = 0;
    
    memset(header->reserved, 0, sizeof(header->reserved));
}
void fcef_print_header(const fcef_header_t *header) {
    if (!header) {
        printf("NULL header\n");
        return;
    }
    
    // From 32 bit magic to 4 chars
    uint8_t magic_bytes[4];
    magic_bytes[0] = (header->magic >> 0) & 0xFF;  // 1
    magic_bytes[1] = (header->magic >> 8) & 0xFF;  // 2
    magic_bytes[2] = (header->magic >> 16) & 0xFF; // 3
    magic_bytes[3] = (header->magic >> 24) & 0xFF; // 4
    
    printf("┌─────────────────────────────────────────────┐\n");
    printf("│              FCEF File Header               │\n");
    printf("├─────────────────────────────────────────────┤\n");
    
    // Print Magic
    printf("│ Magic:    %c%c%c%c (0x%08X)           │\n", 
           magic_bytes[0], magic_bytes[1], magic_bytes[2], magic_bytes[3],
           header->magic);
    
    // Print Version
    printf("│ Version:  %u.%u (0x%02X%02X)               │\n", 
           header->version_major, header->version_minor,
           header->version_major, header->version_minor);
    
    // Print CRC32
    printf("│ CRC32:    0x%08X                      │\n", header->crc32);
    
    // Print file size
    printf("│ File Size: %u bytes                    │\n", header->file_size);
    
    // Print reserved bytes (as hex)
    printf("│ Reserved: ");
    for (int i = 0; i < 8 && i < 40; i++) {  // Only print first 8 bytes for brevity
        printf("%02X ", header->reserved[i]);
    }
    printf("...           │\n");
    printf("└─────────────────────────────────────────────┘\n");
}