/**
 * @file fcef_validator.c
 * @brief FCEF file validator implementation
 * 
 * Provides functions for validating FCEF file integrity and structure.
 */

#include "fcef.h"
#include <stdio.h>
#include <string.h>

// CRC32 lookup table
static uint32_t crc32_table[256];
static bool crc32_table_initialized = false;

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

/**
 * @brief Validate program header
 * 
 * @param file FCEF file handle
 * @param phdr Program header to validate
 * @param index Index of program header (for error messages)
 * @return true Valid
 * @return false Invalid
 */
static bool validate_program_header(fcef_file_t *file, fcef_program_header_t *phdr, uint32_t index) {
    if (!file || !phdr) {
        return false;
    }
    
    // Check segment offset
    if (phdr->offset >= file->size) {
        fprintf(stderr, "Error: Program header %u: offset 0x%08X exceeds file size 0x%08zX\n",
                index, phdr->offset, file->size);
        return false;
    }
    
    // Check segment data doesn't exceed file bounds
    if (phdr->offset + phdr->filesz > file->size) {
        fprintf(stderr, "Error: Program header %u: segment data exceeds file bounds\n", index);
        return false;
    }
    
    // Check memory size is not less than file size
    if (phdr->memsz < phdr->filesz) {
        fprintf(stderr, "Error: Program header %u: memory size (0x%08X) is less than file size (0x%08X)\n",
                index, phdr->memsz, phdr->filesz);
        return false;
    }
    
    // Check alignment is power of two (or zero)
    if (phdr->align != 0) {
        if ((phdr->align & (phdr->align - 1)) != 0) {
            fprintf(stderr, "Error: Program header %u: alignment 0x%08X is not a power of two\n",
                    index, phdr->align);
            return false;
        }
    }
    
    return true;
}

/**
 * @brief Validate section header
 * 
 * @param file FCEF file handle
 * @param shdr Section header to validate
 * @param index Index of section header (for error messages)
 * @return true Valid
 * @return false Invalid
 */
static bool validate_section_header(fcef_file_t *file, fcef_section_header_t *shdr, uint32_t index) {
    if (!file || !shdr) {
        return false;
    }
    
    // For sections with data, check bounds
    if (shdr->type != FCEF_SHT_NOBITS && shdr->type != FCEF_SHT_NULL) {
        if (shdr->offset >= file->size) {
            fprintf(stderr, "Error: Section header %u: offset 0x%08X exceeds file size\n",
                    index, shdr->offset);
            return false;
        }
        
        if (shdr->offset + shdr->size > file->size) {
            fprintf(stderr, "Error: Section header %u: section data exceeds file bounds\n", index);
            return false;
        }
    }
    
    // Check alignment is power of two (or zero)
    if (shdr->addralign != 0) {
        if ((shdr->addralign & (shdr->addralign - 1)) != 0) {
            fprintf(stderr, "Error: Section header %u: alignment 0x%08X is not a power of two\n",
                    index, shdr->addralign);
            return false;
        }
    }
    
    return true;
}

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
    
    fcef_header_t *header = file->header;
    
    // Check magic number
    const uint8_t *magic_bytes = (const uint8_t*)&header->magic;
    if (magic_bytes[0] != 0x46 || magic_bytes[1] != 0x43 ||
        magic_bytes[2] != 0x45 || magic_bytes[3] != 0x46) {
        printf("Invalid magic number: 0x%02X%02X%02X%02X (expected 0x46434546)\n",
               magic_bytes[3], magic_bytes[2], magic_bytes[1], magic_bytes[0]);
        return false;
    }
    
    // Check version
    if (header->version_major == 0) {
        fprintf(stderr, "Error: Invalid version: %u.%u\n",
                header->version_major, header->version_minor);
        return false;
    }
    
    // Check file size consistency
    if (header->file_size > file->size) {
        fprintf(stderr, "Error: Header file size (%u) exceeds actual file size (%zu)\n",
                header->file_size, file->size);
        return false;
    }
    
    // Validate program headers
    if (header->phnum > 0) {
        // Check program header table bounds
        if (header->phoff + header->phnum * sizeof(fcef_program_header_t) > file->size) {
            fprintf(stderr, "Error: Program header table exceeds file bounds\n");
            return false;
        }
        
        fcef_program_header_t *phdrs = (fcef_program_header_t*)(file->data + header->phoff);
        
        for (uint32_t i = 0; i < header->phnum; i++) {
            if (!validate_program_header(file, &phdrs[i], i)) {
                return false;
            }
        }
    }
    
    // Validate section headers
    if (header->shnum > 0) {
        // Check section header table bounds
        if (header->shoff + header->shnum * sizeof(fcef_section_header_t) > file->size) {
            fprintf(stderr, "Error: Section header table exceeds file bounds\n");
            return false;
        }
        
        // Check string table index is valid
        if (header->shstrndx >= header->shnum && header->shstrndx != 0) {
            fprintf(stderr, "Error: Invalid string table index: %u (max: %u)\n",
                    header->shstrndx, header->shnum - 1);
            return false;
        }
        
        fcef_section_header_t *shdrs = (fcef_section_header_t*)(file->data + header->shoff);
        
        for (uint32_t i = 0; i < header->shnum; i++) {
            if (!validate_section_header(file, &shdrs[i], i)) {
                return false;
            }
        }
    }
    
    // Validate CRC32 if present
    if (header->crc32 != 0) {
        uint32_t saved_crc = header->crc32;
        header->crc32 = 0;
        uint32_t calculated_crc = fcef_calculate_crc32(file->data, file->size);
        header->crc32 = saved_crc;
        
        if (calculated_crc != saved_crc) {
            fprintf(stderr, "Error: CRC32 mismatch: calculated 0x%08X, stored 0x%08X\n",
                    calculated_crc, saved_crc);
            return false;
        }
    }
    
    return true;
}

/**
 * @brief Perform relocation on loaded segments
 * 
 * @param file FCEF file handle
 * @param memory Base address of loaded memory
 * @param base_address Load base address
 * @return true Success
 * @return false Error
 */
bool fcef_relocate(fcef_file_t *file, void *memory, uint32_t base_address) {
    if (!file || !memory) {
        return false;
    }
    
    // This is a simplified relocation implementation
    // A real implementation would process relocation sections
    
    // For now, just update the base address
    file->base_address = base_address;
    
    return true;
}

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
    
    // Check segment is loadable
    if (phdr->type != FCEF_PT_LOAD) {
        fprintf(stderr, "Error: Cannot load non-LOAD segment\n");
        return false;
    }
    
    // Check bounds
    if (phdr->offset + phdr->filesz > file->size) {
        fprintf(stderr, "Error: Segment data exceeds file bounds\n");
        return false;
    }
    
    // Calculate destination address
    uint8_t *dest = (uint8_t*)memory + phdr->vaddr;
    uint8_t *src = file->data + phdr->offset;
    
    // Copy segment data
    memcpy(dest, src, phdr->filesz);
    
    // Zero out BSS area if memory size > file size
    if (phdr->memsz > phdr->filesz) {
        memset(dest + phdr->filesz, 0, phdr->memsz - phdr->filesz);
    }
    
    return true;
}

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
    printf("Magic:          0x%08X ('%c%c%c%c')\n",
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