/**
 * @file fcef.h
 * @brief FCEF (Flexible Compact Executable Format) Definitions
 */

#ifndef FCEF_H
#define FCEF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Magic number for FCEF files
#define FCEF_MAGIC 0x46434546  // ASCII "FCEF"

// Architecture identifiers
typedef enum {
    FCEF_ARCH_X86     = 0x03,
    FCEF_ARCH_X86_64  = 0x3E,
    FCEF_ARCH_ARM     = 0x28,
    FCEF_ARCH_AARCH64 = 0xB7,
    FCEF_ARCH_RISCV32 = 0xF1,
    FCEF_ARCH_RISCV64 = 0xF3,
    FCEF_ARCH_CUSTOM  = 0xFF
} fcef_arch_t;

// Segment types
typedef enum {
    FCEF_PT_NULL    = 0,
    FCEF_PT_LOAD    = 1,
    FCEF_PT_DYNAMIC = 2,
    FCEF_PT_INTERP  = 3,
    FCEF_PT_NOTE    = 4,
    FCEF_PT_SHLIB   = 5,
    FCEF_PT_PHDR    = 6,
    FCEF_PT_TLS     = 7
} fcef_segment_type_t;

// Segment flags
#define FCEF_PF_X 0x1  // Execute
#define FCEF_PF_W 0x2  // Write
#define FCEF_PF_R 0x4  // Read

#define FCEF_SHT_NULL       0
#define FCEF_SHT_PROGBITS   1
#define FCEF_SHT_SYMTAB     2
#define FCEF_SHT_STRTAB     3
#define FCEF_SHT_RELA       4
#define FCEF_SHT_HASH       5
#define FCEF_SHT_DYNAMIC    6
#define FCEF_SHT_NOTE       7
#define FCEF_SHT_NOBITS     8
#define FCEF_SHT_REL        9
#define FCEF_SHT_SHLIB      10
#define FCEF_SHT_DYNSYM     11
// File header
typedef struct {
    uint32_t magic;
    uint8_t  arch;
    uint8_t  version;
    uint16_t flags;
    uint32_t entry_point;
    uint32_t phoff;
    uint32_t shoff;
    uint32_t phnum;
    uint32_t shnum;
    uint32_t shstrndx;
    uint32_t crc32;
    uint8_t  reserved[40];
    uint32_t file_size;
    uint8_t  version_major;
    uint8_t  version_minor;
} __attribute__((packed)) fcef_header_t;

typedef struct {
    uint32_t name;
    uint32_t value;
    uint32_t size;
    uint8_t info;
    uint8_t other;
    uint16_t shndx;
} fcef_sym_t;

// Program header (segment header)
typedef struct {
    uint32_t type;
    uint32_t offset;
    uint32_t vaddr;
    uint32_t paddr;
    uint32_t filesz;
    uint32_t memsz;
    uint32_t flags;
    uint32_t align;
} __attribute__((packed)) fcef_program_header_t;

typedef struct {
    uint32_t name;           
    uint32_t type;          
    uint32_t flags;          
    uint32_t addr;           
    uint32_t offset;         
    uint32_t size;           
    uint32_t link;           
    uint32_t info;           
    uint32_t addralign;      
    uint32_t entsize;        
} fcef_section_header_t;

// File handle structure
typedef struct fcef_file {
    uint8_t *data;
    size_t size;
    fcef_header_t *header;
    bool allocated;
    uint32_t base_address;
} fcef_file_t;

// API Functions
fcef_file_t* fcef_open(const char *filename);
fcef_file_t* fcef_create(uint8_t arch, uint16_t version);
fcef_file_t* fcef_create_from_memory(void *data, size_t size, bool take_ownership);
bool fcef_save(fcef_file_t *file, const char *filename);
void fcef_close(fcef_file_t *file);

bool fcef_validate(fcef_file_t *file);
uint32_t fcef_calculate_crc32(const uint8_t *data, size_t length);

fcef_program_header_t* fcef_get_program_headers(fcef_file_t *file);
uint32_t fcef_get_program_header_count(fcef_file_t *file);
bool fcef_add_segment(fcef_file_t *file, const fcef_program_header_t *phdr, 
                     const void *data, size_t data_size);

fcef_section_header_t* fcef_get_section_headers(fcef_file_t *file);
uint32_t fcef_get_section_header_count(fcef_file_t *file);
bool fcef_add_section(fcef_file_t *file, const fcef_section_header_t *shdr,
                     const void *data, size_t data_size);

const char* fcef_get_string(fcef_file_t *file, uint32_t strtab_offset, uint32_t index);
uint32_t fcef_add_string(fcef_file_t *file, const char *str);

fcef_sym_t* fcef_find_symbol(fcef_file_t *file, const char *name);
bool fcef_add_symbol(fcef_file_t *file, const char *name, uint32_t value, 
                    uint32_t size, uint8_t info, uint16_t shndx);

bool fcef_load_segment(fcef_file_t *file, fcef_program_header_t *phdr, void *memory);
bool fcef_relocate(fcef_file_t *file, void *memory, uint32_t base_address);

bool fcef_update_crc32(fcef_file_t *file);


void fcef_set_entry_point(fcef_file_t *file, uint32_t entry_point);
// uint64_t fcef_get_entry_point(fcef_file_t *file);
void fcef_set_base_address(fcef_file_t *file, uint32_t base_address);
uint32_t fcef_get_base_address(fcef_file_t *file);

void fcef_dump_header(const fcef_header_t *header);

void fcef_dump_program_header(const fcef_program_header_t *phdr);
void fcef_dump_section_header(const fcef_section_header_t *shdr);
#ifdef __cplusplus
}
#endif

#endif // FCEF_H