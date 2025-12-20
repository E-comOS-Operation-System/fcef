/**
 * @file fcef-dump.c
 * @brief FCEF file viewer tool
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "fcef.h"

static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] <file.fcef>\n", program_name);
    printf("Options:\n");
    printf("  -h, --help     Show this help message\n");
    printf("  -v, --verbose  Verbose output\n");
    printf("  -H, --header   Show header only\n");
    printf("  -P, --phdrs    Show program headers only\n");
    printf("  -S, --shdrs    Show section headers only\n");
    printf("  -a, --all      Show all information (default)\n");
}

int main(int argc, char *argv[]) {
    const char *filename = NULL;
    bool show_header = true;
    bool show_phdrs = true;
    bool show_shdrs = true;
    bool verbose = false;
    
    
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"header", no_argument, 0, 'H'},
        {"phdrs", no_argument, 0, 'P'},
        {"shdrs", no_argument, 0, 'S'},
        {"all", no_argument, 0, 'a'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "hvHPSa", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                verbose = true;
                break;
            case 'H':
                show_header = true;
                show_phdrs = false;
                show_shdrs = false;
                break;
            case 'P':
                show_header = false;
                show_phdrs = true;
                show_shdrs = false;
                break;
            case 'S':
                show_header = false;
                show_phdrs = false;
                show_shdrs = true;
                break;
            case 'a':
                show_header = true;
                show_phdrs = true;
                show_shdrs = true;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Get file name
    if (optind >= argc) {
        fprintf(stderr, "Error: No input file specified\n");
        print_usage(argv[0]);
        return 1;
    }
    
    filename = argv[optind];
    
    // Open file
    fcef_file_t *file = fcef_open(filename);
    if (!file) {
        fprintf(stderr, "Error: Failed to open file '%s'\n", filename);
        return 1;
    }
    
    // Check validity
    if (!fcef_validate(file)) {
        fprintf(stderr, "Error: File '%s' is not a valid FCEF file\n", filename);
        fcef_close(file);
        return 1;
    }
    
    printf("FCEF File: %s\n", filename);
    printf("File size: %zu bytes\n", file->size);
    printf("Valid FCEF file\n\n");
    
    // Show header
    if (show_header) {
        fcef_dump_header(file->header);
        printf("\n");
    }
    
    // Show program headers
    if (show_phdrs) {
        uint32_t phnum = fcef_get_program_header_count(file);
        fcef_program_header_t *phdrs = fcef_get_program_headers(file);
        
        if (phnum > 0) {
            printf("Program Headers (%u):\n", phnum);
            for (uint32_t i = 0; i < phnum; i++) {
                printf("\n[%u]", i);
                fcef_dump_program_header(&phdrs[i]);
            }
            printf("\n");
        } else {
            printf("No program headers found\n\n");
        }
    }
    
    // Show section headers
    if (show_shdrs) {
        uint32_t shnum = fcef_get_section_header_count(file);
        fcef_section_header_t *shdrs = fcef_get_section_headers(file);
        
        if (shnum > 0) {
            printf("Section Headers (%u):\n", shnum);
            for (uint32_t i = 0; i < shnum; i++) {
                printf("\n[%u]", i);
                fcef_dump_section_header(&shdrs[i]);
            }
            printf("\n");
        } else {
            printf("No section headers found\n\n");
        }
    }
    
    // Show verbose info
    if (verbose) {
        printf("Detailed information:\n");
        printf("  Calculated CRC32: 0x%08X\n", 
               fcef_calculate_crc32(file->data, file->size));
        printf("  Stored CRC32:     0x%08X\n", file->header->crc32);
        
        // Check CRC32
        if (file->header->crc32 != 0) {
            uint32_t saved_crc = file->header->crc32;
            file->header->crc32 = 0;
            uint32_t calculated = fcef_calculate_crc32(file->data, file->size);
            file->header->crc32 = saved_crc;
            
            if (calculated == saved_crc) {
                printf("  CRC32:            OK\n");
            } else {
                printf("  CRC32:            MISMATCH (calculated: 0x%08X)\n", calculated);
            }
        }
    }
    
    // Close file
    fcef_close(file);
    
    return 0;
}