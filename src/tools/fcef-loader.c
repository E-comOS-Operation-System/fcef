/**
 * @file fcef-loader.c
 * @brief FCEF executable loader tool
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../../include/fcef.h"

static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] <file.fcef>\n", program_name);
    printf("Load and execute an FCEF executable\n");
    printf("Options:\n");
    printf("  -h, --help     Show this help message\n");
    printf("  -i, --info     Show file information before execution\n");
    printf("  -v, --verify   Verify file integrity before execution\n");
}

int main(int argc, char *argv[]) {
    const char *filename = NULL;
    bool show_info = false;
    bool verify_integrity = false;
    
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"info", no_argument, 0, 'i'},
        {"verify", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "hiv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'i':
                show_info = true;
                break;
            case 'v':
                verify_integrity = true;
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
    
    // First, let's optionally display file information
    if (show_info || verify_integrity) {
        fcef_file_t *temp_file = fcef_open(filename);
        if (!temp_file) {
            fprintf(stderr, "Error: Failed to open file '%s' for inspection\n", filename);
            return 1;
        }
        
        if (!fcef_validate(temp_file)) {
            fprintf(stderr, "Error: File '%s' is not a valid FCEF file\n", filename);
            fcef_close(temp_file);
            return 1;
        }
        
        if (show_info) {
            printf("FCEF File: %s\n", filename);
            printf("File size: %zu bytes\n", temp_file->size);
            fcef_dump_header(temp_file->header);
            printf("\n");
        }
        
        fcef_close(temp_file);
    }
    
    // Now load and execute the file
    printf("Loading and executing: %s\n", filename);
    int exit_code = fcef_load_and_execute_file(filename);
    
    if (exit_code == -1) {
        fprintf(stderr, "Error: Failed to load and execute file '%s'\n", filename);
        return 1;
    }
    
    printf("Execution completed with exit code: %d\n", exit_code);
    return 0;
}