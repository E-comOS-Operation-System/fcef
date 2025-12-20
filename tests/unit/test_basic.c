#include "fcef.h"
#include <stdio.h>

int main() {
    printf("FCEF Unit Tests\n");
    printf("===============\n\n");
    

    fcef_header_t header;
    fcef_init_header(&header);
    
    if (fcef_validate(&header)) {
        printf("✅ Header validation passed\n");
    } else {
        printf("❌ Header validation failed\n");
        return 1;
    }
    
    fcef_print_header(&header);
    
    printf("\n✅ All tests passed!\n");
    return 0;
}
