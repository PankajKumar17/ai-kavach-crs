#include <stdio.h>
#include <string.h>

// CWE-121: Stack-based Buffer Overflow
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 0;
    }
    
    char buffer[16];
    // Vulnerable: no bounds check before copying argv[1] into a 16-byte buffer
    strcpy(buffer, argv[1]);
    
    printf("Input was: %s\n", buffer);
    return 0;
}
