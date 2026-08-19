#include <stdio.h>
#include <string.h>

void parse_input(char *input) {
    char buffer[16];
    // Vulnerability: strcpy without bounds checking
    strcpy(buffer, input);
    printf("Parsed: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    parse_input(argv[1]);
    return 0;
}
