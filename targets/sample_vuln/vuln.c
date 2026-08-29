#include <stdio.h>
#include <string.h>

// CWE-121: Stack-based Buffer Overflow
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 0;
    }

    char buffer[16];

    // Read the input file named on the command line (the AFL++ "@@" style).
    // Falls back to treating argv[1] as a literal string when reading fails,
    // so direct invocation still exercises the vulnerable copy.
    FILE *f = fopen(argv[1], "rb");
    if (f) {
        char filebuf[256];
        size_t n = fread(filebuf, 1, sizeof(filebuf) - 1, f);
        fclose(f);
        filebuf[n] = '\0';

        // Vulnerable: no bounds check before copying up to 255 bytes of file
        // contents into a 16-byte buffer.
        strcpy(buffer, filebuf);

        printf("Input was: %s\n", buffer);
        return 0;
    }

    // Vulnerable: no bounds check before copying argv[1] into a 16-byte buffer
    strcpy(buffer, argv[1]);

    printf("Input was: %s\n", buffer);
    return 0;
}
