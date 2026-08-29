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

    // Read the input file named on the command line (the AFL++ "@@" style)
    // and pass its contents to the vulnerable parser. Falls back to argv[1]
    // as a literal string when the file cannot be opened.
    FILE *f = fopen(argv[1], "rb");
    if (f) {
        char filebuf[256];
        size_t n = fread(filebuf, 1, sizeof(filebuf) - 1, f);
        fclose(f);
        filebuf[n] = '\0';
        parse_input(filebuf);
        return 0;
    }

    parse_input(argv[1]);
    return 0;
}
