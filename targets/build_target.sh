#!/bin/bash
# targets/build_target.sh

if [ -z "$1" ]; then
    echo "Usage: $0 <source_dir> [sanitizers]"
    exit 1
fi

SOURCE_DIR="$1"
SANITIZERS="${2:-address,undefined}"
OUTPUT_BIN="$SOURCE_DIR/target_bin"

# Prefer AFL++'s compiler wrapper when available so the binary carries the
# coverage instrumentation afl-fuzz requires; plain clang otherwise.
if command -v afl-clang-fast >/dev/null 2>&1; then
    CC=afl-clang-fast
else
    CC=clang
fi

$CC -fsanitize=$SANITIZERS -g -O1 "$SOURCE_DIR"/*.c -o "$OUTPUT_BIN"

if [ $? -ne 0 ]; then
    exit 1
fi

echo "$OUTPUT_BIN"
exit 0
