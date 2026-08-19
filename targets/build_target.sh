#!/bin/bash
# targets/build_target.sh

if [ -z "$1" ]; then
    echo "Usage: $0 <source_dir> [sanitizers]"
    exit 1
fi

SOURCE_DIR="$1"
SANITIZERS="${2:-address,undefined}"
OUTPUT_BIN="$SOURCE_DIR/target_bin"

clang -fsanitize=$SANITIZERS -g -O1 "$SOURCE_DIR"/*.c -o "$OUTPUT_BIN"

if [ $? -ne 0 ]; then
    exit 1
fi

echo "$OUTPUT_BIN"
exit 0
