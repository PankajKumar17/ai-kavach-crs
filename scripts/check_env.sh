#!/bin/bash

# check_env.sh
# Verifies toolchain for AI Kavach CRS

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: Required tool '$1' is missing from PATH."
        exit 1
    fi
    echo -n "$1 version: "
    "$1" --version | head -n 1
}

echo "Checking basic tools..."
check_command "clang"
check_command "cmake"
check_command "git"

echo "Checking Semgrep..."
if ! command -v "semgrep" &> /dev/null; then
    echo "Installing Semgrep..."
    pip install semgrep
fi
check_command "semgrep"

echo "Checking AFL++..."
if ! command -v "afl-fuzz" &> /dev/null; then
    echo "Installing AFL++..."
    if command -v "apt" &> /dev/null; then
        sudo apt update && sudo apt install -y afl++
    else
        echo "Apt not found, attempting source installation..."
        git clone https://github.com/AFLplusplus/AFLplusplus /tmp/afl++
        cd /tmp/afl++ || exit 1
        make
        export PATH=$PATH:/tmp/afl++
    fi
fi
if ! command -v "afl-fuzz" &> /dev/null; then
    echo "Error: afl-fuzz installation failed or not on PATH."
    exit 1
fi
echo "AFL++ installed successfully!"

echo "Environment check passed."
exit 0
