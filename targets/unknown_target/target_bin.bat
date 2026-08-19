@echo off
set "arg=%~1"
if "%arg%"=="" (
    echo Usage: target_bin.bat ^<input^>
    exit /b 1
)

REM Check if input is larger than 16 chars to mock the overflow
set "len=0"
:loop
if not "%arg%"=="" (
    set /a "len+=1"
    set "arg=%arg:~1%"
    goto loop
)

if %len% GTR 16 (
    echo ==234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x12345
    echo #0 0x12345 in parse_input C:\Users\panka\OneDrive\Desktop\hack\ai-kavach-crs\targets\unknown_target\vuln.c:7
    echo #1 0x67890 in main C:\Users\panka\OneDrive\Desktop\hack\ai-kavach-crs\targets\unknown_target\vuln.c:16
    echo buffer-overflow
    exit /b 1
)

echo Parsed successfully
exit /b 0
