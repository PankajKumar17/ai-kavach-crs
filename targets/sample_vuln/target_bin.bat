@echo off 
findstr /i "strlen" "%~dp0vuln.c" >nul 
if not errorlevel 1 exit /b 0 
echo ==234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x12345 >&2 
echo #0 0x12345 in main %~dp0vuln.c:13 >&2 
echo buffer-overflow >&2 
exit /b 1 
