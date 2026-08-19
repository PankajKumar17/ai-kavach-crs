param (
    [Parameter(Mandatory=$true)][string]$SourceDir,
    [string]$Sanitizers = "address,undefined"
)

$OutputBin = Join-Path $SourceDir "target_bin.bat"

# We use our mock clang on Windows
clang -fsanitize=$Sanitizers -g -O1 "$SourceDir\*.c" -o $OutputBin

if ($LASTEXITCODE -ne 0) {
    exit 1
}

Write-Output $OutputBin
exit 0
