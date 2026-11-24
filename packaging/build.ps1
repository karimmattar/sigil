# Build the Sigil desktop app on Windows.
#
#   powershell -ExecutionPolicy Bypass -File packaging\build.ps1
#   $env:PYTHON = "C:\Python313\python.exe"; .\packaging\build.ps1
#
# Use a 64-bit Python: Egypt Trust / ePass2003 drivers in System32 are 64-bit.
# Output: dist\sigil.exe
$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")
$python = if ($env:PYTHON) { $env:PYTHON } else { "python" }

$bits = & $python -c "import struct; print(struct.calcsize('P') * 8)"
if ($bits -ne "64") { Write-Warning "This Python is $bits-bit; 64-bit is recommended to match the token drivers." }

& $python -m pip install --upgrade pip
& $python -m pip install ".[tray,build]"
& $python -m PyInstaller --noconfirm --clean packaging\sigil.spec

Write-Host ""
Write-Host "Build finished:"
Get-ChildItem dist
