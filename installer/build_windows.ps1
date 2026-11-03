# Builds the Windows executable and installer. Run from repo root in PowerShell on Windows 10/11 x64.
$ErrorActionPreference = "Stop"
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\pip install -r requirements-dev.txt
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\pyinstaller installer\audit_bot.spec --noconfirm --distpath dist --workpath build
# Bundle Playwright Chromium next to the exe (used for DOM XSS checks)
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD\dist\CreativeStallAuditBot\ms-playwright"
.\.venv\Scripts\python -m playwright install chromium
& .\dist\CreativeStallAuditBot\CreativeStallAuditBot.exe --self-test
if ($LASTEXITCODE -ne 0) { throw "Self-test of built exe failed" }
$iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) { throw "Inno Setup 6 not found. Install from https://jrsoftware.org/isdl.php" }
& $iscc installer\setup.iss
Write-Host "Installer: dist\installer\CreativeStallAuditBot-Setup-1.0.0.exe"
