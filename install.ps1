# JS Agent One-Click Installer for Windows
# Run: powershell -ExecutionPolicy Bypass -File install.ps1
#
# Parameters:
#   -NoShortcut   Skip desktop shortcut creation
#   -NoStart      Skip auto-start prompt after installation
#   -ProjectDir   Override installation directory (default: script location)

param(
    [switch]$NoShortcut,
    [switch]$NoStart,
    [string]$ProjectDir = ""
)

$ErrorActionPreference = "Stop"

if ($ProjectDir) {
    $PROJECT_DIR = Resolve-Path $ProjectDir
} else {
    $PROJECT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
}

$PYTHON_MIN = [System.Version]"3.12.0"
$VENV_DIR = Join-Path $PROJECT_DIR ".venv"

function Write-Header($text) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Step($num, $total, $text) {
    Write-Host ""
    Write-Host "[$num/$total] $text" -ForegroundColor Yellow
}

Write-Header "JS Agent Windows Installer"
Write-Host "  Project: $PROJECT_DIR" -ForegroundColor Gray

# 1. Check Python
Write-Step 1 5 "Checking Python..."
$pythonCmd = $null
foreach ($cmd in @("python3", "python", "py")) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        $pythonCmd = $cmd
        break
    }
}

if (-not $pythonCmd) {
    Write-Host "  X Python not found. Please install Python 3.12+ from https://python.org" -ForegroundColor Red
    exit 1
}

$pyVersionStr = & $pythonCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
$pyVersion = [System.Version]$pyVersionStr
Write-Host "  Found Python $pyVersionStr"

if ($pyVersion -lt $PYTHON_MIN) {
    Write-Host "  X Requires Python 3.12 or higher" -ForegroundColor Red
    exit 1
}
Write-Host "  + Python version OK" -ForegroundColor Green

# 2. Create virtual environment
Write-Step 2 5 "Creating virtual environment..."
if (-not (Test-Path $VENV_DIR)) {
    & $pythonCmd -m venv "$VENV_DIR"
    Write-Host "  + Virtual environment created" -ForegroundColor Green
} else {
    Write-Host "  + Virtual environment already exists" -ForegroundColor Green
}

# 3. Install dependencies
Write-Step 3 5 "Installing dependencies..."
$pipCmd = Join-Path $VENV_DIR "Scripts\pip.exe"

# Try uv first
$uvCmd = Join-Path $VENV_DIR "Scripts\uv.exe"
if (Get-Command "uv" -ErrorAction SilentlyContinue) {
    Write-Host "  Using uv (fast)..."
    & uv pip install -e "$PROJECT_DIR"
} else {
    Write-Host "  Using pip..."
    & $pipCmd install --upgrade pip
    & $pipCmd install -e "$PROJECT_DIR"
}
Write-Host "  + Dependencies installed" -ForegroundColor Green

# 4. Create desktop shortcut (unless -NoShortcut)
if (-not $NoShortcut) {
    Write-Step 4 5 "Creating shortcuts..."
    $WshShell = New-Object -ComObject WScript.Shell
    $shortcutPath = Join-Path $env:USERPROFILE "Desktop\JS Agent.lnk"
    $Shortcut = $WshShell.CreateShortcut($shortcutPath)
    $Shortcut.TargetPath = "powershell.exe"
    $Shortcut.Arguments = "-NoExit -Command `"& '$VENV_DIR\Scripts\Activate.ps1'; js web`""
    $Shortcut.WorkingDirectory = $PROJECT_DIR
    $Shortcut.IconLocation = "%SystemRoot%\System32\SHELL32.dll,14"
    $Shortcut.Save()
    Write-Host "  + Desktop shortcut created: $shortcutPath" -ForegroundColor Green
} else {
    Write-Step 4 5 "Skipping shortcut creation (-NoShortcut)"
    Write-Host "  + Skipped" -ForegroundColor Gray
}

# 5. Run setup
Write-Step 5 5 "Running setup wizard..."
$jsCmd = Join-Path $VENV_DIR "Scripts\js.exe"
& $jsCmd setup -y

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  JS Agent installed successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Start commands:" -ForegroundColor Cyan
Write-Host "  cd $PROJECT_DIR" -ForegroundColor White
Write-Host "  .venv\Scripts\activate" -ForegroundColor White
Write-Host "  js web --port 8000" -ForegroundColor White
if (-not $NoShortcut) {
    Write-Host ""
    Write-Host "Or simply double-click the Desktop shortcut." -ForegroundColor Yellow
}
Write-Host ""

# Ask to start (unless -NoStart)
if (-not $NoStart) {
    $start = Read-Host "Start now? (y/n)"
    if ($start -eq "y" -or $start -eq "Y") {
        & $jsCmd web --port 8000
    }
} else {
    Write-Host "Skipped auto-start (-NoStart)." -ForegroundColor Gray
}
