#!/usr/bin/env bash
#
# JS Agent macOS One-Click Installer
# Usage (preferred, offline-friendly):
#   cd /path/to/titan-agent && bash scripts/install.sh
#
# Do NOT pipe remote scripts into a shell. Download install.sh from a trusted
# source, verify it locally, then run it. Remote ``curl | sh`` install paths
# are intentionally unsupported until a pinned checksum/signature is published.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}/.."
INSTALL_DIR="${INSTALL_DIR:-$HOME/.js-agent}"
DRY_RUN="${DRY_RUN:-0}"
PYTHON_MIN="3.12"
PYTHON_MAX="3.15"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_step() {
    echo -e "${BLUE}[JS Agent]${NC} $1"
}

log_ok() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_err() {
    echo -e "${RED}✗${NC} $1"
}

# ───────────────────────────────────────────────
# 1. Detect if running from project dir or standalone
# ───────────────────────────────────────────────
if [[ -f "$PROJECT_DIR/pyproject.toml" ]]; then
    RUN_MODE="local"
    SOURCE_DIR="$PROJECT_DIR"
    log_step "检测到本地项目目录: $SOURCE_DIR"
else
    RUN_MODE="remote"
    SOURCE_DIR="$INSTALL_DIR"
    log_step "将以远程模式安装到: $SOURCE_DIR"
fi

# Remote mode is fail-closed until a pinned artifact + checksum/signature exists.
if [[ "$RUN_MODE" == "remote" ]]; then
    log_err "远程安装模式已禁用：缺少可信制品、摘要或签名钉扎。"
    log_err "请在已校验的本地仓库目录中运行: bash scripts/install.sh"
    exit 1
fi

# ───────────────────────────────────────────────
# 2. Check macOS
# ───────────────────────────────────────────────
if [[ "$OSTYPE" != "darwin"* ]]; then
    log_warn "当前不是 macOS 系统。此脚本主要针对 macOS 优化。"
    read -p "是否继续? (y/n) " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || exit 1
fi

# ───────────────────────────────────────────────
# 3. Check Python 3.12+
# ───────────────────────────────────────────────
log_step "检查 Python 环境..."

is_supported_python() {
    PYTHONNOUSERSITE=1 "$1" -c "import sys; v=sys.version_info; exit(0 if ('$PYTHON_MIN' <= f'{v.major}.{v.minor}' < '$PYTHON_MAX') else 1)" 2>/dev/null
}

find_python() {
    for candidate in python3.14 python3.13 python3.12 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && is_supported_python "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

PYTHON_BIN="$(find_python)" || {
    log_err "需要 Python $PYTHON_MIN - $PYTHON_MAX"
    echo ""
    echo "安装方式:"
    echo "  1. Homebrew (推荐): brew install python@3.12"
    echo "  2. 官方安装包: https://www.python.org/downloads/macos/"
    echo ""
    exit 1
}

    PYTHON_VERSION="$(PYTHONNOUSERSITE=1 "$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
log_ok "Python $PYTHON_VERSION 可用"

# ───────────────────────────────────────────────
# 4. Check uv and frozen lock (required even for DRY_RUN)
# ───────────────────────────────────────────────
log_step "检查 uv 包管理器..."
if command -v uv >/dev/null 2>&1; then
    log_ok "uv 已安装"
else
    log_err "未找到 uv。请从 https://github.com/astral-sh/uv/releases 下载已验证的发行版并安装后重试。"
    log_err "本安装器不会通过 curl|sh 拉取远程脚本（缺少钉扎摘要/签名）。"
    exit 1
fi

cd "$SOURCE_DIR"

if [[ ! -f "uv.lock" ]]; then
    log_err "缺少 uv.lock；无法执行冻结依赖安装。"
    exit 1
fi
log_ok "uv.lock 存在"

if [[ "$DRY_RUN" == "1" ]]; then
    log_warn "干运行模式 — 仅检查，不执行安装"
    log_ok "Python 检测通过"
    log_ok "所有前置检查通过"
    exit 0
fi

# ───────────────────────────────────────────────
# 5. Create venv and install from frozen lock
# ───────────────────────────────────────────────
log_step "创建虚拟环境..."

if [[ ! -d ".venv" ]]; then
    PYTHONNOUSERSITE=1 "$PYTHON_BIN" -m venv .venv
fi
log_ok "虚拟环境就绪"

log_step "安装依赖 (uv sync --frozen)..."
if ! uv sync --frozen; then
    log_err "依赖安装失败（uv sync --frozen）。"
    exit 1
fi
log_ok "依赖安装完成"

# ───────────────────────────────────────────────
# 6. Run setup wizard
# ───────────────────────────────────────────────
log_step "运行首次配置向导..."
if [[ ! -f "$HOME/.config/js/config.yaml" ]]; then
    if ! .venv/bin/python -m js setup -y; then
        log_err "首次配置向导失败"
        exit 1
    fi
    log_ok "配置完成"
else
    log_ok "配置文件已存在，跳过"
fi

# ───────────────────────────────────────────────
# 7. Create launcher scripts
# ───────────────────────────────────────────────
log_step "创建启动器..."

# start.sh
cat > "$SOURCE_DIR/start.sh" << 'EOF'
#!/usr/bin/env bash
set -e
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SOURCE_DIR"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
echo "Preparing JS Agent..."
echo "Open the JS Agent desktop app."
echo "Local Host (does not open a browser): .venv/bin/python -m js appshell --no-browser --host ${HOST} --port ${PORT}"
EOF
chmod +x "$SOURCE_DIR/start.sh"

# cli shortcut
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/js-agent" << EOF
#!/usr/bin/env bash
exec "$SOURCE_DIR/.venv/bin/python" -m js "\$@"
EOF
chmod +x "$HOME/.local/bin/js-agent"

log_ok "启动器已创建"

# ───────────────────────────────────────────────
# 8. Create macOS app shortcut
# ───────────────────────────────────────────────
log_step "创建 macOS 应用快捷方式..."
APP_DIR="$HOME/Applications/JS Agent.app"
mkdir -p "$APP_DIR/Contents/MacOS"

cat > "$APP_DIR/Contents/MacOS/JS Agent" << EOF
#!/usr/bin/env bash
osascript -e 'tell application "Terminal" to do script "cd $SOURCE_DIR && ./start.sh"' -e 'tell application "Terminal" to activate'
EOF
chmod +x "$APP_DIR/Contents/MacOS/JS Agent"

# Create Info.plist for better Finder integration
cat > "$APP_DIR/Contents/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>JS Agent</string>
    <key>CFBundleIdentifier</key>
    <string>com.jsagent.app</string>
    <key>CFBundleName</key>
    <string>JS Agent</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
</dict>
</plist>
EOF

log_ok "macOS 应用快捷方式已创建"

# ───────────────────────────────────────────────
# 9. Smoke test
# ───────────────────────────────────────────────
log_step "运行安装验证..."
if "$SOURCE_DIR/.venv/bin/python" -c "import js; print('import ok')" 2>/dev/null; then
    log_ok "Python 包导入正常"
else
    log_err "Python 包导入失败"
    exit 1
fi

# ───────────────────────────────────────────────
# 10. Done
# ───────────────────────────────────────────────
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  JS Agent 安装完成!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "启动方式:"
echo "  1. 打开 JS Agent 桌面应用"
echo "  2. 命令行 CLI: js-agent (如果 ~/.local/bin 在 PATH 中)"
echo "  3. 本机 Host（不打开浏览器）: $SOURCE_DIR/.venv/bin/python -m js appshell"
echo ""

# Ask to start
read -p "配置已完成。请打开 JS Agent 桌面应用。按 Enter 退出。 " -n 1 -r
echo
