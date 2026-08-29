#!/bin/bash
# JS Agent 一键部署脚本
# 用法: ./scripts/deploy.sh（在仓库根执行）

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON_MIN="3.12"
VENV_DIR="$PROJECT_DIR/.venv"

echo "========================================"
echo "  JS Agent 一键部署脚本"
echo "========================================"

# 1. 检查 Python 版本
echo ""
echo "[1/5] 检查 Python 环境..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    echo "  发现 Python $PYTHON_VERSION"
    if [ "$(printf '%s\n' "$PYTHON_MIN" "$PYTHON_VERSION" | sort -V | head -n1)" != "$PYTHON_MIN" ]; then
        echo "  ❌ 需要 Python $PYTHON_MIN 或更高版本"
        echo "     请安装 Python $PYTHON_MIN+ 后重试"
        echo "     macOS: brew install python@3.12"
        echo "     Ubuntu: sudo apt install python3.12 python3.12-venv"
        exit 1
    fi
    PYTHON_CMD=python3
elif command -v python &> /dev/null; then
    PYTHON_VERSION=$(python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    echo "  发现 Python $PYTHON_VERSION"
    if [ "$(printf '%s\n' "$PYTHON_MIN" "$PYTHON_VERSION" | sort -V | head -n1)" != "$PYTHON_MIN" ]; then
        echo "  ❌ 需要 Python $PYTHON_MIN 或更高版本"
        exit 1
    fi
    PYTHON_CMD=python
else
    echo "  ❌ 未找到 Python"
    echo "     请先安装 Python $PYTHON_MIN+"
    echo "     macOS: brew install python@3.12"
    echo "     Ubuntu: sudo apt install python3.12 python3.12-venv"
    exit 1
fi
echo "  ✅ Python 版本符合要求"

# 2. 创建虚拟环境
echo ""
echo "[2/5] 创建虚拟环境..."
if [ ! -d "$VENV_DIR" ]; then
    $PYTHON_CMD -m venv "$VENV_DIR"
    echo "  ✅ 虚拟环境已创建"
else
    echo "  ✅ 虚拟环境已存在，跳过"
fi

# 3. 安装依赖（uv 钉版本 + uv sync --frozen，与 scripts/install.sh 对齐）
echo ""
echo "[3/5] 安装依赖..."
source "$VENV_DIR/bin/activate"

UV_PINNED_VERSION="0.11.24"
if ! command -v uv &> /dev/null; then
    echo "  正在安装 uv==$UV_PINNED_VERSION (Python 包管理加速器，钉版本)..."
    pip install "uv==$UV_PINNED_VERSION" --quiet
fi

if [ ! -f "$PROJECT_DIR/uv.lock" ]; then
    echo "  ❌ 缺少 uv.lock；无法执行冻结依赖安装"
    exit 1
fi

echo "  使用 uv sync --frozen (冻结锁文件)..."
(cd "$PROJECT_DIR" && uv sync --frozen)
echo "  ✅ 依赖安装完成"

# 4. 一键配置
echo ""
echo "[4/5] 运行首次配置向导..."
if [ ! -f "$HOME/.config/js/config.yaml" ]; then
    js setup -y
    echo "  ✅ 配置完成"
else
    echo "  ✅ 配置文件已存在，跳过"
fi

# 5. 创建启动脚本
echo ""
echo "[5/5] 创建启动脚本..."
LAUNCH_SCRIPT="$PROJECT_DIR/start.sh"
cat > "$LAUNCH_SCRIPT" << 'EOF'
#!/bin/bash
set -e
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$PROJECT_DIR/.venv/bin/activate"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
echo "Preparing JS Agent..."
echo "Open the JS Agent desktop app."
echo "Local Host (does not open a browser): js appshell --no-browser --host ${HOST} --port ${PORT}"
EOF
chmod +x "$LAUNCH_SCRIPT"
echo "  ✅ 启动脚本已创建: $LAUNCH_SCRIPT"

# macOS: 创建 Automator 快捷方式
if [[ "$OSTYPE" == "darwin"* ]]; then
    APP_DIR="$HOME/Applications/JS Agent.app"
    if [ ! -d "$APP_DIR" ]; then
        mkdir -p "$APP_DIR/Contents/MacOS"
        cat > "$APP_DIR/Contents/MacOS/JS Agent" << EOF
#!/bin/bash
osascript -e 'tell application "Terminal" to do script "cd $PROJECT_DIR && ./start.sh"'
EOF
        chmod +x "$APP_DIR/Contents/MacOS/JS Agent"
        echo "  ✅ macOS 应用快捷方式已创建: $APP_DIR"
    fi
fi

echo ""
echo "========================================"
echo "  ✅ JS Agent 部署完成!"
echo "========================================"
echo ""
echo "启动方式:"
echo "  1. 打开 JS Agent 桌面应用"
echo "  2. CLI: js"
echo "  3. 本机 Host（不打开浏览器）: js appshell"
echo ""

read -p "配置已完成。请打开 JS Agent 桌面应用。按 Enter 退出。 " -n 1 -r
echo ""
