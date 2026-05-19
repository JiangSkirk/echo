#!/bin/bash
# JS Agent 一键部署脚本
# 用法: ./deploy.sh

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_MIN="3.12"
VENV_DIR="$PROJECT_DIR/.venv"

echo "========================================"
echo "  JS Agent 部署脚本"
echo "========================================"

# 1. 检查 Python 版本
echo ""
echo "[1/4] 检查 Python 环境..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    echo "  发现 Python $PYTHON_VERSION"
    if [ "$(printf '%s\n' "$PYTHON_MIN" "$PYTHON_VERSION" | sort -V | head -n1)" != "$PYTHON_MIN" ]; then
        echo "  ❌ 需要 Python $PYTHON_MIN 或更高版本"
        echo "     请安装 Python $PYTHON_MIN+ 后重试"
        echo "     推荐: brew install python@3.12"
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
    echo "     推荐: brew install python@3.12"
    exit 1
fi
echo "  ✅ Python 版本符合要求"

# 2. 创建虚拟环境
echo ""
echo "[2/4] 创建虚拟环境..."
if [ ! -d "$VENV_DIR" ]; then
    $PYTHON_CMD -m venv "$VENV_DIR"
    echo "  ✅ 虚拟环境已创建"
else
    echo "  ✅ 虚拟环境已存在，跳过"
fi

# 3. 安装依赖
echo ""
echo "[3/4] 安装依赖..."
source "$VENV_DIR/bin/activate"

if command -v uv &> /dev/null; then
    echo "  使用 uv 安装 (更快)..."
    uv pip install -e "$PROJECT_DIR"
else
    echo "  使用 pip 安装..."
    pip install -e "$PROJECT_DIR"
fi
echo "  ✅ 依赖安装完成"

# 4. 启动服务
echo ""
echo "[4/4] 启动服务..."
echo ""
echo "========================================"
echo "  ✅ JS Agent 部署完成!"
echo "========================================"
echo ""
echo "  启动命令:"
echo "    cd $PROJECT_DIR"
echo "    source .venv/bin/activate"
echo "    js web --host 0.0.0.0 --port 8000"
echo ""
echo "  然后打开浏览器访问:"
echo "    http://localhost:8000"
echo ""
echo "  在 模型管理 页面配置 LM Studio 连接"
echo ""

# 询问是否立即启动
read -p "是否立即启动服务? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "启动中..."
    js web --host 0.0.0.0 --port 8000
fi
