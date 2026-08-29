#!/usr/bin/env bash
#
# JS Agent macOS 一键准备脚本
# 首次运行会自动创建 .venv、安装依赖、初始化配置。
# 产品主入口是桌面应用；本脚本不打开浏览器、不启动网页服务。
#
# 用法:
#   ./scripts/macos_start.sh                # 准备环境并提示打开桌面应用
#   ./scripts/macos_start.sh setup -y       # 透传子命令给 js
#   DRY_RUN=1 ./scripts/macos_start.sh      # 仅检查环境，不安装、不启动
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DRY_RUN="${DRY_RUN:-0}"

# ── 中文彩色日志（风格对齐 install.sh）──────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_step() { echo -e "${BLUE}[JS Agent]${NC} $1"; }
log_ok()   { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_err()  { echo -e "${RED}✗${NC} $1"; }

is_supported_python() {
  "$1" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if (3, 12) <= sys.version_info[:2] < (3, 15) else 1)
PY
}

find_python() {
  if [[ -n "${PYTHON_BIN:-}" ]]; then
    if is_supported_python "$PYTHON_BIN"; then
      printf '%s\n' "$PYTHON_BIN"
      return 0
    fi
    return 1
  fi

  for candidate in python3.14 python3.13 python3.12 python python3; do
    if command -v "$candidate" >/dev/null 2>&1 && is_supported_python "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

log_step "检查 Python 环境（需要 3.12 / 3.13 / 3.14）..."
PYTHON_BIN="$(find_python)" || {
  log_err "未找到合适的 Python（需要 3.12、3.13 或 3.14）。"
  echo ""
  echo "安装方式:"
  echo "  1. Homebrew (推荐): brew install python@3.12"
  echo "  2. 官方安装包: https://www.python.org/downloads/macos/"
  echo ""
  echo "安装完成后重新运行本脚本。"
  exit 1
}
PYTHON_VERSION="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
log_ok "Python $PYTHON_VERSION 可用"

# 干运行：只验证环境，不创建虚拟环境、不安装、不启动。
if [[ "$DRY_RUN" == "1" ]]; then
  log_warn "干运行模式 — 仅检查环境，不安装也不启动"
  log_ok "Python 检测通过"
  log_ok "所有前置检查通过"
  exit 0
fi

if [[ ! -x ".venv/bin/python" ]]; then
  log_step "创建虚拟环境 .venv ..."
  "$PYTHON_BIN" -m venv .venv
fi

if ! is_supported_python ".venv/bin/python"; then
  log_warn "现有 .venv 的 Python 版本不受支持，正在重建..."
  rm -rf .venv
  "$PYTHON_BIN" -m venv .venv
fi

VENV_PY=".venv/bin/python"
STAMP=".venv/.js-agent-installed"
if [[ ! -f "$STAMP" || "pyproject.toml" -nt "$STAMP" ]]; then
  log_step "安装/更新依赖（首次或 pyproject.toml 有变更时执行）..."
  "$VENV_PY" -m pip install --upgrade pip
  install_target=(-e ".")
  if [[ "${INSTALL_DEV:-0}" == "1" ]]; then
    install_target=(-e ".[dev]")
  fi
  "$VENV_PY" -m pip install "${install_target[@]}"
  "$VENV_PY" -m pip check
  touch "$STAMP"
  log_ok "依赖就绪"
fi

CONFIG_FILE="${JS_CONFIG_PATH:-$HOME/.config/js/config.yaml}"
if [[ ! -f "$CONFIG_FILE" ]]; then
  log_step "首次运行：执行配置向导（自动探测 LM Studio / Ollama）..."
  "$VENV_PY" -m js setup -y
  log_ok "配置完成：$CONFIG_FILE"
fi

# 透传模式：把后续参数原样交给 js（如 setup / search / skill 等）。
if [[ $# -gt 0 ]]; then
  exec "$VENV_PY" -m js "$@"
fi

log_ok "环境已就绪。请打开 JS Agent 桌面应用。"
echo "终端可用: js / js tui / js daemon"
echo "本机 Host（不打开浏览器）: js appshell"
