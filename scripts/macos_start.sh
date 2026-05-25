#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"

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

PYTHON_BIN="$(find_python)" || {
  echo "Python 3.12, 3.13, or 3.14 is required."
  echo "Install it from https://www.python.org/downloads/macos/ and run this script again."
  exit 1
}

if [[ ! -x ".venv/bin/python" ]]; then
  "$PYTHON_BIN" -m venv .venv
fi

if ! is_supported_python ".venv/bin/python"; then
  rm -rf .venv
  "$PYTHON_BIN" -m venv .venv
fi

VENV_PY=".venv/bin/python"
STAMP=".venv/.js-agent-installed"
if [[ ! -f "$STAMP" || "pyproject.toml" -nt "$STAMP" ]]; then
  "$VENV_PY" -m pip install --upgrade pip
  install_target=(-e ".")
  if [[ "${INSTALL_DEV:-0}" == "1" ]]; then
    install_target=(-e ".[dev]")
  fi
  "$VENV_PY" -m pip install "${install_target[@]}"
  "$VENV_PY" -m pip check
  touch "$STAMP"
fi

CONFIG_FILE="${JS_CONFIG_PATH:-$HOME/.config/js/config.yaml}"
if [[ ! -f "$CONFIG_FILE" ]]; then
  "$VENV_PY" -m js setup -y
fi

if [[ $# -gt 0 ]]; then
  exec "$VENV_PY" -m js "$@"
fi

echo "Starting JS Agent at http://${HOST}:${PORT}"
exec "$VENV_PY" -m js open --host "$HOST" --port "$PORT"
