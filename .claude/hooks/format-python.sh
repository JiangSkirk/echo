#!/usr/bin/env bash
# PostToolUse hook: ruff autofix + format the just-edited Python file (scoped to
# that one file, fast). Always exits 0 — advisory, never blocks an edit. Keeps
# the ruff/format half of the 三件套 continuously green.
set -u
file=$(python3 -c "import sys,json
try: print(json.load(sys.stdin).get('tool_input',{}).get('file_path',''))
except Exception: print('')" 2>/dev/null)
case "$file" in
  *.py)
    [ -f "$file" ] || exit 0
    cd "${CLAUDE_PROJECT_DIR:-.}" 2>/dev/null || true
    uv run ruff check --fix "$file" >/dev/null 2>&1 || true
    uv run ruff format "$file" >/dev/null 2>&1 || true
    ;;
esac
exit 0
