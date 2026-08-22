#!/usr/bin/env bash
# PostToolUse hook: syntax-check the just-edited frontend JS. The vanilla-JS
# frontend has no build step, so ruff/mypy/pytest never see it — a syntax slip
# in js/web/static/*.js ships silently. Copy to a temp .mjs and `node --check`
# (pure ESM parse, no execution); surface parse errors to the agent via exit 2.
set -u
command -v node >/dev/null 2>&1 || exit 0
file=$(python3 -c "import sys,json
try: print(json.load(sys.stdin).get('tool_input',{}).get('file_path',''))
except Exception: print('')" 2>/dev/null)
case "$file" in
  *js/web/static/*.js)
    [ -f "$file" ] || exit 0
    tmp="${TMPDIR:-/tmp}/jscheck.$$.mjs"
    cp "$file" "$tmp"
    if ! err=$(node --check "$tmp" 2>&1); then
      rm -f "$tmp"
      echo "[check-js] 前端 JS 语法错误: $file" >&2
      echo "$err" >&2
      exit 2
    fi
    rm -f "$tmp"
    ;;
esac
exit 0
