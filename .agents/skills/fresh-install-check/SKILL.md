---
name: fresh-install-check
description: macOS fresh-install acceptance check for the JS Agent web app. Spins up a real server in a throwaway HOME on a temp port, verifies first-start + bootstrap admin key + key-gated endpoints, then tears everything down. Use to validate that a clean install boots and serves correctly.
---

# Fresh-Install Acceptance (macOS)

Validate a clean install boots: setup → server → first-start → bootstrap admin
key → key-gated endpoints, all in an isolated throwaway HOME so the user's real
state is never touched.

## Procedure

1. **Sandbox**: make a temp dir; export `HOME="$tmp"` and `JS_STATE_DIR="$tmp/state"`
   so config + state land in the sandbox, not the user's real `~`.
2. **Setup** (only if no config yet): `uv run js setup -y`.
3. **Pick a free port** (probe with a python socket bind to port 0).
4. **Start server in background**: `uv run js web --host 127.0.0.1 --port <port>`
   (foreground serve, no browser popup; `js open` would open a real browser
   window on the user's machine). Capture the PID. Poll `/` until 200 (timeout ~20s).
5. **Smoke checks** (report expect vs actual):
   - `GET /` → 200
   - bootstrap admin key file at `$JS_STATE_DIR/bootstrap_admin_key.txt` (0600)
   - entry URL carries the credential as a fragment: `bootstrap_browser_url()`
     (js/appshell/entry_url.py) returns `<url>/#bootstrap-api-key=<key>` for the
     sandbox state dir, and js/web/static/app.js exchanges that fragment for an
     HttpOnly session cookie (grep for `bootstrap-api-key`). The key is NOT
     injected into the `/` HTML — the fragment mechanism replaced that.
   - `GET /api/status` **without** key → 401
   - `GET /api/status` **with** `X-API-Key: <bootstrap key>` → 200
   - `GET /api/models` with key → 200
   - `GET /api/setup/first-start` with key → 200
6. **Teardown**: terminate the server PID **and its python child** (`uv run` forks
   a child — kill both or uvicorn orphans). The server has graceful drain, so a
   plain `kill` (SIGTERM) may not exit within the timeout: send SIGTERM, wait
   ~1s, then SIGKILL (`kill -9`) any survivor as a fallback. Confirm none remain:
   `pgrep -fl "js .*open|uvicorn"`.

## Notes

- status/models/first-start sit behind `require_auth` — a loopback browser
  auto-adopts the key from the `#bootstrap-api-key` URL fragment (the fragment
  never enters HTTP request logs; app.js swaps it for an HttpOnly session
  cookie). curl must send `X-API-Key` or you'll see a 401 (test artifact, not
  a product bug).
- Never weaken product auth to make a check pass — fix the check.
- End with a clear PASS/FAIL summary.
