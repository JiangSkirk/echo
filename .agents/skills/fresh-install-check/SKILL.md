---
name: fresh-install-check
description: macOS fresh-install acceptance check for the JS Agent desktop Host. Spins up a real AppShell Host in a throwaway HOME on a temp port, verifies first-start + bootstrap admin key + key-gated endpoints, then tears everything down. Use to validate that a clean install boots and serves correctly.
---

# Fresh-Install Acceptance (macOS)

Validate a clean install boots: setup → local Host → first-start → bootstrap admin
key → key-gated endpoints, all in an isolated throwaway HOME so the user's real
state is never touched. Do not open a system browser.

There are two credential handoffs. Do not mix them:

- **Headless Host smoke** (this skill): read `bootstrap_admin_key.txt`, optionally
  confirm `#bootstrap-api-key=` from `bootstrap_browser_url()` in
  `js/appshell/entry_url.py`, then **exchange** that key at
  `POST /api/appshell/session` for the HttpOnly `js_appshell_session` cookie.
  Child `/api/*` routes ignore a raw `X-API-Key`. That helper is not the desktop
  path.
- **Desktop app**: Tauri sidecar uses `#bootstrap=` plus
  `/api/appshell/desktop-bootstrap`. Do not treat `#bootstrap-api-key=` as the
  desktop product path.

## Procedure

1. **Sandbox**: make a temp dir; export `HOME="$tmp"` and `JS_STATE_DIR="$tmp/state"`
   so config + state land in the sandbox, not the user's real `~`.
2. **Setup** (only if no config yet): `uv run js setup -y`.
3. **Pick a free port** (probe with a python socket bind to port 0).
4. **Start Host in background**: export `JS_APPSHELL_PROVISION_KEY=1`, then
   `uv run js appshell --no-browser --host 127.0.0.1 --port <port>`
   (local AppShell Host; never `js web` / `js open`). Capture the PID. Poll `/`
   with `curl -fsS` until HTTP 200 (timeout ~20s). Without the env, AppShell
   waits for loopback `POST /api/appshell/bootstrap` and will not write
   `bootstrap_admin_key.txt` at start.
5. **Smoke checks** (report expect vs actual; check the key file **before** login):
   - `GET /` → 200
   - bootstrap admin key file at `$JS_STATE_DIR/bootstrap_admin_key.txt` (0600)
   - headless fragment (optional): `bootstrap_browser_url()` returns
     `<url>/#bootstrap-api-key=<key>` for the sandbox state dir. `app.js`
     exchanges that fragment for an HttpOnly session cookie. The key is NOT
     injected into the `/` HTML.
   - `GET /api/status` **without** credentials → 401
   - `GET /api/status` **with only** `X-API-Key` (no AppShell session) → 401
     (`AppShell session is required`). This is product-correct.
   - `POST /api/appshell/session` with `Origin: http://127.0.0.1:<port>` and
     `X-API-Key: <bootstrap key>` → 200 and `Set-Cookie: js_appshell_session=...`
   - `GET /api/status`, `/api/models`, `/api/setup/first-start` **with the
     session cookie** → 200
   - After the session exchange the key file is consumed (deleted). Expected.
6. **Teardown**: terminate the server PID **and its python child** (`uv run` forks
   a child — kill both or uvicorn orphans). The server has graceful drain, so a
   plain `kill` (SIGTERM) may not exit within the timeout: send SIGTERM, wait
   ~1s, then SIGKILL (`kill -9`) any survivor as a fallback. Confirm none remain:
   `pgrep -fl "js .*appshell|uvicorn"`.

## Notes

- AppShell child routes sit behind a parent session, not a raw API key.
  Exchange first:

  ```bash
  curl -fsS -c "$jar" \
    -H "Origin: http://127.0.0.1:$PORT" \
    -H "X-API-Key: $KEY" \
    -X POST "http://127.0.0.1:$PORT/api/appshell/session"
  curl -fsS -b "$jar" "http://127.0.0.1:$PORT/api/status"
  ```

- Never weaken product auth to make a check pass — fix the check.
- End with a clear PASS/FAIL summary.
