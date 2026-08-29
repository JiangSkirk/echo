# Multi-Device Release Candidate Test Checklist

Use this checklist before tagging a release. Tests should pass on all target platforms.

---

## 1. macOS (Development Machine)

| Step | Action | Expected Result | Pass |
|------|--------|-----------------|------|
| 1.1 | `js appshell --no-browser` starts without errors | Local AppShell Host available at `http://127.0.0.1:8000` | ☐ |
| 1.2 | Open the JS Agent desktop app → Chat → send "hello" | Assistant responds with streaming tokens | ☐ |
| 1.3 | Memory tab shows embedder status | Green badge: `LLMEmbedder(...)` (not "降级") | ☐ |
| 1.4 | Models tab shows **only loaded** models | `qwen3.5-122b-a10b` present; `qwen3.6-35b-a3b` absent if not loaded | ☐ |
| 1.5 | Models tab shows **single** provider | Only one `lmstudio` entry (no `127.0.0.1` + `localhost` dupes) | ☐ |
| 1.6 | First-Start Wizard appears on fresh state | `GET /api/setup/first-start` returns `false`; wizard modal visible | ☐ |
| 1.7 | Complete wizard → model selector works | Wizard dismisses; config saved without clobbering providers | ☐ |
| 1.8 | Memory CRUD: add, edit, delete semantic memory | All operations succeed; source citation visible | ☐ |
| 1.9 | Factory Demo ingestion | `cd demos/factory && python ingest.py` → 5 docs, 5+ chunks loaded | ☐ |
| 1.10 | Factory Demo query | "What is the fabric of HL-2026-TShirt?" → correct answer from memory | ☐ |
| 1.11 | Checkpoint/Resume | Cancel a run → refresh page → resume from checkpoint succeeds | ☐ |
| 1.12 | `pytest tests/ -q --tb=short` | Full suite passes | ☐ |
| 1.13 | `ruff check js/ tests/ scripts/` + `mypy js/ --no-error-summary` | 0 errors | ☐ |

---

## 2. Windows (PowerShell)

| Step | Action | Expected Result | Pass |
|------|--------|-----------------|------|
| 2.1 | `powershell -ExecutionPolicy Bypass -File install.ps1` | Installs venv, deps, shortcut, runs setup | ☐ |
| 2.2 | `install.ps1 -NoShortcut -NoStart` | Skips shortcut + auto-start; exits cleanly | ☐ |
| 2.3 | `install.ps1 -ProjectDir "C:\js-agent"` | Installs to specified directory | ☐ |
| 2.4 | `.venv\Scripts\activate` + `js appshell --no-browser --port 8000` | Local Host starts; desktop app can attach | ☐ |
| 2.5 | First-Start Wizard on Windows | Same behavior as macOS | ☐ |
| 2.6 | Chat + Memory + Model switcher | All tabs functional | ☐ |

---

## 3. Docker

| Step | Action | Expected Result | Pass |
|------|--------|-----------------|------|
| 3.1 | `docker compose up js-agent` | Container starts; healthcheck passes | ☐ |
| 3.2 | `docker compose up js-agent-dev` | Dev container starts `js appshell --no-browser` (no `--reload`) | ☐ |
| 3.3 | `curl http://localhost:8000/api/status` | Returns JSON with `degraded: false` | ☐ |
| 3.4 | Healthcheck endpoint (`/api/status`) | Returns 200 within 30s of container start | ☐ |
| 3.5 | Volume persistence | Stop → restart container; memory and checkpoints survive | ☐ |

---

## 4. Model Disconnect & Recovery

| Step | Action | Expected Result | Pass |
|------|--------|-----------------|------|
| 4.1 | Stop LM Studio → `GET /api/status` | `degraded: true`, reason mentions provider unhealthy | ☐ |
| 4.2 | Restart LM Studio → wait 60s → `GET /api/status` | `degraded: false`, auto-recovery successful | ☐ |
| 4.3 | Memory tab shows "降级: KeywordEmbedder" | Yellow badge visible after 2 consecutive embed failures | ☐ |
| 4.4 | Click "恢复嵌入器" button | `POST /api/memory/embedder/recover` → success; green badge returns | ☐ |
| 4.5 | Cancel a running task → `POST /api/cancel/{session_id}` | Task stops; checkpoint saved to SQLite | ☐ |
| 4.6 | Resume from checkpoint | `POST /api/resume/{session_id}` → continues from saved turn | ☐ |

---

## 5. Host Restart & Config Persistence

| Step | Action | Expected Result | Pass |
|------|--------|-----------------|------|
| 5.1 | `POST /api/setup/complete` | `first_run_completed: true` saved; config **does not** lose providers | ☐ |
| 5.2 | Verify config file after setup | `providers` list preserved; `models` list preserved | ☐ |
| 5.3 | Stop server → delete `~/.js/state/*.db` → restart | Fresh databases created; WAL mode confirmed | ☐ |
| 5.4 | Corrupt `checkpoints.db` → restart | StateStore auto-deletes corrupt file and recreates tables | ☐ |

---

## 6. Factory Demo Import

| Step | Action | Expected Result | Pass |
|------|--------|-----------------|------|
| 6.1 | `cd demos/factory && python ingest.py` | 5 documents loaded; chunks stored with `source` citation | ☐ |
| 6.2 | Query: "What is the MOQ of HL-2026-TShirt?" | Correct answer: "500 units per color" | ☐ |
| 6.3 | Query: "What are the sewing tolerances?" | Correct answer from `Sewing-Assembly-v2.md` | ☐ |
| 6.4 | Query: "What is the AQL level for major defects?" | Correct answer: "2.5" | ☐ |
| 6.5 | Memory tab shows factory docs | Each semantic memory has `source` = file path; category badge visible | ☐ |
| 6.6 | Edit a factory memory → save | `PUT /api/memory/semantic/{id}` succeeds; updated value persisted | ☐ |
| 6.7 | Delete a factory memory | `DELETE /api/memory/semantic/{id}` succeeds; item removed from UI | ☐ |

---

## 7. Memory Source Verification

| Step | Action | Expected Result | Pass |
|------|--------|-----------------|------|
| 7.1 | Add manual memory with source | `POST /api/memory/semantic` → response includes `source: manual` | ☐ |
| 7.2 | Factory doc memory shows source | `source` field contains original file path (e.g. `products/HL-2026-TShirt.md`) | ☐ |
| 7.3 | Memory search returns sources | `GET /api/memory/enhanced` → semantic memories include `source` field | ☐ |
| 7.4 | Chat response cites memory source | Agent response includes `[source: ...]` when using semantic memory | ☐ |

---

## Sign-off

| Platform | Tester | Date | Result |
|----------|--------|------|--------|
| macOS | | | |
| Windows | | | |
| Docker | | | |
