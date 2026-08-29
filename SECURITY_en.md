# JS Agent Security Policy

This is the public trust model: load-bearing boundary, deployment postures,
and the scope of vulnerability reports. Internal Orin specs under
[`docs/security/orin/`](docs/security/orin/) and [`TECH_DEBT.md`](TECH_DEBT.md)
do not replace this file.

JS Agent is a **single-tenant local personal Agent Harness**, not multi-tenant SaaS.

## 1. Reporting a Vulnerability

Report privately via GitHub Security Advisories. **JS Agent does not operate a
bug bounty.**

A useful report includes:

- A concise description and severity assessment.
- The affected component (file path and line range).
- Environment (`js-agent` version, commit SHA, OS, Python version).
- A reproduction against `main` or the latest release.
- Which trust boundary in §2 is crossed.

Read §2 and §3 first. Reports that only defeat an in-process heuristic this
policy does not treat as a boundary will be closed as out of scope under §3.2 —
they are still welcome as regular issues or pull requests.

## 2. Trust Model

### 2.1 Definitions

- **Agent process.** The Python interpreter running JS Agent, including loaded
  skills, plugins, and hooks.
- **Input surface.** Any channel that feeds the turn context: operator input,
  web fetches, inbound messages, file reads, MCP responses, tool results.
- **Trust envelope.** Resources the operator implicitly grants by running JS
  Agent as their user account.
- **Stance.** An explicit statement in docs or code about how a layer should
  treat agent output, or which isolation posture is in force.

### 2.2 The Boundary: OS-Level Isolation

**The only load-bearing security boundary against an adversarial model is
operating-system isolation.** Echo leases, the ledger, the guard, taint,
tool allowlists, and approval gates are **authorization and defense in depth**,
not a containment boundary. Any in-process screen of LLM output is a heuristic.

JS Agent supports two OS-level postures:

#### Per-tool OS sandbox (default macOS desktop)

`SandboxExecutor` wraps shell/code children fail-closed:

- macOS: `sandbox-exec` with network deny and a deny-default filesystem.
- Linux: `bwrap` + `unshare`; cgroup / `RLIMIT_AS` when available.
- If the backend is missing and `strict_isolation=True`, execution is refused.

Product paths (shell, code, skill execution) call the sandbox with
`strict_isolation=True`. This confines **child tool processes**, not the agent
process. Model calls, MCP, skill imports, and the Host remain in-process.

Running with `strict_isolation` off while ingesting untrusted input is an
unsupported posture.

#### Whole-process container posture (recommended for untrusted surfaces)

The production `Dockerfile` runs as non-root. `docker-compose.yaml` binds
loopback only by default. This is optional, not the native desktop default.

When the agent ingests the open web, inbound messaging, untrusted MCP, or
shared-host traffic, use whole-process wrapping rather than the per-tool
sandbox alone.

**Not implemented by default — do not claim otherwise:**

- `orin.enabled` defaults to `false` (`OrinConfig.enabled`).
- `orin.enforce` defaults to `false` (`OrinConfig.enforce`). Stage C cells /
  process split are `not_implemented`; see
  [`docs/security/orin/ORIN_STAGE_C_CLOSEOUT.md`](docs/security/orin/ORIN_STAGE_C_CLOSEOUT.md).
- Echo RCE is not closed.
- No official TCC / Developer ID / notarization.
- No independent external red-team attestation.

### 2.3 Authorization and Depth (Not the Boundary)

- **One Echo runtime boundary.** Models, tools, attachments, and side effects
  enter only through `run_echo_turn` / `execute_tool_effect`. Missing or
  unverifiable gates fail closed.
- **Single-use leases** bind product, owner, session, run, tool, arguments,
  and budget.
- **Taint and the policy table.** Untrusted input is marked. The
  `OrinConfig.policy_profile` field default is `conservative` (unmatched rows
  require approval). When AppShell turns on Stage A and `orin.enforce` is still
  false, that default is rewritten to `compat`: non-allow verdicts become
  allow-with-log. **The default desktop/Host path does not treat taint as an
  approval gate.** `conservative` is an explicit setting or a future enforce
  posture, not the current product default.
- **Skill trust tiers** `builtin` → `trusted` → `community` → `quarantine`.
  TRUSTED requires an unrevoked key in the trusted public-key directory;
  self-signatures stop at COMMUNITY.
- **In-process heuristics** (approval regexes, redaction, skill scans, shell
  allowlists) catch cooperative mistakes. Bypassing them is not a §3.1 issue.

### 2.4 Inbound Surfaces Off by Default

These flags default to `false`; enabling them widens the input surface:

- `friends_enabled` (`JSSettings.friends_enabled`)
- `mobile_enabled` (`JSSettings.mobile_enabled`)
- `remote_collaboration_enabled`
- `gateway.enabled` (`JSSettings.gateway.enabled`, default `false`; unpaired senders are discarded)
- Telegram and similar integrations are optional extras, not Host cold-start.

`features.pipeline_enabled` defaulting to `true` is a capability flag only; it
does not import `js.pipeline` on Host cold start.

`security.untrusted_ingestion_policy` defaults to `warn`: native posture may
enable those surfaces, and the status page / `js doctor --security` keep a
warning. `enforce` allows them only when `isolation_posture=container-full`.

### 2.5 Supply Chain

- Release and install paths require `uv.lock` and `uv sync --frozen`.
- The Docker image pins `uv` `0.11.24` and installs `--frozen`.
- CI, Release Smoke, and the weekly audit use that same `uv` version,
  `uv lock --check`, and SHA-pinned GitHub Actions (no live `pip install -e`
  resolution).
- `.github/workflows/deps-audit.yml` runs `pip-audit` weekly.
- Desktop `desktop/requirements-build.txt` uses exact pins plus `--hash`.
- `scripts/install.sh` refuses remote `curl | sh` and lockless installs.
- Version ranges in `pyproject.toml` are resolver bounds; reproducible builds
  follow the lockfile.
- Downstream installs that do not use `uv.lock` must consume repo-root
  `constraints.txt` (`pip install js-agent -c constraints.txt`; to verify
  transitive hashes: `pip install --require-hashes -r constraints.txt`
  then `pip install --no-deps js-agent`).
  `scripts/export_constraints.py` exports it from the lockfile; CI `--check`
  fails on drift.

## 3. Scope

### 3.1 In Scope

- Escape from a declared OS isolation posture (per-tool sandbox or
  whole-process container).
- Unauthorized Host / AppShell API access (key bypass, exposing a loopback
  service to unauthorized callers).
- Credential exfiltration that a documented control should have prevented.
- Cross-owner read or write (memory, bot rooms, fleet, approval queues).
- Code that contradicts this policy or a documented product stance.

### 3.2 Out of Scope

- Bypasses of in-process heuristics alone.
- Prompt injection without a chained §3.1 outcome.
- Behavior permitted by the chosen posture (for example the native desktop
  agent process reading the operator home directory).
- Operator-selected break-glass (`strict_isolation=False`, binding Host to
  `0.0.0.0`, disabling auth).
- Third-party skills or plugins that the operator did not review.
- Stage C remaining `not_implemented` (already disclosed).

## 4. Deployment Hardening

- Match isolation posture to input trust: prefer a container for untrusted
  inbound surfaces.
- Run containers as non-root; do not mount the Docker socket or writable
  secret directories.
- Keep the Host on loopback; LAN exposure requires keys plus network controls.
- Review third-party skill code, not just `SKILL.md`.
- Keep API keys out of the main config and out of version control.

## 5. Disclosure

- **Coordinated disclosure window:** 90 days from report, or until a fix is
  released, whichever comes first.
- **Channel:** GitHub Security Advisories.
- **Credit:** reporters are credited in release notes unless they ask otherwise.

## 6. In-repo auditability

- Multi-owner threat model: [`docs/security/THREAT_MODEL.md`](docs/security/THREAT_MODEL.md)
- External-review entry: [`docs/security/AUDIT_PACK.md`](docs/security/AUDIT_PACK.md)
- Trial topology: `docker-compose.staging.yaml`
- This tree has **no** independent red-team endorsement; archive reports under
  `docs/security/external/`.
