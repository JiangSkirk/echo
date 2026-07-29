# Echo External Review Packet

Status: PENDING_EXTERNAL_REVIEW

This is the handoff index for independent reviewers. Local implementation and
automated tools cannot mark any external approval complete.

## Scope

- Architecture and execution: `docs/echo/ECHO_2_ARCHITECTURE.md` and
  `docs/echo/ECHO_UNIFIED_EXECUTION_CONTRACT.md`.
- Runtime: `js/echo/`, `js/agent/`, `js/models/`, `js/tools/`, and `js/web/`.
- Work product isolation: `js_work/`.
- Security matrix: `js/echo/ledger/security_matrix.py`.
- Sandbox: `js/echo/os_sandbox.py`.
- Provenance: `ORIGIN_LEDGER.md` and `THIRD_PARTY_NOTICES.md`.
- Local evidence: `docs/security/ECHO_SLO_BENCHMARK.json`,
  `docs/security/SBOM.spdx.json`, and `docs/security/LICENSE_SCAN.md`.

## Required Sign-Off

The stable gate requires a real reviewer name, date, and approved status in:

1. `docs/security/LEGAL_FTO_REVIEW.md`
2. `docs/security/CLEAN_ROOM_REVIEW.md`
3. `docs/security/EXTERNAL_SECURITY_AUDIT.md`
4. `docs/security/REDTEAM_REPORT.md`

