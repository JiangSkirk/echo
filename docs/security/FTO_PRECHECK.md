# FTO Precheck Packet

Status: COMPLETE_LOCAL_PRECHECK_EXTERNAL_FTO_REQUIRED
Generated: 2026-07-16T21:27:26Z

This packet is engineering input for outside counsel or an external FTO reviewer. It is not legal advice and is not an FTO approval.

## Materials Prepared

- `ORIGIN_LEDGER.md` records Echo 2.0 engineering-origin boundaries and non-claims.
- `THIRD_PARTY_NOTICES.md` records newly added runtime dependency posture.
- `docs/echo/ECHO_SELF_DEVELOPED_BOUNDARY.md` defines the guarded engineering-originality boundary.
- `docs/security/ECHO_2_CLEAN_ROOM.md` records project-specific API avoidance rules.
- `docs/security/SBOM.spdx.json` records lockfile-derived package inventory.
- `docs/security/LICENSE_SCAN.md` records local dependency license metadata.

## Local Gate Evidence

```text
$ /Users/jiangxuanzhen/titan-agent/.venv/bin/python -c from pathlib import Path; from js.echo.ledger.release_gates import verify_release_readiness; r=verify_release_readiness(Path('.')); print(f'internal_ready={r.internal_ready} stable_ready={r.stable_ready}'); print('passed=' + ','.join(r.passed)); print('external_blockers=' + ','.join(r.external_blockers))
exit=0
internal_ready=True stable_ready=False
passed=origin_ledger,third_party_notices,codeowners,adr,rfc_template,echo_self_developed_boundary,echo_unified_execution_contract,security_matrix_25,real_sandbox_backend,echo_ip_boundary,echo_kernel_core,echo_recovery_probe,echo_local_sandbox_adapter,echo_live_acceptance_60m,sbom_spdx,license_scan,echo_slo_benchmark,echo_audit_reports_bound
external_blockers=legal_fto_review_pending,clean_room_reviewer_pending,external_security_audit_missing,redteam_report_missing
```

## Dependency Scope

- Lockfile packages inventoried: 132
- Source package: `js-agent` declared license is MIT in `pyproject.toml`.

## Required External Review

Outside review must decide copyright provenance, patent/FTO, trademark/name risk, dependency-license acceptability, and publication wording before stable GitHub release.
