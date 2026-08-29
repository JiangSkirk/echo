"""In-repo audit pack and threat model stay complete and mapped."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
THREAT = ROOT / "docs" / "security" / "THREAT_MODEL.md"
PACK = ROOT / "docs" / "security" / "AUDIT_PACK.md"
STAGING = ROOT / "docker-compose.staging.yaml"


def test_threat_model_maps_required_surfaces() -> None:
    text = THREAT.read_text(encoding="utf-8")
    for marker in (
        "T-BOT-1",
        "T-FLT-1",
        "T-MEM-1",
        "T-WEB-1",
        "T-GW-1",
        "T-CRON-1",
        "T-EVO-1",
        "T-FR-1",
        "tests/multiuser/test_abuse_matrix.py",
        "orin.enforce",
    ):
        assert marker in text


def test_audit_pack_points_at_boundaries_and_repro() -> None:
    text = PACK.read_text(encoding="utf-8")
    for marker in (
        "SECURITY.md",
        "TECH_DEBT.md",
        "docker-compose.staging.yaml",
        "orin.enforce",
        "tests/multiuser",
        "docs/security/external/",
        "scripts/staging_trial.py",
        "staging-trial-2026-08-29.md",
    ):
        assert marker in text


def test_staging_compose_is_hardened_and_loopback() -> None:
    text = STAGING.read_text(encoding="utf-8")
    assert "127.0.0.1:8000:8000" in text
    assert "read_only: true" in text
    assert "no-new-privileges:true" in text
    assert "/var/run/docker.sock" not in text
    assert "./audit-logs:/app/state/logs" in text
