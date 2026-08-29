"""Hardened compose file keeps the recommended whole-process posture."""

from __future__ import annotations

from pathlib import Path

import yaml

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.hardened.yaml"


def test_hardened_compose_exists() -> None:
    assert COMPOSE.is_file()


def test_hardened_compose_isolation_keys() -> None:
    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    service = data["services"]["js-agent"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert service["ports"] == ["127.0.0.1:8000:8000"]
    assert "docker.sock" not in yaml.dump(service)
