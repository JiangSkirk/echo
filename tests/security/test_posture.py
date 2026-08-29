"""Isolation posture detection and untrusted-surface policy."""

from __future__ import annotations

from pathlib import Path

from js.config import SecurityConfig
from js.security.posture import (
    IsolationLevel,
    detect_container,
    detect_posture,
    refuse_untrusted_surface,
    security_doctor_findings,
)


def test_detect_container_dockerenv(tmp_path: Path) -> None:
    marker = tmp_path / ".dockerenv"
    marker.write_text("", encoding="utf-8")
    assert detect_container(dockerenv=marker, cgroup=tmp_path / "missing") is True


def test_detect_container_env_marker() -> None:
    assert (
        detect_container(
            dockerenv=Path("/no/such/dockerenv"),
            cgroup=Path("/no/such/cgroup"),
            environ={"container": "podman"},
        )
        is True
    )


def test_native_sandbox_when_sandbox_exec_present() -> None:
    posture = detect_posture(
        policy="warn",
        environ={},
        which=lambda name: "/usr/bin/sandbox-exec" if name == "sandbox-exec" else None,
    )
    assert posture.level is IsolationLevel.NATIVE_TOOL_SANDBOX
    assert posture.allows_untrusted_surface() is True
    assert refuse_untrusted_surface(posture, "gateway") is None


def test_enforce_blocks_untrusted_without_container() -> None:
    posture = detect_posture(
        policy="enforce",
        environ={},
        which=lambda name: "/usr/bin/sandbox-exec" if name == "sandbox-exec" else None,
    )
    assert posture.level is IsolationLevel.NATIVE_TOOL_SANDBOX
    assert posture.allows_untrusted_surface() is False
    message = refuse_untrusted_surface(posture, "gateway")
    assert message is not None
    assert "container-full" in message


def test_container_full_allows_enforce(tmp_path: Path, monkeypatch) -> None:
    marker = tmp_path / ".dockerenv"
    marker.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        "js.security.posture.detect_container",
        lambda **_kwargs: True,
    )
    posture = detect_posture(policy="enforce", which=lambda _name: None)
    assert posture.level is IsolationLevel.CONTAINER_FULL
    assert refuse_untrusted_surface(posture, "gateway") is None


def test_security_config_defaults_warn() -> None:
    assert SecurityConfig.model_fields["untrusted_ingestion_policy"].default == "warn"


def test_doctor_flags_non_loopback_and_disabled_key() -> None:
    class _Security:
        untrusted_ingestion_policy = "warn"
        api_key_required = False

    class _Settings:
        security = _Security()
        friends_enabled = True
        mobile_enabled = False
        orin = None

    findings = security_doctor_findings(_Settings(), bind_host="0.0.0.0")
    ids = {item["id"] for item in findings}
    assert "non_loopback_bind" in ids
    assert "api_key_disabled" in ids
    assert "friends_enabled" in ids
