"""Runtime isolation posture — observation, not a second security boundary."""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

UntrustedIngestionPolicy = Literal["warn", "enforce"]


class IsolationLevel(StrEnum):
    CONTAINER_FULL = "container-full"
    NATIVE_TOOL_SANDBOX = "native-tool-sandbox"
    DEGRADED = "degraded"


@dataclass(frozen=True, slots=True)
class IsolationPosture:
    level: IsolationLevel
    in_container: bool
    sandbox_exec: bool
    bwrap: bool
    unshare: bool
    rlimit_as: bool
    platform_name: str
    untrusted_ingestion_policy: UntrustedIngestionPolicy = "warn"
    warning: str = ""
    findings: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "level": str(self.level),
            "in_container": self.in_container,
            "sandbox_exec": self.sandbox_exec,
            "bwrap": self.bwrap,
            "unshare": self.unshare,
            "rlimit_as": self.rlimit_as,
            "platform": self.platform_name,
            "untrusted_ingestion_policy": self.untrusted_ingestion_policy,
            "warning": self.warning,
            "findings": list(self.findings),
        }

    def allows_untrusted_surface(self) -> bool:
        if self.untrusted_ingestion_policy == "warn":
            return True
        return self.level is IsolationLevel.CONTAINER_FULL


def detect_container(
    *,
    dockerenv: Path = Path("/.dockerenv"),
    cgroup: Path = Path("/proc/1/cgroup"),
    environ: dict[str, str] | None = None,
) -> bool:
    env = environ if environ is not None else dict(os.environ)
    if env.get("container") in {"docker", "podman", "lxc"}:
        return True
    if dockerenv.exists():
        return True
    try:
        text = cgroup.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    markers = ("docker", "containerd", "podman", "libpod", "lxc")
    return any(marker in text for marker in markers)


def detect_rlimit_as() -> bool:
    try:
        import resource
    except ImportError:
        return False
    return hasattr(resource, "RLIMIT_AS") and platform.system() == "Linux"


def detect_posture(
    *,
    policy: UntrustedIngestionPolicy = "warn",
    environ: dict[str, str] | None = None,
    which: Any = shutil.which,
) -> IsolationPosture:
    in_container = detect_container(environ=environ)
    sandbox_exec = which("sandbox-exec") is not None
    bwrap = which("bwrap") is not None
    unshare = which("unshare") is not None
    rlimit_as = detect_rlimit_as()
    system = platform.system()
    if in_container:
        level = IsolationLevel.CONTAINER_FULL
        warning = ""
    elif sandbox_exec or bwrap:
        level = IsolationLevel.NATIVE_TOOL_SANDBOX
        warning = (
            "Per-tool OS sandbox is available; the agent process itself is not "
            "container-wrapped. Untrusted inbound surfaces stay marked."
        )
    else:
        level = IsolationLevel.DEGRADED
        warning = (
            "No container and no sandbox-exec/bwrap. Tool isolation is degraded; "
            "do not ingest untrusted content."
        )
    return IsolationPosture(
        level=level,
        in_container=in_container,
        sandbox_exec=sandbox_exec,
        bwrap=bwrap,
        unshare=unshare,
        rlimit_as=rlimit_as,
        platform_name=system,
        untrusted_ingestion_policy=policy,
        warning=warning,
    )


def security_doctor_findings(
    settings: Any,
    *,
    posture: IsolationPosture | None = None,
    bind_host: str = "127.0.0.1",
) -> list[dict[str, str]]:
    """Return graded findings. Does not execute tools or mutate state."""

    security = getattr(settings, "security", None)
    policy = str(getattr(security, "untrusted_ingestion_policy", "warn") or "warn")
    typed_policy: UntrustedIngestionPolicy = "enforce" if policy == "enforce" else "warn"
    current = posture or detect_posture(policy=typed_policy)
    findings: list[dict[str, str]] = [
        {
            "severity": "info",
            "id": "posture",
            "message": f"isolation_posture={current.level}",
        }
    ]
    if current.level is IsolationLevel.DEGRADED:
        findings.append(
            {
                "severity": "high",
                "id": "degraded_isolation",
                "message": current.warning,
            }
        )
    elif current.warning:
        findings.append(
            {
                "severity": "warn",
                "id": "native_process",
                "message": current.warning,
            }
        )
    if bind_host not in {"127.0.0.1", "localhost", "::1"}:
        findings.append(
            {
                "severity": "high",
                "id": "non_loopback_bind",
                "message": f"Host bind {bind_host} is not loopback",
            }
        )
    if getattr(security, "api_key_required", True) is False:
        findings.append(
            {
                "severity": "high",
                "id": "api_key_disabled",
                "message": "security.api_key_required is false",
            }
        )
    if getattr(settings, "friends_enabled", False):
        findings.append(
            {
                "severity": "warn",
                "id": "friends_enabled",
                "message": "friends_enabled widens the inbound surface",
            }
        )
    if getattr(settings, "mobile_enabled", False):
        findings.append(
            {
                "severity": "warn",
                "id": "mobile_enabled",
                "message": "mobile_enabled widens the inbound surface",
            }
        )
    orin = getattr(settings, "orin", None)
    if typed_policy == "enforce" and current.level is not IsolationLevel.CONTAINER_FULL:
        findings.append(
            {
                "severity": "high",
                "id": "enforce_without_container",
                "message": (
                    "untrusted_ingestion_policy=enforce requires container-full; "
                    f"current={current.level}"
                ),
            }
        )
    if getattr(orin, "enforce", False) is True:
        findings.append(
            {
                "severity": "info",
                "id": "orin_enforce",
                "message": "orin.enforce is on; Stage C conjunction still applies",
            }
        )
    return findings


def require_untrusted_surface(settings: Any, surface: str) -> IsolationPosture:
    """Fail-closed gate for inbound untrusted surfaces."""

    security = getattr(settings, "security", None)
    policy = str(getattr(security, "untrusted_ingestion_policy", "warn") or "warn")
    typed: UntrustedIngestionPolicy = "enforce" if policy == "enforce" else "warn"
    posture = detect_posture(policy=typed)
    message = refuse_untrusted_surface(posture, surface)
    if message is not None:
        raise RuntimeError(message)
    return posture


def refuse_untrusted_surface(posture: IsolationPosture, surface: str) -> str | None:
    """Return an error message when enforce policy blocks a surface."""

    if posture.allows_untrusted_surface():
        return None
    return (
        f"{surface} is blocked: untrusted_ingestion_policy=enforce requires "
        f"isolation_posture=container-full (current={posture.level})"
    )
