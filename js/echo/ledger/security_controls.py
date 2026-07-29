from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from js.echo.ledger.privacy import redact_for_model


class AuditSanitizer:
    def sanitize(self, event: dict[str, str]) -> dict[str, str]:
        return {key: redact_for_model(value).text for key, value in event.items()}


@dataclass(frozen=True)
class FileScope:
    root: Path

    def resolve(self, user_path: str) -> Path:
        root = self.root.resolve()
        target = (root / user_path).resolve()
        if not target.is_relative_to(root):
            raise PermissionError("path resolves outside file scope")
        return target


@dataclass(frozen=True)
class NetworkScope:
    allowed_hosts: tuple[str, ...]

    def allow_url(self, url: str) -> str:
        parsed = urlparse(url)
        host = parsed.hostname
        if host is None:
            raise PermissionError("network destination missing host")
        _deny_unsafe_ip_host(host)
        if host not in self.allowed_hosts:
            raise PermissionError("network host not in allowlist")
        return host


@dataclass(frozen=True)
class SandboxBudget:
    max_cpu_ms: int
    max_memory_mb: int
    max_output_bytes: int
    max_pids: int


@dataclass(frozen=True)
class SandboxObservation:
    cpu_ms: int
    memory_mb: int
    output_bytes: int
    pids: int


ViolationKind = Literal["none", "cpu_exceeded", "memory_exceeded", "output_exceeded", "pid_exceeded"]


@dataclass(frozen=True)
class SandboxViolation:
    kind: ViolationKind
    action: Literal["allow", "kill_capsule"]


def prompt_text_cannot_grant_scope(prompt: str, *, requested_scope: str) -> bool:
    lower_prompt = prompt.casefold()
    if requested_scope.casefold() in lower_prompt:
        return False
    return not ("user approved" in lower_prompt or "ignore prior rules" in lower_prompt)


def classify_sandbox_observation(
    observation: SandboxObservation,
    budget: SandboxBudget,
) -> SandboxViolation:
    if observation.cpu_ms > budget.max_cpu_ms:
        return SandboxViolation(kind="cpu_exceeded", action="kill_capsule")
    if observation.memory_mb > budget.max_memory_mb:
        return SandboxViolation(kind="memory_exceeded", action="kill_capsule")
    if observation.output_bytes > budget.max_output_bytes:
        return SandboxViolation(kind="output_exceeded", action="kill_capsule")
    if observation.pids > budget.max_pids:
        return SandboxViolation(kind="pid_exceeded", action="kill_capsule")
    return SandboxViolation(kind="none", action="allow")


def _deny_unsafe_ip_host(host: str) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if address.is_link_local:
        raise PermissionError("metadata/link-local network destination denied")
    if address.is_loopback or address.is_private or address.is_multicast or address.is_reserved:
        raise PermissionError("private network destination denied")
