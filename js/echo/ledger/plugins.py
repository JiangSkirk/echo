from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from js.echo.ledger._hashing import stable_hash

PluginMode = Literal["dev", "stable"]
PluginState = Literal["active", "quarantined", "drained", "revoked"]


@dataclass(frozen=True)
class BudgetView:
    tokens: int


@dataclass(frozen=True)
class BlobRef:
    blob_id: str
    mime: str
    size: int


@dataclass(frozen=True)
class PluginManifest:
    plugin_id: str
    version: str
    license: str
    permissions: tuple[str, ...]
    mode: PluginMode
    dev_bypasses: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mode == "stable" and self.dev_bypasses:
            raise ValueError("stable plugin manifest cannot contain dev bypass entries")
        if not self.plugin_id:
            raise ValueError("plugin_id is required")
        if not self.license:
            raise ValueError("license is required")


@dataclass(frozen=True)
class PluginRecord:
    manifest: PluginManifest
    state: PluginState
    reason: str | None = None


@dataclass(frozen=True)
class ConformanceReport:
    ok: bool
    failures: tuple[str, ...]


class PluginRegistry:
    def __init__(
        self,
        *,
        allowed_licenses: tuple[str, ...] = ("MIT", "Apache-2.0", "BSD-3-Clause"),
    ) -> None:
        self._allowed_licenses = allowed_licenses
        self._records: dict[str, PluginRecord] = {}

    def register(self, manifest: PluginManifest) -> PluginRecord:
        if manifest.license not in self._allowed_licenses:
            record = PluginRecord(
                manifest=manifest,
                state="quarantined",
                reason="license_not_allowed",
            )
        else:
            record = PluginRecord(manifest=manifest, state="active")
        self._records[manifest.plugin_id] = record
        return record

    def check_conformance(self, plugin_id: str) -> ConformanceReport:
        record = self._records[plugin_id]
        failures: list[str] = []
        if record.state != "active":
            failures.append(f"state:{record.state}")
        if not record.manifest.permissions:
            failures.append("permissions_missing")
        if record.manifest.mode == "stable" and record.manifest.dev_bypasses:
            failures.append("stable_dev_bypass")
        if record.manifest.license not in self._allowed_licenses:
            failures.append("license_not_allowed")
        return ConformanceReport(ok=not failures, failures=tuple(failures))

    def drain(self, plugin_id: str, *, reason: str) -> PluginRecord:
        return self._transition(plugin_id, state="drained", reason=reason)

    def revoke(self, plugin_id: str, *, reason: str) -> PluginRecord:
        return self._transition(plugin_id, state="revoked", reason=reason)

    def quarantine(self, plugin_id: str, *, reason: str) -> PluginRecord:
        return self._transition(plugin_id, state="quarantined", reason=reason)

    def _transition(self, plugin_id: str, *, state: PluginState, reason: str) -> PluginRecord:
        previous = self._records[plugin_id]
        record = PluginRecord(manifest=previous.manifest, state=state, reason=reason)
        self._records[plugin_id] = record
        return record


class InMemorySafePluginContext:
    def __init__(self, *, input_blob: bytes, budget_tokens: int) -> None:
        self._input_blob = input_blob
        self._budget_tokens = budget_tokens
        self._outputs: list[BlobRef] = []
        self._safe_logs: list[dict[str, str]] = []

    def read_input_blob(self) -> bytes:
        return self._input_blob

    def emit_output_blob(self, data: bytes, mime: str) -> BlobRef:
        blob = BlobRef(
            blob_id="blob_" + stable_hash({"data": data.hex(), "mime": mime})[-16:],
            mime=mime,
            size=len(data),
        )
        self._outputs.append(blob)
        return blob

    def log_safe(self, event: dict[str, str]) -> None:
        self._safe_logs.append(dict(event))

    def remaining_budget(self) -> BudgetView:
        return BudgetView(tokens=self._budget_tokens)
