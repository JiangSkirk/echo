from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import quantiles
from time import monotonic_ns, perf_counter, time
from typing import Any, Literal, cast

from js.config import EchoLedgerConfig, JSSettings
from js.echo.execution_contract import ReplayClass, build_effect_bridge
from js.echo.ledger._hashing import canonical_json, stable_hash
from js.echo.ledger.effects import DurableEffectLog, EffectReceipt, OutboxRow
from js.echo.ledger.journal import (
    FileEchoLedger,
    JournalEntry,
    VerificationReport,
    verify_file,
)
from js.echo.ledger.kernel import decide
from js.echo.ledger.partition_retention import (
    GENESIS_HASH as RETENTION_GENESIS_HASH,
)
from js.echo.ledger.partition_retention import (
    PartitionArtifactCapacityError,
    PartitionRetentionError,
    RetentionReceiptInput,
    RetiredArtifactReceiptInput,
    clear_pending_retirement,
    load_and_verify_checkpoint,
    retired_artifact_entries,
    retired_history_complete,
    stage_retirement,
)
from js.echo.ledger.policy import (
    IdentityContext,
    PermitSeal,
    PolicyBundle,
    PolicyDecisionRecord,
    PolicyRule,
    create_permit_seal,
    evaluate_policy,
)
from js.echo.ledger.privacy import (
    ModelCallRequest,
    ProviderCapability,
    build_model_privacy_envelope,
    contains_secret_shape,
)
from js.echo.ledger.types import EffectIntent, IntakeEvent, KernelSnapshot
from js.echo.mode_contract import AppMode, ArtifactRefV1
from js.echo.primitives import (
    ECHO_2_ARCHITECTURE,
    ScopeGate,
    ScopeRequest,
    stable_payload_hash,
)

_BEGIN_RECORD_TYPES = (
    "intake",
    "decision",
    "policy_decision",
    "permit",
    "model_privacy_envelope",
    "outbox",
)
_FINISH_RECORD_TYPES = ("receipt", "merge")
_CLAIM_RECORD_TYPES = ("outbox_claimed",)
_MANUAL_REVIEW_RECORD_TYPES = ("outbox_manual_review",)
_MANUAL_REVIEW_RESOLUTION_RECORD_TYPES = ("manual_review_resolution", "merge")
_DATA_URL_BASE64_RE = re.compile(
    r"data:[^;,\s]+;base64,(?P<data>[A-Za-z0-9+/=\r\n]+)",
    re.IGNORECASE,
)
_SHA256_REF_RE = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_TENANT_STATES = 512
_MAX_TOOL_ARTIFACT_REFS = 32
_MAX_TOOL_ARTIFACT_BYTES = 128 * 1024
_TOKEN_SOURCES = {"provider_actual", "tokenizer", "estimated", "unavailable"}


class EchoBlockedError(PermissionError):
    """Raised when Echo policy blocks a real model call."""


class EchoUnavailableError(RuntimeError):
    """Raised when Echo cannot durably authorize or finalize a model call."""


class _ClaimNoLongerAbandonedError(RuntimeError):
    pass


class _ReceiptNoLongerPendingError(RuntimeError):
    pass


@dataclass(frozen=True)
class EchoHealth:
    mode: str
    ok: bool
    journal_path: str
    record_count: int
    error_count: int
    last_error: str | None
    journal_append_p95_ms: float | None
    pending_effect_count: int = 0
    claimed_effect_count: int = 0
    receipted_effect_count: int = 0
    manual_review_effect_count: int = 0
    architecture: str = "echo-2.0"
    ledger_name: str = "FrameLedger"
    ledger_contract: str = "FrameLedger"
    journal_impl: str = "FileEchoLedger"
    scope_gate_name: str = "ScopeGate"
    loaded_tenant_state_count: int = 0
    tenant_state_limit: int = _MAX_TENANT_STATES
    journal_state_scan_truncated: bool = False
    skipped_tenant_count: int = 0
    last_compaction_error: str | None = None
    last_compaction_skip_reason: str | None = None
    active_session_partition_count: int = 0
    retired_session_partition_count: int = 0
    partition_retention_error: str | None = None


@dataclass(frozen=True)
class EchoRecordResult:
    ok: bool
    mode: str
    record_types: tuple[str, ...]
    error: str | None = None


@dataclass(frozen=True)
class ManualReviewRow:
    """Safe operator-facing projection of a manual-review effect."""

    effect_id: str
    outbox_id: str
    tenant_id: str
    action_kind: str
    status: Literal["manual_review"]
    session_id: str | None = None
    run_id: str | None = None
    product_id: str | None = None
    effect_digest: str | None = None
    args_digest: str | None = None


@dataclass(frozen=True, slots=True)
class VerifiedArtifactReceiptV1:
    """Artifact-bearing receipt reconstructed only from verified journal state."""

    receipt_id: str
    effect_id: str
    tenant_id: str
    run_id: str
    artifact_refs: tuple[ArtifactRefV1, ...]


@dataclass(frozen=True, slots=True)
class VerifiedArtifactProjectionV1:
    """Verified active and retired artifact history with explicit coverage."""

    receipts: tuple[VerifiedArtifactReceiptV1, ...]
    refs: tuple[ArtifactRefV1, ...]
    retired_history_complete: bool


@dataclass(frozen=True, slots=True)
class ArtifactVisibilityQueryV1:
    """Typed AppShell visibility filter applied before projection truncation."""

    session: str | None = None
    run: str | None = None

    def __post_init__(self) -> None:
        if self.session is not None and (
            not isinstance(self.session, str) or not self.session.strip()
        ):
            raise ValueError("artifact visibility session is invalid")
        if self.run is not None and (
            not isinstance(self.run, str) or not self.run.strip()
        ):
            raise ValueError("artifact visibility run is invalid")


def artifact_ref_visible(
    ref: ArtifactRefV1,
    query: ArtifactVisibilityQueryV1,
) -> bool:
    """Apply the shared owner/workspace/session/private ACL query."""
    if type(ref) is not ArtifactRefV1 or type(query) is not ArtifactVisibilityQueryV1:
        raise TypeError("artifact visibility requires exact typed values")
    if query.session is not None and query.session != ref.session:
        return False
    if query.run is not None and query.run != ref.created_by_run:
        return False
    if ref.acl == "owner":
        return True
    if ref.acl == "workspace":
        if ref.mode is AppMode.PERSONAL:
            raise ValueError("Personal artifact cannot carry workspace ACL")
        return True
    if ref.acl == "session":
        return query.session is not None and query.session == ref.session
    if ref.acl == "private":
        return (
            query.session is not None
            and query.run is not None
            and query.session == ref.session
            and query.run == ref.created_by_run
        )
    raise ValueError("artifact ACL is invalid")


@dataclass(frozen=True)
class EchoTurnContext:
    tenant_id: str
    run_id: str
    effect_id: str
    outbox_id: str
    record_start: int
    permit_seal: PermitSeal | None = None
    product_id: str | None = None
    session_id: str | None = None


@dataclass(frozen=True)
class EchoToolEffectContext:
    tenant_id: str
    product_id: str
    session_id: str
    run_id: str
    tool_name: str
    tool_call_id: str
    args_hash: str
    lease_id: str
    replay_class: ReplayClass
    effect_id: str
    outbox_id: str
    record_start: int
    permit_seal: PermitSeal
    workspace: str | None = None


@dataclass(frozen=True)
class EchoConnectorEffectContext:
    """Durable context for one connector effect execution.

    Mirrors :class:`EchoToolEffectContext` but binds connector-specific
    fields (connector_type, operation, connection_id, manifest/binding hashes).
    """

    tenant_id: str
    product_id: str
    session_id: str
    run_id: str
    workspace: str | None
    connector_type: str
    operation: Literal["read", "write"]
    connection_id: str
    task_ref_hash: str
    manifest_digest: str
    binding_hash: str
    params_digest: str
    directory_grant_hash: str | None
    vault_ref_hash: str | None
    approval_id: str | None
    lease_id: str
    replay_class: Literal["idempotent", "non_idempotent"]
    effect_id: str
    outbox_id: str
    record_start: int
    permit_seal: PermitSeal


@dataclass(frozen=True, slots=True)
class _VerifiedEffectBinding:
    tenant_id: str
    product_id: str
    session_id: str
    run_id: str
    effect_id: str
    outbox_id: str
    args_digest: str
    workspace: str | None


@dataclass(frozen=True)
class _TenantJournalState:
    journal_path: Path
    journal_key: bytes
    permit_key: bytes
    journal: FileEchoLedger
    effects: DurableEffectLog


@dataclass(frozen=True, slots=True)
class _PartitionSourceEvidence:
    source_files_hash: str
    source_file_count: int
    source_total_bytes: int


class EchoSafetyService:
    def __init__(
        self,
        *,
        state_dir: Path,
        ledger_config: EchoLedgerConfig | None = None,
    ) -> None:
        self._root = state_dir / "echo" / "ledger"
        _ensure_private_directory(self._root)
        self._error_count = 0
        self._last_error: str | None = None
        self._last_compaction_error: str | None = None
        self._last_compaction_skip_reason: str | None = None
        self._partition_retention_error: str | None = None
        self._ledger_config = ledger_config or EchoLedgerConfig()
        self._journal_append_durations_ms: list[float] = []
        self._tenant_scan_truncated = False
        self._skipped_tenant_count = 0
        self._health_verify_cache: dict[
            str,
            tuple[int, tuple[int, int, int, int, int], VerificationReport],
        ] = {}
        self._state_lock = threading.RLock()
        self._claim_lock_fds: dict[tuple[str, str], int] = {}
        self._reservation_lock_fds: dict[tuple[str, str], int] = {}
        try:
            self._default_state = _load_journal_state(self._root)
        except OSError as exc:
            raise EchoUnavailableError(f"Echo journal unavailable: {exc}") from exc
        self._recover_abandoned_claims(self._default_state)
        self._remember_health_verified(self._default_state)
        self._tenant_states: OrderedDict[str, _TenantJournalState] = OrderedDict()
        self._recover_interrupted_partition_retirements()

    def __del__(self) -> None:
        fds = {
            *getattr(self, "_claim_lock_fds", {}).values(),
            *getattr(self, "_reservation_lock_fds", {}).values(),
        }
        for fd in tuple(fds):
            try:
                self._unlock_claim_fd(fd)
            except OSError:
                pass

    @classmethod
    def from_settings(cls, settings: JSSettings) -> EchoSafetyService:
        if settings.echo_engine != "on":
            raise EchoUnavailableError("Echo safety service requires echo_engine='on'")
        return cls(state_dir=settings.state_dir, ledger_config=settings.echo_ledger)

    @property
    def ledger_config(self) -> EchoLedgerConfig:
        return self._ledger_config

    @property
    def journal_path(self) -> Path:
        return self._default_state.journal_path

    @property
    def state_dir(self) -> Path:
        return self._root.parent.parent

    @property
    def mode(self) -> str:
        return "on"

    @property
    def journal_key(self) -> bytes:
        return self._default_state.journal_key

    def journal_path_for(self, tenant_id: str) -> Path:
        return self._tenant_state(tenant_id).journal_path

    def journal_key_for(self, tenant_id: str) -> bytes:
        return self._tenant_state(tenant_id).journal_key

    def journal_path_for_scope(
        self,
        tenant_id: str,
        *,
        product_id: str,
        session_id: str,
    ) -> Path:
        """Return the physically isolated runtime journal for one exact scope."""
        with self._state_lock, self._partition_operation_guard(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
        ):
            return self._partition_state_locked(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
            ).journal_path

    def journal_key_for_scope(
        self,
        tenant_id: str,
        *,
        product_id: str,
        session_id: str,
    ) -> bytes:
        """Return the per-scope journal MAC key without exposing raw identifiers in paths."""
        with self._state_lock, self._partition_operation_guard(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
        ):
            return self._partition_state_locked(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
            ).journal_key

    def compact_journals(self, *, max_records: int | None = None) -> dict[str, bool]:
        """Compact verified journals while retaining open effect state."""
        results: dict[str, bool] = {}
        retained = max_records or self._ledger_config.retain_records
        with self._state_lock, self._partition_lifecycle_lock(exclusive=False):
            for state in self._known_journal_states(recover_claims=False):
                try:
                    compacted = state.journal.compact(
                        max_records=retained,
                        archive=True,
                        max_archives=self._ledger_config.max_archives,
                    )
                except Exception as exc:  # noqa: BLE001 - compaction must not break live journal
                    self._record_compaction_error(exc)
                    results[str(state.journal_path)] = False
                    continue
                if compacted:
                    state.effects.remove_merged()
                    state.effects.clear_completed_effects()
                    self._last_compaction_skip_reason = None
                results[str(state.journal_path)] = compacted
        return results

    def maybe_compact(self, state: _TenantJournalState) -> bool:
        if state.journal.record_count <= self._ledger_config.trigger_records:
            self._last_compaction_skip_reason = "below_trigger"
            return False
        try:
            compacted = state.journal.compact(
                max_records=self._ledger_config.retain_records,
                archive=True,
                max_archives=self._ledger_config.max_archives,
            )
        except Exception as exc:  # noqa: BLE001 - chat completion remains durable
            self._record_compaction_error(exc)
            return False
        if compacted:
            state.effects.remove_merged()
            state.effects.clear_completed_effects()
            self._last_compaction_error = None
            self._last_compaction_skip_reason = None
        return compacted

    def _record_compaction_error(self, exc: Exception) -> None:
        message = f"{exc.__class__.__name__}: {exc}"
        self._error_count += 1
        self._last_error = message
        self._last_compaction_error = message
        self._last_compaction_skip_reason = None

    def _assert_open_effect_capacity(self, state: _TenantJournalState) -> None:
        limit = self._ledger_config.max_open_effects_per_tenant
        if state.effects.open_count() >= limit:
            raise EchoUnavailableError(
                f"tenant open effect capacity reached ({limit}); resolve pending effects"
            )

    def close(self) -> None:
        """Fail closed any in-flight claims and release process claim locks."""
        with self._state_lock, self._partition_lifecycle_lock(exclusive=False):
            states = {
                str(state.journal_path.resolve()): state
                for state in (self._default_state, *self._tenant_states.values())
            }
            for (journal_path, outbox_id), fd in tuple(self._claim_lock_fds.items()):
                state = states.get(journal_path)
                try:
                    if state is not None and state.effects.status(outbox_id) == "claimed":
                        row = next(
                            item
                            for item in state.effects.claimed_rows()
                            if item.outbox_id == outbox_id
                        )

                        def semantic_sync(
                            records: tuple[Any, ...],
                            disk_changed: bool,
                            current_state: _TenantJournalState = state,
                            current_outbox_id: str = outbox_id,
                        ) -> None:
                            if disk_changed:
                                current_state.effects.replace_from(
                                    _replay_state_effects(current_state, records)
                                )
                            try:
                                status = current_state.effects.status(current_outbox_id)
                            except KeyError as exc:
                                raise _ClaimNoLongerAbandonedError from exc
                            if status != "claimed":
                                raise _ClaimNoLongerAbandonedError

                        try:
                            state.journal.append(
                                record_type="outbox_manual_review",
                                tenant_id=row.seal.tenant_id,
                                run_id="shutdown",
                                payload={
                                    "outbox_id": outbox_id,
                                    "effect_id": row.seal.effect_id,
                                    "reason": "service_closed_with_claim_in_flight",
                                },
                                semantic_sync=semantic_sync,
                            )
                        except _ClaimNoLongerAbandonedError:
                            pass
                        else:
                            state.effects.mark_manual_review(outbox_id)
                            self._remember_health_verified(state)
                except Exception as exc:  # noqa: BLE001 - close must release every claim
                    self._error_count += 1
                    self._last_error = f"{exc.__class__.__name__}: {exc}"
                finally:
                    try:
                        if state is None:
                            self._unlock_claim_fd(fd)
                        else:
                            self._release_claim_fd(state, outbox_id, fd)
                    except Exception as exc:  # noqa: BLE001 - raw fd fallback is mandatory
                        self._error_count += 1
                        self._last_error = f"{exc.__class__.__name__}: {exc}"
                        try:
                            self._unlock_claim_fd(fd)
                        except OSError:
                            pass
                    finally:
                        self._claim_lock_fds.pop((journal_path, outbox_id), None)
            for (journal_path, effect_id), fd in tuple(self._reservation_lock_fds.items()):
                state = states.get(journal_path)
                try:
                    if state is None:
                        self._unlock_claim_fd(fd)
                    else:
                        self._release_reservation_fd(state, effect_id, fd)
                except Exception as exc:  # noqa: BLE001 - close must release every lock
                    self._error_count += 1
                    self._last_error = f"{exc.__class__.__name__}: {exc}"
                    try:
                        self._unlock_claim_fd(fd)
                    except OSError:
                        pass
                finally:
                    self._reservation_lock_fds.pop((journal_path, effect_id), None)

    def _recover_abandoned_claims(
        self,
        state: _TenantJournalState,
        *,
        refresh: bool = True,
    ) -> None:
        def semantic_sync(records: tuple[Any, ...], disk_changed: bool) -> None:
            if disk_changed:
                state.effects.replace_from(_replay_state_effects(state, records))

        if refresh:
            _disk_changed, archive_report = state.journal.refresh_and_verify_required_archives(
                semantic_sync=semantic_sync
            )
            if not archive_report.ok:
                raise ValueError(
                    "invalid required journal archive: " + ",".join(archive_report.errors)
                )
        self._prune_claim_lock_files(state)
        self._recover_receipted_merges(state)
        for row in state.effects.claimed_rows():
            if self._claim_lock_key(state, row.outbox_id) in self._claim_lock_fds:
                continue
            try:
                fd = self._open_claim_fd(state, row.outbox_id)
            except BlockingIOError:
                continue
            try:

                def verify_claim_sync(
                    records: tuple[Any, ...],
                    disk_changed: bool,
                    outbox_id: str = row.outbox_id,
                ) -> None:
                    if disk_changed:
                        state.effects.replace_from(_replay_state_effects(state, records))
                    try:
                        status = state.effects.status(outbox_id)
                    except KeyError as exc:
                        raise _ClaimNoLongerAbandonedError from exc
                    if status != "claimed":
                        raise _ClaimNoLongerAbandonedError

                state.journal.append(
                    record_type="outbox_manual_review",
                    tenant_id=row.seal.tenant_id,
                    run_id="recovery",
                    payload={
                        "outbox_id": row.outbox_id,
                        "effect_id": row.seal.effect_id,
                        "reason": "claimed_without_receipt_after_restart",
                    },
                    semantic_sync=verify_claim_sync,
                )
                state.effects.mark_manual_review(row.outbox_id)
                self._remember_health_verified(state)
            except _ClaimNoLongerAbandonedError:
                continue
            finally:
                self._release_claim_fd(state, row.outbox_id, fd)

    def _recover_receipted_merges(self, state: _TenantJournalState) -> None:
        """Complete a crash-interrupted receipt/merge pair without re-executing."""
        for row in state.effects.receipted_rows():
            effect_id = row.seal.effect_id

            def verify_receipt_sync(
                records: tuple[Any, ...],
                disk_changed: bool,
                outbox_id: str = row.outbox_id,
            ) -> None:
                if disk_changed:
                    state.effects.replace_from(_replay_state_effects(state, records))
                try:
                    status = state.effects.status(outbox_id)
                except KeyError as exc:
                    raise _ReceiptNoLongerPendingError from exc
                if status != "receipted":
                    raise _ReceiptNoLongerPendingError

            try:
                state.journal.append(
                    record_type="merge",
                    tenant_id=row.seal.tenant_id,
                    run_id="recovery",
                    payload={
                        "effect_id": effect_id,
                        "status": "durable_receipt_recovered",
                    },
                    semantic_sync=verify_receipt_sync,
                )
            except _ReceiptNoLongerPendingError:
                continue
            state.effects.mark_merged(effect_id)
            self._remember_health_verified(state)

    def _verify_execution_boundary(self, state: _TenantJournalState) -> bool:
        def semantic_sync(records: tuple[Any, ...], disk_changed: bool) -> None:
            if disk_changed:
                state.effects.replace_from(_replay_state_effects(state, records))

        try:
            disk_changed, archive_report = state.journal.refresh_and_verify_required_archives(
                semantic_sync=semantic_sync
            )
            journal_report = self._health_verify_report(
                state,
                max_verify_age_seconds=60.0,
            )
        except (OSError, ValueError) as exc:
            raise EchoUnavailableError(f"Echo journal verification failed: {exc}") from exc
        if not archive_report.ok:
            raise EchoUnavailableError(
                "Echo required archive verification failed: " + ",".join(archive_report.errors)
            )
        if not journal_report.ok:
            raise EchoUnavailableError(
                "Echo journal verification failed: " + ",".join(journal_report.errors)
            )
        return disk_changed

    def _acquire_claim_lock(self, state: _TenantJournalState, outbox_id: str) -> None:
        key = self._claim_lock_key(state, outbox_id)
        if key in self._claim_lock_fds:
            return
        try:
            fd = self._open_claim_fd(state, outbox_id)
        except BlockingIOError as exc:
            raise EchoUnavailableError("effect is claimed by another live Echo service") from exc
        self._claim_lock_fds[key] = fd

    def _acquire_effect_reservation(
        self,
        state: _TenantJournalState,
        effect_id: str,
    ) -> None:
        """Serialize creation of one logical effect across processes."""
        key = self._reservation_lock_key(state, effect_id)
        if key in self._reservation_lock_fds:
            return
        try:
            fd = self._open_reservation_fd(state, effect_id)
        except BlockingIOError as exc:
            raise EchoUnavailableError(
                "effect is being authorized by another live Echo service"
            ) from exc
        self._reservation_lock_fds[key] = fd

    def _release_effect_reservation(
        self,
        state: _TenantJournalState,
        effect_id: str,
    ) -> None:
        key = self._reservation_lock_key(state, effect_id)
        fd = self._reservation_lock_fds.pop(key, None)
        if fd is not None:
            self._release_reservation_fd(state, effect_id, fd)

    def _release_claim_lock(self, state: _TenantJournalState, outbox_id: str) -> None:
        key = self._claim_lock_key(state, outbox_id)
        fd = self._claim_lock_fds.pop(key, None)
        if fd is not None:
            self._release_claim_fd(state, outbox_id, fd)

    @staticmethod
    def _claim_lock_key(state: _TenantJournalState, outbox_id: str) -> tuple[str, str]:
        return str(state.journal_path.resolve()), outbox_id

    @staticmethod
    def _reservation_lock_key(state: _TenantJournalState, effect_id: str) -> tuple[str, str]:
        return str(state.journal_path.resolve()), effect_id

    def _open_claim_fd(self, state: _TenantJournalState, outbox_id: str) -> int:
        claims_dir = state.journal_path.parent / "claims"
        _ensure_private_directory(claims_dir)
        guard_fd = self._open_claim_guard_fd(state)
        try:
            self._prune_claim_lock_files_locked(state)
            path = self._claim_lock_path(state, outbox_id)
            fd = _open_private_lock_file(path)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                raise
            return fd
        finally:
            self._unlock_claim_fd(guard_fd)

    def _open_reservation_fd(self, state: _TenantJournalState, effect_id: str) -> int:
        claims_dir = state.journal_path.parent / "claims"
        _ensure_private_directory(claims_dir)
        guard_fd = self._open_claim_guard_fd(state)
        try:
            self._prune_claim_lock_files_locked(state)
            path = self._reservation_lock_path(state, effect_id)
            fd = _open_private_lock_file(path)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                raise
            return fd
        finally:
            self._unlock_claim_fd(guard_fd)

    def _release_claim_fd(
        self,
        state: _TenantJournalState,
        outbox_id: str,
        fd: int,
    ) -> None:
        self._release_lock_fd(
            state,
            path=self._claim_lock_path(state, outbox_id),
            fd=fd,
        )

    def _release_reservation_fd(
        self,
        state: _TenantJournalState,
        effect_id: str,
        fd: int,
    ) -> None:
        self._release_lock_fd(
            state,
            path=self._reservation_lock_path(state, effect_id),
            fd=fd,
        )

    def _release_lock_fd(
        self,
        state: _TenantJournalState,
        *,
        path: Path,
        fd: int,
    ) -> None:
        guard_fd = self._open_claim_guard_fd(state)
        try:
            locked_stat = os.fstat(fd)
            self._unlock_claim_fd(fd)
            try:
                path_stat = path.stat()
            except FileNotFoundError:
                return
            if (path_stat.st_dev, path_stat.st_ino) == (locked_stat.st_dev, locked_stat.st_ino):
                path.unlink()
        finally:
            self._unlock_claim_fd(guard_fd)

    def _prune_claim_lock_files(self, state: _TenantJournalState) -> None:
        guard_fd = self._open_claim_guard_fd(state)
        try:
            self._prune_claim_lock_files_locked(state)
        finally:
            self._unlock_claim_fd(guard_fd)

    def _prune_claim_lock_files_locked(self, state: _TenantJournalState) -> None:
        claims_dir = state.journal_path.parent / "claims"
        _ensure_private_directory(claims_dir)
        journal_path = str(state.journal_path.resolve())
        protected = {
            self._claim_lock_path(state, outbox_id)
            for locked_journal, outbox_id in self._claim_lock_fds
            if locked_journal == journal_path
        }
        protected.update(
            self._reservation_lock_path(state, effect_id)
            for locked_journal, effect_id in self._reservation_lock_fds
            if locked_journal == journal_path
        )
        for path in claims_dir.glob("*.lock"):
            if path in protected:
                continue
            try:
                fd = _open_private_lock_file(path)
            except (FileNotFoundError, ValueError):
                continue
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                locked_stat = os.fstat(fd)
                try:
                    path_stat = path.stat()
                except FileNotFoundError:
                    continue
                if (path_stat.st_dev, path_stat.st_ino) == (
                    locked_stat.st_dev,
                    locked_stat.st_ino,
                ):
                    path.unlink()
            finally:
                self._unlock_claim_fd(fd)

    @staticmethod
    def _claim_lock_path(state: _TenantJournalState, outbox_id: str) -> Path:
        slug = stable_hash({"outbox_id": outbox_id}).removeprefix("sha256:")
        return state.journal_path.parent / "claims" / f"{slug}.lock"

    @staticmethod
    def _reservation_lock_path(state: _TenantJournalState, effect_id: str) -> Path:
        slug = stable_hash({"effect_id": effect_id}).removeprefix("sha256:")
        return state.journal_path.parent / "claims" / f"reservation-{slug}.lock"

    @staticmethod
    def _open_claim_guard_fd(state: _TenantJournalState) -> int:
        path = state.journal_path.parent / "claims.guard"
        fd = _open_private_lock_file(path)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    @staticmethod
    def _unlock_claim_fd(fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def health(self, *, max_verify_age_seconds: float = 0.0) -> EchoHealth:
        with self._state_lock, self._partition_lifecycle_lock(exclusive=False):
            return self._health_locked(max_verify_age_seconds=max_verify_age_seconds)

    def _health_locked(self, *, max_verify_age_seconds: float) -> EchoHealth:
        states = self._known_journal_states(recover_claims=False)
        (
            active_session_partition_count,
            retired_session_partition_count,
            retention_error,
        ) = self._retention_health_locked()
        reports_list: list[tuple[_TenantJournalState, VerificationReport]] = []
        for state in states:

            def semantic_sync(
                records: tuple[Any, ...],
                disk_changed: bool,
                current_state: _TenantJournalState = state,
            ) -> None:
                if disk_changed:
                    current_state.effects.replace_from(
                        _replay_state_effects(current_state, records)
                    )

            try:
                _disk_changed, archive_report = state.journal.refresh_and_verify_required_archives(
                    semantic_sync=semantic_sync
                )
            except (OSError, ValueError) as exc:
                report = VerificationReport(ok=False, errors=(str(exc),))
            else:
                try:
                    report = self._health_verify_report(
                        state,
                        max_verify_age_seconds=max_verify_age_seconds,
                    )
                    if report.ok and not archive_report.ok:
                        report = archive_report
                    elif report.ok:
                        self._recover_abandoned_claims(state, refresh=False)
                except (OSError, ValueError) as exc:
                    report = VerificationReport(ok=False, errors=(str(exc),))
            reports_list.append((state, report))
        reports = tuple(reports_list)
        first_error = next(
            (report.errors[0] for _state, report in reports if report.errors),
            None,
        )
        pending_effect_count = sum(state.effects.pending_count() for state in states)
        claimed_effect_count = sum(state.effects.claimed_count() for state in states)
        receipted_effect_count = sum(state.effects.receipted_count() for state in states)
        manual_review_effect_count = sum(state.effects.manual_review_count() for state in states)
        scan_error = (
            f"journal_state_scan_truncated: skipped {self._skipped_tenant_count} tenant states"
            if self._tenant_scan_truncated
            else None
        )
        return EchoHealth(
            mode="on",
            ok=(
                all(report.ok for _state, report in reports)
                and self._error_count == 0
                and self._last_error is None
                and retention_error is None
                and not self._tenant_scan_truncated
                and pending_effect_count == 0
                and claimed_effect_count == 0
                and receipted_effect_count == 0
                and manual_review_effect_count == 0
            ),
            journal_path=str(self.journal_path),
            record_count=sum(state.journal.record_count for state, report in reports if report.ok),
            error_count=self._error_count,
            last_error=(
                self._last_error
                if self._last_error
                else first_error or scan_error or retention_error
            ),
            journal_append_p95_ms=_p95(self._journal_append_durations_ms),
            pending_effect_count=pending_effect_count,
            claimed_effect_count=claimed_effect_count,
            receipted_effect_count=receipted_effect_count,
            manual_review_effect_count=manual_review_effect_count,
            loaded_tenant_state_count=len(self._tenant_states),
            tenant_state_limit=_MAX_TENANT_STATES,
            journal_state_scan_truncated=self._tenant_scan_truncated,
            skipped_tenant_count=self._skipped_tenant_count,
            last_compaction_error=self._last_compaction_error,
            last_compaction_skip_reason=self._last_compaction_skip_reason,
            active_session_partition_count=active_session_partition_count,
            retired_session_partition_count=retired_session_partition_count,
            partition_retention_error=retention_error,
        )

    def record_chat_turn(
        self,
        *,
        tenant_id: str,
        run_id: str,
        user_text: str,
        assistant_text: str,
        status: str,
        token_totals: dict[str, int],
    ) -> EchoRecordResult:
        context = self.begin_chat_turn(
            tenant_id=tenant_id,
            run_id=run_id,
            user_text=user_text,
            model_id="mock",
        )
        self.assert_model_execution_permitted(context)
        self.finish_chat_turn(
            context,
            assistant_text=assistant_text,
            status=status,
            token_totals=token_totals,
        )
        return EchoRecordResult(
            ok=True,
            mode="on",
            record_types=_BEGIN_RECORD_TYPES + _CLAIM_RECORD_TYPES + _FINISH_RECORD_TYPES,
        )

    def begin_tool_effect(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
        run_id: str,
        tool_name: str,
        tool_call_id: str,
        args_hash: str,
        lease_id: str,
        replay_class: ReplayClass,
        workspace: str | None = None,
    ) -> EchoToolEffectContext:
        """Durably authorize and claim one exact tool effect before execution."""
        _validate_tool_effect_binding(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
            run_id=run_id,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            args_hash=args_hash,
            lease_id=lease_id,
            replay_class=replay_class,
        )
        with self._state_lock, self._partition_operation_guard(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
        ):
            tenant_state = self._partition_state_locked(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
            )
            if self._verify_execution_boundary(tenant_state):
                raise EchoUnavailableError("journal advanced during effect authorization; retry")
            record_start = tenant_state.journal.record_count
            intent = _tool_effect_intent(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
                run_id=run_id,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                args_hash=args_hash,
                lease_id=lease_id,
                replay_class=replay_class,
            )
            decision_id = (
                "dec_"
                + stable_hash(
                    {
                        "effect_id": intent.effect_id,
                        "input_hash": intent.input_hash,
                        "run_seq": record_start,
                    }
                ).removeprefix("sha256:")[:32]
            )
            policy_decision = _tool_effect_policy_decision(
                intent,
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
                tool_name=tool_name,
                lease_id=lease_id,
                mac_key=tenant_state.permit_key,
            )
            now_ms = monotonic_ns() // 1_000_000
            seal = create_permit_seal(
                intent=intent,
                decision=policy_decision,
                key_epoch="permit-epoch-1",
                journal_seq=record_start + 3,
                deadline_ms=now_ms + 60_000,
                signing_key=tenant_state.permit_key,
            )
            self._assert_open_effect_capacity(tenant_state)
            outbox_row = tenant_state.effects.enqueue(
                seal=seal,
                sealed_input_ref=args_hash,
            )
            context = EchoToolEffectContext(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
                run_id=run_id,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                args_hash=args_hash,
                lease_id=lease_id,
                replay_class=replay_class,
                effect_id=seal.effect_id,
                outbox_id=outbox_row.outbox_id,
                record_start=record_start,
                permit_seal=seal,
                workspace=workspace,
            )
            execution_bridge = build_effect_bridge(
                tenant_id=tenant_id,
                session_id=session_id,
                run_id=run_id,
                channel="tool_call",
                executor_kind="tool",
                effect_id=seal.effect_id,
                outbox_id=outbox_row.outbox_id,
                action_kind=seal.action_kind,
                resource=intent.resource,
                scopes=seal.granted_scopes,
                input_hash=args_hash,
                replay_class=replay_class,
                state_refs={
                    "journal_record_start": record_start,
                    "permit_journal_seq": seal.journal_seq,
                    "partition_bound": True,
                    "product_id": product_id,
                    "tool_name": tool_name,
                    "tool_call_id": tool_call_id,
                    "args_hash": args_hash,
                    "lease_id": lease_id,
                    "workspace": workspace,
                },
            )
            safe_metadata = {
                "product_id": product_id,
                "session_id": session_id,
                "tool_name": tool_name,
                "tool_call_id": tool_call_id,
                "args_hash": args_hash,
                "lease_id": lease_id,
                "workspace": workspace,
            }
            entries: tuple[JournalEntry, ...] = (
                {
                    "record_type": "intake",
                    "tenant_id": tenant_id,
                    "run_id": run_id,
                    "payload": {
                        "payload_ref": stable_hash(safe_metadata),
                        "tool_effect": safe_metadata,
                    },
                },
                {
                    "record_type": "decision",
                    "tenant_id": tenant_id,
                    "run_id": run_id,
                    "payload": {"decision_id": decision_id},
                },
                {
                    "record_type": "policy_decision",
                    "tenant_id": tenant_id,
                    "run_id": run_id,
                    "payload": {"policy_decision_id": policy_decision.decision_id},
                },
                {
                    "record_type": "permit",
                    "tenant_id": tenant_id,
                    "run_id": run_id,
                    "payload": {
                        "seal_id": seal.seal_id,
                        "effect_id": seal.effect_id,
                        "seal": _seal_to_payload(seal),
                        "tool_effect": safe_metadata,
                    },
                },
                {
                    "record_type": "outbox",
                    "tenant_id": tenant_id,
                    "run_id": run_id,
                    "payload": {
                        "outbox_id": outbox_row.outbox_id,
                        "effect_id": seal.effect_id,
                        "sealed_input_ref": args_hash,
                        "seal": _seal_to_payload(seal),
                        "execution_contract": execution_bridge.to_payload(),
                    },
                },
                {
                    "record_type": "outbox_claimed",
                    "tenant_id": tenant_id,
                    "run_id": run_id,
                    "payload": {
                        "outbox_id": outbox_row.outbox_id,
                        "effect_id": seal.effect_id,
                    },
                },
            )
            self._verify_tool_effect_permit(context, tenant_state=tenant_state)
            self._acquire_claim_lock(tenant_state, context.outbox_id)

            def ensure_effect_is_new(
                effects: DurableEffectLog,
                disk_changed: bool,
            ) -> None:
                if not disk_changed:
                    return
                if effects.row_for_effect(context.effect_id) is not None:
                    raise PermissionError("effect already has durable journal state")
                raise EchoUnavailableError("journal advanced during effect authorization; retry")

            try:
                self._append_many(
                    tenant_id,
                    entries,
                    state=tenant_state,
                    semantic_check=ensure_effect_is_new,
                )
            except Exception:
                self._release_claim_lock(tenant_state, context.outbox_id)
                tenant_state.effects.discard_queued(context.outbox_id)
                raise
            tenant_state.effects.claim(context.outbox_id)
            return context

    _APPROVAL_EVENT_TYPES = frozenset(
        {
            "approval_requested",
            "approval_approved",
            "approval_rejected",
            "approval_edited",
            "approval_responded",
            "approval_expired",
            "approval_cancelled",
            "approval_execution_claimed",
            "approval_finalized",
        }
    )

    def record_approval_event(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
        run_id: str,
        event_type: str,
        request_id: str,
        tool_name: str,
        arguments_hash: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Authoritatively record one approval lifecycle event in EchoLedger.

        The event is appended to the same scope partition journal as the Echo
        run it belongs to, so approval state is atomically ordered with the
        run's effects and receipts.  Failures propagate (fail closed).
        """
        if event_type not in self._APPROVAL_EVENT_TYPES:
            raise ValueError(f"unknown approval event type: {event_type}")
        with self._state_lock, self._partition_operation_guard(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
        ):
            tenant_state = self._partition_state_locked(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
            )
            payload: dict[str, Any] = {
                "event_type": event_type,
                "request_id": request_id,
                "tool_name": tool_name,
                "arguments_hash": arguments_hash,
                "session_id": session_id,
                "run_id": run_id,
                "owner_key_hash": tenant_id,
            }
            if extra:
                payload.update(extra)
            entries: tuple[JournalEntry, ...] = (
                {
                    "record_type": "approval",
                    "tenant_id": tenant_id,
                    "run_id": run_id,
                    "payload": payload,
                },
            )
            self._append_many(tenant_id, entries, state=tenant_state)

    # ------------------------------------------------------------------
    # R4-B Task B5: Connector durable effect (begin / finish / mark unknown)
    # ------------------------------------------------------------------

    def begin_connector_effect(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
        run_id: str,
        workspace: str | None,
        connector_type: str,
        operation: Literal["read", "write"],
        connection_id: str,
        task_ref_hash: str,
        manifest_digest: str,
        binding_hash: str,
        params_digest: str,
        directory_grant_hash: str | None,
        vault_ref_hash: str | None,
        approval_id: str | None,
        lease_id: str,
    ) -> EchoConnectorEffectContext:
        """Begin a durable connector effect with outbox claim.

        Reuses the existing ``begin_tool_effect`` infrastructure with
        ``tool_name="connector.<type>.<op>"`` and ``tool_call_id=connection_id``.
        The binding hash serves as ``args_hash``.
        """
        action_kind = f"connector.{connector_type}.{operation}"
        replay_class: ReplayClass = (
            "idempotent" if operation == "read" else "non_idempotent"
        )
        tool_ctx = self.begin_tool_effect(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
            run_id=run_id,
            tool_name=action_kind,
            tool_call_id=connection_id,
            args_hash=binding_hash,
            lease_id=lease_id,
            replay_class=replay_class,
            workspace=workspace,
        )
        return EchoConnectorEffectContext(
            tenant_id=tool_ctx.tenant_id,
            product_id=tool_ctx.product_id,
            session_id=tool_ctx.session_id,
            run_id=tool_ctx.run_id,
            workspace=tool_ctx.workspace,
            connector_type=connector_type,
            operation=operation,
            connection_id=connection_id,
            task_ref_hash=task_ref_hash,
            manifest_digest=manifest_digest,
            binding_hash=binding_hash,
            params_digest=params_digest,
            directory_grant_hash=directory_grant_hash,
            vault_ref_hash=vault_ref_hash,
            approval_id=approval_id,
            lease_id=lease_id,
            replay_class=cast(
                "Literal['idempotent', 'non_idempotent']", replay_class
            ),
            effect_id=tool_ctx.effect_id,
            outbox_id=tool_ctx.outbox_id,
            record_start=tool_ctx.record_start,
            permit_seal=tool_ctx.permit_seal,
        )

    def finish_connector_effect(
        self,
        context: EchoConnectorEffectContext,
        *,
        status: Literal["ok", "failed", "cancelled"],
        output_hash: str,
        artifact_refs: tuple[ArtifactRefV1, ...] = (),
        error_code: str | None = None,
    ) -> EchoRecordResult:
        """Finish a connector effect with a durable receipt."""
        # Build a tool-like context adapter for finish_tool_effect
        tool_ctx = EchoToolEffectContext(
            tenant_id=context.tenant_id,
            product_id=context.product_id,
            session_id=context.session_id,
            run_id=context.run_id,
            tool_name=f"connector.{context.connector_type}.{context.operation}",
            tool_call_id=context.connection_id,
            args_hash=context.binding_hash,
            lease_id=context.lease_id,
            replay_class=context.replay_class,
            effect_id=context.effect_id,
            outbox_id=context.outbox_id,
            record_start=context.record_start,
            permit_seal=context.permit_seal,
            workspace=context.workspace,
        )
        return self.finish_tool_effect(
            tool_ctx,
            status=status,
            output_hash=output_hash,
            artifact_refs=artifact_refs,
        )

    def mark_connector_unknown(
        self,
        context: EchoConnectorEffectContext,
        *,
        reason: str,
    ) -> None:
        """Mark a connector effect as manual_review (unknown outcome)."""
        with self._state_lock, self._partition_operation_guard(
            tenant_id=context.tenant_id,
            product_id=context.product_id,
            session_id=context.session_id,
        ):
            tenant_state = self._partition_state_locked(
                tenant_id=context.tenant_id,
                product_id=context.product_id,
                session_id=context.session_id,
            )
            outbox_id = context.outbox_id
            entries: tuple[JournalEntry, ...] = (
                {
                    "record_type": "outbox_manual_review",
                    "tenant_id": context.tenant_id,
                    "run_id": context.run_id,
                    "payload": {
                        "effect_id": context.effect_id,
                        "outbox_id": outbox_id,
                        "reason": reason,
                        "connector_type": context.connector_type,
                        "operation": context.operation,
                    },
                },
            )
            self._append_many(
                context.tenant_id,
                entries,
                state=tenant_state,
            )
            tenant_state.effects.mark_manual_review(outbox_id)
            self._release_claim_lock(tenant_state, outbox_id)

    # ------------------------------------------------------------------
    # R4A-B2: Atomic approval binding claim (CAS in Echo journal)
    # ------------------------------------------------------------------
    class _ApprovalClaimAlreadyExistsError(Exception):
        """Internal: raised inside semantic_check to abort duplicate append."""

    @dataclass(frozen=True, slots=True)
    class ApprovalClaimReceipt:
        """Durable proof of an atomic approval binding claim.

        ``claimed_now`` distinguishes a fresh claim from a pre-existing
        one (idempotent recovery).  Even an ``already_claimed`` receipt
        must NOT re-authorize execution; it only confirms the binding
        was previously claimed.
        """

        request_id: str
        binding_hash: str
        journal_record_hash: str
        journal_seq: int
        claimed_now: bool

    def claim_approval_binding_once(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
        run_id: str,
        request_id: str,
        tool_name: str,
        arguments_hash: str,
        approval_mode: str,
        expires_at: float,
        requested_at: float,
    ) -> EchoSafetyService.ApprovalClaimReceipt:
        """Atomically claim one approval binding at most once.

        Uses the Echo journal's cross-process ``fcntl.flock`` via
        ``_append_many(semantic_check=...)`` to ensure check + append +
        fsync are atomic.  If the same ``request_id`` with the exact same
        binding already has a claim, returns the existing receipt with
        ``claimed_now=False`` (idempotent recovery).  If the same
        ``request_id`` has a claim with a *different* binding, raises
        ``ValueError`` (corruption/conflict).
        """

        binding_hash = self._approval_binding_hash(
            tenant_id=tenant_id,
            session_id=session_id,
            run_id=run_id,
            tool_name=tool_name,
            arguments_hash=arguments_hash,
            approval_mode=approval_mode,
        )
        with self._state_lock, self._partition_operation_guard(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
        ):
            tenant_state = self._partition_state_locked(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
            )

            # Pre-scan cached state for existing claim (fast path).
            for record in tenant_state.journal.records:
                p = record.payload
                if not isinstance(p, dict):
                    continue
                if p.get("event_type") != "approval_execution_claimed":
                    continue
                if p.get("request_id") != request_id:
                    continue
                existing_hash = p.get("binding_hash", "")
                if existing_hash != binding_hash:
                    raise ValueError(
                        "approval binding conflict: request_id already"
                        " claimed with different binding"
                    )
                return EchoSafetyService.ApprovalClaimReceipt(
                    request_id=request_id,
                    binding_hash=binding_hash,
                    journal_record_hash=getattr(record, "record_hash", ""),
                    journal_seq=getattr(record, "seq", 0),
                    claimed_now=False,
                )

            # No existing claim in cached state: append with semantic_check
            # that re-verifies inside the journal's cross-process flock.
            payload: dict[str, Any] = {
                "event_type": "approval_execution_claimed",
                "request_id": request_id,
                "tool_name": tool_name,
                "arguments_hash": arguments_hash,
                "session_id": session_id,
                "run_id": run_id,
                "owner_key_hash": tenant_id,
                "approval_mode": approval_mode,
                "expires_at": expires_at,
                "requested_at": requested_at,
                "binding_hash": binding_hash,
            }
            entries: tuple[JournalEntry, ...] = (
                {
                    "record_type": "approval",
                    "tenant_id": tenant_id,
                    "run_id": run_id,
                    "payload": payload,
                },
            )

            found_existing: list[Any] = []

            def check_before_append(
                _effects: DurableEffectLog,
                _disk_changed: bool,
            ) -> None:
                # Scan the journal's in-memory records (synced from disk
                # inside the flock).  Do NOT call verified_logical_records()
                # here -- it would re-acquire the same lock and deadlock.
                for rec in tenant_state.journal.records:
                    p = rec.payload
                    if not isinstance(p, dict):
                        continue
                    if p.get("event_type") != "approval_execution_claimed":
                        continue
                    if p.get("request_id") != request_id:
                        continue
                    existing_hash = p.get("binding_hash", "")
                    if existing_hash != binding_hash:
                        raise ValueError(
                            "approval binding conflict: request_id already"
                            " claimed with different binding"
                        )
                    found_existing.append(rec)
                    raise EchoSafetyService._ApprovalClaimAlreadyExistsError()

            try:
                self._append_many(
                    tenant_id,
                    entries,
                    state=tenant_state,
                    semantic_check=check_before_append,
                )
            except EchoSafetyService._ApprovalClaimAlreadyExistsError:
                rec = found_existing[0]
                return EchoSafetyService.ApprovalClaimReceipt(
                    request_id=request_id,
                    binding_hash=binding_hash,
                    journal_record_hash=getattr(rec, "record_hash", ""),
                    journal_seq=getattr(rec, "seq", 0),
                    claimed_now=False,
                )

            # Read back the just-appended record from cached journal state
            for record in tenant_state.journal.records:
                p = record.payload
                if (
                    isinstance(p, dict)
                    and p.get("event_type") == "approval_execution_claimed"
                    and p.get("request_id") == request_id
                    and p.get("binding_hash") == binding_hash
                ):
                    return EchoSafetyService.ApprovalClaimReceipt(
                        request_id=request_id,
                        binding_hash=binding_hash,
                        journal_record_hash=getattr(record, "record_hash", ""),
                        journal_seq=getattr(record, "seq", 0),
                        claimed_now=True,
                    )
            raise RuntimeError("approval claim append succeeded but record not found")

    def lookup_approval_claim(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
        request_id: str,
    ) -> EchoSafetyService.ApprovalClaimReceipt | None:
        """Query whether an approval binding claim exists in the Echo journal.

        Used by ``ApprovalQueue._durable_resolved_record`` to detect
        claims that exist in the Echo authority but are missing from the
        local mirror (e.g. mirror truncation).
        """

        with self._state_lock, self._partition_operation_guard(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
        ):
            tenant_state = self._partition_state_locked(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
            )
            for record in tenant_state.journal.records:
                p = record.payload
                if not isinstance(p, dict):
                    continue
                if p.get("event_type") != "approval_execution_claimed":
                    continue
                if p.get("request_id") != request_id:
                    continue
                return EchoSafetyService.ApprovalClaimReceipt(
                    request_id=request_id,
                    binding_hash=str(p.get("binding_hash", "")),
                    journal_record_hash=getattr(record, "record_hash", ""),
                    journal_seq=getattr(record, "seq", 0),
                    claimed_now=False,
                )
            return None

    @staticmethod
    def _approval_binding_hash(
        *,
        tenant_id: str,
        session_id: str,
        run_id: str,
        tool_name: str,
        arguments_hash: str,
        approval_mode: str,
    ) -> str:
        """Compute a domain-separated canonical binding hash."""
        import hashlib as _hl

        payload = _stable_json_for_hash(
            {
                "owner_key_hash": tenant_id,
                "session_id": session_id,
                "run_id": run_id,
                "tool_name": tool_name,
                "arguments_hash": arguments_hash,
                "approval_mode": approval_mode,
            }
        )
        return (
            "sha256:"
            + _hl.sha256(
                b"js-agent:approval-binding:v1\0" + payload.encode("utf-8")
            ).hexdigest()
        )

    # ------------------------------------------------------------------
    # R4A-B1: Two-phase lease consume anchor
    # ------------------------------------------------------------------
    _LEASE_ANCHOR_EVENT_TYPES = frozenset(
        {
            "lease_consume_pending",
            "lease_consume_finalized",
        }
    )

    def record_lease_consume_pending(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
        run_id: str,
        lease_id: str,
        nonce: str,
    ) -> str:
        """Phase 1: record a durable *intent* to consume a lease.

        Must be called **before** ``LeaseAuthority.consume_bound()``.
        If the process crashes between this write and the actual consume,
        restart recovery can detect the pending intent and mark the
        operation for manual review.
        """

        return self._append_lease_anchor(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
            run_id=run_id,
            event_type="lease_consume_pending",
            lease_id=lease_id,
            nonce=nonce,
            consume_receipt_hash=None,
        )

    def record_lease_consume_finalized(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
        run_id: str,
        lease_id: str,
        nonce: str,
        consume_receipt_hash: str,
    ) -> str:
        """Phase 2: record the durable, finalized consume anchor.

        Must be called **after** ``LeaseAuthority.consume_bound()`` succeeds.
        The ``consume_receipt_hash`` binds the Echo anchor to the exact
        lease ledger record, detecting valid-prefix rollback of the lease
        ledger alone.
        """

        return self._append_lease_anchor(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
            run_id=run_id,
            event_type="lease_consume_finalized",
            lease_id=lease_id,
            nonce=nonce,
            consume_receipt_hash=consume_receipt_hash,
        )

    def lookup_lease_consume_anchor(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
        lease_id: str,
        nonce: str,
    ) -> str | None:
        """Query whether a finalized consume anchor exists.

        Returns the ``consume_receipt_hash`` if a finalized anchor is found,
        ``None`` otherwise.  Used by ``LeaseAuthority.verify_consume_anchor``
        to detect valid-prefix rollback of the lease ledger.
        """

        with self._state_lock, self._partition_operation_guard(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
        ):
            tenant_state = self._partition_state_locked(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
            )
            for record in tenant_state.journal.records:
                payload = record.payload
                if not isinstance(payload, dict):
                    continue
                if payload.get("event_type") != "lease_consume_finalized":
                    continue
                if payload.get("lease_id") != lease_id:
                    continue
                if payload.get("nonce") != nonce:
                    continue
                result = payload.get("consume_receipt_hash")
                if isinstance(result, str):
                    return result
            return None

    def _append_lease_anchor(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
        run_id: str,
        event_type: str,
        lease_id: str,
        nonce: str,
        consume_receipt_hash: str | None,
    ) -> str:
        """Append a lease anchor record to the Echo journal.

        Uses ``semantic_check`` to ensure idempotency: if the same
        ``(lease_id, nonce, event_type)`` anchor already exists, returns
        the existing record hash without appending a duplicate.
        """

        with self._state_lock, self._partition_operation_guard(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
        ):
            tenant_state = self._partition_state_locked(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
            )
            payload: dict[str, Any] = {
                "event_type": event_type,
                "lease_id": lease_id,
                "nonce": nonce,
                "session_id": session_id,
                "run_id": run_id,
                "owner_key_hash": tenant_id,
            }
            if consume_receipt_hash is not None:
                payload["consume_receipt_hash"] = consume_receipt_hash
            entries: tuple[JournalEntry, ...] = (
                {
                    "record_type": "lease_anchor",
                    "tenant_id": tenant_id,
                    "run_id": run_id,
                    "payload": payload,
                },
            )
            existing_hash: str | None = None

            def ensure_not_duplicate(
                _effects: DurableEffectLog,
                _disk_changed: bool,
            ) -> None:
                nonlocal existing_hash
                for record in tenant_state.journal.records:
                    p = record.payload
                    if not isinstance(p, dict):
                        continue
                    if p.get("event_type") != event_type:
                        continue
                    if p.get("lease_id") != lease_id:
                        continue
                    if p.get("nonce") != nonce:
                        continue
                    existing_hash = getattr(record, "record_hash", None)
                    if isinstance(existing_hash, str):
                        return
                    return

            self._append_many(
                tenant_id,
                entries,
                state=tenant_state,
                semantic_check=ensure_not_duplicate,
            )
            if existing_hash is not None:
                return existing_hash
            # Return the hash of the just-appended record
            for record in tenant_state.journal.records:
                p = record.payload
                if (
                    isinstance(p, dict)
                    and p.get("event_type") == event_type
                    and p.get("lease_id") == lease_id
                    and p.get("nonce") == nonce
                ):
                    rh = getattr(record, "record_hash", None)
                    if isinstance(rh, str):
                        return rh
            return ""

    _DAEMON_EVENT_TYPES = frozenset(
        {
            "daemon_started",
            "daemon_heartbeat",
            "daemon_degraded",
            "daemon_stopped",
        }
    )

    def record_daemon_event(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Authoritatively record a daemon lifecycle/health event in EchoLedger.

        The daemon_heartbeat.json file is only a derived snapshot; this is
        the system of record.  Failures propagate so the daemon can mark
        itself ledger-degraded (fail-closed health signal).
        """
        if event_type not in self._DAEMON_EVENT_TYPES:
            raise ValueError(f"unknown daemon event type: {event_type}")
        with self._state_lock, self._partition_operation_guard(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
        ):
            tenant_state = self._partition_state_locked(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
            )
            record_payload: dict[str, Any] = {
                "event_type": event_type,
                "recorded_at": time(),
            }
            if payload:
                record_payload.update(payload)
            entries: tuple[JournalEntry, ...] = (
                {
                    "record_type": "daemon",
                    "tenant_id": tenant_id,
                    "run_id": "daemon",
                    "payload": record_payload,
                },
            )
            self._append_many(tenant_id, entries, state=tenant_state)

    def finish_tool_effect(
        self,
        context: EchoToolEffectContext,
        *,
        status: Literal["ok", "failed", "cancelled"],
        output_hash: str,
        artifact_refs: tuple[ArtifactRefV1, ...] = (),
    ) -> EchoRecordResult:
        """Durably receipt and merge a previously claimed tool effect."""
        _validate_artifact_refs_for_context(
            context,
            status=status,
            artifact_refs=artifact_refs,
        )
        with self._state_lock, self._turn_partition_operation_guard(context):
            if status not in {"ok", "failed", "cancelled"}:
                raise ValueError("invalid tool effect status")
            if _SHA256_REF_RE.fullmatch(output_hash) is None:
                raise ValueError("tool effect output_hash must be a sha256 reference")
            tenant_state = self._partition_state_locked(
                tenant_id=context.tenant_id,
                product_id=context.product_id,
                session_id=context.session_id,
            )
            self._verify_tool_effect_permit(
                context,
                tenant_state=tenant_state,
                check_deadline=False,
            )
            try:
                current_status = tenant_state.effects.status(context.outbox_id)
            except KeyError as exc:
                raise PermissionError("tool effect outbox row missing") from exc
            if current_status != "claimed":
                raise PermissionError("outbox row is not claimed")
            if self._claim_lock_key(tenant_state, context.outbox_id) not in self._claim_lock_fds:
                raise PermissionError("durable claim is not owned by this Echo service")

            receipt = EffectReceipt(
                receipt_id=f"receipt:{context.effect_id}",
                effect_id=context.effect_id,
                tenant_id=context.tenant_id,
                status=status,
                output_ref=output_hash,
                replay_class=context.replay_class,
                artifact_refs=artifact_refs,
            )
            entries: tuple[JournalEntry, ...] = (
                {
                    "record_type": "receipt",
                    "tenant_id": context.tenant_id,
                    "run_id": context.run_id,
                    "payload": {
                        "effect_id": context.effect_id,
                        "outbox_id": context.outbox_id,
                        "status": status,
                        "output_ref": output_hash,
                        "output_hash": output_hash,
                        "replay_class": context.replay_class,
                        "artifact_refs": [ref.to_dict() for ref in artifact_refs],
                    },
                },
                {
                    "record_type": "merge",
                    "tenant_id": context.tenant_id,
                    "run_id": context.run_id,
                    "payload": {"effect_id": context.effect_id, "status": status},
                },
            )

            def ensure_claim_is_current(
                effects: DurableEffectLog,
                _disk_changed: bool,
            ) -> None:
                row = effects.row_for_effect(context.effect_id)
                if row is None or row.outbox_id != context.outbox_id:
                    raise PermissionError("tool effect outbox row missing")
                if row.status != "claimed":
                    raise PermissionError("outbox row is not claimed")

            try:
                self._append_many(
                    context.tenant_id,
                    entries,
                    state=tenant_state,
                    semantic_check=ensure_claim_is_current,
                )
            except Exception as exc:
                self._error_count += 1
                self._last_error = exc.__class__.__name__
                raise
            tenant_state.effects.record_receipt(context.outbox_id, receipt)
            tenant_state.effects.mark_merged(context.effect_id)
            self._release_claim_lock(tenant_state, context.outbox_id)
            self.maybe_compact(tenant_state)
            result = EchoRecordResult(
                ok=True,
                mode="on",
                record_types=_FINISH_RECORD_TYPES,
            )
        self._maybe_retire_partitions(
            tenant_id=context.tenant_id,
            product_id=context.product_id,
            protected_session_id=context.session_id,
        )
        return result

    def _verify_tool_effect_permit(
        self,
        context: EchoToolEffectContext,
        *,
        tenant_state: _TenantJournalState,
        check_deadline: bool = True,
    ) -> None:
        expected_intent = _tool_effect_intent(
            tenant_id=context.tenant_id,
            product_id=context.product_id,
            session_id=context.session_id,
            run_id=context.run_id,
            tool_name=context.tool_name,
            tool_call_id=context.tool_call_id,
            args_hash=context.args_hash,
            lease_id=context.lease_id,
            replay_class=context.replay_class,
        )
        seal = context.permit_seal
        if not seal.verify(tenant_state.permit_key):
            raise PermissionError("tool effect PermitSeal MAC invalid")
        if seal.tenant_id != context.tenant_id:
            raise PermissionError("tool effect PermitSeal tenant mismatch")
        if seal.effect_id != context.effect_id or context.effect_id != expected_intent.effect_id:
            raise PermissionError("tool effect PermitSeal binding mismatch")
        if seal.action_kind != expected_intent.action_kind:
            raise PermissionError("tool effect PermitSeal action mismatch")
        if expected_intent.scopes[0] not in seal.granted_scopes:
            raise PermissionError("tool effect PermitSeal missing exact tool scope")
        if seal.replay_class != context.replay_class:
            raise PermissionError("tool effect PermitSeal replay class mismatch")
        expected_policy = _tool_effect_policy_decision(
            expected_intent,
            tenant_id=context.tenant_id,
            product_id=context.product_id,
            session_id=context.session_id,
            tool_name=context.tool_name,
            lease_id=context.lease_id,
            mac_key=tenant_state.permit_key,
        )
        if seal.policy_decision_id != expected_policy.decision_id:
            raise PermissionError("tool effect PermitSeal lease binding mismatch")
        if check_deadline and monotonic_ns() // 1_000_000 > seal.deadline_ms:
            raise PermissionError("tool effect PermitSeal expired")

    def begin_chat_turn(
        self,
        *,
        tenant_id: str,
        run_id: str,
        user_text: str,
        model_id: str | None,
        call_metadata: dict[str, Any] | None = None,
    ) -> EchoTurnContext:
        return self._begin_chat_turn(
            tenant_id=tenant_id,
            run_id=run_id,
            user_text=user_text,
            model_id=model_id,
            call_metadata=call_metadata,
            claim_before_return=False,
        )

    def _begin_chat_turn(
        self,
        *,
        tenant_id: str,
        run_id: str,
        user_text: str,
        model_id: str | None,
        call_metadata: dict[str, Any] | None = None,
        claim_before_return: bool = False,
    ) -> EchoTurnContext:
        metadata_product = (call_metadata or {}).get("product_id")
        metadata_session = (call_metadata or {}).get("session_id")
        if (metadata_product is None) != (metadata_session is None):
            raise ValueError("Echo model partition requires both product_id and session_id")
        if metadata_product is not None and metadata_session is not None:
            with self._state_lock, self._partition_operation_guard(
                tenant_id=tenant_id,
                product_id=str(metadata_product),
                session_id=str(metadata_session),
            ):
                return self._begin_chat_turn_locked(
                    tenant_id=tenant_id,
                    run_id=run_id,
                    user_text=user_text,
                    model_id=model_id,
                    call_metadata=call_metadata,
                    claim_before_return=claim_before_return,
                )
        with self._state_lock:
            return self._begin_chat_turn_locked(
                tenant_id=tenant_id,
                run_id=run_id,
                user_text=user_text,
                model_id=model_id,
                call_metadata=call_metadata,
                claim_before_return=claim_before_return,
            )

    def _begin_chat_turn_locked(
        self,
        *,
        tenant_id: str,
        run_id: str,
        user_text: str,
        model_id: str | None,
        call_metadata: dict[str, Any] | None,
        claim_before_return: bool,
    ) -> EchoTurnContext:
        if _contains_secret(user_text):
            raise EchoBlockedError("Secret data cannot enter Echo model path")

        metadata_product = (call_metadata or {}).get("product_id")
        metadata_session = (call_metadata or {}).get("session_id")
        if (metadata_product is None) != (metadata_session is None):
            raise ValueError("Echo model partition requires both product_id and session_id")
        product_id = str(metadata_product) if metadata_product is not None else None
        session_id = str(metadata_session) if metadata_session is not None else None
        tenant_state = (
            self._partition_state(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
            )
            if product_id is not None and session_id is not None
            else self._tenant_state(tenant_id)
        )
        if self._verify_execution_boundary(tenant_state):
            raise EchoUnavailableError("journal advanced during effect authorization; retry")
        journal = tenant_state.journal
        record_start = journal.record_count
        payload_ref = stable_hash({"text": user_text})
        now_ms = monotonic_ns() // 1_000_000
        event = IntakeEvent(
            event_id=f"evt-{record_start + 1}",
            tenant_id=tenant_id,
            run_id=run_id,
            payload_ref=payload_ref,
            trust_level="user",
            monotonic_ms=now_ms,
            wall_time=datetime.now(UTC).isoformat(),
        )
        decision = decide(
            KernelSnapshot(tenant_id=tenant_id, run_id=run_id, run_seq=record_start, facts=()),
            (event,),
        )
        provider_id = str((call_metadata or {}).get("provider_id") or "local-adapter")
        intent = _agent_chat_intent(
            decision.intents[0],
            provider_id=provider_id,
            model_id=model_id or "default",
        )
        policy_decision = evaluate_policy(
            intent,
            IdentityContext(actor_id=tenant_id, tenant_id=tenant_id, roles=("local-user",)),
            PolicyBundle(
                bundle_id="echo-ledger-agent-chat",
                rules=(
                    PolicyRule(
                        rule_id="allow-model",
                        effect="allow",
                        scopes=("model:invoke",),
                        action_prefix="model.",
                    ),
                ),
            ),
            resource_snapshot_hash="sha256:agent-chat",
            mac_key=tenant_state.permit_key,
        )
        seal = create_permit_seal(
            intent=intent,
            decision=policy_decision,
            key_epoch="permit-epoch-1",
            journal_seq=record_start + 3,
            deadline_ms=now_ms + 60_000,
            signing_key=tenant_state.permit_key,
        )
        envelope = build_model_privacy_envelope(
            ModelCallRequest(
                model_request_id=f"model-{record_start + 1}",
                tenant_id=tenant_id,
                provider_id=provider_id,
                model_id=model_id or "default",
                prompt=user_text,
                data_classes=("UserPrivate",),
                prompt_slots_used=("user",),
                max_tokens=0,
                cost_budget=0,
                policy_decision_id=policy_decision.decision_id,
            ),
            ProviderCapability(
                provider_id=provider_id,
                zero_data_retention=False,
                retention_class="provider-policy-unverified",
                region_policy=None,
            ),
        )
        self._assert_open_effect_capacity(tenant_state)
        outbox_row = tenant_state.effects.enqueue(seal=seal, sealed_input_ref=payload_ref)
        context = EchoTurnContext(
            tenant_id=tenant_id,
            run_id=run_id,
            effect_id=seal.effect_id,
            outbox_id=outbox_row.outbox_id,
            record_start=record_start,
            permit_seal=seal,
            product_id=product_id,
            session_id=session_id,
        )
        execution_bridge = build_effect_bridge(
            tenant_id=tenant_id,
            session_id=str((call_metadata or {}).get("session_id") or run_id),
            run_id=run_id,
            channel="model_call",
            executor_kind="model",
            effect_id=seal.effect_id,
            outbox_id=outbox_row.outbox_id,
            action_kind=seal.action_kind,
            resource=intent.resource,
            scopes=seal.granted_scopes,
            input_hash=intent.input_hash,
            replay_class=cast("ReplayClass", seal.replay_class),
            state_refs={
                "journal_record_start": record_start,
                "permit_journal_seq": seal.journal_seq,
                "model_id": model_id or "default",
                "partition_bound": product_id is not None and session_id is not None,
                "provider_id": provider_id,
                "product_id": str((call_metadata or {}).get("product_id") or "js-agent"),
            },
        )
        entries: tuple[JournalEntry, ...] = (
            {
                "record_type": "intake",
                "tenant_id": tenant_id,
                "run_id": run_id,
                "payload": {"payload_ref": payload_ref, "model_call": call_metadata or {}},
            },
            {
                "record_type": "decision",
                "tenant_id": tenant_id,
                "run_id": run_id,
                "payload": {"decision_id": decision.decision_id},
            },
            {
                "record_type": "policy_decision",
                "tenant_id": tenant_id,
                "run_id": run_id,
                "payload": {"policy_decision_id": policy_decision.decision_id},
            },
            {
                "record_type": "permit",
                "tenant_id": tenant_id,
                "run_id": run_id,
                "payload": {
                    "seal_id": seal.seal_id,
                    "effect_id": seal.effect_id,
                    "seal": _seal_to_payload(seal),
                    **_scope_permit_payload(call_metadata),
                },
            },
            {
                "record_type": "model_privacy_envelope",
                "tenant_id": tenant_id,
                "run_id": run_id,
                "payload": {
                    "model_request_id": envelope.model_request_id,
                    "provider_id": envelope.provider_id,
                    "allow_training": envelope.allow_training,
                },
            },
            {
                "record_type": "outbox",
                "tenant_id": tenant_id,
                "run_id": run_id,
                "payload": {
                    "outbox_id": outbox_row.outbox_id,
                    "effect_id": seal.effect_id,
                    "sealed_input_ref": payload_ref,
                    "seal": _seal_to_payload(seal),
                    "execution_contract": execution_bridge.to_payload(),
                },
            },
        )
        if claim_before_return:
            entries = entries + (
                {
                    "record_type": "outbox_claimed",
                    "tenant_id": context.tenant_id,
                    "run_id": context.run_id,
                    "payload": {
                        "outbox_id": context.outbox_id,
                        "effect_id": context.effect_id,
                    },
                },
            )

        def ensure_effect_is_new(
            effects: DurableEffectLog,
            disk_changed: bool,
        ) -> None:
            if not disk_changed:
                return
            if effects.row_for_effect(context.effect_id) is not None:
                raise PermissionError("effect already has durable journal state")
            raise EchoUnavailableError("journal advanced during effect authorization; retry")

        reservation_acquired = False
        claim_lock_acquired = False
        try:
            self._acquire_effect_reservation(
                tenant_state,
                context.effect_id,
            )
            reservation_acquired = True
            if claim_before_return:
                self._verify_model_execution_permit(context, tenant_state=tenant_state)
                self._acquire_claim_lock(tenant_state, context.outbox_id)
                claim_lock_acquired = True
            self._append_many(
                tenant_id,
                entries,
                state=tenant_state,
                semantic_check=ensure_effect_is_new,
            )
        except Exception:
            if claim_lock_acquired:
                self._release_claim_lock(tenant_state, context.outbox_id)
            if reservation_acquired:
                self._release_effect_reservation(tenant_state, context.effect_id)
            tenant_state.effects.discard_queued(context.outbox_id)
            raise
        if claim_before_return:
            tenant_state.effects.claim(context.outbox_id)
            self._release_effect_reservation(tenant_state, context.effect_id)
        return context

    def authorize_model_call(
        self,
        *,
        tenant_id: str,
        session_id: str | None = None,
        run_id: str,
        product_id: str = "js-agent",
        provider_id: str,
        model_id: str | None,
        messages: Sequence[Any],
        tools_schema: Sequence[dict[str, Any]] | None = None,
        attachments_manifest: Sequence[dict[str, Any]] | None = None,
    ) -> EchoTurnContext:
        """Authorize the exact provider-bound payload immediately before invocation."""
        if _contains_image_data_url(messages):
            raise EchoBlockedError(
                "Vision attachments require explicit Echo vision safety approval"
            )
        if _contains_secret(_model_call_secret_scan_text(messages, tools_schema)):
            raise EchoBlockedError("Secret data cannot enter Echo model path")
        resolved_session_id = session_id or run_id
        resolved_product_id = product_id or "js-agent"
        resolved_provider_id = provider_id.strip()
        if not resolved_provider_id:
            raise ValueError("model provider_id must not be empty")
        normalized_attachments = _normalize_attachment_manifest(attachments_manifest)
        with self._state_lock, self._partition_operation_guard(
            tenant_id=tenant_id,
            product_id=resolved_product_id,
            session_id=resolved_session_id,
        ):
            return self._authorize_model_call_locked(
                tenant_id=tenant_id,
                session_id=resolved_session_id,
                run_id=run_id,
                product_id=resolved_product_id,
                provider_id=resolved_provider_id,
                model_id=model_id,
                messages=messages,
                tools_schema=tools_schema,
                attachments_manifest=normalized_attachments,
            )

    def _authorize_model_call_locked(
        self,
        *,
        tenant_id: str,
        session_id: str,
        run_id: str,
        product_id: str,
        provider_id: str,
        model_id: str | None,
        messages: Sequence[Any],
        tools_schema: Sequence[dict[str, Any]] | None,
        attachments_manifest: tuple[dict[str, Any], ...],
    ) -> EchoTurnContext:
        model_call_payload = _model_call_payload(
            product_id=product_id,
            session_id=session_id,
            run_id=run_id,
            provider_id=provider_id,
            model_id=model_id or "default",
            messages=messages,
            tools_schema=tools_schema,
            attachments_manifest=attachments_manifest,
        )
        partition_state = self._partition_state_locked(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
        )
        scope_gate = ScopeGate(signing_key=partition_state.permit_key)
        requested_scopes = (
            "model:invoke",
            f"product:{product_id}",
            *_tool_scopes(tools_schema),
        )
        scope_permit = scope_gate.authorize_model_request(
            ScopeRequest(
                owner_id=tenant_id,
                session_id=session_id,
                run_id=run_id,
                provider_id=provider_id,
                model_id=model_id or "default",
                messages=tuple(model_call_payload["messages"]),
                tools_schema=tuple(model_call_payload["tools_schema"]),
                attachments=tuple(model_call_payload["attachments_manifest"]),
                requested_scopes=requested_scopes,
            )
        )
        model_call_text = json.dumps(
            model_call_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        metadata = {
            "architecture": ECHO_2_ARCHITECTURE,
            "scope_gate": "ScopeGate",
            "product_id": product_id,
            "session_id": session_id,
            "run_id": run_id,
            "provider_id": provider_id,
            "model_id": model_id or "default",
            "messages_hash": scope_permit.messages_hash,
            "tools_schema_hash": scope_permit.tools_schema_hash,
            "attachments_hash": scope_permit.attachments_hash,
            "request_hash": scope_permit.request_hash,
            "model_call_hash": stable_payload_hash(model_call_payload),
            "attachments_manifest": list(attachments_manifest),
            "scope_permit": _scope_permit_to_payload(scope_permit),
        }
        return self._begin_chat_turn_locked(
            tenant_id=tenant_id,
            run_id=run_id,
            user_text=model_call_text,
            model_id=model_id,
            call_metadata=metadata,
            claim_before_return=True,
        )

    def assert_model_execution_permitted(self, context: EchoTurnContext) -> None:
        with self._state_lock, self._turn_partition_operation_guard(context):
            tenant_state = self._state_for_turn_context(context)
            self._verify_execution_boundary(tenant_state)
            self._verify_model_execution_permit(context, tenant_state=tenant_state)
            try:
                if tenant_state.effects.status(context.outbox_id) != "queued":
                    raise PermissionError("outbox row is not queued")
            except KeyError as exc:
                raise PermissionError("model execution outbox row missing") from exc
            self._acquire_claim_lock(tenant_state, context.outbox_id)

            def ensure_effect_is_claimable(
                effects: DurableEffectLog,
                _disk_changed: bool,
            ) -> None:
                row = effects.row_for_effect(context.effect_id)
                if row is None or row.outbox_id != context.outbox_id:
                    raise PermissionError("model execution outbox row missing")
                if row.status != "queued":
                    raise PermissionError("outbox row is not queued")

            try:
                self._append_many(
                    context.tenant_id,
                    (
                        {
                            "record_type": "outbox_claimed",
                            "tenant_id": context.tenant_id,
                            "run_id": context.run_id,
                            "payload": {
                                "outbox_id": context.outbox_id,
                                "effect_id": context.effect_id,
                            },
                        },
                    ),
                    state=tenant_state,
                    semantic_check=ensure_effect_is_claimable,
                )
            except Exception:
                self._release_claim_lock(tenant_state, context.outbox_id)
                self._release_effect_reservation(tenant_state, context.effect_id)
                raise
            tenant_state.effects.claim(context.outbox_id)
            self._release_effect_reservation(tenant_state, context.effect_id)

    def _verify_model_execution_permit(
        self,
        context: EchoTurnContext,
        *,
        tenant_state: _TenantJournalState,
    ) -> None:
        seal = context.permit_seal
        if seal is None:
            raise PermissionError("model execution missing PermitSeal")
        if not seal.verify(tenant_state.permit_key):
            raise PermissionError("model execution PermitSeal MAC invalid")
        if seal.tenant_id != context.tenant_id:
            raise PermissionError("model execution PermitSeal tenant mismatch")
        if seal.effect_id != context.effect_id:
            raise PermissionError("model execution PermitSeal effect mismatch")
        if seal.action_kind != "model.js_agent_chat":
            raise PermissionError("model execution PermitSeal action mismatch")
        if "model:invoke" not in seal.granted_scopes:
            raise PermissionError("model execution PermitSeal missing model:invoke scope")
        if monotonic_ns() // 1_000_000 > seal.deadline_ms:
            raise PermissionError("model execution PermitSeal expired")

    def finish_chat_turn(
        self,
        context: EchoTurnContext,
        *,
        assistant_text: str,
        status: str,
        token_totals: dict[str, int],
        token_source: str = "unavailable",
    ) -> EchoRecordResult:
        with self._state_lock, self._turn_partition_operation_guard(context):
            if token_source not in _TOKEN_SOURCES:
                raise ValueError("invalid Echo token source")
            output_ref = "assistant:" + stable_hash({"text": assistant_text})
            tenant_state = self._state_for_turn_context(context)
            try:
                current_status = tenant_state.effects.status(context.outbox_id)
            except KeyError as exc:
                raise PermissionError("model execution outbox row missing") from exc
            if current_status != "claimed":
                raise PermissionError("outbox row is not claimed")
            if self._claim_lock_key(tenant_state, context.outbox_id) not in self._claim_lock_fds:
                raise PermissionError("durable claim is not owned by this Echo service")
            receipt_status: Literal["ok", "failed", "cancelled"] = (
                "ok"
                if status == "completed"
                else "cancelled"
                if status == "cancelled"
                else "failed"
            )
            receipt = EffectReceipt(
                receipt_id=f"receipt:{context.effect_id}",
                effect_id=context.effect_id,
                tenant_id=context.tenant_id,
                status=receipt_status,
                output_ref=output_ref,
                replay_class="probe_required",
            )
            entries: tuple[JournalEntry, ...] = (
                {
                    "record_type": "receipt",
                    "tenant_id": context.tenant_id,
                    "run_id": context.run_id,
                    "payload": {
                        "effect_id": context.effect_id,
                        "outbox_id": context.outbox_id,
                        "status": status,
                        "output_ref": output_ref,
                        "token_totals": token_totals,
                        "token_source": token_source,
                    },
                },
                {
                    "record_type": "merge",
                    "tenant_id": context.tenant_id,
                    "run_id": context.run_id,
                    "payload": {"effect_id": context.effect_id, "status": status},
                },
            )

            def ensure_claim_is_current(
                effects: DurableEffectLog,
                _disk_changed: bool,
            ) -> None:
                row = effects.row_for_effect(context.effect_id)
                if row is None or row.outbox_id != context.outbox_id:
                    raise PermissionError("model execution outbox row missing")
                if row.status != "claimed":
                    raise PermissionError("outbox row is not claimed")

            try:
                self._append_many(
                    context.tenant_id,
                    entries,
                    state=tenant_state,
                    semantic_check=ensure_claim_is_current,
                )
            except Exception as exc:
                self._error_count += 1
                self._last_error = exc.__class__.__name__
                raise
            tenant_state.effects.record_receipt(context.outbox_id, receipt)
            tenant_state.effects.mark_merged(context.effect_id)
            self._release_claim_lock(tenant_state, context.outbox_id)
            self.maybe_compact(tenant_state)
            result = EchoRecordResult(
                ok=True,
                mode="on",
                record_types=_FINISH_RECORD_TYPES,
            )
        if context.product_id is not None and context.session_id is not None:
            self._maybe_retire_partitions(
                tenant_id=context.tenant_id,
                product_id=context.product_id,
                protected_session_id=context.session_id,
            )
        return result

    def resolve_manual_review(
        self,
        *,
        tenant_id: str,
        effect_id: str,
        action: Literal["cancel", "override", "resolved"],
        operator: str,
        reason: str,
    ) -> EchoRecordResult:
        with self._state_lock, self._partition_lifecycle_lock(exclusive=False):
            return self._resolve_manual_review_locked(
                tenant_id=tenant_id,
                effect_id=effect_id,
                action=action,
                operator=operator,
                reason=reason,
            )

    def list_manual_reviews(
        self,
        *,
        tenant_id: str,
        product_id: str | None = None,
    ) -> tuple[ManualReviewRow, ...]:
        """Return verified owner reviews, optionally from one exact product root."""
        with self._state_lock, self._partition_lifecycle_lock(exclusive=False):
            reviews: list[ManualReviewRow] = []
            if product_id is None:
                states = self._known_journal_states(recover_claims=False)
                if self._tenant_scan_truncated:
                    raise EchoUnavailableError(
                        "Echo manual review projection is truncated and incomplete"
                    )
            else:
                if product_id not in {"js-agent", "js-work"}:
                    raise ValueError("manual review product is unsupported")
                states = (
                    self._tenant_state_locked(tenant_id),
                    *self._artifact_projection_states(
                        tenant_id=tenant_id,
                        product_id=product_id,
                    ),
                )
            for tenant_state in states:

                def semantic_sync(
                    records: tuple[Any, ...],
                    disk_changed: bool,
                    current_state: _TenantJournalState = tenant_state,
                ) -> None:
                    if disk_changed:
                        current_state.effects.replace_from(
                            _replay_state_effects(current_state, records)
                        )

                _disk_changed, archive_report = (
                    tenant_state.journal.refresh_and_verify_required_archives(
                        semantic_sync=semantic_sync
                    )
                )
                if not archive_report.ok:
                    raise ValueError(
                        "invalid required journal archive: "
                        + ",".join(archive_report.errors)
                    )
                self._recover_abandoned_claims(tenant_state, refresh=False)
                bindings = _verified_effect_bindings(tenant_state.journal.records)
                reviews.extend(
                    ManualReviewRow(
                        effect_id=row.seal.effect_id,
                        outbox_id=row.outbox_id,
                        tenant_id=row.seal.tenant_id,
                        action_kind=row.seal.action_kind,
                        status="manual_review",
                        session_id=(
                            bindings[row.seal.effect_id].session_id
                            if row.seal.effect_id in bindings
                            else None
                        ),
                        run_id=(
                            bindings[row.seal.effect_id].run_id
                            if row.seal.effect_id in bindings
                            else None
                        ),
                        product_id=(
                            bindings[row.seal.effect_id].product_id
                            if row.seal.effect_id in bindings
                            else None
                        ),
                        effect_digest=(
                            stable_hash(
                                {
                                    "domain": "js-agent:manual-review:v1",
                                    "effect_id": row.seal.effect_id,
                                    "outbox_id": row.outbox_id,
                                    "tenant_id": row.seal.tenant_id,
                                    "session_id": bindings[row.seal.effect_id].session_id,
                                    "run_id": bindings[row.seal.effect_id].run_id,
                                }
                            )
                            if row.seal.effect_id in bindings
                            else None
                        ),
                        args_digest=(
                            bindings[row.seal.effect_id].args_digest
                            if row.seal.effect_id in bindings
                            else None
                        ),
                    )
                    for row in tenant_state.effects.manual_review_rows()
                    if row.seal.tenant_id == tenant_id
                    and (
                        product_id is None
                        or row.seal.effect_id not in bindings
                        or bindings[row.seal.effect_id].product_id == product_id
                    )
                )
            return tuple(
                sorted(reviews, key=lambda review: (review.effect_id, review.outbox_id))
            )

    def project_verified_artifacts(
        self,
        *,
        tenant_id: str,
        mode: AppMode,
        workspace: str | None,
        limit: int = 50,
        visibility: ArtifactVisibilityQueryV1 | None = None,
    ) -> VerifiedArtifactProjectionV1:
        """Verify and merge active/archive and retired-catalog artifact history."""
        if type(mode) is not AppMode:
            raise TypeError("artifact receipt mode must be AppMode")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("artifact receipt limit must be between 1 and 100")
        if mode is AppMode.PERSONAL and workspace is not None:
            raise ValueError("personal artifact receipt workspace must be null")
        if mode is AppMode.WORK and not isinstance(workspace, str):
            raise ValueError("work artifact receipt workspace is required")
        if visibility is not None and type(visibility) is not ArtifactVisibilityQueryV1:
            raise TypeError("artifact visibility must be ArtifactVisibilityQueryV1")

        with self._state_lock, self._partition_lifecycle_lock(exclusive=False):
            product_id = "js-work" if mode is AppMode.WORK else "js-agent"
            verified: list[VerifiedArtifactReceiptV1] = []
            for tenant_state in self._artifact_projection_states(
                tenant_id=tenant_id,
                product_id=product_id,
            ):

                def semantic_sync(
                    records: tuple[Any, ...],
                    disk_changed: bool,
                    current_state: _TenantJournalState = tenant_state,
                ) -> None:
                    if disk_changed:
                        current_state.effects.replace_from(
                            _replay_state_effects(current_state, records)
                        )

                _disk_changed, archive_report = (
                    tenant_state.journal.refresh_and_verify_required_archives(
                        semantic_sync=semantic_sync
                    )
                )
                if not archive_report.ok:
                    raise EchoUnavailableError(
                        "Echo required archive verification failed: "
                        + ",".join(archive_report.errors)
                    )
                logical_records = tenant_state.journal.verified_logical_records()
                logical_effects = _replay_effects(logical_records)
                bindings = _verified_effect_bindings(logical_records)
                for active_receipt in logical_effects.receipt_snapshot():
                    if active_receipt.tenant_id != tenant_id or active_receipt.status != "ok":
                        continue
                    if not active_receipt.artifact_refs:
                        continue
                    binding = bindings.get(active_receipt.effect_id)
                    if binding is None:
                        raise ValueError("artifact receipt has no verified effect binding")
                    refs = tuple(
                        ref
                        for ref in active_receipt.artifact_refs
                        if ref.mode is mode and ref.workspace == workspace
                        and (
                            visibility is None
                            or artifact_ref_visible(ref, visibility)
                        )
                    )
                    if not refs:
                        continue
                    for ref in refs:
                        _validate_artifact_ref_binding(ref, binding)
                    _append_bounded_artifact_receipt(
                        verified,
                        VerifiedArtifactReceiptV1(
                            receipt_id=active_receipt.receipt_id,
                            effect_id=active_receipt.effect_id,
                            tenant_id=active_receipt.tenant_id,
                            run_id=binding.run_id,
                            artifact_refs=refs,
                        ),
                        limit=limit,
                    )
            checkpoint = self._artifact_retention_checkpoint_locked(
                tenant_id=tenant_id,
                product_id=product_id,
            )
            coverage_complete = True
            if checkpoint is not None:
                if checkpoint.get("pending_retirement") is not None:
                    raise EchoUnavailableError("Echo artifact retirement is incomplete")
                coverage_complete = retired_history_complete(checkpoint)
                retired_groups: dict[
                    tuple[str, str, str, str],
                    list[tuple[int, ArtifactRefV1]],
                ] = {}
                for entry in retired_artifact_entries(checkpoint):
                    binding = entry["binding"]
                    ref = ArtifactRefV1.from_dict(entry["artifact_ref"])
                    if (
                        entry["tenant_id"] != tenant_id
                        or binding["tenant_id"] != tenant_id
                        or binding["product_id"] != product_id
                        or ref.owner != tenant_id
                        or ref.mode is not mode
                    ):
                        raise ValueError("retired artifact owner or product binding mismatch")
                    if ref.workspace != workspace:
                        continue
                    if visibility is not None and not artifact_ref_visible(ref, visibility):
                        continue
                    key = (
                        str(entry["receipt_id"]),
                        str(entry["effect_id"]),
                        str(entry["tenant_id"]),
                        str(entry["run_id"]),
                    )
                    retired_groups.setdefault(key, []).append((entry["ordinal"], ref))
                for key, indexed_refs in retired_groups.items():
                    indexed_refs.sort(key=lambda item: item[0])
                    _append_bounded_artifact_receipt(
                        verified,
                        VerifiedArtifactReceiptV1(
                            receipt_id=key[0],
                            effect_id=key[1],
                            tenant_id=key[2],
                            run_id=key[3],
                            artifact_refs=tuple(ref for _ordinal, ref in indexed_refs),
                        ),
                        limit=limit,
                    )
            receipts = tuple(
                sorted(
                    verified,
                    key=lambda item: (item.run_id, item.receipt_id, item.effect_id),
                )[:limit]
            )
            projected_refs = [
                ref for current_receipt in receipts for ref in current_receipt.artifact_refs
            ]
            projected_refs.sort(
                key=lambda ref: (
                    ref.created_by_run,
                    ref.session,
                    ref.digest,
                    ref.uri,
                )
            )
            return VerifiedArtifactProjectionV1(
                receipts=receipts,
                refs=tuple(projected_refs[:limit]),
                retired_history_complete=coverage_complete,
            )

    def list_verified_artifact_receipts(
        self,
        *,
        tenant_id: str,
        mode: AppMode,
        workspace: str | None,
        limit: int = 50,
    ) -> tuple[VerifiedArtifactReceiptV1, ...]:
        """Compatibility wrapper that never represents incomplete history as complete."""
        projection = self.project_verified_artifacts(
            tenant_id=tenant_id,
            mode=mode,
            workspace=workspace,
            limit=limit,
        )
        if not projection.retired_history_complete:
            raise EchoUnavailableError("retired artifact history is incomplete")
        return projection.receipts

    def list_verified_artifact_refs(
        self,
        *,
        tenant_id: str,
        mode: AppMode,
        workspace: str | None,
        limit: int = 50,
    ) -> tuple[ArtifactRefV1, ...]:
        """Return the exact R1 refs consumed by the AppShell Artifact Center."""
        projection = self.project_verified_artifacts(
            tenant_id=tenant_id,
            mode=mode,
            workspace=workspace,
            limit=limit,
        )
        if not projection.retired_history_complete:
            raise EchoUnavailableError("retired artifact history is incomplete")
        return projection.refs

    def _artifact_retention_checkpoint_locked(
        self,
        *,
        tenant_id: str,
        product_id: str,
    ) -> dict[str, Any] | None:
        product_slug, owner_slug, _unused_session = _scope_partition_slugs(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id="artifact-projection",
        )
        owner_root = self._root / "partitions" / product_slug / owner_slug
        checkpoint_path = owner_root / "retired-sessions.json"
        if not checkpoint_path.exists():
            return None
        retention_key = _read_strict_key(owner_root / "retention.key")
        return load_and_verify_checkpoint(
            checkpoint_path,
            mac_key=retention_key,
            product_partition=product_slug,
            owner_partition=owner_slug,
            max_receipts=self._ledger_config.max_retired_session_receipts_per_owner,
            max_artifact_refs=self._ledger_config.max_retired_artifact_refs_per_owner,
            max_artifact_bytes=(
                self._ledger_config.max_retired_artifact_bytes_per_owner
            ),
        )

    def _resolve_manual_review_locked(
        self,
        *,
        tenant_id: str,
        effect_id: str,
        action: Literal["cancel", "override", "resolved"],
        operator: str,
        reason: str,
    ) -> EchoRecordResult:
        matches: list[tuple[_TenantJournalState, OutboxRow]] = []
        for candidate_state in self._known_journal_states(recover_claims=False):
            self._verify_execution_boundary(candidate_state)
            self._recover_abandoned_claims(candidate_state, refresh=False)
            candidate_row = candidate_state.effects.row_for_effect(effect_id)
            if candidate_row is not None and candidate_row.seal.tenant_id == tenant_id:
                matches.append((candidate_state, candidate_row))
        if not matches:
            raise KeyError(f"manual review effect not found: {effect_id}")
        if len(matches) != 1:
            raise EchoUnavailableError("manual review effect exists in multiple partitions")
        tenant_state, row = matches[0]
        if row.status != "manual_review":
            raise PermissionError("effect is no longer awaiting manual review")
        payload = {
            "outbox_id": row.outbox_id,
            "effect_id": effect_id,
            "action": action,
            "operator": operator,
            "reason": reason,
            "resolved_at": datetime.now(UTC).isoformat(),
        }
        entries: tuple[JournalEntry, ...] = (
            {
                "record_type": "manual_review_resolution",
                "tenant_id": tenant_id,
                "run_id": "manual-review",
                "payload": payload,
            },
            {
                "record_type": "merge",
                "tenant_id": tenant_id,
                "run_id": "manual-review",
                "payload": {"effect_id": effect_id, "status": action},
            },
        )

        def ensure_review_is_current(
            effects: DurableEffectLog,
            _disk_changed: bool,
        ) -> None:
            current = effects.row_for_effect(effect_id)
            if current is None or current.outbox_id != row.outbox_id:
                raise KeyError(f"manual review effect not found: {effect_id}")
            if current.status != "manual_review":
                raise PermissionError("effect is no longer awaiting manual review")

        self._append_many(
            tenant_id,
            entries,
            state=tenant_state,
            semantic_check=ensure_review_is_current,
        )
        tenant_state.effects.mark_merged(effect_id)
        return EchoRecordResult(
            ok=True,
            mode="on",
            record_types=_MANUAL_REVIEW_RESOLUTION_RECORD_TYPES,
        )

    def _append_many(
        self,
        tenant_id: str,
        entries: tuple[JournalEntry, ...],
        *,
        state: _TenantJournalState | None = None,
        semantic_check: Callable[[DurableEffectLog, bool], None] | None = None,
    ) -> None:
        with self._state_lock:
            selected_state = state or self._tenant_state(tenant_id)

            def semantic_sync(records: tuple[Any, ...], disk_changed: bool) -> None:
                if disk_changed:
                    selected_state.effects.replace_from(
                        _replay_state_effects(selected_state, records)
                    )
                if semantic_check is not None:
                    semantic_check(selected_state.effects, disk_changed)

            start = perf_counter()
            try:
                selected_state.journal.append_many(entries, semantic_sync=semantic_sync)
                self._remember_health_verified(selected_state)
            except OSError as exc:
                raise EchoUnavailableError(f"Echo journal unavailable: {exc}") from exc
            duration_ms = (perf_counter() - start) * 1000
            self._journal_append_durations_ms.append(duration_ms)
            if len(self._journal_append_durations_ms) > 256:
                self._journal_append_durations_ms = self._journal_append_durations_ms[-256:]

    def _tenant_state(self, tenant_id: str) -> _TenantJournalState:
        with self._state_lock:
            return self._tenant_state_locked(tenant_id)

    def _partition_state(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
    ) -> _TenantJournalState:
        with self._state_lock:
            return self._partition_state_locked(
                tenant_id=tenant_id,
                product_id=product_id,
                session_id=session_id,
            )

    def _partition_state_locked(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
    ) -> _TenantJournalState:
        product_slug, owner_slug, session_slug = _scope_partition_slugs(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
        )
        cache_key = f"partitions/{product_slug}/{owner_slug}/{session_slug}"
        state = self._tenant_states.get(cache_key)
        if state is None:
            partition_root = (
                self._root / "partitions" / product_slug / owner_slug / session_slug
            )
            _ensure_private_directory(partition_root)
            try:
                state = _load_journal_state(partition_root)
                self._anchor_partition_to_retention_checkpoint(
                    state,
                    tenant_id=tenant_id,
                    product_slug=product_slug,
                    owner_slug=owner_slug,
                    session_slug=session_slug,
                )
            except (OSError, ValueError, PartitionRetentionError) as exc:
                raise EchoUnavailableError(f"Echo journal unavailable: {exc}") from exc
            self._recover_abandoned_claims(state)
            self._remember_health_verified(state)
            self._tenant_states[cache_key] = state
            self._trim_tenant_states()
        else:
            self._tenant_states.move_to_end(cache_key)
        return state

    def _state_for_turn_context(self, context: EchoTurnContext) -> _TenantJournalState:
        if context.product_id is None or context.session_id is None:
            return self._tenant_state(context.tenant_id)
        return self._partition_state(
            tenant_id=context.tenant_id,
            product_id=context.product_id,
            session_id=context.session_id,
        )

    def _tenant_state_locked(self, tenant_id: str) -> _TenantJournalState:
        slug = _tenant_slug(tenant_id)
        if slug is None:
            return self._default_state
        state = self._tenant_states.get(slug)
        if state is None:
            _ensure_private_directory(self._root / "tenants")
            try:
                state = _load_journal_state(self._root / "tenants" / slug)
            except OSError as exc:
                raise EchoUnavailableError(f"Echo journal unavailable: {exc}") from exc
            self._recover_abandoned_claims(state)
            self._remember_health_verified(state)
            self._tenant_states[slug] = state
            self._trim_tenant_states()
        else:
            self._tenant_states.move_to_end(slug)
        return state

    def _known_journal_states(
        self,
        *,
        recover_claims: bool = True,
        strict: bool = False,
    ) -> tuple[_TenantJournalState, ...]:
        tenants_root = self._root / "tenants"
        partitions_root = self._root / "partitions"
        self._tenant_scan_truncated = False
        self._skipped_tenant_count = 0
        candidates: list[tuple[str, Path]] = []
        if tenants_root.exists():
            _ensure_private_directory(tenants_root)
            candidates.extend(
                (child.name, child)
                for child in sorted(tenants_root.iterdir(), key=lambda path: path.name)
                if child.is_dir() and not child.is_symlink()
            )
        if partitions_root.exists():
            _ensure_private_directory(partitions_root)
            candidates.extend(
                (
                    str(partition.relative_to(self._root)),
                    partition,
                )
                for partition in sorted(partitions_root.glob("*/*/*"))
                if partition.is_dir()
                and not partition.is_symlink()
                and (partition / "chat.jsonl").is_file()
            )
        for index, (cache_key, journal_root) in enumerate(candidates):
            if (
                len(self._tenant_states) >= _MAX_TENANT_STATES
                and cache_key not in self._tenant_states
            ):
                self._tenant_scan_truncated = True
                self._skipped_tenant_count = sum(
                    1
                    for remaining_key, _remaining_path in candidates[index:]
                    if remaining_key not in self._tenant_states
                )
                if strict:
                    raise EchoUnavailableError(
                        "Echo journal projection exceeded verified state capacity"
                    )
                break
            if cache_key not in self._tenant_states:
                try:
                    state = _load_journal_state(journal_root)
                    self._remember_health_verified(state)
                    self._tenant_states[cache_key] = state
                    self._trim_tenant_states()
                except Exception as exc:  # noqa: BLE001 - health should report, not raise
                    self._last_error = exc.__class__.__name__
                    if strict:
                        raise EchoUnavailableError(
                            "Echo journal unavailable during verified projection"
                        ) from exc
        states = (self._default_state, *self._tenant_states.values())
        if recover_claims:
            for state in states:
                self._recover_abandoned_claims(state)
        return states

    def _artifact_projection_states(
        self,
        *,
        tenant_id: str,
        product_id: str,
    ) -> tuple[_TenantJournalState, ...]:
        """Load only the exact owner/product partitions eligible for Artifact Center."""
        product_slug, owner_slug, _unused_session = _scope_partition_slugs(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id="artifact-projection",
        )
        owner_root = self._root / "partitions" / product_slug / owner_slug
        if not owner_root.exists():
            return ()
        if owner_root.is_symlink() or not owner_root.is_dir():
            raise EchoUnavailableError("Echo artifact owner partition is invalid")
        try:
            session_roots = _session_partition_roots(owner_root)
        except (OSError, ValueError, PartitionRetentionError) as exc:
            raise EchoUnavailableError("Echo artifact session partitions are invalid") from exc
        if len(session_roots) > self._ledger_config.max_session_partitions_per_owner:
            raise EchoUnavailableError("Echo artifact session partition capacity is invalid")

        states: list[_TenantJournalState] = []
        for session_root in sorted(session_roots, key=lambda path: path.name):
            journal_path = session_root / "chat.jsonl"
            if not journal_path.is_file() or journal_path.is_symlink():
                raise EchoUnavailableError("Echo artifact journal partition is invalid")
            cache_key = str(session_root.relative_to(self._root))
            state = self._tenant_states.get(cache_key)
            if state is None:
                try:
                    state = _load_journal_state(session_root)
                except Exception as exc:  # noqa: BLE001 - exact authority must fail closed
                    raise EchoUnavailableError(
                        "Echo journal unavailable during verified projection"
                    ) from exc
                self._remember_health_verified(state)
                self._tenant_states[cache_key] = state
                self._trim_tenant_states()
            else:
                self._tenant_states.move_to_end(cache_key)
            states.append(state)
        return tuple(states)

    def _trim_tenant_states(self) -> None:
        while len(self._tenant_states) > _MAX_TENANT_STATES:
            _slug, evicted = self._tenant_states.popitem(last=False)
            self._health_verify_cache.pop(str(evicted.journal_path), None)

    @contextmanager
    def _partition_lifecycle_lock(self, *, exclusive: bool) -> Iterator[None]:
        """Coordinate partition use and retirement across local processes."""
        path = self._root / "partitions.guard"
        existed = path.exists() or path.is_symlink()
        try:
            fd = _open_private_lock_file(path)
        except (OSError, ValueError) as exc:
            raise EchoUnavailableError(f"Echo partition guard unavailable: {exc}") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            if not existed:
                _fsync_directory(path.parent)
            yield
        finally:
            self._unlock_claim_fd(fd)

    @contextmanager
    def _partition_operation_guard(
        self,
        *,
        tenant_id: str,
        product_id: str,
        session_id: str,
    ) -> Iterator[None]:
        """Use a shared guard, or serialize creation when a new partition is needed."""
        product_slug, owner_slug, session_slug = _scope_partition_slugs(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=session_id,
        )
        owner_root = self._root / "partitions" / product_slug / owner_slug
        partition_root = owner_root / session_slug
        with self._partition_lifecycle_lock(exclusive=False):
            if partition_root.is_symlink():
                raise EchoUnavailableError("Echo session partition must not be a symlink")
            if partition_root.exists():
                yield
                return

        with self._partition_lifecycle_lock(exclusive=True):
            if partition_root.is_symlink():
                raise EchoUnavailableError("Echo session partition must not be a symlink")
            if not partition_root.exists():
                try:
                    remaining = self._retire_owner_partitions_locked(
                        owner_root,
                        target_count=(
                            self._ledger_config.max_session_partitions_per_owner - 1
                        ),
                        protected_session_slug=session_slug,
                    )
                except (OSError, ValueError, PartitionRetentionError) as exc:
                    self._partition_retention_error = f"{exc.__class__.__name__}: {exc}"
                    raise EchoUnavailableError(
                        f"Echo session partition retirement failed: {exc}"
                    ) from exc
                if remaining >= self._ledger_config.max_session_partitions_per_owner:
                    raise EchoUnavailableError(
                        "owner session partition capacity reached; "
                        "resolve open or manual-review effects"
                    )
            yield

    @contextmanager
    def _turn_partition_operation_guard(
        self,
        context: EchoTurnContext | EchoToolEffectContext,
    ) -> Iterator[None]:
        product_id = context.product_id
        session_id = context.session_id
        if product_id is None or session_id is None:
            yield
            return
        with self._partition_operation_guard(
            tenant_id=context.tenant_id,
            product_id=product_id,
            session_id=session_id,
        ):
            yield

    def _maybe_retire_partitions(
        self,
        *,
        tenant_id: str,
        product_id: str,
        protected_session_id: str,
    ) -> None:
        product_slug, owner_slug, session_slug = _scope_partition_slugs(
            tenant_id=tenant_id,
            product_id=product_id,
            session_id=protected_session_id,
        )
        owner_root = self._root / "partitions" / product_slug / owner_slug
        try:
            with self._state_lock, self._partition_lifecycle_lock(exclusive=True):
                self._retire_owner_partitions_locked(
                    owner_root,
                    target_count=self._ledger_config.max_session_partitions_per_owner,
                    protected_session_slug=session_slug,
                )
        except Exception as exc:  # noqa: BLE001 - terminal turn remains durable
            self._partition_retention_error = f"{exc.__class__.__name__}: {exc}"

    def _anchor_partition_to_retention_checkpoint(
        self,
        state: _TenantJournalState,
        *,
        tenant_id: str,
        product_slug: str,
        owner_slug: str,
        session_slug: str,
    ) -> None:
        if state.journal.record_count != 0:
            return
        owner_root = state.journal_path.parent.parent
        checkpoint_path = owner_root / "retired-sessions.json"
        if not checkpoint_path.exists():
            return
        retention_key = _read_strict_key(owner_root / "retention.key")
        checkpoint = load_and_verify_checkpoint(
            checkpoint_path,
            mac_key=retention_key,
            product_partition=product_slug,
            owner_partition=owner_slug,
            max_receipts=self._ledger_config.max_retired_session_receipts_per_owner,
            max_artifact_refs=self._ledger_config.max_retired_artifact_refs_per_owner,
            max_artifact_bytes=(
                self._ledger_config.max_retired_artifact_bytes_per_owner
            ),
        )
        prior_session_receipt = next(
            (
                receipt["receipt_hash"]
                for receipt in reversed(checkpoint["receipts"])
                if receipt["session_partition"] == session_slug
            ),
            None,
        )
        state.journal.append(
            record_type="partition_resume",
            tenant_id=tenant_id,
            run_id="retention-resume",
            payload={
                "schema_version": "echo-session-retention-resume-v1",
                "product_partition": product_slug,
                "owner_partition": owner_slug,
                "session_partition": session_slug,
                "retired_count": checkpoint["retired_count"],
                "retention_checkpoint_tip": checkpoint["tip"],
                "prior_session_receipt_hash": prior_session_receipt,
            },
        )

    def _recover_interrupted_partition_retirements(self) -> None:
        partitions_root = self._root / "partitions"
        if not partitions_root.exists():
            return
        try:
            with self._partition_lifecycle_lock(exclusive=True):
                for owner_root in sorted(partitions_root.glob("*/*")):
                    if owner_root.is_symlink() or not owner_root.is_dir():
                        raise PartitionRetentionError(
                            "partition owner root is not a private directory"
                        )
                    try:
                        self._finish_interrupted_retirement_locked(owner_root)
                    except (OSError, ValueError, PartitionRetentionError) as exc:
                        retiring_root = owner_root / ".retiring"
                        if retiring_root.exists() or retiring_root.is_symlink():
                            raise
                        self._partition_retention_error = (
                            f"{exc.__class__.__name__}: {exc}"
                        )
        except (OSError, ValueError, PartitionRetentionError) as exc:
            raise EchoUnavailableError(
                f"Echo partition retirement recovery failed: {exc}"
            ) from exc

    def _retire_owner_partitions_locked(
        self,
        owner_root: Path,
        *,
        target_count: int,
        protected_session_slug: str,
    ) -> int:
        if target_count < 0:
            raise ValueError("partition retention target must be non-negative")
        if not owner_root.exists():
            return 0
        if owner_root.is_symlink() or not owner_root.is_dir():
            raise PartitionRetentionError("partition owner root is invalid")
        self._finish_interrupted_retirement_locked(owner_root)
        session_roots = _session_partition_roots(owner_root)
        while len(session_roots) > target_count:
            candidates = sorted(
                (
                    root
                    for root in session_roots
                    if root.name != protected_session_slug
                ),
                key=_partition_retirement_order,
            )
            retired = False
            capacity_error: PartitionArtifactCapacityError | None = None
            for candidate in candidates:
                try:
                    if self._retire_partition_locked(owner_root, candidate):
                        retired = True
                        break
                except PartitionArtifactCapacityError as exc:
                    capacity_error = exc
                    continue
            if not retired:
                if capacity_error is not None:
                    raise capacity_error
                break
            session_roots = _session_partition_roots(owner_root)
        return len(session_roots)

    def _retire_partition_locked(self, owner_root: Path, session_root: Path) -> bool:
        cache_key = str(session_root.relative_to(self._root))
        cached = self._tenant_states.pop(cache_key, None)
        if cached is not None:
            self._health_verify_cache.pop(str(cached.journal_path), None)
        journal_path = session_root / "chat.jsonl"
        resolved_journal = str(journal_path.resolve())
        if any(path == resolved_journal for path, _effect in self._claim_lock_fds):
            return False
        if any(path == resolved_journal for path, _effect in self._reservation_lock_fds):
            return False
        try:
            state = _load_journal_state(session_root)
            _disk_changed, archive_report = state.journal.refresh_and_verify_required_archives()
            if not archive_report.ok:
                raise PartitionRetentionError(
                    "session partition archive verification failed: "
                    + ",".join(archive_report.errors)
                )
            journal_report = verify_file(state.journal_path, mac_key=state.journal_key)
            if not journal_report.ok:
                raise PartitionRetentionError(
                    "session partition journal verification failed: "
                    + ",".join(journal_report.errors)
                )
            if state.effects.open_count() != 0 or _contains_nonretirable_terminal(state.journal):
                return False
            self._prune_claim_lock_files(state)
            logical_records = state.journal.verified_logical_records()
            artifact_receipts = _retired_artifact_receipt_inputs(logical_records)
            evidence = _partition_source_evidence(session_root)
            records = state.journal.records
            tip_hash = records[-1].record_hash if records else RETENTION_GENESIS_HASH
            product_slug = owner_root.parent.name
            owner_slug = owner_root.name
            retention_key = _load_or_create_key(owner_root / "retention.key")
            _checkpoint, receipt = stage_retirement(
                owner_root / "retired-sessions.json",
                mac_key=retention_key,
                product_partition=product_slug,
                owner_partition=owner_slug,
                max_receipts=(
                    self._ledger_config.max_retired_session_receipts_per_owner
                ),
                max_artifact_refs=(
                    self._ledger_config.max_retired_artifact_refs_per_owner
                ),
                max_artifact_bytes=(
                    self._ledger_config.max_retired_artifact_bytes_per_owner
                ),
                receipt=RetentionReceiptInput(
                    session_partition=session_root.name,
                    source_files_hash=evidence.source_files_hash,
                    source_file_count=evidence.source_file_count,
                    source_total_bytes=evidence.source_total_bytes,
                    journal_record_count=len(records),
                    journal_tip_hash=tip_hash,
                    retired_at=datetime.now(UTC).isoformat(),
                ),
                artifact_receipts=artifact_receipts,
            )
            if receipt["source_files_hash"] != evidence.source_files_hash:
                raise PartitionRetentionError("retirement receipt source hash mismatch")
            retiring_root = owner_root / ".retiring"
            if retiring_root.exists() or retiring_root.is_symlink():
                raise PartitionRetentionError("interrupted retirement was not recovered")
            os.rename(session_root, retiring_root)
            _fsync_directory(owner_root)
            self._finish_interrupted_retirement_locked(owner_root)
            self._partition_retention_error = None
            return True
        except PartitionArtifactCapacityError as exc:
            self._partition_retention_error = f"{exc.__class__.__name__}: {exc}"
            raise
        except (OSError, ValueError, PartitionRetentionError) as exc:
            self._partition_retention_error = f"{exc.__class__.__name__}: {exc}"
            raise PartitionRetentionError(
                f"session partition retirement failed: {exc}"
            ) from exc

    def _finish_interrupted_retirement_locked(self, owner_root: Path) -> None:
        retiring_root = owner_root / ".retiring"
        checkpoint_path = owner_root / "retired-sessions.json"
        key_path = owner_root / "retention.key"
        if not checkpoint_path.exists():
            if retiring_root.exists() or retiring_root.is_symlink():
                raise PartitionRetentionError("retiring partition has no durable checkpoint")
            return
        if not checkpoint_path.is_file() or checkpoint_path.is_symlink() or not key_path.is_file():
            raise PartitionRetentionError("retirement checkpoint is not a private file")
        retention_key = _read_strict_key(key_path)
        checkpoint = load_and_verify_checkpoint(
            checkpoint_path,
            mac_key=retention_key,
            product_partition=owner_root.parent.name,
            owner_partition=owner_root.name,
            max_receipts=self._ledger_config.max_retired_session_receipts_per_owner,
            max_artifact_refs=self._ledger_config.max_retired_artifact_refs_per_owner,
            max_artifact_bytes=(
                self._ledger_config.max_retired_artifact_bytes_per_owner
            ),
        )
        pending = checkpoint.get("pending_retirement")
        if pending is not None:
            if retiring_root.is_symlink():
                raise PartitionRetentionError("retiring partition is not a private directory")
            active_root = owner_root / pending["session_partition"]
            if active_root.is_symlink():
                raise PartitionRetentionError("pending retirement source is not private")
            if active_root.exists() and retiring_root.exists():
                raise PartitionRetentionError("pending retirement has conflicting sources")
            if active_root.exists():
                evidence = _partition_source_evidence(active_root)
                if evidence.source_files_hash != pending["source_files_hash"]:
                    raise PartitionRetentionError(
                        "pending retirement source no longer matches its receipt"
                    )
                os.rename(active_root, retiring_root)
                _fsync_directory(owner_root)
            if retiring_root.exists():
                if not retiring_root.is_dir():
                    raise PartitionRetentionError(
                        "retiring partition is not a private directory"
                    )
                evidence = _partition_source_evidence(retiring_root)
                if evidence.source_files_hash != pending["source_files_hash"]:
                    raise PartitionRetentionError(
                        "retiring partition no longer matches its receipt"
                    )
                _remove_retired_partition(retiring_root)
                _fsync_directory(owner_root)
            clear_pending_retirement(
                checkpoint_path,
                mac_key=retention_key,
                product_partition=owner_root.parent.name,
                owner_partition=owner_root.name,
                max_receipts=(
                    self._ledger_config.max_retired_session_receipts_per_owner
                ),
                max_artifact_refs=(
                    self._ledger_config.max_retired_artifact_refs_per_owner
                ),
                max_artifact_bytes=(
                    self._ledger_config.max_retired_artifact_bytes_per_owner
                ),
                session_partition=pending["session_partition"],
                source_files_hash=pending["source_files_hash"],
            )
            return
        if not retiring_root.exists() and not retiring_root.is_symlink():
            return
        if retiring_root.is_symlink() or not retiring_root.is_dir():
            raise PartitionRetentionError("retiring partition is not a private directory")
        receipts = checkpoint["receipts"]
        if not receipts:
            raise PartitionRetentionError("retiring partition receipt is missing")
        evidence = _partition_source_evidence(retiring_root)
        latest = receipts[-1]
        if latest["source_files_hash"] != evidence.source_files_hash:
            raise PartitionRetentionError("retiring partition no longer matches its receipt")
        _remove_retired_partition(retiring_root)
        _fsync_directory(owner_root)

    def _retention_health_locked(self) -> tuple[int, int, str | None]:
        partitions_root = self._root / "partitions"
        if not partitions_root.exists():
            return 0, 0, None
        active_count = 0
        retired_count = 0
        try:
            for owner_root in sorted(partitions_root.glob("*/*")):
                if owner_root.is_symlink() or not owner_root.is_dir():
                    raise PartitionRetentionError("partition owner root is invalid")
                if (owner_root / ".retiring").exists() or (
                    owner_root / ".retiring"
                ).is_symlink():
                    raise PartitionRetentionError("partition retirement is incomplete")
                owner_sessions = _session_partition_roots(owner_root)
                active_count += len(owner_sessions)
                if len(owner_sessions) > self._ledger_config.max_session_partitions_per_owner:
                    raise PartitionRetentionError("active session partition limit exceeded")
                checkpoint_path = owner_root / "retired-sessions.json"
                if not checkpoint_path.exists():
                    continue
                retention_key = _read_strict_key(owner_root / "retention.key")
                checkpoint = load_and_verify_checkpoint(
                    checkpoint_path,
                    mac_key=retention_key,
                    product_partition=owner_root.parent.name,
                    owner_partition=owner_root.name,
                    max_receipts=(
                        self._ledger_config.max_retired_session_receipts_per_owner
                    ),
                    max_artifact_refs=(
                        self._ledger_config.max_retired_artifact_refs_per_owner
                    ),
                    max_artifact_bytes=(
                        self._ledger_config.max_retired_artifact_bytes_per_owner
                    ),
                )
                if checkpoint.get("pending_retirement") is not None:
                    raise PartitionRetentionError("partition retirement is incomplete")
                retired_count += int(checkpoint["retired_count"])
        except (OSError, ValueError, PartitionRetentionError) as exc:
            return active_count, retired_count, f"{exc.__class__.__name__}: {exc}"
        return active_count, retired_count, self._partition_retention_error

    def _health_verify_report(
        self,
        state: _TenantJournalState,
        *,
        max_verify_age_seconds: float,
    ) -> VerificationReport:
        cache_key = str(state.journal_path)
        now_ns = monotonic_ns()
        max_age_ns = int(max(0.0, max_verify_age_seconds) * 1_000_000_000)
        cached = self._health_verify_cache.get(cache_key)
        fingerprint = _journal_fingerprint(state.journal_path)
        if cached is not None and max_age_ns > 0:
            cached_at_ns, cached_fingerprint, cached_report = cached
            if cached_fingerprint == fingerprint and now_ns - cached_at_ns <= max_age_ns:
                return cached_report
        report = verify_file(state.journal_path, mac_key=state.journal_key)
        self._health_verify_cache[cache_key] = (now_ns, fingerprint, report)
        return report

    def _remember_health_verified(self, state: _TenantJournalState) -> None:
        self._health_verify_cache[str(state.journal_path)] = (
            monotonic_ns(),
            _journal_fingerprint(state.journal_path),
            VerificationReport(ok=True, errors=()),
        )


def _load_or_create_key(path: Path) -> bytes:
    _ensure_private_directory(path.parent)
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = _open_private_lock_file(lock_path)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    tmp_path: Path | None = None
    try:
        if path.exists() or path.is_symlink():
            return _read_strict_key(path)
        key = secrets.token_bytes(32)
        tmp_path = path.with_name(
            f".{path.name}.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(8)}.tmp"
        )
        key_fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchmod(key_fd, 0o600)
        with os.fdopen(key_fd, "w", encoding="utf-8") as handle:
            handle.write(key.hex())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        tmp_path = None
        os.chmod(path, 0o600)
        _fsync_directory(path.parent)
        return _read_strict_key(path)
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass
        EchoSafetyService._unlock_claim_fd(lock_fd)


def _open_private_lock_file(path: Path) -> int:
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ValueError(f"invalid lock file {path}: expected a private regular file")
        os.fchmod(fd, 0o600)
        return fd
    except Exception:
        os.close(fd)
        raise


def _read_strict_key(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"invalid MAC key {path}: expected a 32-byte key file") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"invalid MAC key {path}: expected a 32-byte regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise ValueError(f"invalid MAC key {path}: key file changed while opening")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            encoded = handle.read().strip()
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ValueError(f"invalid MAC key {path}: key file changed while reading")
    finally:
        if fd >= 0:
            os.close(fd)
    try:
        key = bytes.fromhex(encoded)
    except ValueError as exc:
        raise ValueError(f"invalid MAC key {path}: expected 32-byte hexadecimal data") from exc
    if len(encoded) != 64 or len(key) != 32:
        raise ValueError(f"invalid MAC key {path}: expected 32-byte hexadecimal data")
    if stat.S_IMODE(current.st_mode) != 0o600:
        raise ValueError(f"invalid MAC key {path}: expected mode 0600")
    return key


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _journal_fingerprint(path: Path) -> tuple[int, int, int, int, int]:
    metadata = path.stat()
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _load_journal_state(root: Path) -> _TenantJournalState:
    _ensure_private_directory(root)
    journal_path = root / "chat.jsonl"
    journal_key = _load_or_create_key(root / "journal.key")
    permit_key = _load_or_create_key(root / "permit.key")
    journal = FileEchoLedger(journal_path, mac_key=journal_key)
    effects = _replay_effects(
        journal.records,
        completed_effect_lookup=journal.contains_archived_effect,
    )
    return _TenantJournalState(
        journal_path=journal_path,
        journal_key=journal_key,
        permit_key=permit_key,
        journal=journal,
        effects=effects,
    )


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def _mode_for_product(product_id: str) -> AppMode:
    if product_id == "js-agent":
        return AppMode.PERSONAL
    if product_id == "js-work":
        return AppMode.WORK
    raise ValueError("artifact receipt product is not a supported AppShell mode")


def _validate_artifact_ref_binding(
    ref: ArtifactRefV1,
    binding: _VerifiedEffectBinding,
) -> None:
    expected_mode = _mode_for_product(binding.product_id)
    if ref.owner != binding.tenant_id:
        raise ValueError("artifact ref owner does not match effect binding")
    if ref.mode is not expected_mode:
        raise ValueError("artifact ref mode does not match effect binding")
    if ref.workspace != binding.workspace:
        raise ValueError("artifact ref workspace does not match effect binding")
    if ref.session != binding.session_id:
        raise ValueError("artifact ref session does not match effect binding")
    if ref.created_by_run != binding.run_id:
        raise ValueError("artifact ref created_by_run does not match effect binding")
    if ArtifactRefV1.from_dict(ref.to_dict()) != ref:
        raise ValueError("artifact ref does not survive strict R1 round-trip")


def _validate_artifact_refs_for_context(
    context: EchoToolEffectContext,
    *,
    status: Literal["ok", "failed", "cancelled"],
    artifact_refs: tuple[ArtifactRefV1, ...],
) -> None:
    if type(artifact_refs) is not tuple:
        raise TypeError("artifact_refs must be an immutable tuple")
    if artifact_refs and status != "ok":
        raise ValueError("artifact refs require a successful tool receipt")
    if len(artifact_refs) > _MAX_TOOL_ARTIFACT_REFS:
        raise ValueError("artifact refs count limit exceeded")
    if any(type(ref) is not ArtifactRefV1 for ref in artifact_refs):
        raise TypeError("artifact_refs must contain exact ArtifactRefV1 values")
    serialized_bytes = len(
        canonical_json([ref.to_dict() for ref in artifact_refs]).encode("utf-8")
    )
    if serialized_bytes > _MAX_TOOL_ARTIFACT_BYTES:
        raise ValueError("artifact refs byte limit exceeded")
    binding = _VerifiedEffectBinding(
        tenant_id=context.tenant_id,
        product_id=context.product_id,
        session_id=context.session_id,
        run_id=context.run_id,
        effect_id=context.effect_id,
        outbox_id=context.outbox_id,
        args_digest=context.args_hash,
        workspace=context.workspace,
    )
    for ref in artifact_refs:
        _validate_artifact_ref_binding(ref, binding)


def _verified_effect_binding_from_outbox(record: Any) -> _VerifiedEffectBinding | None:
    payload = getattr(record, "payload", None)
    if not isinstance(payload, dict):
        return None
    contract = payload.get("execution_contract")
    seal_payload = payload.get("seal")
    if not isinstance(contract, dict) or not isinstance(seal_payload, dict):
        return None
    state_mapping = contract.get("state_mapping")
    effect = contract.get("effect")
    outbox = contract.get("outbox")
    if not isinstance(state_mapping, dict) or not isinstance(effect, dict):
        return None
    if not isinstance(outbox, dict):
        return None
    tenant_id = getattr(record, "tenant_id", None)
    run_id = getattr(record, "run_id", None)
    product_id = state_mapping.get("product_id")
    session_id = contract.get("session_id")
    effect_id = payload.get("effect_id")
    outbox_id = payload.get("outbox_id")
    args_digest = payload.get("sealed_input_ref")
    workspace = state_mapping.get("workspace")
    if workspace is not None and not isinstance(workspace, str):
        return None
    if state_mapping.get("partition_bound") is not True:
        return None
    required = (
        tenant_id,
        run_id,
        product_id,
        session_id,
        effect_id,
        outbox_id,
        args_digest,
    )
    if not all(isinstance(value, str) and value for value in required):
        return None
    args_digest_text = cast("str", args_digest)
    if (
        contract.get("tenant_id") != tenant_id
        or contract.get("run_id") != run_id
        or effect.get("effect_id") != effect_id
        or outbox.get("outbox_id") != outbox_id
        or outbox.get("effect_id") != effect_id
        or seal_payload.get("effect_id") != effect_id
        or _SHA256_REF_RE.fullmatch(args_digest_text) is None
    ):
        return None
    return _VerifiedEffectBinding(
        tenant_id=cast("str", tenant_id),
        product_id=cast("str", product_id),
        session_id=cast("str", session_id),
        run_id=cast("str", run_id),
        effect_id=cast("str", effect_id),
        outbox_id=cast("str", outbox_id),
        args_digest=args_digest_text,
        workspace=workspace,
    )


def _verified_effect_bindings(
    records: Sequence[Any],
) -> dict[str, _VerifiedEffectBinding]:
    bindings: dict[str, _VerifiedEffectBinding] = {}
    for record in records:
        if getattr(record, "record_type", "") != "outbox":
            continue
        binding = _verified_effect_binding_from_outbox(record)
        if binding is None:
            continue
        prior = bindings.get(binding.effect_id)
        if prior is not None and prior != binding:
            raise ValueError("effect has conflicting verified outbox bindings")
        bindings[binding.effect_id] = binding
    return bindings


def _retired_artifact_receipt_inputs(
    records: Sequence[Any],
) -> tuple[RetiredArtifactReceiptInput, ...]:
    effects = _replay_effects(records)
    bindings = _verified_effect_bindings(records)
    inputs: list[RetiredArtifactReceiptInput] = []
    for receipt in effects.receipt_snapshot():
        if receipt.status != "ok" or not receipt.artifact_refs:
            continue
        binding = bindings.get(receipt.effect_id)
        if binding is None:
            raise ValueError("retired artifact receipt has no verified binding")
        if receipt.tenant_id != binding.tenant_id:
            raise ValueError("retired artifact receipt tenant binding mismatch")
        for ref in receipt.artifact_refs:
            _validate_artifact_ref_binding(ref, binding)
        inputs.append(
            RetiredArtifactReceiptInput(
                receipt_id=receipt.receipt_id,
                effect_id=receipt.effect_id,
                tenant_id=receipt.tenant_id,
                run_id=binding.run_id,
                product_id=binding.product_id,
                workspace=binding.workspace,
                session_id=binding.session_id,
                artifact_refs=receipt.artifact_refs,
            )
        )
    return tuple(
        sorted(
            inputs,
            key=lambda item: (item.run_id, item.receipt_id, item.effect_id),
        )
    )


def _append_bounded_artifact_receipt(
    receipts: list[VerifiedArtifactReceiptV1],
    candidate: VerifiedArtifactReceiptV1,
    *,
    limit: int,
) -> None:
    identity = (
        candidate.receipt_id,
        candidate.effect_id,
        candidate.tenant_id,
        candidate.run_id,
    )
    for prior in receipts:
        prior_identity = (
            prior.receipt_id,
            prior.effect_id,
            prior.tenant_id,
            prior.run_id,
        )
        if prior_identity != identity:
            continue
        if prior != candidate:
            raise ValueError("artifact receipt has conflicting active and retired data")
        return
    receipts.append(candidate)
    receipts.sort(key=lambda item: (item.run_id, item.receipt_id, item.effect_id))
    del receipts[limit:]


def _replay_state_effects(
    state: _TenantJournalState,
    records: Sequence[Any],
) -> DurableEffectLog:
    return _replay_effects(
        records,
        completed_effect_lookup=state.journal.contains_archived_effect,
    )


def _stable_json_for_hash(value: object) -> str:
    """Canonical JSON for hash computation (sorted keys, no whitespace)."""
    import json as _json

    return _json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _replay_effects(
    records: Sequence[Any],
    *,
    completed_effect_lookup: Callable[[str], bool] | None = None,
) -> DurableEffectLog:
    # Replays can run while FileEchoLedger owns its process/file lock.  Delay
    # archive lookups until replay finishes so loading an outbox row cannot
    # recursively acquire the same journal lock through contains_archived_effect.
    effects = DurableEffectLog()
    bindings = _verified_effect_bindings(records)
    snapshot_seen = False
    known_effects: set[str] = set()
    for index, record in enumerate(records):
        payload = getattr(record, "payload", {})
        if not isinstance(payload, dict):
            raise ValueError(f"semantic journal error at record {index}: payload is not an object")
        record_type = getattr(record, "record_type", "")
        try:
            if record_type == "snapshot_anchor":
                snapshot_seen = True
                tombstones = payload.get("effect_tombstones", [])
                if not isinstance(tombstones, list) or not all(
                    isinstance(effect_id, str) and effect_id for effect_id in tombstones
                ):
                    raise ValueError("snapshot effect tombstones are invalid")
                effects.load_completed_effects(tuple(tombstones))
            elif record_type == "outbox":
                seal_payload = payload.get("seal")
                if not isinstance(seal_payload, dict):
                    raise ValueError("outbox seal is missing")
                seal = _seal_from_payload(seal_payload)
                outbox_id = str(payload["outbox_id"])
                if str(payload.get("effect_id", "")) != seal.effect_id:
                    raise ValueError("outbox effect does not match seal")
                effects.load_outbox(
                    OutboxRow(
                        outbox_id=outbox_id,
                        seal=seal,
                        sealed_input_ref=str(payload.get("sealed_input_ref", "")),
                        status="queued",
                    ),
                    supersedes_snapshot_tombstone=snapshot_seen,
                )
                known_effects.add(seal.effect_id)
            elif record_type == "outbox_claimed":
                outbox_id = str(payload["outbox_id"])
                try:
                    row_status = effects.status(outbox_id)
                except KeyError as exc:
                    raise ValueError("orphan outbox_claimed") from exc
                if row_status != "queued":
                    raise ValueError("outbox_claimed does not follow queued outbox")
                effects.mark_claimed(outbox_id)
            elif record_type == "outbox_manual_review":
                outbox_id = str(payload["outbox_id"])
                try:
                    effects.status(outbox_id)
                except KeyError as exc:
                    raise ValueError("orphan outbox_manual_review") from exc
                effects.mark_manual_review(outbox_id)
            elif record_type == "receipt":
                outbox_id = str(payload["outbox_id"])
                try:
                    row_status = effects.status(outbox_id)
                except KeyError as exc:
                    raise ValueError("orphan receipt") from exc
                if row_status != "claimed":
                    raise ValueError("receipt does not follow a durable claim")
                effect_id = str(payload["effect_id"])
                row = effects.row_for_effect(effect_id)
                if row is None or row.outbox_id != outbox_id:
                    raise ValueError("receipt effect does not match outbox")
                replay_class = str(payload.get("replay_class") or row.seal.replay_class)
                if replay_class not in {"idempotent", "probe_required", "non_idempotent"}:
                    raise ValueError("receipt replay class is invalid")
                raw_artifact_refs = payload.get("artifact_refs", [])
                if not isinstance(raw_artifact_refs, list):
                    raise ValueError("receipt artifact_refs must be a list")
                artifact_refs = tuple(
                    ArtifactRefV1.from_dict(item) for item in raw_artifact_refs
                )
                receipt_status = _receipt_status(str(payload.get("status", "")))
                if artifact_refs and receipt_status != "ok":
                    raise ValueError("failed receipt cannot contain artifact refs")
                if artifact_refs:
                    binding = bindings.get(effect_id)
                    if binding is None:
                        raise ValueError("artifact receipt has no verified effect binding")
                    if getattr(record, "tenant_id", "") != binding.tenant_id:
                        raise ValueError("artifact receipt tenant does not match effect binding")
                    if getattr(record, "run_id", "") != binding.run_id:
                        raise ValueError("artifact receipt run does not match effect binding")
                    for ref in artifact_refs:
                        _validate_artifact_ref_binding(ref, binding)
                effects.record_receipt(
                    outbox_id,
                    EffectReceipt(
                        receipt_id=f"receipt:{effect_id}",
                        effect_id=effect_id,
                        tenant_id=str(getattr(record, "tenant_id", "")),
                        status=receipt_status,
                        output_ref=str(payload.get("output_ref", "")),
                        replay_class=replay_class,
                        artifact_refs=artifact_refs,
                    ),
                )
            elif record_type in {"merge", "manual_review_resolution"}:
                effect_id = str(payload["effect_id"])
                if effect_id not in known_effects:
                    raise ValueError(f"orphan {record_type}")
                effects.mark_merged(effect_id)
        except (KeyError, PermissionError, TypeError, ValueError) as exc:
            if isinstance(exc, ValueError) and str(exc).startswith("semantic journal error"):
                raise
            raise ValueError(
                f"semantic journal error at record {index} ({record_type}): {exc}"
            ) from exc
    effects.set_completed_effect_lookup(completed_effect_lookup)
    return effects


def _receipt_status(status: str) -> Literal["ok", "failed", "cancelled"]:
    if status == "completed" or status == "ok":
        return "ok"
    if status == "cancelled":
        return "cancelled"
    return "failed"


def _seal_to_payload(seal: PermitSeal) -> dict[str, Any]:
    return {
        "seal_id": seal.seal_id,
        "effect_id": seal.effect_id,
        "tenant_id": seal.tenant_id,
        "action_kind": seal.action_kind,
        "policy_decision_id": seal.policy_decision_id,
        "granted_scopes": list(seal.granted_scopes),
        "key_epoch": seal.key_epoch,
        "journal_seq": seal.journal_seq,
        "deadline_ms": seal.deadline_ms,
        "replay_class": seal.replay_class,
        "mac": seal.mac.hex(),
    }


def _seal_from_payload(payload: dict[str, Any]) -> PermitSeal:
    return PermitSeal(
        seal_id=str(payload["seal_id"]),
        effect_id=str(payload["effect_id"]),
        tenant_id=str(payload["tenant_id"]),
        action_kind=str(payload["action_kind"]),
        policy_decision_id=str(payload["policy_decision_id"]),
        granted_scopes=tuple(str(scope) for scope in payload.get("granted_scopes", ())),
        key_epoch=str(payload["key_epoch"]),
        journal_seq=int(payload["journal_seq"]),
        deadline_ms=int(payload["deadline_ms"]),
        replay_class=str(payload["replay_class"]),
        mac=bytes.fromhex(str(payload["mac"])),
    )


def _scope_permit_payload(call_metadata: dict[str, Any] | None) -> dict[str, Any]:
    if not call_metadata:
        return {}
    permit = call_metadata.get("scope_permit")
    if not isinstance(permit, dict):
        return {}
    return {"scope_permit": permit}


def _scope_permit_to_payload(permit: Any) -> dict[str, Any]:
    return {
        "architecture": str(getattr(permit, "architecture", "")),
        "owner_id": str(getattr(permit, "owner_id", "")),
        "session_id": str(getattr(permit, "session_id", "")),
        "run_id": str(getattr(permit, "run_id", "")),
        "provider_id": str(getattr(permit, "provider_id", "")),
        "model_id": str(getattr(permit, "model_id", "")),
        "granted_scopes": list(getattr(permit, "granted_scopes", ())),
        "messages_hash": str(getattr(permit, "messages_hash", "")),
        "tools_schema_hash": str(getattr(permit, "tools_schema_hash", "")),
        "attachments_hash": str(getattr(permit, "attachments_hash", "")),
        "request_hash": str(getattr(permit, "request_hash", "")),
        "mac": getattr(permit, "mac", b"").hex(),
    }


def _model_call_payload(
    *,
    product_id: str,
    session_id: str,
    run_id: str,
    provider_id: str,
    model_id: str,
    messages: Sequence[Any],
    tools_schema: Sequence[dict[str, Any]] | None,
    attachments_manifest: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "product_id": product_id,
        "session_id": session_id,
        "run_id": run_id,
        "provider_id": provider_id,
        "model_id": model_id,
        "messages": [_message_to_payload(message) for message in messages],
        "tools_schema": list(tools_schema or ()),
        "attachments_manifest": [dict(item) for item in attachments_manifest],
    }


def _normalize_attachment_manifest(
    attachments_manifest: Sequence[dict[str, Any]] | None,
) -> tuple[dict[str, Any], ...]:
    entries = tuple(attachments_manifest or ())
    if len(entries) > 32:
        raise ValueError("model attachment manifest exceeds 32 entries")
    normalized: list[dict[str, Any]] = []
    total_size = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("model attachment manifest entry must be an object")
        name = entry.get("name")
        size = entry.get("size")
        digest = entry.get("sha256")
        media_type = entry.get("media_type")
        if (
            not isinstance(name, str)
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or "\x00" in name
            or len(name) > 255
        ):
            raise ValueError("model attachment manifest name is invalid")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError("model attachment manifest size is invalid")
        if not isinstance(digest, str) or _SHA256_REF_RE.fullmatch(digest) is None:
            raise ValueError("model attachment manifest sha256 is invalid")
        if not isinstance(media_type, str) or not media_type or len(media_type) > 255:
            raise ValueError("model attachment manifest media_type is invalid")
        total_size += size
        if total_size > 100 * 1024 * 1024:
            raise ValueError("model attachment manifest exceeds 100 MiB")
        normalized.append(
            {
                "name": name,
                "size": size,
                "sha256": digest,
                "media_type": media_type,
            }
        )
    return tuple(normalized)


def _model_call_secret_scan_text(
    messages: Sequence[Any],
    tools_schema: Sequence[dict[str, Any]] | None,
) -> str:
    parts: list[str] = []
    for message in messages:
        parts.extend(_strings_from_value(getattr(message, "content", "")))
        parts.extend(_strings_from_value(getattr(message, "tool_calls", None)))
        parts.extend(_strings_from_value(getattr(message, "reasoning_content", None)))
    parts.extend(_strings_from_value(list(tools_schema or ())))
    return "\n".join(part for part in parts if part)


def _message_to_payload(message: Any) -> dict[str, Any]:
    return {
        "role": str(getattr(message, "role", "")),
        "content": getattr(message, "content", None),
        "name": getattr(message, "name", None),
        "tool_call_id": getattr(message, "tool_call_id", None),
        "tool_calls": getattr(message, "tool_calls", None),
        "reasoning_content": getattr(message, "reasoning_content", None),
    }


def _strings_from_value(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value, *_decoded_data_url_strings(value)]
    if isinstance(value, dict):
        dict_parts: list[str] = []
        for item in value.values():
            dict_parts.extend(_strings_from_value(item))
        return dict_parts
    if isinstance(value, (list, tuple)):
        list_parts: list[str] = []
        for item in value:
            list_parts.extend(_strings_from_value(item))
        return list_parts
    return [str(value)]


def _decoded_data_url_strings(value: str) -> list[str]:
    decoded: list[str] = []
    for match in _DATA_URL_BASE64_RE.finditer(value):
        raw = match.group("data")
        try:
            payload = base64.b64decode(raw, validate=False)
        except (binascii.Error, ValueError):
            continue
        text = payload.decode("utf-8", errors="ignore")
        if text:
            decoded.append(text)
    return decoded


def _contains_image_data_url(messages: Sequence[Any]) -> bool:
    for message in messages:
        if any(
            _is_image_data_url(value)
            for value in _strings_from_value(getattr(message, "content", ""))
        ):
            return True
    return False


def _is_image_data_url(value: str) -> bool:
    return value.strip().lower().startswith("data:image/")


def _tool_scopes(tools_schema: Sequence[dict[str, Any]] | None) -> tuple[str, ...]:
    scopes: list[str] = []
    for schema in tools_schema or ():
        name = ""
        function = schema.get("function")
        if isinstance(function, dict):
            name = str(function.get("name") or "")
        if not name:
            name = str(schema.get("name") or "")
        safe_name = re.sub(r"[^A-Za-z0-9_.:-]+", "_", name.strip())
        if safe_name:
            scopes.append(f"tool:{safe_name}")
    return tuple(dict.fromkeys(scopes))


def _tenant_slug(tenant_id: str) -> str | None:
    tenant = tenant_id.strip()
    if tenant in {"", "local"}:
        return None
    return stable_hash({"tenant_id": tenant}).removeprefix("sha256:")[:32]


def _scope_partition_slugs(
    *,
    tenant_id: str,
    product_id: str,
    session_id: str,
) -> tuple[str, str, str]:
    values = {
        "owner": tenant_id.strip(),
        "product": product_id.strip(),
        "session": session_id.strip(),
    }
    for name, value in values.items():
        if not value:
            raise ValueError(f"Echo partition {name}_id must not be empty")
    return (
        "product_"
        + stable_hash({"product_id": values["product"]}).removeprefix("sha256:")[:32],
        "owner_"
        + stable_hash({"owner_id": values["owner"]}).removeprefix("sha256:")[:32],
        "session_"
        + stable_hash({"session_id": values["session"]}).removeprefix("sha256:")[:32],
    )


def _session_partition_roots(owner_root: Path) -> list[Path]:
    roots: list[Path] = []
    for candidate in owner_root.glob("session_*"):
        if candidate.is_symlink() or not candidate.is_dir():
            raise PartitionRetentionError("session partition root is invalid")
        if re.fullmatch(r"session_[0-9a-f]{32}", candidate.name) is None:
            raise PartitionRetentionError("session partition name is invalid")
        roots.append(candidate)
    return roots


def _partition_retirement_order(path: Path) -> tuple[int, str]:
    journal = path / "chat.jsonl"
    try:
        modified_ns = journal.stat().st_mtime_ns
    except FileNotFoundError:
        modified_ns = path.stat().st_mtime_ns
    return modified_ns, path.name


def _partition_source_evidence(root: Path) -> _PartitionSourceEvidence:
    if root.is_symlink() or not root.is_dir():
        raise PartitionRetentionError("session partition is not a private directory")
    entries: list[dict[str, int | str]] = []
    for candidate in sorted(root.rglob("*"), key=lambda path: str(path.relative_to(root))):
        relative = candidate.relative_to(root)
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise PartitionRetentionError("session partition contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            if relative != Path("claims"):
                raise PartitionRetentionError(
                    f"session partition contains unexpected directory: {relative}"
                )
            continue
        if not stat.S_ISREG(metadata.st_mode) or not _is_retirable_partition_file(relative):
            raise PartitionRetentionError(
                f"session partition contains unexpected file: {relative}"
            )
        digest, size = _hash_regular_file_no_follow(candidate)
        entries.append(
            {
                "path": relative.as_posix(),
                "sha256": digest,
                "size": size,
            }
        )
    return _PartitionSourceEvidence(
        source_files_hash=stable_hash({"files": entries}),
        source_file_count=len(entries),
        source_total_bytes=sum(int(entry["size"]) for entry in entries),
    )


def _hash_regular_file_no_follow(path: Path) -> tuple[str, int]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise PartitionRetentionError("session partition file is not regular")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise PartitionRetentionError("session partition file changed before hashing")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        after = path.lstat()
        if after.st_nlink != 1 or (after.st_dev, after.st_ino, after.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            raise PartitionRetentionError("session partition file changed while hashing")
        return digest.hexdigest(), size
    finally:
        if fd >= 0:
            os.close(fd)


def _remove_retired_partition(root: Path) -> None:
    """Unlink only verified internal entries without ever following a symlink."""
    _partition_source_evidence(root)
    entries = sorted(
        root.rglob("*"),
        key=lambda path: (len(path.relative_to(root).parts), path.as_posix()),
        reverse=True,
    )
    for candidate in entries:
        relative = candidate.relative_to(root)
        metadata = candidate.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            if relative != Path("claims"):
                raise PartitionRetentionError("retired partition directory changed")
            candidate.rmdir()
            continue
        if not stat.S_ISREG(metadata.st_mode) or not _is_retirable_partition_file(relative):
            raise PartitionRetentionError("retired partition entry changed")
        candidate.unlink()
    root.rmdir()


def _is_retirable_partition_file(relative: Path) -> bool:
    value = relative.as_posix()
    if value == "chat.jsonl.corrupt":
        return False
    if relative.parent == Path("claims"):
        return relative.name.endswith(".lock")
    if relative.parent != Path("."):
        return False
    if value in {
        "chat.jsonl",
        "chat.jsonl.lock",
        "claims.guard",
        "journal.key",
        "journal.key.lock",
        "permit.key",
        "permit.key.lock",
        "chat.jsonl.archive.sqlite3",
        "chat.jsonl.archive.sqlite3-wal",
        "chat.jsonl.archive.sqlite3-shm",
        "chat.jsonl.archive.sqlite3-journal",
    }:
        return True
    return bool(re.fullmatch(r"chat\.jsonl\.archive\.[0-9]+\.gz", value))


def _contains_nonretirable_terminal(journal: FileEchoLedger) -> bool:
    for record in journal.records:
        if record.record_type not in {"receipt", "merge"}:
            continue
        status = str(record.payload.get("status") or "").strip().lower()
        if status in {"unknown", "manual_review"}:
            return True
    return False


def _contains_secret(text: str) -> bool:
    return contains_secret_shape(text)


def _p95(values: list[float]) -> float | None:
    if not values:
        return None
    if len(values) < 2:
        return values[0]
    return quantiles(values, n=20, method="inclusive")[18]


def _agent_chat_intent(
    intent: EffectIntent,
    *,
    provider_id: str,
    model_id: str,
) -> EffectIntent:
    return EffectIntent.build(
        tenant_id=intent.tenant_id,
        run_id=intent.run_id,
        task_path=intent.task_path,
        action_kind="model.js_agent_chat",
        resource=f"model:{provider_id}/{model_id}",
        scopes=("model:invoke",),
        input_hash=intent.input_hash,
        replay_class="probe_required",
        risk="medium",
    )


def _validate_tool_effect_binding(
    *,
    tenant_id: str,
    product_id: str,
    session_id: str,
    run_id: str,
    tool_name: str,
    tool_call_id: str,
    args_hash: str,
    lease_id: str,
    replay_class: ReplayClass,
) -> None:
    fields = {
        "tenant_id": tenant_id,
        "product_id": product_id,
        "session_id": session_id,
        "run_id": run_id,
        "tool_name": tool_name,
        "tool_call_id": tool_call_id,
        "lease_id": lease_id,
    }
    for name, value in fields.items():
        if not value:
            raise ValueError(f"tool effect {name} must not be empty")
    if _SHA256_REF_RE.fullmatch(args_hash) is None:
        raise ValueError("tool effect args_hash must be a sha256 reference")
    if replay_class not in {"idempotent", "probe_required", "non_idempotent"}:
        raise ValueError("invalid tool effect replay_class")


def _tool_effect_intent(
    *,
    tenant_id: str,
    product_id: str,
    session_id: str,
    run_id: str,
    tool_name: str,
    tool_call_id: str,
    args_hash: str,
    lease_id: str,
    replay_class: ReplayClass,
) -> EffectIntent:
    _validate_tool_effect_binding(
        tenant_id=tenant_id,
        product_id=product_id,
        session_id=session_id,
        run_id=run_id,
        tool_name=tool_name,
        tool_call_id=tool_call_id,
        args_hash=args_hash,
        lease_id=lease_id,
        replay_class=replay_class,
    )
    safe_tool_name = re.sub(r"[^A-Za-z0-9_.:-]+", "_", tool_name.strip())
    if not safe_tool_name:
        raise ValueError("tool effect tool_name is invalid")
    return EffectIntent.build(
        tenant_id=tenant_id,
        run_id=run_id,
        task_path=("tool", product_id, session_id, tool_name, tool_call_id)
        + ((lease_id,) if replay_class == "idempotent" else ()),
        action_kind=f"tool.{safe_tool_name}",
        resource=f"tool:{safe_tool_name}",
        scopes=(f"tool:{safe_tool_name}",),
        input_hash=args_hash,
        replay_class=replay_class,
        risk="low" if replay_class == "idempotent" else "high",
    )


def _tool_effect_policy_decision(
    intent: EffectIntent,
    *,
    tenant_id: str,
    product_id: str,
    session_id: str,
    tool_name: str,
    lease_id: str,
    mac_key: bytes,
) -> PolicyDecisionRecord:
    tool_scope = intent.scopes[0]
    return evaluate_policy(
        intent,
        IdentityContext(actor_id=tenant_id, tenant_id=tenant_id, roles=("local-user",)),
        PolicyBundle(
            bundle_id="echo-ledger-tool-effect",
            rules=(
                PolicyRule(
                    rule_id="allow-exact-tool",
                    effect="allow",
                    scopes=(tool_scope,),
                    action_prefix="tool.",
                ),
            ),
        ),
        resource_snapshot_hash=stable_hash(
            {
                "product_id": product_id,
                "session_id": session_id,
                "tool_name": tool_name,
                "lease_id": lease_id,
            }
        ),
        mac_key=mac_key,
    )
