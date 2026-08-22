from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from js.echo.ledger._hashing import stable_hash
from js.echo.ledger.policy import PermitSeal
from js.echo.mode_contract import ArtifactRefV1

ReceiptStatus = Literal["ok", "failed", "cancelled"]
ProbeStatus = Literal["found", "missing", "unknown"]
OutboxStatus = Literal["queued", "claimed", "receipted", "merged", "manual_review"]


@dataclass(frozen=True)
class EffectReceipt:
    receipt_id: str
    effect_id: str
    tenant_id: str
    status: ReceiptStatus
    output_ref: str
    replay_class: str
    artifact_refs: tuple[ArtifactRefV1, ...] = ()


@dataclass(frozen=True)
class ProbeResult:
    effect_id: str
    status: ProbeStatus
    receipt: EffectReceipt | None


class EffectAdapter(Protocol):
    def execute(self, effect_id: str, sealed_input_ref: str) -> EffectReceipt: ...

    def probe(self, effect_id: str) -> ProbeResult: ...

    def cancel(self, effect_id: str) -> str: ...


@dataclass(frozen=True)
class OutboxRow:
    outbox_id: str
    seal: PermitSeal
    sealed_input_ref: str
    status: OutboxStatus


@dataclass(frozen=True)
class RecoveryPlan:
    dispatch_effect_ids: tuple[str, ...]
    merge_effect_ids: tuple[str, ...]
    manual_review_effect_ids: tuple[str, ...]


class DurableEffectLog:
    def __init__(
        self,
        *,
        completed_effect_lookup: Callable[[str], bool] | None = None,
    ) -> None:
        self._outbox: dict[str, OutboxRow] = {}
        self._effect_outbox: dict[str, str] = {}
        self._receipts: dict[str, EffectReceipt] = {}
        self._merged: set[str] = set()
        self._completed_effects: set[str] = set()
        self._completed_effect_lookup = completed_effect_lookup

    def _is_completed(self, effect_id: str) -> bool:
        if effect_id in self._completed_effects:
            return True
        lookup = self._completed_effect_lookup
        return lookup(effect_id) if lookup is not None else False

    def set_completed_effect_lookup(
        self,
        lookup: Callable[[str], bool] | None,
    ) -> None:
        """Install the archive lookup after lock-scoped journal replay completes."""
        self._completed_effect_lookup = lookup

    def enqueue(self, *, seal: PermitSeal | None, sealed_input_ref: str) -> OutboxRow:
        if seal is None:
            raise PermissionError("outbox enqueue requires a PermitSeal")
        if seal.effect_id in self._effect_outbox or self._is_completed(seal.effect_id):
            raise PermissionError("effect already has a durable outbox row")
        outbox_id = "out_" + stable_hash(
            {"effect_id": seal.effect_id, "input": sealed_input_ref, "seal_id": seal.seal_id}
        ).removeprefix("sha256:")[:32]
        if outbox_id in self._outbox:
            raise PermissionError("outbox row already exists")
        row = OutboxRow(
            outbox_id=outbox_id,
            seal=seal,
            sealed_input_ref=sealed_input_ref,
            status="queued",
        )
        self._outbox[outbox_id] = row
        self._effect_outbox[seal.effect_id] = outbox_id
        return row

    def load_outbox(
        self,
        row: OutboxRow,
        *,
        supersedes_snapshot_tombstone: bool = False,
    ) -> None:
        """Restore one outbox row from the verified journal."""
        if row.outbox_id in self._outbox or row.seal.effect_id in self._effect_outbox:
            raise PermissionError("effect already has a durable outbox row")
        if self._is_completed(row.seal.effect_id):
            if not supersedes_snapshot_tombstone:
                raise PermissionError("effect already has a durable outbox row")
            self._completed_effects.discard(row.seal.effect_id)
        self._outbox[row.outbox_id] = row
        self._effect_outbox[row.seal.effect_id] = row.outbox_id
        if row.status in {"merged"}:
            self._merged.add(row.seal.effect_id)
            self._completed_effects.add(row.seal.effect_id)

    def discard_queued(self, outbox_id: str) -> None:
        """Rollback an enqueue whose durable journal append failed."""
        row = self._outbox.get(outbox_id)
        if row is None:
            return
        if row.status != "queued":
            return
        self._outbox.pop(outbox_id, None)
        self._effect_outbox.pop(row.seal.effect_id, None)

    def replace_from(self, other: DurableEffectLog) -> None:
        """Replace this process snapshot with a journal-replayed snapshot."""
        self._outbox = dict(other._outbox)
        self._effect_outbox = dict(other._effect_outbox)
        self._receipts = dict(other._receipts)
        self._merged = set(other._merged)
        self._completed_effects = set(other._completed_effects)
        self._completed_effect_lookup = other._completed_effect_lookup

    def load_completed_effects(self, effect_ids: tuple[str, ...]) -> None:
        """Restore exact non-idempotent effect tombstones from a snapshot anchor."""
        self._completed_effects.update(effect_id for effect_id in effect_ids if effect_id)

    def completed_effect_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._completed_effects))

    def clear_completed_effects(self) -> int:
        """Release local tombstones after the caller durably archives them."""
        removed = len(self._completed_effects)
        self._completed_effects.clear()
        return removed

    def row_for_effect(self, effect_id: str) -> OutboxRow | None:
        outbox_id = self._effect_outbox.get(effect_id)
        return self._outbox.get(outbox_id) if outbox_id is not None else None

    def mark_claimed(self, outbox_id: str) -> OutboxRow:
        row = self._outbox[outbox_id]
        if row.status not in {"queued", "claimed"}:
            raise PermissionError("outbox row is not claimable")
        claimed = OutboxRow(
            outbox_id=row.outbox_id,
            seal=row.seal,
            sealed_input_ref=row.sealed_input_ref,
            status="claimed",
        )
        self._outbox[outbox_id] = claimed
        return claimed

    def claim(self, outbox_id: str) -> OutboxRow:
        if self._outbox[outbox_id].status != "queued":
            raise PermissionError("outbox row is not queued")
        return self.mark_claimed(outbox_id)

    def dispatch(self, outbox_id: str, adapter: EffectAdapter) -> EffectReceipt:
        row = self._outbox[outbox_id]
        if row.status == "queued":
            row = self.claim(outbox_id)
        elif row.status != "claimed":
            raise PermissionError("outbox row is not dispatchable")
        receipt = adapter.execute(row.seal.effect_id, row.sealed_input_ref)
        return self.record_receipt(outbox_id, receipt)

    def record_receipt(self, outbox_id: str, receipt: EffectReceipt) -> EffectReceipt:
        row = self._outbox[outbox_id]
        if row.status != "claimed":
            raise PermissionError("outbox row is not claimed")
        if receipt.effect_id != row.seal.effect_id:
            raise ValueError("receipt effect_id does not match outbox row")
        if receipt.tenant_id != row.seal.tenant_id:
            raise ValueError("receipt tenant_id does not match outbox row")
        self._receipts[receipt.effect_id] = receipt
        self._outbox[outbox_id] = OutboxRow(
            outbox_id=row.outbox_id,
            seal=row.seal,
            sealed_input_ref=row.sealed_input_ref,
            status="receipted",
        )
        return receipt

    def status(self, outbox_id: str) -> OutboxStatus:
        return self._outbox[outbox_id].status

    def pending_count(self) -> int:
        return sum(1 for row in self._outbox.values() if row.status == "queued")

    def claimed_count(self) -> int:
        return sum(1 for row in self._outbox.values() if row.status == "claimed")

    def claimed_rows(self) -> tuple[OutboxRow, ...]:
        return tuple(row for row in self._outbox.values() if row.status == "claimed")

    def receipted_count(self) -> int:
        return sum(1 for row in self._outbox.values() if row.status == "receipted")

    def receipted_rows(self) -> tuple[OutboxRow, ...]:
        return tuple(row for row in self._outbox.values() if row.status == "receipted")

    def receipt_snapshot(self) -> tuple[EffectReceipt, ...]:
        """Return an immutable snapshot of replay-verified receipts."""
        return tuple(
            sorted(
                self._receipts.values(),
                key=lambda receipt: (receipt.receipt_id, receipt.effect_id),
            )
        )

    def manual_review_count(self) -> int:
        return sum(1 for row in self._outbox.values() if row.status == "manual_review")

    def manual_review_rows(self) -> tuple[OutboxRow, ...]:
        return tuple(row for row in self._outbox.values() if row.status == "manual_review")

    def open_count(self) -> int:
        return sum(1 for row in self._outbox.values() if row.status != "merged")

    def mark_manual_review(self, outbox_id: str) -> OutboxRow:
        row = self._outbox[outbox_id]
        if row.status not in {"queued", "claimed", "manual_review"}:
            raise PermissionError("outbox row is not reviewable")
        review = OutboxRow(
            outbox_id=row.outbox_id,
            seal=row.seal,
            sealed_input_ref=row.sealed_input_ref,
            status="manual_review",
        )
        self._outbox[outbox_id] = review
        return review

    def mark_merged(self, effect_id: str) -> None:
        self._merged.add(effect_id)
        self._completed_effects.add(effect_id)
        outbox_id = self._effect_outbox.get(effect_id)
        if outbox_id is None:
            return
        row = self._outbox[outbox_id]
        self._outbox[outbox_id] = OutboxRow(
            outbox_id=row.outbox_id,
            seal=row.seal,
            sealed_input_ref=row.sealed_input_ref,
            status="merged",
        )

    def remove_merged(self) -> int:
        removed = 0
        for outbox_id, row in tuple(self._outbox.items()):
            if row.status == "merged":
                self._outbox.pop(outbox_id, None)
                self._effect_outbox.pop(row.seal.effect_id, None)
                self._receipts.pop(row.seal.effect_id, None)
                self._merged.discard(row.seal.effect_id)
                if not (
                    row.seal.action_kind.startswith("tool.")
                    and row.seal.replay_class in {"probe_required", "non_idempotent"}
                ):
                    self._completed_effects.discard(row.seal.effect_id)
                removed += 1
        return removed

    def recover(self, adapters: dict[str, EffectAdapter]) -> RecoveryPlan:
        dispatch: list[str] = []
        merge: list[str] = []
        manual: list[str] = []

        for row in self._outbox.values():
            effect_id = row.seal.effect_id
            if effect_id in self._merged:
                continue
            if effect_id in self._receipts:
                merge.append(effect_id)
                continue
            if row.status == "queued":
                dispatch.append(effect_id)
                continue

            adapter = adapters.get(row.seal.action_kind)
            if adapter is None:
                manual.append(effect_id)
                continue
            probe = adapter.probe(effect_id)
            if probe.status == "found" and probe.receipt is not None:
                self._receipts[effect_id] = probe.receipt
                merge.append(effect_id)
            else:
                manual.append(effect_id)

        return RecoveryPlan(
            dispatch_effect_ids=tuple(dispatch),
            merge_effect_ids=tuple(merge),
            manual_review_effect_ids=tuple(manual),
        )
