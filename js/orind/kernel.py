"""Gate Kernel (K§7.7): deterministic three-witness conjunction.

ALLOW is the conjunction of owner intent, origin-handle contracts, a fresh
state witness, local policy, satisfied approval requirements, remaining
quotas and no active freeze/revocation. Any missing, unknown or stale input
denies — there are no permissive defaults anywhere in this module and no
model/classifier call on the decision path.

``assess`` answers the Echo-facing question "what does this draft need?"
using exactly ``protocol.GATE_VERDICTS``. Commit readiness (every conjunct
green) is a separate query — ``commit_blockers`` — consumed by the WP10
membrane before a permit is ever minted; it never crosses the wire to Echo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from js.orin.desktop import (
    normalize_desktop_action,
    normalize_desktop_observe_arguments,
)
from js.orin.draft import (
    DRAFT_ID_PREFIX,
    EffectDraft,
    ExportPass,
    StateWitness,
    draft_from_dict,
)
from js.orin.handles import OriginHandle
from js.orin.intent import EFFECT_CLASSES, IntentEnvelope
from js.orin.protocol import GATE_VERDICTS, canonical_json
from js.orind.manifest import EffectManifest


def canonical_effect_hash_of(draft: EffectDraft) -> str:
    """Orin-side recomputation of what will actually be sent (K§7.5).

    ``declared_expectation`` is ignored; handles resolve to their sealed ids
    so the digest binds destinations without embedding secret bytes.
    """

    import hashlib

    arguments: dict[str, Any] = {}
    for key, value in sorted(draft.arguments.items()):
        # Destination sets are order-independent, but content-bearing lists
        # such as File Cell ``changes`` are ordered structured data.  Sorting
        # every list both changed semantics and raised TypeError for dicts.
        if (
            key.endswith("_handles")
            and isinstance(value, list)
            and all(isinstance(item, str) for item in value)
        ):
            arguments[key] = sorted(value)
        else:
            arguments[key] = value
    body = canonical_json({"effect_type": draft.effect_type, "arguments": arguments})
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


READ_EFFECTS: frozenset[str] = frozenset({"artifact.read", "desktop.observe", "memory.read"})
STAGE_EFFECTS: frozenset[str] = frozenset({"artifact.stage", "net.fetch"})
AUTO_EFFECTS: frozenset[str] = READ_EFFECTS | STAGE_EFFECTS
DUAL_CONTROL_EFFECTS: frozenset[str] = frozenset({"policy.change", "admin.unfreeze"})
EXPORT_EFFECTS: frozenset[str] = frozenset({"net.send", "email.send_exact"})


@dataclass(frozen=True, slots=True)
class GateDecision:
    """Low-information result handed back toward the model."""

    verdict: str
    missing: tuple[str, ...] = ()
    reason_code: str = ""

    def __post_init__(self) -> None:
        if self.verdict not in GATE_VERDICTS:
            raise ValueError(f"unknown gate verdict {self.verdict!r}")


@dataclass(slots=True)
class GateInputs:
    """Everything the conjunction needs; every absent field fails closed."""

    now_ms: int = 0
    intent: IntentEnvelope | None = None
    handles_by_id: dict[str, OriginHandle] = field(default_factory=dict)
    witness: StateWitness | None = None
    canonical_effect_hash: str | None = None
    expected_executor_id: str | None = None
    policy_verdict: str = "approval_required"
    # Kept as a source-compatible, authority-free field for early Stage-B
    # callers.  A boolean supplied by a caller can never stand in for the
    # signed, exact ExportPass objects below.
    export_pass_satisfied: bool = False
    export_passes: tuple[ExportPass, ...] = ()
    approval_satisfied: bool = False
    context_has_secret: bool = False
    quotas_ok: bool = True
    freeze_active: bool = False
    reconciliation_pending: bool = False
    policy_profile: str = "conservative"


def _deny(missing: tuple[str, ...], reason: str) -> GateDecision:
    return GateDecision(verdict="deny_missing_witness", missing=missing, reason_code=reason)


def handle_refs(arguments: dict[str, Any]) -> set[str]:
    """Collect permission-typed argument references (``*_handle[s]`` keys)."""

    refs: set[str] = set()
    for key, value in arguments.items():
        if key.endswith("_handle"):
            if isinstance(value, str):
                refs.add(value)
        elif key.endswith("_handles") and isinstance(value, list):
            refs.update(item for item in value if isinstance(item, str))
    return refs


class GateKernel:
    """Pure function object: inputs in, deterministic verdict out."""

    def __init__(
        self,
        *,
        secret_taint_bit: int,
        manifest: EffectManifest | None = None,
    ) -> None:
        self._known_effects = frozenset(EFFECT_CLASSES)
        self._secret_bit = int(secret_taint_bit)
        self._manifest = manifest

    def parse_draft(self, data: dict[str, Any]) -> EffectDraft:
        return draft_from_dict(data)

    def assess(self, draft: EffectDraft, inputs: GateInputs) -> GateDecision:
        # 1) Unknown effect types are open-world (MCP manifests): they may
        # request approval like anything else but are never auto-allowed.
        entry = self._manifest.get(draft.effect_type) if self._manifest else None
        if self._manifest is not None and entry is None:
            return GateDecision(
                verdict="deny_policy",
                reason_code="unregistered_or_invalid_manifest",
            )
        if draft.effect_type not in self._known_effects and entry is None:
            return GateDecision(
                verdict="require_approval",
                missing=("unknown_effect_manifest",),
                reason_code="unregistered_effect_type",
            )
        if entry is not None:
            # 1b) Closed-world argument table: anything the manifest does not
            # declare is refused outright, so a free-text "recipient" can
            # never smuggle a permission decision past the handle layer.
            declared = set(entry.permission_args) | set(entry.content_args)
            for arg_name in draft.arguments:
                if arg_name not in declared:
                    return GateDecision(
                        verdict="deny_policy",
                        reason_code=f"undeclared_argument:{arg_name}",
                    )
            # 1c) Permission-typed arguments accept ONLY handles of the
            # declared kind — model text can never mint one (K§7.3).
            for arg_name, prefix in entry.permission_args.items():
                value = draft.arguments.get(arg_name)
                if value is None:
                    continue
                values = value if isinstance(value, list) else [value]
                if (
                    isinstance(value, list)
                    and all(isinstance(item, str) for item in value)
                    and len(set(value)) != len(value)
                ):
                    return GateDecision(
                        verdict="deny_policy",
                        reason_code=f"duplicate_permission_arg:{arg_name}",
                    )
                for item in values:
                    if not isinstance(item, str) or not item.startswith(f"{prefix}:"):
                        return GateDecision(
                            verdict="deny_policy",
                            reason_code=f"free_text_permission_arg:{arg_name}",
                        )
            raw_refs = _handle_ref_sequence(draft.arguments)
            if len(raw_refs) != len(set(raw_refs)):
                return GateDecision(verdict="deny_policy", reason_code="duplicate_handle_reference")
            if draft.effect_type == "file.commit":
                directory_handle = draft.arguments.get("directory_handle")
                changes = draft.arguments.get("changes")
                if not isinstance(directory_handle, str) or not directory_handle.startswith(
                    "dirh:"
                ):
                    return GateDecision(
                        verdict="deny_policy",
                        reason_code="file_commit_requires_directory_handle",
                    )
                if (
                    not isinstance(changes, list)
                    or not 1 <= len(changes) <= 128
                    or any(
                        not isinstance(change, dict)
                        or set(change) != {"path", "content"}
                        or not isinstance(change.get("path"), str)
                        or not isinstance(change.get("content"), str)
                        or not change["path"]
                        or len(change["path"]) > 1024
                        for change in changes
                    )
                ):
                    return GateDecision(
                        verdict="deny_policy",
                        reason_code="invalid_file_commit_changes",
                    )
            elif draft.effect_type == "desktop.observe":
                try:
                    normalize_desktop_observe_arguments(draft.arguments)
                except Exception:
                    return GateDecision(
                        verdict="deny_policy",
                        reason_code="invalid_desktop_observe",
                    )
            elif draft.effect_type == "desktop.action":
                target_handle = draft.arguments.get("desktop_target_handle")
                if not isinstance(target_handle, str) or not target_handle.startswith("desktop:"):
                    return GateDecision(
                        verdict="deny_policy",
                        reason_code="desktop_action_requires_target_handle",
                    )
                try:
                    desktop_action = normalize_desktop_action(draft.arguments.get("action"))
                except Exception:
                    return GateDecision(
                        verdict="deny_policy",
                        reason_code="invalid_desktop_action",
                    )
                if desktop_action["kind"] in {"clear_stop", "set_mode"}:
                    return GateDecision(
                        verdict="deny_policy",
                        reason_code="desktop_owner_control_required",
                    )

        # 2) Hard denials short-circuit.  They deliberately carry no
        # ``missing`` entries: no approval or later witness can repair them.
        if inputs.reconciliation_pending:
            return GateDecision(verdict="defer_reconciliation", reason_code="prior_commit_unknown")

        # 3) Freeze blocks everything beyond pure reads.
        if inputs.freeze_active and draft.effect_type not in READ_EFFECTS:
            return GateDecision(verdict="deny_policy", reason_code="freeze_active")

        if not inputs.quotas_ok:
            return GateDecision(verdict="deny_policy", reason_code="budget_exhausted")

        if inputs.policy_verdict in {"deny", "denied", "deny_policy", "policy_deny"}:
            return GateDecision(verdict="deny_policy", reason_code="local_policy_denied")

        # 3) Owner intent: absence is fillable; invalid or non-authorizing
        # intent is a hard denial.
        missing: list[str] = []
        intent = inputs.intent
        if intent is None:
            missing.append("owner_intent")
        else:
            if inputs.now_ms >= intent.expires_at_ms:
                return GateDecision(verdict="deny_policy", reason_code="intent_expired")
            if draft.task_id != intent.task_id:
                return GateDecision(verdict="deny_policy", reason_code="task_mismatch")
            if draft.effect_type not in intent.allowed_effect_classes:
                return GateDecision(verdict="deny_policy", reason_code="effect_class_not_granted")

        # 4) Permission-typed arguments resolve to valid sealed handles only.
        refs = handle_refs(draft.arguments)
        unresolved = sorted(h for h in refs if h not in inputs.handles_by_id)
        if unresolved:
            missing.extend(f"handle:{h}" for h in unresolved)
        for handle_id in sorted(refs - set(unresolved)):
            handle = inputs.handles_by_id[handle_id]
            if handle.handle_id != handle_id:
                return GateDecision(verdict="deny_policy", reason_code="handle_id_mismatch")
            if inputs.now_ms >= handle.expires_at_ms:
                return GateDecision(verdict="deny_policy", reason_code="handle_expired")
            if intent is not None and handle.owner_key_hash != intent.owner_key_hash:
                return GateDecision(verdict="deny_policy", reason_code="handle_owner_mismatch")
            if intent is not None and handle.kind in {
                "DirectoryHandle",
                "ArtifactHandle",
                "ApplicationHandle",
            }:
                if handle_id not in intent.allowed_resource_handles:
                    return GateDecision(
                        verdict="deny_policy",
                        reason_code="resource_handle_not_granted",
                    )
                if handle.tenant != intent.profile:
                    return GateDecision(
                        verdict="deny_policy",
                        reason_code="resource_handle_tenant_mismatch",
                    )
                required = _resource_capabilities_for(draft.effect_type)
                if not required.issubset(handle.capabilities):
                    return GateDecision(
                        verdict="deny_policy",
                        reason_code="resource_handle_capability_mismatch",
                    )
            if (
                intent is not None
                and handle.kind == "DesktopTargetHandle"
                and (handle.tenant != intent.profile or "use" not in handle.capabilities)
            ):
                return GateDecision(
                    verdict="deny_policy",
                    reason_code="desktop_target_handle_scope_mismatch",
                )

        # 5) Fresh state witness bound to this draft for anything irreversible.
        witness_missing = False
        if draft.effect_type not in AUTO_EFFECTS:
            witness = inputs.witness
            if witness is None:
                witness_missing = True
                missing.append("state_witness")
            else:
                if witness.draft_id != draft.draft_id or not witness.draft_id.startswith(
                    DRAFT_ID_PREFIX
                ):
                    return GateDecision(
                        verdict="deny_stale_state", reason_code="witness_draft_mismatch"
                    )
                if witness.expired(inputs.now_ms):
                    return GateDecision(verdict="deny_stale_state", reason_code="witness_expired")
                expected_executor = inputs.expected_executor_id
                if expected_executor is not None and witness.executor_id != expected_executor:
                    return GateDecision(
                        verdict="deny_stale_state", reason_code="witness_executor_mismatch"
                    )
                expected = inputs.canonical_effect_hash
                if expected is None or witness.canonical_effect_hash != expected:
                    return GateDecision(
                        verdict="deny_stale_state", reason_code="canonical_effect_changed"
                    )

        # 6) Every external send requires an exact ExportPass.  ``net.fetch``
        # and local ``file.commit`` are intentionally outside this class.
        needs_export = draft.effect_type in EXPORT_EFFECTS
        export_ok = self._export_pass_matches(draft, inputs) if needs_export else True
        if needs_export and not export_ok:
            missing.append("export_pass")

        # StateWitness is the non-substitutable conjunct.  Continue far
        # enough to report other fillable requirements, but keep its verdict.
        if witness_missing:
            return _deny(tuple(missing), "no_state_witness")
        if missing == ["export_pass"]:
            return GateDecision(
                verdict="require_approval",
                missing=("export_pass",),
                reason_code="export_pass_required",
            )
        if missing:
            return _deny(tuple(missing), "missing_conjunct")
        assert intent is not None  # owner_intent would have returned above

        if draft.effect_type == "policy.change":
            from js.orin.policy_lattice import evaluate_policy_change_intent

            lattice = evaluate_policy_change_intent(
                dict(draft.arguments),
                current_profile=str(inputs.policy_profile or "conservative"),
                approved=bool(inputs.approval_satisfied),
            )
            if not lattice.allowed:
                return GateDecision(
                    verdict="require_dual_control",
                    reason_code="policy_widen_requires_approval",
                )

        # 7) Echo-facing requirement label for non-automatic effects.
        if draft.effect_type in READ_EFFECTS:
            return GateDecision(verdict="allow_read")
        if draft.effect_type in STAGE_EFFECTS:
            return GateDecision(verdict="allow_stage")
        # K4 grid: a commit-class effect whose connector cannot answer all
        # four capability questions escalates to dual control (residual
        # risk of duplicate/lost commits must be human-acknowledged).
        grid_incomplete = entry is not None and not entry.capability_grid_complete
        if (
            grid_incomplete
            or draft.effect_type in DUAL_CONTROL_EFFECTS
            or (entry is not None and entry.side_effect_class == "R3")
            or intent.approval_policy == "dual_control"
        ):
            return GateDecision(verdict="require_dual_control", reason_code="dual_control_required")
        if not inputs.approval_satisfied:
            return GateDecision(verdict="require_approval", missing=("exact_approval",))
        return GateDecision(verdict="require_approval", reason_code="commit_ready")

    @staticmethod
    def _export_pass_matches(draft: EffectDraft, inputs: GateInputs) -> bool:
        expected_hash = inputs.canonical_effect_hash
        witness = inputs.witness
        if expected_hash is None or witness is None:
            return False
        requested = _canonical_destinations(_handle_ref_sequence(draft.arguments))
        if requested is None or any(item not in inputs.handles_by_id for item in requested):
            return False
        for export_pass in inputs.export_passes:
            destinations = _canonical_destinations(export_pass.destination_handles)
            if destinations is None:
                continue
            if export_pass.task_id != draft.task_id:
                continue
            if export_pass.payload_hash != expected_hash:
                continue
            if destinations != requested:
                continue
            if export_pass.witness_id != witness.witness_id:
                continue
            if not export_pass.created_at_ms <= inputs.now_ms < export_pass.expires_at_ms:
                continue
            return True
        return False

    def commit_blockers(self, draft: EffectDraft, inputs: GateInputs) -> tuple[str, ...]:
        """Empty result ⇒ every K§7.7 conjunct is green and a permit may be
        minted onto the Cell connection. Never surfaced to Echo."""

        decision = self.assess(draft, inputs)
        if decision.verdict in ("allow_read", "allow_stage"):
            return ()
        if (
            decision.verdict == "require_approval"
            and not decision.missing
            and inputs.approval_satisfied
        ):
            return ()
        blockers: list[str] = [decision.reason_code or decision.verdict]
        blockers.extend(decision.missing)
        return tuple(blockers)


def _canonical_destinations(values: Any) -> tuple[str, ...] | None:
    """Canonicalize one exact destination set; duplicates are invalid."""

    try:
        items = tuple(values)
    except TypeError:
        return None
    if not 1 <= len(items) <= 32 or any(
        not isinstance(item, str) or not item or len(item) > 512 for item in items
    ):
        return None
    if len(set(items)) != len(items):
        return None
    return tuple(sorted(items))


def _resource_capabilities_for(effect_type: str) -> frozenset[str]:
    if effect_type == "file.commit":
        return frozenset({"stage", "write"})
    if effect_type == "artifact.stage":
        return frozenset({"stage"})
    return frozenset({"read"})


def _handle_ref_sequence(arguments: dict[str, Any]) -> tuple[Any, ...]:
    """Like :func:`handle_refs`, but preserve multiplicity for exact binding."""

    refs: list[Any] = []
    for key, value in arguments.items():
        if key.endswith("_handle"):
            refs.append(value)
        elif key.endswith("_handles"):
            if not isinstance(value, list):
                refs.append(value)
            else:
                refs.extend(value)
    return tuple(refs)


__all__ = [
    "AUTO_EFFECTS",
    "DUAL_CONTROL_EFFECTS",
    "EXPORT_EFFECTS",
    "GateDecision",
    "GateInputs",
    "GateKernel",
    "READ_EFFECTS",
    "STAGE_EFFECTS",
    "handle_refs",
]
