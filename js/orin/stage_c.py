"""Stage C §6.1 conjunction and product-route helpers.

``orin.enforce=true`` is allowed only when every conjunction bit is observed.
External gates (official TCC, K§15.6 #8/#9) stay false in this tree; the
checker lists them instead of hiding behind a vague C2-C7 sentence.
Product Desktop/Memory Cell routes are live only while enforce is on.
"""

from __future__ import annotations

import contextvars
from dataclasses import dataclass
from typing import Any, Final

from js.orin.container_vm import production_sandbox_carrier_available
from js.orin.inventory import (
    ENFORCE_DISABLED_TOOL_NAMES,
    inventory_digest_matches,
    should_register_product_tool,
    tool_disabled_under_enforce,
)
from js.orin.process_split import (
    production_appshell_echo_separated,
    provider_tokens_out_of_echo,
)

_CONFIG_BITS: Final[tuple[str, ...]] = (
    "enabled",
    "stage_b",
    "cell_build",
    "cell_secret",
    "cell_net",
    "cell_file",
    "commit_membrane",
    "cell_desktop",
    "cell_memory",
    "cell_identity_enforce",
    "echo_minimal_os",
)

_product_enforce: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "orin_product_enforce",
    default=False,
)

CLOSEOUT_NOT_IMPLEMENTED: Final[str] = "not_implemented"
CLOSEOUT_IMPLEMENTED_CANDIDATE: Final[str] = "implemented_candidate"
CLOSEOUT_AS_OF: Final[str] = "2026-08-28"

_FORBIDDEN_CLAIMS: Final[tuple[str, ...]] = (
    "Stage C is implemented",
    "Echo RCE is closed",
    "orin.enforce is production-ready",
)

_EXTERNAL_GATES: Final[tuple[str, ...]] = (
    "official_tcc_packaging",
    "k156_8_real_model_e2e",
    "k156_9_independent_red_team",
)


@dataclass(frozen=True, slots=True)
class ConjunctionBit:
    name: str
    observed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class StageCEvidence:
    """Runtime/external evidence that config flags cannot observe alone."""

    appshell_echo_separated: bool = False
    production_sandbox_carrier: bool = False
    official_tcc_packaging: bool = False
    k156_8_real_model_e2e: bool = False
    k156_9_independent_red_team: bool = False
    provider_tokens_out_of_echo: bool = False
    unclassified_exits_denied: bool = False
    signed_receipt_schema: bool = False

    @staticmethod
    def observed() -> StageCEvidence:
        from js.orin.draft import SignedEffectReceiptV1

        _ = SignedEffectReceiptV1
        return StageCEvidence(
            appshell_echo_separated=production_appshell_echo_separated(),
            production_sandbox_carrier=production_sandbox_carrier_available(),
            official_tcc_packaging=False,
            k156_8_real_model_e2e=False,
            k156_9_independent_red_team=False,
            provider_tokens_out_of_echo=provider_tokens_out_of_echo(),
            unclassified_exits_denied=inventory_digest_matches(),
            signed_receipt_schema=True,
        )


@dataclass(frozen=True, slots=True)
class ConjunctionReport:
    bits: tuple[ConjunctionBit, ...]

    @property
    def ok(self) -> bool:
        return all(bit.observed for bit in self.bits)

    @property
    def missing(self) -> tuple[str, ...]:
        return tuple(bit.name for bit in self.bits if not bit.observed)

    def reject_message(self) -> str:
        details = (
            "; ".join(f"{bit.name} ({bit.reason})" for bit in self.bits if not bit.observed)
            or "(unknown)"
        )
        return (
            "orin.enforce is unavailable; Stage C §6.1 conjunction incomplete: "
            f"{details}. official_tcc_packaging, k156_8_real_model_e2e, "
            "k156_9_independent_red_team, and AppShell/Echo process split stay "
            "external-false in this tree; a local harness is not production enforce."
        )


def evaluate_stage_c_conjunction(
    config: Any,
    *,
    evidence: StageCEvidence | None = None,
) -> ConjunctionReport:
    """Evaluate the §6.1 conjunction plus the extra fail-fast conditions."""

    snapshot = evidence if evidence is not None else StageCEvidence.observed()
    bits: list[ConjunctionBit] = []
    for name in _CONFIG_BITS:
        observed = bool(getattr(config, name, False))
        if name == "echo_minimal_os":
            observed = observed and snapshot.production_sandbox_carrier
        bits.append(
            ConjunctionBit(
                name=name,
                observed=observed,
                reason="config flag" if observed else f"orin.{name} is not observed",
            )
        )
    extras = (
        ConjunctionBit(
            "signed_receipt_schema",
            snapshot.signed_receipt_schema,
            "receipt.signed.v1 exists" if snapshot.signed_receipt_schema else "missing",
        ),
        ConjunctionBit(
            "unclassified_exits_denied",
            snapshot.unclassified_exits_denied,
            "enforce deny-list wired" if snapshot.unclassified_exits_denied else "open exits",
        ),
        ConjunctionBit(
            "appshell_echo_separated",
            snapshot.appshell_echo_separated,
            "AppShell/Echo still share a process",
        ),
        ConjunctionBit(
            "production_sandbox_carrier",
            snapshot.production_sandbox_carrier,
            "file/build container_vm or L1 sandbox-exec"
            if snapshot.production_sandbox_carrier
            else "no file/build container_vm or L1 carrier",
        ),
        ConjunctionBit(
            "official_tcc_packaging",
            snapshot.official_tcc_packaging,
            "Developer ID/notary/TCC remain external-pending",
        ),
        ConjunctionBit(
            "k156_8_real_model_e2e",
            snapshot.k156_8_real_model_e2e,
            "K§15.6 #8 real-model desktop loop is blocked",
        ),
        ConjunctionBit(
            "k156_9_independent_red_team",
            snapshot.k156_9_independent_red_team,
            "K§15.6 #9 independent red team is external-pending",
        ),
        ConjunctionBit(
            "provider_tokens_out_of_echo",
            snapshot.provider_tokens_out_of_echo,
            "Echo still hydrates provider tokens in-process",
        ),
    )
    bits.extend(extras)
    return ConjunctionReport(bits=tuple(bits))


def require_stage_c_enforce(config: Any, *, evidence: StageCEvidence | None = None) -> None:
    report = evaluate_stage_c_conjunction(config, evidence=evidence)
    if not report.ok:
        raise ValueError(report.reject_message())


@dataclass(frozen=True, slots=True)
class StageCCloseoutDeclaration:
    """WP-C7 release verdict. Never claims Stage C shipped while conjunction fails."""

    as_of: str
    verdict: str
    conjunction_ok: bool
    missing: tuple[str, ...]
    external_gates_missing: tuple[str, ...]
    forbidden_claims: tuple[str, ...]
    statement: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of,
            "verdict": self.verdict,
            "conjunction_ok": self.conjunction_ok,
            "missing": list(self.missing),
            "external_gates_missing": list(self.external_gates_missing),
            "forbidden_claims": list(self.forbidden_claims),
            "statement": self.statement,
        }


def stage_c_closeout_declaration(
    config: Any | None = None,
    *,
    evidence: StageCEvidence | None = None,
) -> StageCCloseoutDeclaration:
    """Production closeout. Default ``OrinConfig()`` is the live product snapshot."""

    from js.config import OrinConfig

    snapshot = config if config is not None else OrinConfig()
    report = evaluate_stage_c_conjunction(snapshot, evidence=evidence)
    external_missing = tuple(name for name in _EXTERNAL_GATES if name in report.missing)
    if report.ok:
        verdict = CLOSEOUT_IMPLEMENTED_CANDIDATE
        statement = (
            "§6.1 conjunction is observed in this snapshot; this is an "
            "implemented-candidate only. Human review of K§15.6 and a macOS "
            "signed-build report are still required before any release claim."
        )
    else:
        verdict = CLOSEOUT_NOT_IMPLEMENTED
        statement = (
            "Stage C is not implemented. Echo RCE is not closed. "
            "orin.enforce stays fail-fast. " + report.reject_message()
        )
    return StageCCloseoutDeclaration(
        as_of=CLOSEOUT_AS_OF,
        verdict=verdict,
        conjunction_ok=report.ok,
        missing=report.missing,
        external_gates_missing=external_missing,
        forbidden_claims=_FORBIDDEN_CLAIMS,
        statement=statement,
    )


def _config_flag(config: Any, name: str) -> bool:
    """Read a real bool flag. MagicMock attributes must not count as observed."""

    if config is None:
        return False
    return getattr(config, name, False) is True


def product_enforce_enabled(config: Any) -> bool:
    return _config_flag(config, "enforce")


def product_desktop_cell_required(config: Any) -> bool:
    return product_enforce_enabled(config) and _config_flag(config, "cell_desktop")


def product_memory_cell_required(config: Any) -> bool:
    return product_enforce_enabled(config) and _config_flag(config, "cell_memory")


def echo_may_hold_provider_tokens(config: Any) -> bool:
    return not product_enforce_enabled(config)


def echo_may_use_ambient_memory(config: Any) -> bool:
    return not product_memory_cell_required(config)


def bind_product_enforce(value: bool) -> contextvars.Token[bool]:
    return _product_enforce.set(bool(value))


def reset_product_enforce(token: contextvars.Token[bool]) -> None:
    _product_enforce.reset(token)


def ambient_memory_blocked() -> bool:
    return bool(_product_enforce.get())


def in_process_provider_tokens_blocked() -> bool:
    return bool(_product_enforce.get())


def desktop_memory_cells_allowed(*, identity: bool, harness: bool, enforce: bool) -> bool:
    """Desktop/Memory spawn only for the C2/C3 harness or a live enforce process."""

    return bool(identity) and (bool(harness) or bool(enforce))


__all__ = [
    "CLOSEOUT_IMPLEMENTED_CANDIDATE",
    "CLOSEOUT_NOT_IMPLEMENTED",
    "ConjunctionBit",
    "ConjunctionReport",
    "ENFORCE_DISABLED_TOOL_NAMES",
    "StageCCloseoutDeclaration",
    "StageCEvidence",
    "ambient_memory_blocked",
    "bind_product_enforce",
    "desktop_memory_cells_allowed",
    "echo_may_hold_provider_tokens",
    "echo_may_use_ambient_memory",
    "evaluate_stage_c_conjunction",
    "in_process_provider_tokens_blocked",
    "product_desktop_cell_required",
    "product_enforce_enabled",
    "product_memory_cell_required",
    "require_stage_c_enforce",
    "reset_product_enforce",
    "should_register_product_tool",
    "stage_c_closeout_declaration",
    "tool_disabled_under_enforce",
]
