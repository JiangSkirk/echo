"""Echo deterministic-kernel interface and purity contract tests.

These tests pin the signature of ``js.echo.core.pulse`` and prove that the
deterministic kernel stays hermetic and zero-I/O while runtime adapters remain
free to integrate the model, tool, memory, and web boundaries.

The tests are intentionally strict: any drift in parameter order, naming,
annotations, return type, source-level I/O, or legacy imports must fail loudly.
"""

from __future__ import annotations

import ast
import copy
import inspect
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ECHO_DIR = REPO_ROOT / "js" / "echo"


# ---------------------------------------------------------------------------
# Signature freeze
# ---------------------------------------------------------------------------
def test_pulse_signature_frozen() -> None:
    """pulse() parameter names, order and annotations are frozen contracts."""
    from js.echo.core import pulse

    sig = inspect.signature(pulse)
    params = list(sig.parameters.values())

    assert [p.name for p in params] == ["now", "inbound", "amber", "wheel", "tide"], (
        f"pulse() parameter order/names drifted: {[p.name for p in params]!r}"
    )

    # ``from __future__ import annotations`` keeps annotations as strings,
    # which is exactly what we want to assert against verbatim.
    expected_annotations = {
        "now": "int",
        "inbound": "list[InboundEvent]",
        "amber": "AmberTree",
        "wheel": "TimingWheel",
        "tide": "TideController",
    }
    for name, expected in expected_annotations.items():
        actual = sig.parameters[name].annotation
        assert actual == expected, (
            f"pulse() parameter {name!r} annotation drifted: expected {expected!r}, got {actual!r}"
        )

    assert sig.return_annotation == "tuple[AmberTree, list[Action]]", (
        f"pulse() return annotation drifted: {sig.return_annotation!r}"
    )

    for p in params:
        assert p.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.POSITIONAL_ONLY,
        ), f"pulse() parameter {p.name!r} must be positional-or-keyword, got {p.kind!r}"
        assert p.default is inspect.Parameter.empty, (
            f"pulse() parameter {p.name!r} must not have a default"
        )


# ---------------------------------------------------------------------------
# Determinism & purity
# ---------------------------------------------------------------------------
def test_pulse_is_pure_function() -> None:
    """Same inputs must yield equal outputs across two independent calls."""
    from js.echo.core import pulse
    from js.echo.testing import new_fake_amber, new_fake_tide, new_fake_wheel

    # Use real fakes since T5 pulse() calls wheel.due / tide.admit
    # / amber.commit_checked. Each call gets a fresh triple so wheel
    # state never leaks between invocations.
    inbound1: list = []
    inbound2: list = []

    out_a = pulse(1, inbound1, new_fake_amber(), new_fake_wheel(), new_fake_tide())
    out_b = pulse(1, inbound2, new_fake_amber(), new_fake_wheel(), new_fake_tide())

    # Compare the action list — that's the deterministic part. The
    # returned amber identities differ because each call got its
    # own fake, but the action sequences must match exactly.
    assert out_a[1] == out_b[1], f"pulse() not deterministic: {out_a!r} vs {out_b!r}"


def test_pulse_does_not_mutate_inputs() -> None:
    """pulse() must not mutate ``inbound`` or rebind ``amber``.

    At T5 the kernel does call ``amber.commit_checked`` / ``wheel.due``
    / ``tide.admit`` — so the returned amber may be a CoW successor
    of the input rather than the same object. What we still pin here
    is the *input* side: the caller's ``inbound`` list stays exactly
    as it was passed, and ``amber`` (the parameter binding) is never
    rebound. The deeper "what does pulse compute" contract lives in
    :mod:`tests.echo.test_pulse_purity` and
    :mod:`tests.echo.test_pulse_runtime`.
    """
    from js.echo.core import pulse
    from js.echo.testing import new_fake_amber, new_fake_tide, new_fake_wheel

    inbound: list = []
    inbound_snapshot = copy.deepcopy(inbound)
    amber = new_fake_amber()
    amber_id_before = id(amber)
    wheel = new_fake_wheel()
    tide = new_fake_tide()

    _new_amber, actions = pulse(0, inbound, amber, wheel, tide)

    assert inbound == inbound_snapshot, "pulse() mutated inbound contents"
    assert len(inbound) == len(inbound_snapshot), "pulse() changed inbound length"
    assert id(amber) == amber_id_before, "pulse() rebound the amber input object"
    assert isinstance(actions, list), "pulse() must return a list of actions"


# ---------------------------------------------------------------------------
# Source-level I/O guard
# ---------------------------------------------------------------------------
_FORBIDDEN_SOURCE_TOKENS = (
    "open(",
    "os.",
    "time.",
    "random",
    "logging",
    "asyncio",
    "subprocess",
    "httpx",
    "requests",
    "pathlib",
)


def test_pulse_source_has_no_io() -> None:
    """pulse() implementation source must not reference any I/O primitive."""
    from js.echo.core import pulse

    src = inspect.getsource(pulse)
    for token in _FORBIDDEN_SOURCE_TOKENS:
        assert token not in src, f"pulse() source must not mention {token!r}; found in:\n{src}"


# ---------------------------------------------------------------------------
# Hermetic package: no legacy imports
# ---------------------------------------------------------------------------
_FORBIDDEN_IMPORT_PREFIXES = (
    "js.agent",
    "js.clcr",
    "js.web",
    "js.tools",
    "js.memory",
    "js.models",
    "js.security",
)


def _iter_echo_python_files() -> list[pathlib.Path]:
    assert ECHO_DIR.is_dir(), f"js/echo/ not found at {ECHO_DIR}"
    kernel_modules = (
        "amber.py",
        "core.py",
        "tide_controller.py",
        "timing_wheel.py",
        "types.py",
    )
    return [ECHO_DIR / name for name in kernel_modules]


def test_echo_kernel_does_not_import_legacy() -> None:
    """Keep the deterministic Echo kernel hermetic while runtime adapters integrate I/O."""
    files = _iter_echo_python_files()
    assert files, "js/echo/ contains no .py files"

    offenders: list[str] = []
    for py_file in files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(
                        alias.name == p or alias.name.startswith(p + ".")
                        for p in _FORBIDDEN_IMPORT_PREFIXES
                    ):
                        offenders.append(f"{py_file}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if any(mod == p or mod.startswith(p + ".") for p in _FORBIDDEN_IMPORT_PREFIXES):
                    offenders.append(f"{py_file}: from {mod} import ...")

    assert not offenders, (
        "js/echo/ must not import legacy engine modules; offenders:\n  " + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# T1A.1 — Data-contract alignment with Echo spec §4 / §7
# ---------------------------------------------------------------------------
def test_amber_tree_protocol_shape() -> None:
    """AmberTree must expose the §7 method/property surface."""
    from js.echo.amber import AmberTree

    # ``root_hash`` is a property, not a method.
    root_hash = getattr(AmberTree, "root_hash", None)
    assert root_hash is not None, "AmberTree missing 'root_hash'"
    assert isinstance(root_hash, property), (
        f"AmberTree.root_hash must be a property, got {type(root_hash)!r}"
    )

    expected_methods = {
        "commit_checked": ["self", "path", "payload"],
        "mark": ["self", "path", "status"],
        "ready_index": ["self"],
        "context_view": ["self", "path"],
        "delta_since_last": ["self"],
    }
    for name, expected_params in expected_methods.items():
        member = getattr(AmberTree, name, None)
        assert callable(member), f"AmberTree.{name} missing or not callable"
        sig = inspect.signature(member)
        actual_params = list(sig.parameters)
        assert actual_params == expected_params, (
            f"AmberTree.{name} param list drifted: "
            f"expected {expected_params!r}, got {actual_params!r}"
        )


def test_pulse_frame_fields() -> None:
    """PulseFrame fields must match Echo spec §4 verbatim."""
    import dataclasses

    from js.echo.types import PulseFrame

    assert dataclasses.is_dataclass(PulseFrame), "PulseFrame must be a dataclass"
    assert PulseFrame.__dataclass_params__.frozen, "PulseFrame must be frozen"

    fields = {f.name for f in dataclasses.fields(PulseFrame)}
    expected = {"frame_seq", "root_hash", "delta", "prev_frame_hash", "mac", "crc32"}
    assert fields == expected, f"PulseFrame fields drifted: {fields!r}"


def test_request_envelope_identity_fields() -> None:
    """RequestEnvelope must carry the identity fields from the Echo blueprint."""
    import dataclasses

    from js.echo.types import RequestEnvelope

    assert dataclasses.is_dataclass(RequestEnvelope), "RequestEnvelope must be a dataclass"
    assert RequestEnvelope.__dataclass_params__.frozen, "RequestEnvelope must be frozen"

    fields = {f.name for f in dataclasses.fields(RequestEnvelope)}
    expected = {
        "request_id",
        "channel",
        "payload_hash",
        "envelope_id",
        "owner_key_hash",
        "session_id",
        "run_id",
        "source",
        "request_hash",
        "idempotency_key",
        "created_at",
        "auth_role",
        "state_key",
    }
    assert fields == expected, f"RequestEnvelope fields drifted: {fields!r}"

    envelope = RequestEnvelope(request_id="r1", channel="api_chat", payload_hash="abc")
    assert envelope.envelope_id == "r1"
    assert envelope.request_hash == "abc"
    assert envelope.idempotency_key == "r1"
    assert envelope.state_key == "r1"


def test_capability_lease_fields() -> None:
    """CapabilityLease includes the full product/session/network binding contract."""
    import dataclasses

    from js.echo.types import CapabilityLease

    assert dataclasses.is_dataclass(CapabilityLease), "CapabilityLease must be a dataclass"
    assert CapabilityLease.__dataclass_params__.frozen, "CapabilityLease must be frozen"

    fields = {f.name for f in dataclasses.fields(CapabilityLease)}
    expected = {
        "lease_id",
        "product_id",
        "session_id",
        "owner_key_hash",
        "run_id",
        "tool_name",
        "args_schema",
        "resource_scope",
        "fs_roots",
        "network_policy",
        "network_hosts",
        "max_bytes",
        "max_duration_ms",
        "max_invocations",
        "nonce",
        "expires_at",
        "parent_lease_id",
        "mac",
    }
    assert fields == expected, f"CapabilityLease fields drifted: {fields!r}"
    assert len(fields) == 18, f"CapabilityLease must have exactly 18 fields, got {len(fields)}"


def test_node_status_enum_values() -> None:
    """NodeStatus must enumerate exactly the §4 AmberNode.status set."""
    from js.echo.amber import NodeStatus

    members = {m.name for m in NodeStatus}
    expected = {"PENDING", "READY", "RUNNING", "DONE", "FAILED"}
    assert members == expected, f"NodeStatus members drifted: {members!r}"


# ---------------------------------------------------------------------------
# T1A.2 — SPI surface alignment with Echo spec §7
# ---------------------------------------------------------------------------
def _public_methods(proto: type) -> set[str]:
    """Return the user-defined attribute names on a Protocol (no dunders)."""
    return {
        name for name in vars(proto) if not name.startswith("_") and callable(vars(proto)[name])
    }


def test_sandbox_grant_signature() -> None:
    """Sandbox.grant must mirror §4 CapabilityLease keys; execute stays put."""
    from js.echo.spi import Sandbox

    grant_sig = inspect.signature(Sandbox.grant)
    assert list(grant_sig.parameters) == ["self", "tool_name", "resource_scope", "now"], (
        f"Sandbox.grant param order drifted: {list(grant_sig.parameters)!r}"
    )
    expected_grant_annotations = {
        "tool_name": "str",
        "resource_scope": "str",
        "now": "int",
    }
    for name, expected in expected_grant_annotations.items():
        actual = grant_sig.parameters[name].annotation
        assert actual == expected, (
            f"Sandbox.grant param {name!r} annotation drifted: "
            f"expected {expected!r}, got {actual!r}"
        )
    assert grant_sig.return_annotation == "CapabilityLease", (
        f"Sandbox.grant return annotation drifted: {grant_sig.return_annotation!r}"
    )

    execute_sig = inspect.signature(Sandbox.execute)
    assert list(execute_sig.parameters) == ["self", "lease", "arguments_hash"], (
        f"Sandbox.execute params drifted: {list(execute_sig.parameters)!r}"
    )
    assert execute_sig.return_annotation == "str", (
        f"Sandbox.execute return annotation drifted: {execute_sig.return_annotation!r}"
    )


def test_ledger_store_has_three_methods() -> None:
    """LedgerStore must expose exactly {append, frames, flock} (no head)."""
    from js.echo.spi import LedgerStore

    methods = _public_methods(LedgerStore)
    expected = {"append", "frames", "flock"}
    assert methods == expected, f"LedgerStore method set drifted: {methods!r}"
    assert not hasattr(LedgerStore, "head"), "LedgerStore.head must be removed at T1A.2"


def test_ledger_store_method_signatures() -> None:
    """LedgerStore method signatures must match §7 verbatim."""
    from js.echo.spi import LedgerStore

    append_sig = inspect.signature(LedgerStore.append)
    assert list(append_sig.parameters) == ["self", "frame"], (
        f"LedgerStore.append params drifted: {list(append_sig.parameters)!r}"
    )
    assert append_sig.parameters["frame"].annotation == "PulseFrame", (
        f"LedgerStore.append.frame annotation drifted: "
        f"{append_sig.parameters['frame'].annotation!r}"
    )
    assert append_sig.return_annotation == "int", (
        f"LedgerStore.append return annotation drifted: {append_sig.return_annotation!r}"
    )

    frames_sig = inspect.signature(LedgerStore.frames)
    assert list(frames_sig.parameters) == ["self"], (
        f"LedgerStore.frames params drifted: {list(frames_sig.parameters)!r}"
    )
    assert frames_sig.return_annotation == "Iterator[PulseFrame]", (
        f"LedgerStore.frames return annotation drifted: {frames_sig.return_annotation!r}"
    )

    flock_sig = inspect.signature(LedgerStore.flock)
    assert list(flock_sig.parameters) == ["self"], (
        f"LedgerStore.flock params drifted: {list(flock_sig.parameters)!r}"
    )
    assert flock_sig.return_annotation == "bool", (
        f"LedgerStore.flock return annotation drifted: {flock_sig.return_annotation!r}"
    )


def test_other_spi_protocols_unchanged() -> None:
    """InboundDriver / OutboundDriver / Store must not drift at T1A.2."""
    from js.echo.spi import InboundDriver, OutboundDriver, Store

    assert _public_methods(InboundDriver) == {"drain", "acknowledge"}, (
        f"InboundDriver method set drifted: {_public_methods(InboundDriver)!r}"
    )
    assert list(inspect.signature(InboundDriver.drain).parameters) == ["self", "now"]
    assert list(inspect.signature(InboundDriver.acknowledge).parameters) == ["self", "event"]

    assert _public_methods(OutboundDriver) == {"dispatch", "respond"}, (
        f"OutboundDriver method set drifted: {_public_methods(OutboundDriver)!r}"
    )
    assert list(inspect.signature(OutboundDriver.dispatch).parameters) == ["self", "action"]
    assert list(inspect.signature(OutboundDriver.respond).parameters) == [
        "self",
        "envelope",
        "payload_hash",
    ]

    assert _public_methods(Store) == {"load", "save"}, (
        f"Store method set drifted: {_public_methods(Store)!r}"
    )
    assert list(inspect.signature(Store.load).parameters) == ["self", "key"]
    assert list(inspect.signature(Store.save).parameters) == ["self", "key", "blob", "version"]
