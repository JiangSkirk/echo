"""Echo T5 — TideController contract & policy tests.

Pins :class:`js.echo.tide_controller.TideControllerImpl` against the
``TideController`` Protocol defined in :mod:`js.echo.tide`. Each test
exercises a single property of the admission / budget / observation
contract so failures point at one knob.

Contracts proven:

- Protocol conformance.
- Unknown channels are admitted with the baseline budget; no
  side-effect on state (admit / budget_for never mutate).
- ``observe`` builds per-channel EWMA; the first sample snaps the
  EWMA to the observed latency.
- Hysteresis: a single fast latency after a series of slow ones does
  NOT immediately exit ``congested``; EWMA must drop below
  ``exit_low_ms`` first. A single slow sample after a sequence of
  fast ones does NOT enter ``congested`` unless EWMA crosses
  ``enter_high_ms``.
- ``severe`` (EWMA >= severe_ms) is the only state that denies
  admission. ``congested`` admits but returns a shrunk budget.
- Recovery: once EWMA falls back below thresholds, admission and
  budget return to baseline.
- Per-channel isolation: high latency on channel A does NOT change
  admission / budget on channel B.
- Budget field set is invariant under congestion — the controller
  cannot accidentally hide a safety field.
- Determinism: two controllers fed the same (now, channel,
  latency_ms) sequence produce identical outputs at every step.
- Negative inputs (bad types, negative latency, empty channel) raise
  ``ValueError``.
- Hermetic: no I/O / clock / asyncio imports in source.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import pathlib

import pytest

from js.echo.tide import TideController
from js.echo.tide_controller import (
    DEFAULT_BASELINE_BUDGET,
    TideControllerImpl,
    new_tide_controller,
)
from js.echo.types import Budget


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------
def test_impl_satisfies_protocol() -> None:
    tide = new_tide_controller()
    assert isinstance(tide, TideController)


def test_fresh_controller_has_no_known_channels() -> None:
    tide = new_tide_controller()
    assert tide.known_channels() == ()
    assert tide.channel_state("anything") is None


# ---------------------------------------------------------------------------
# Unknown channel — admit + baseline budget
# ---------------------------------------------------------------------------
def test_unknown_channel_admitted_with_baseline_budget() -> None:
    tide = new_tide_controller()
    assert tide.admit(now=0, channel="api_chat") is True
    assert tide.budget_for("api_chat") == DEFAULT_BASELINE_BUDGET


def test_admit_does_not_mutate_state() -> None:
    """admit() and budget_for() are observers — no state created."""
    tide = new_tide_controller()
    tide.admit(now=0, channel="api_chat")
    tide.budget_for("api_chat")
    assert tide.known_channels() == ()
    assert tide.channel_state("api_chat") is None


# ---------------------------------------------------------------------------
# observe — EWMA & state creation
# ---------------------------------------------------------------------------
def test_first_observe_snaps_ewma_to_sample() -> None:
    tide = new_tide_controller()
    tide.observe(now=0, channel="api_chat", latency_ms=42)
    state = tide.channel_state("api_chat")
    assert state is not None
    assert state.observe_count == 1
    # First sample → EWMA snaps to the observed value.
    assert state.ewma_latency_ms == pytest.approx(42.0)
    assert state.is_congested is False
    assert state.is_severe is False


def test_observe_creates_state_for_new_channel() -> None:
    tide = new_tide_controller()
    tide.observe(now=0, channel="a", latency_ms=10)
    tide.observe(now=0, channel="b", latency_ms=20)
    assert set(tide.known_channels()) == {"a", "b"}


def test_observe_smooths_subsequent_samples() -> None:
    tide = new_tide_controller(ewma_alpha=0.5)
    tide.observe(now=0, channel="api_chat", latency_ms=100)
    tide.observe(now=1, channel="api_chat", latency_ms=200)
    state = tide.channel_state("api_chat")
    assert state is not None
    # 0.5 * 200 + 0.5 * 100 = 150
    assert state.ewma_latency_ms == pytest.approx(150.0)


# ---------------------------------------------------------------------------
# Congestion entry & hysteresis
# ---------------------------------------------------------------------------
def test_single_slow_sample_below_high_does_not_congest() -> None:
    """A blip just below enter_high_ms must stay in normal."""
    tide = new_tide_controller(enter_high_ms=500, exit_low_ms=200, severe_ms=2000, ewma_alpha=1.0)
    tide.observe(now=0, channel="api_chat", latency_ms=499)
    state = tide.channel_state("api_chat")
    assert state is not None
    assert state.is_congested is False
    assert tide.admit(now=0, channel="api_chat") is True
    assert tide.budget_for("api_chat") == DEFAULT_BASELINE_BUDGET


def test_crossing_enter_high_enters_congested() -> None:
    tide = new_tide_controller(enter_high_ms=500, exit_low_ms=200, severe_ms=2000, ewma_alpha=1.0)
    tide.observe(now=0, channel="api_chat", latency_ms=500)
    state = tide.channel_state("api_chat")
    assert state is not None
    assert state.is_congested is True
    assert state.is_severe is False
    # Admission still True; budget shrunk.
    assert tide.admit(now=0, channel="api_chat") is True
    assert tide.budget_for("api_chat") != DEFAULT_BASELINE_BUDGET


def test_hysteresis_does_not_exit_above_low_threshold() -> None:
    """Once congested, a single fast sample that lands between
    exit_low_ms and enter_high_ms must NOT exit congestion."""
    tide = new_tide_controller(enter_high_ms=500, exit_low_ms=200, severe_ms=2000, ewma_alpha=1.0)
    tide.observe(now=0, channel="api_chat", latency_ms=600)
    assert tide.channel_state("api_chat").is_congested is True  # type: ignore[union-attr]
    # Drop below high, still above low — must stay congested.
    tide.observe(now=1, channel="api_chat", latency_ms=300)
    state = tide.channel_state("api_chat")
    assert state is not None
    assert state.is_congested is True, "hysteresis: must not exit above exit_low_ms"


def test_hysteresis_exits_once_below_exit_low() -> None:
    """Drop below exit_low_ms → back to normal."""
    tide = new_tide_controller(enter_high_ms=500, exit_low_ms=200, severe_ms=2000, ewma_alpha=1.0)
    tide.observe(now=0, channel="api_chat", latency_ms=800)
    assert tide.channel_state("api_chat").is_congested is True  # type: ignore[union-attr]
    tide.observe(now=1, channel="api_chat", latency_ms=50)
    state = tide.channel_state("api_chat")
    assert state is not None
    assert state.is_congested is False
    assert tide.budget_for("api_chat") == DEFAULT_BASELINE_BUDGET


# ---------------------------------------------------------------------------
# Severe state — admission denied
# ---------------------------------------------------------------------------
def test_severe_threshold_denies_admit() -> None:
    tide = new_tide_controller(enter_high_ms=500, exit_low_ms=200, severe_ms=2000, ewma_alpha=1.0)
    tide.observe(now=0, channel="api_chat", latency_ms=3000)
    state = tide.channel_state("api_chat")
    assert state is not None
    assert state.is_severe is True
    assert state.is_congested is True
    assert tide.admit(now=0, channel="api_chat") is False
    # Budget is still shrunk (congested), not absent.
    shrunk = tide.budget_for("api_chat")
    assert shrunk != DEFAULT_BASELINE_BUDGET
    assert shrunk.tokens > 0 and shrunk.wall_ms > 0 and shrunk.depth > 0


def test_recovery_from_severe_to_congested_to_normal() -> None:
    tide = new_tide_controller(enter_high_ms=500, exit_low_ms=200, severe_ms=2000, ewma_alpha=1.0)
    tide.observe(now=0, channel="api_chat", latency_ms=3000)
    assert tide.admit(now=0, channel="api_chat") is False
    # Drop to congested range (between exit_low and severe).
    tide.observe(now=1, channel="api_chat", latency_ms=300)
    assert tide.admit(now=1, channel="api_chat") is True
    assert tide.budget_for("api_chat") != DEFAULT_BASELINE_BUDGET
    # Drop below exit_low → normal.
    tide.observe(now=2, channel="api_chat", latency_ms=10)
    assert tide.admit(now=2, channel="api_chat") is True
    assert tide.budget_for("api_chat") == DEFAULT_BASELINE_BUDGET


# ---------------------------------------------------------------------------
# Per-channel isolation
# ---------------------------------------------------------------------------
def test_congestion_does_not_leak_across_channels() -> None:
    tide = new_tide_controller(enter_high_ms=500, exit_low_ms=200, severe_ms=2000, ewma_alpha=1.0)
    # Hammer channel A; channel B stays untouched.
    tide.observe(now=0, channel="A", latency_ms=3000)
    assert tide.admit(now=0, channel="A") is False
    assert tide.budget_for("A") != DEFAULT_BASELINE_BUDGET

    # Channel B is unknown — admit + baseline.
    assert tide.admit(now=0, channel="B") is True
    assert tide.budget_for("B") == DEFAULT_BASELINE_BUDGET

    # Once channel B is observed at a normal latency, still baseline.
    tide.observe(now=1, channel="B", latency_ms=10)
    assert tide.admit(now=1, channel="B") is True
    assert tide.budget_for("B") == DEFAULT_BASELINE_BUDGET


def test_recovery_on_one_channel_does_not_change_other() -> None:
    """Observing only on channel A must not advance channel B's state."""
    tide = new_tide_controller(ewma_alpha=1.0)
    tide.observe(now=0, channel="A", latency_ms=10)
    tide.observe(now=0, channel="B", latency_ms=3000)
    assert tide.admit(now=0, channel="A") is True
    assert tide.admit(now=0, channel="B") is False
    # Now feed channel A more samples — channel B unchanged.
    tide.observe(now=1, channel="A", latency_ms=5)
    state_b = tide.channel_state("B")
    assert state_b is not None
    assert state_b.is_severe is True


# ---------------------------------------------------------------------------
# Budget field set invariant — congestion only shrinks capacity
# ---------------------------------------------------------------------------
def test_congestion_does_not_change_budget_field_set() -> None:
    """The Budget dataclass has exactly three fields. Congestion must
    NOT add or remove any — only shrink the three capacity knobs."""
    expected_fields = {f.name for f in dataclasses.fields(Budget)}
    assert expected_fields == {"tokens", "wall_ms", "depth"}, (
        f"Budget shape drifted: {expected_fields!r}"
    )

    tide = new_tide_controller(ewma_alpha=1.0)
    # Normal.
    b_normal = tide.budget_for("c")
    assert isinstance(b_normal, Budget)
    assert {f.name for f in dataclasses.fields(b_normal)} == expected_fields

    # Push to severe and re-check.
    tide.observe(now=0, channel="c", latency_ms=3000)
    b_severe = tide.budget_for("c")
    assert isinstance(b_severe, Budget)
    assert {f.name for f in dataclasses.fields(b_severe)} == expected_fields


def test_congestion_only_shrinks_capacity_knobs() -> None:
    """Each of tokens / wall_ms / depth must be < baseline when congested,
    but never below 1 (the floor)."""
    tide = new_tide_controller(
        baseline_budget=Budget(tokens=100, wall_ms=200, depth=4),
        ewma_alpha=1.0,
    )
    tide.observe(now=0, channel="c", latency_ms=600)
    b = tide.budget_for("c")
    assert b.tokens < 100 and b.tokens >= 1
    assert b.wall_ms < 200 and b.wall_ms >= 1
    assert b.depth < 4 and b.depth >= 1


def test_congestion_floor_protects_tiny_baselines() -> None:
    """A baseline of 1/1/1 must still produce a workable shrunk budget."""
    tide = new_tide_controller(
        baseline_budget=Budget(tokens=1, wall_ms=1, depth=1),
        ewma_alpha=1.0,
    )
    tide.observe(now=0, channel="c", latency_ms=600)
    b = tide.budget_for("c")
    assert b.tokens >= 1 and b.wall_ms >= 1 and b.depth >= 1


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------
def test_two_controllers_with_same_history_agree() -> None:
    history = [
        ("A", 100),
        ("A", 200),
        ("B", 50),
        ("A", 800),
        ("B", 75),
        ("A", 3000),
        ("A", 100),
        ("B", 600),
    ]
    a = new_tide_controller()
    b = new_tide_controller()
    for now, (channel, lat) in enumerate(history):
        a.observe(now=now, channel=channel, latency_ms=lat)
        b.observe(now=now, channel=channel, latency_ms=lat)
    for channel in ("A", "B"):
        assert a.admit(now=99, channel=channel) == b.admit(now=99, channel=channel)
        assert a.budget_for(channel) == b.budget_for(channel)


def test_admit_does_not_consume_state() -> None:
    """Calling admit() N times produces N identical results."""
    tide = new_tide_controller(ewma_alpha=1.0)
    tide.observe(now=0, channel="c", latency_ms=10)
    snapshots = [tide.admit(now=i, channel="c") for i in range(20)]
    assert all(snap is True for snap in snapshots)
    state_before = tide.channel_state("c")
    for _ in range(50):
        tide.admit(now=0, channel="c")
        tide.budget_for("c")
    state_after = tide.channel_state("c")
    assert state_before == state_after


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
def test_admit_rejects_non_int_now() -> None:
    tide = new_tide_controller()
    with pytest.raises(ValueError):
        tide.admit(now=1.5, channel="c")  # type: ignore[arg-type]


def test_admit_rejects_bool_now() -> None:
    tide = new_tide_controller()
    with pytest.raises(ValueError):
        tide.admit(now=True, channel="c")  # type: ignore[arg-type]


def test_admit_rejects_empty_channel() -> None:
    tide = new_tide_controller()
    with pytest.raises(ValueError):
        tide.admit(now=0, channel="")


def test_observe_rejects_negative_latency() -> None:
    tide = new_tide_controller()
    with pytest.raises(ValueError):
        tide.observe(now=0, channel="c", latency_ms=-1)


def test_observe_rejects_non_int_latency() -> None:
    tide = new_tide_controller()
    with pytest.raises(ValueError):
        tide.observe(now=0, channel="c", latency_ms=1.5)  # type: ignore[arg-type]


def test_observe_rejects_bool_latency() -> None:
    tide = new_tide_controller()
    with pytest.raises(ValueError):
        tide.observe(now=0, channel="c", latency_ms=True)  # type: ignore[arg-type]


def test_constructor_rejects_bad_threshold_ordering() -> None:
    with pytest.raises(ValueError):
        TideControllerImpl(enter_high_ms=200, exit_low_ms=500, severe_ms=2000)


def test_constructor_rejects_alpha_out_of_range() -> None:
    with pytest.raises(ValueError):
        TideControllerImpl(ewma_alpha=0.0)
    with pytest.raises(ValueError):
        TideControllerImpl(ewma_alpha=1.1)
    with pytest.raises(ValueError):
        TideControllerImpl(ewma_alpha=-0.5)


def test_constructor_rejects_non_positive_baseline_budget() -> None:
    with pytest.raises(ValueError):
        TideControllerImpl(baseline_budget=Budget(tokens=0, wall_ms=1, depth=1))
    with pytest.raises(ValueError):
        TideControllerImpl(baseline_budget=Budget(tokens=1, wall_ms=0, depth=1))
    with pytest.raises(ValueError):
        TideControllerImpl(baseline_budget=Budget(tokens=1, wall_ms=1, depth=0))


# ---------------------------------------------------------------------------
# Hermeticity — no I/O / clock imports
# ---------------------------------------------------------------------------
_FORBIDDEN_TOKENS = (
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


def test_module_source_has_no_io_tokens() -> None:
    src_path = pathlib.Path(inspect.getfile(TideControllerImpl))
    src = src_path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        doc_end_line = tree.body[0].end_lineno or 0
        lines = src.splitlines(keepends=True)
        non_docstring = "".join(lines[doc_end_line:])
    else:
        non_docstring = src
    for token in _FORBIDDEN_TOKENS:
        assert token not in non_docstring, (
            f"tide_controller.py must not mention {token!r}; found:\n{non_docstring}"
        )


def test_module_does_not_import_legacy() -> None:
    src = pathlib.Path(inspect.getfile(TideControllerImpl)).read_text(encoding="utf-8")
    tree = ast.parse(src)
    forbidden_prefixes = (
        "js.agent",
        "js.clcr",
        "js.web",
        "js.tools",
        "js.memory",
        "js.models",
        "js.security",
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for p in forbidden_prefixes:
                    assert not (alias.name == p or alias.name.startswith(p + ".")), (
                        f"tide_controller.py imports legacy: {alias.name}"
                    )
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for p in forbidden_prefixes:
                assert not (mod == p or mod.startswith(p + ".")), (
                    f"tide_controller.py imports legacy: {mod}"
                )


# ---------------------------------------------------------------------------
# Snapshot semantics — channel_state returns a copy, not a live view
# ---------------------------------------------------------------------------
def test_channel_state_returns_snapshot_copy() -> None:
    tide = new_tide_controller(ewma_alpha=1.0)
    tide.observe(now=0, channel="c", latency_ms=100)
    snap = tide.channel_state("c")
    assert snap is not None
    snap.is_congested = True  # mutate the copy
    real = tide.channel_state("c")
    assert real is not None
    assert real.is_congested is False, "channel_state must return a snapshot, not a live ref"
