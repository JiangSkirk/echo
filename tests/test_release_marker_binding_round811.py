from __future__ import annotations

from pathlib import Path

import pytest

from js.echo.ledger.release_gates import (
    REQUIRED_FINAL_LOCAL_GATES,
    format_release_result_line,
    parse_gate_stdout,
)


def _parse(stdout: str, *, expected_gate: str | None) -> dict[str, object]:
    return parse_gate_stdout(
        "release_markers",
        stdout,
        exit_code=0,
        require_exit_code_zero=True,
        expected_gate=expected_gate,
    )


@pytest.mark.parametrize("gate", ["release_smoke", "echo_full_audit"])
def test_release_marker_is_bound_to_exact_expected_gate(gate: str) -> None:
    line = format_release_result_line(gate=gate)
    result = _parse(f"diagnostic\n[OK] complete\n{line}\n", expected_gate=gate)

    assert result["ok"] is True
    assert result["json_ok"] is True
    assert result["expected_gate"] == gate
    assert result["payload"] == {
        "schema_version": "js-agent-release-result-v1",
        "ok": True,
        "gate": gate,
    }


def test_release_marker_requires_expected_gate() -> None:
    line = format_release_result_line(gate="release_smoke")
    result = _parse(line + "\n", expected_gate=None)

    assert result["ok"] is False
    assert result["payload"] is None


def test_release_marker_rejects_cross_gate_replay() -> None:
    line = format_release_result_line(gate="release_smoke")
    result = _parse(line + "\n", expected_gate="echo_full_audit")

    assert result["ok"] is False
    assert result["json_ok"] is False
    assert result["payload"] is None


@pytest.mark.parametrize(
    "gate",
    ["ruff", " release_smoke", "release_smoke ", "RELEASE_SMOKE", ""],
)
def test_formatter_rejects_unregistered_or_inexact_gate(gate: str) -> None:
    with pytest.raises(ValueError):
        format_release_result_line(gate=gate)


def test_release_marker_rejects_false_duplicate_and_trailing_data() -> None:
    good = format_release_result_line(gate="release_smoke")
    false_line = format_release_result_line(gate="release_smoke", ok=False)

    assert _parse(false_line + "\n", expected_gate="release_smoke")["ok"] is False
    assert _parse(f"{good}\n{good}\n", expected_gate="release_smoke")["ok"] is False
    assert _parse(f"{good}\ntrailing\n", expected_gate="release_smoke")["ok"] is False


def test_required_gate_set_contains_both_marker_gates() -> None:
    assert len(REQUIRED_FINAL_LOCAL_GATES) == len(set(REQUIRED_FINAL_LOCAL_GATES))
    assert {"release_smoke", "echo_full_audit"} <= set(REQUIRED_FINAL_LOCAL_GATES)
    assert Path("tests/test_release_marker_binding_round811.py").name.endswith("round811.py")
