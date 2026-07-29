from __future__ import annotations

import json
from pathlib import Path

from js.echo.ledger.release_gates import (
    READINESS_RESULT_SCHEMA_VERSION,
    READINESS_RESULT_SENTINEL,
    REQUIRED_FINAL_LOCAL_GATES,
    format_readiness_result_line,
    get_local_gate_spec,
    parse_gate_stdout,
)

DIGEST = "a" * 64


def _sentinel(
    *,
    ready: bool = True,
    blockers: list[str] | None = None,
    digest: str = DIGEST,
) -> str:
    payload = {
        "schema_version": READINESS_RESULT_SCHEMA_VERSION,
        "source_digest": digest,
        "internal_ready": ready,
        "internal_blockers": [] if blockers is None else blockers,
    }
    return READINESS_RESULT_SENTINEL + json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _ok(text: str) -> bool:
    return (
        parse_gate_stdout("readiness_json", text, exit_code=0, require_exit_code_zero=True).get(
            "ok"
        )
        is True
    )


def test_round89_required_gate() -> None:
    # Round 8.15 owns REQUIRED_FINAL_LOCAL_GATES; round89 specs remain registered.
    assert "pytest_targeted_round815" in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round811" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round812" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round810" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round89" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round88" not in REQUIRED_FINAL_LOCAL_GATES
    assert get_local_gate_spec("pytest_targeted_round89", evidence_dir=Path("/tmp/e")) is not None
    spec = get_local_gate_spec("strict_readiness", evidence_dir=Path("/tmp/evidence"))
    assert spec is not None
    assert "format_readiness_result_line" in " ".join(spec.argv)


def test_embedded_sentinel_in_log_plus_trailing_fails() -> None:
    legit = _sentinel()
    assert not _ok(f"log noise contains {legit} before end\n{legit}\n")


def test_duplicate_json_keys_fail() -> None:
    # Duplicate internal_ready / internal_blockers — last-wins would otherwise green.
    encoded = (
        '{"schema_version":"js-agent-readiness-result-v1",'
        f'"source_digest":"{DIGEST}",'
        '"internal_ready":false,"internal_blockers":["x"],'
        '"internal_ready":true,"internal_blockers":[]}'
    )
    assert not _ok(READINESS_RESULT_SENTINEL + encoded + "\n")


def test_non_canonical_spacing_and_key_order_fail() -> None:
    spaced = json.dumps(
        {
            "schema_version": READINESS_RESULT_SCHEMA_VERSION,
            "source_digest": DIGEST,
            "internal_ready": True,
            "internal_blockers": [],
        },
        sort_keys=True,
    )
    assert not _ok(READINESS_RESULT_SENTINEL + spaced + "\n")
    wrong_order = (
        f'{{"schema_version":"{READINESS_RESULT_SCHEMA_VERSION}",'
        f'"source_digest":"{DIGEST}",'
        '"internal_ready":true,"internal_blockers":[]}'
    )
    assert not _ok(READINESS_RESULT_SENTINEL + wrong_order + "\n")


def test_trailing_error_truncated_multi_plain_unknown_fail() -> None:
    success = _sentinel()
    assert not _ok(f"{success}\nERROR boom\n")
    assert not _ok(f'{success}\n{{"internal_ready": tru\n')
    assert not _ok(f"{success}\n{success}\n")
    assert not _ok('{"internal_blockers": [], "internal_ready": true}\n')
    assert not _ok(
        READINESS_RESULT_SENTINEL
        + json.dumps(
            {
                "schema_version": READINESS_RESULT_SCHEMA_VERSION,
                "source_digest": DIGEST,
                "internal_ready": True,
                "internal_blockers": [],
                "extra": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def test_canonical_sentinel_with_leading_logs_passes() -> None:
    line = format_readiness_result_line(
        type("R", (), {"internal_ready": True, "internal_blockers": ()})(),
        source_digest=DIGEST,
    )
    assert _ok(f"info only\n{line}\n")
