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
    extra: dict[str, object] | None = None,
    schema: str = READINESS_RESULT_SCHEMA_VERSION,
) -> str:
    payload: dict[str, object] = {
        "schema_version": schema,
        "source_digest": digest,
        "internal_ready": ready,
        "internal_blockers": [] if blockers is None else blockers,
    }
    if extra:
        payload.update(extra)
    return READINESS_RESULT_SENTINEL + json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _ok(text: str) -> bool:
    return (
        parse_gate_stdout("readiness_json", text, exit_code=0, require_exit_code_zero=True).get(
            "ok"
        )
        is True
    )


def test_round88_required_gate_and_sentinel_spec() -> None:
    assert "pytest_targeted_round815" in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round811" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round812" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round810" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round89" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round88" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round87" not in REQUIRED_FINAL_LOCAL_GATES
    spec = get_local_gate_spec("strict_readiness", evidence_dir=Path("/tmp/evidence"))
    assert spec is not None
    joined = " ".join(spec.argv)
    assert "format_readiness_result_line" in joined
    assert READINESS_RESULT_SENTINEL.startswith("JS_AGENT_READINESS_V1=")


def test_readiness_sentinel_accepts_leading_logs_only() -> None:
    line = _sentinel()
    assert _ok(f"info noise before\n{line}\n")
    assert _ok(f"{line}\n")


def test_readiness_rejects_trailing_content_and_multi_json_attacks() -> None:
    success = _sentinel()
    fail = _sentinel(ready=False, blockers=["echo_live_acceptance_invalid"])
    assert not _ok(f"{success}\nERROR something failed\n")
    assert not _ok(f'{success}\n{{"internal_ready": tru\n')
    assert not _ok(f"{fail}\n{success}\n")
    assert not _ok(f"log {success} noise\n{fail}\n")
    assert not _ok(f"{success}\n{success}\n")
    assert not _ok(f'{success}\nJS_AGENT_READINESS_V1={{"schema_version":"x"}}\n')


def test_readiness_rejects_unknown_missing_and_type_faults() -> None:
    success = _sentinel()
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
    assert not _ok(
        READINESS_RESULT_SENTINEL
        + json.dumps({"internal_ready": True, "internal_blockers": []}, sort_keys=True)
        + "\n"
    )
    assert not _ok(
        READINESS_RESULT_SENTINEL
        + json.dumps(
            {
                "schema_version": READINESS_RESULT_SCHEMA_VERSION,
                "source_digest": DIGEST,
                "internal_ready": 1,
                "internal_blockers": [],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    assert not _ok(
        READINESS_RESULT_SENTINEL
        + json.dumps(
            {
                "schema_version": READINESS_RESULT_SCHEMA_VERSION,
                "source_digest": DIGEST,
                "internal_ready": True,
                "internal_blockers": [1],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    assert not _ok(success.replace(DIGEST, "ABCDEF" + "0" * 58))
    # plain JSON without sentinel must never green
    assert not _ok('{"internal_blockers": [], "internal_ready": true}\n')
    assert success  # keep fixture used


def test_format_readiness_result_line_is_canonical() -> None:
    report = type(
        "R",
        (),
        {"internal_ready": True, "internal_blockers": ()},
    )()
    line = format_readiness_result_line(report, source_digest=DIGEST)  # type: ignore[arg-type]
    assert line.startswith(READINESS_RESULT_SENTINEL)
    assert _ok(line + "\n")
