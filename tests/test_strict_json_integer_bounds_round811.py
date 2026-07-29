from __future__ import annotations

import json
from pathlib import Path

import pytest

from js.echo.ledger.release_gates import (
    _receipt_duration_consistent,
    _safe_finite_float,
    _valid_echo_live_acceptance,
)
from js.echo.ledger.strict_json import (
    MAX_STRICT_JSON_INT,
    MIN_STRICT_JSON_INT,
    StrictJSONError,
    is_strict_json_int,
    require_finite,
    strict_loads,
)


@pytest.mark.parametrize(
    "text",
    [
        '{"v":' + str(10**400) + "}",
        '{"v":-' + str(10**400) + "}",
        '{"nested":{"v":' + str(10**400) + "}}",
        '{"items":[' + str(10**400) + "]}",
    ],
)
def test_huge_integers_rejected_at_load(text: str) -> None:
    with pytest.raises(StrictJSONError, match="signed-64-bit|out of"):
        strict_loads(text)


def test_signed_64_bit_bounds_accepted_and_next_rejected() -> None:
    assert strict_loads(json.dumps({"v": MAX_STRICT_JSON_INT})) == {"v": MAX_STRICT_JSON_INT}
    assert strict_loads(json.dumps({"v": MIN_STRICT_JSON_INT})) == {"v": MIN_STRICT_JSON_INT}
    with pytest.raises(StrictJSONError):
        strict_loads(str(MAX_STRICT_JSON_INT + 1))
    with pytest.raises(StrictJSONError):
        strict_loads(str(MIN_STRICT_JSON_INT - 1))


def test_bool_rejected_as_strict_int_and_require_finite() -> None:
    assert not is_strict_json_int(True)
    assert not is_strict_json_int(False)
    assert is_strict_json_int(1)
    with pytest.raises(StrictJSONError):
        require_finite(True, field="x")
    assert require_finite(1, field="x") == 1.0
    assert _safe_finite_float(10**400) is None
    assert _safe_finite_float(True) is None


def test_receipt_duration_and_live_validator_fail_closed_on_overflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Defense in depth: even if a huge int bypassed the loader, validators must not raise.
    receipt = {
        "start_utc": "2026-07-25T00:00:00Z",
        "end_utc": "2026-07-25T01:00:00Z",
        "duration_seconds": 10**400,
    }
    assert _receipt_duration_consistent(receipt) is False

    # Live acceptance path uses strict_load_object; oversized ints fail load → False.
    live = tmp_path / "ECHO_LIVE_ACCEPTANCE.json"
    live.write_text(
        '{"schema_version":"echo-live-acceptance-v4","duration_seconds":' + str(10**400) + "}",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    assert _valid_echo_live_acceptance(tmp_path, live) is False


def test_round810_artifact_still_loads_if_present() -> None:
    live = Path("docs/security/ECHO_LIVE_ACCEPTANCE.json")
    if not live.is_file():
        pytest.skip("live acceptance absent")
    data = strict_loads(live.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
