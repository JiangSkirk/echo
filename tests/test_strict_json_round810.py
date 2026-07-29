from __future__ import annotations

import json
from pathlib import Path

import pytest

from js.echo.ledger.strict_json import StrictJSONError, strict_load_path, strict_loads


@pytest.mark.parametrize(
    "text",
    [
        '{"a":1,"a":2}',
        '{"ok":true,"nested":{"k":1,"k":2}}',
        '{"a":1,"b":{"x":true,"x":false}}',
    ],
)
def test_duplicate_keys_rejected(text: str) -> None:
    with pytest.raises(StrictJSONError, match="duplicate"):
        strict_loads(text)


def test_duplicate_key_orders_both_fail() -> None:
    with pytest.raises(StrictJSONError):
        strict_loads('{"ok":false,"ok":true}')
    with pytest.raises(StrictJSONError):
        strict_loads('{"ok":true,"ok":false}')


@pytest.mark.parametrize(
    "text",
    [
        '{"v":NaN}',
        '{"v":Infinity}',
        '{"v":-Infinity}',
        '{"v":1e9999}',
        '{"v":-1e9999}',
        '{"known":1,"unknown":NaN}',
        '{"duration_seconds":Infinity}',
    ],
)
def test_non_finite_rejected(text: str) -> None:
    with pytest.raises(StrictJSONError):
        strict_loads(text)


def test_truncated_and_bom_rejected() -> None:
    with pytest.raises(StrictJSONError):
        strict_loads('{"ok": tru')
    with pytest.raises(StrictJSONError, match="BOM"):
        strict_loads('\ufeff{"ok":true}')


def test_deep_nesting_rejected() -> None:
    depth = 2000
    text = "[" * depth + "0" + "]" * depth
    with pytest.raises(StrictJSONError):
        strict_loads(text)


def test_valid_object_passes(tmp_path: Path) -> None:
    payload = {"ok": True, "n": 1.5, "nested": {"a": [1, 2]}}
    text = json.dumps(payload)
    assert strict_loads(text) == payload
    path = tmp_path / "ok.json"
    path.write_text(text, encoding="utf-8")
    assert strict_load_path(path) == payload


def test_round89_live_acceptance_still_strict_loads_if_present() -> None:
    live = Path("docs/security/ECHO_LIVE_ACCEPTANCE.json")
    if not live.is_file():
        pytest.skip("live acceptance absent")
    data = strict_load_path(live)
    assert isinstance(data, dict)
    assert data.get("schema_version") == "echo-live-acceptance-v4"
