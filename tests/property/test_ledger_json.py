"""Property tests for canonical / strict JSON encoding."""

from __future__ import annotations

import json
import string

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from js.echo.ledger.strict_json import StrictJSONError, canonical_json_text, strict_loads

_KEYS = st.text(alphabet=string.ascii_letters, min_size=1, max_size=8)
_VALUES = st.one_of(
    st.integers(min_value=-(2**62), max_value=2**62),
    st.text(alphabet=string.ascii_letters + " ", max_size=16),
    st.none(),
)
_OBJECTS = st.dictionaries(_KEYS, _VALUES, max_size=6)


@settings(max_examples=80, deadline=None)
@given(_OBJECTS)
def test_canonical_json_is_deterministic_and_round_trips(payload: dict[str, object]) -> None:
    first = canonical_json_text(payload)
    second = canonical_json_text(payload)
    assert first == second
    loaded = json.loads(first)
    assert loaded == payload
    assert canonical_json_text(loaded) == first
    assert strict_loads(first) == payload


@settings(max_examples=30, deadline=None)
@given(_KEYS)
def test_duplicate_keys_fail_closed(key: str) -> None:
    blob = f'{{"{key}":1,"{key}":2}}'
    with pytest.raises(StrictJSONError, match="duplicate"):
        strict_loads(blob)


@settings(max_examples=20, deadline=None)
@given(st.sampled_from(("NaN", "Infinity", "-Infinity")))
def test_non_finite_constants_fail_closed(token: str) -> None:
    with pytest.raises(StrictJSONError):
        strict_loads(f'{{"n": {token}}}')
