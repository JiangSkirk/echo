"""C1 worker wire protocol stays authority-free and MAC-bound."""

from __future__ import annotations

import base64
import json

import pytest

from js.echo import c1_worker as worker


def test_mac_round_trip_and_tamper_fails() -> None:
    key = b"k" * 32
    envelope = {"schema": worker._REQUEST_SCHEMA, "seq": 1, "nonce": "a" * 32, "payload": {}}
    mac = worker._compute_mac(key, envelope)
    signed = {**envelope, "mac": mac}
    assert worker._verify_mac(key, signed) is True
    signed["payload"] = {"token": "nope"}
    assert worker._verify_mac(key, signed) is False
    assert worker._verify_mac(key, envelope) is False


def test_normalize_rejects_authority_bearing_fields() -> None:
    with pytest.raises(worker._AuthorityDeniedError, match="authority-bearing"):
        worker._normalize_json({"apiKey": "secret"}, path="root")
    with pytest.raises(worker._AuthorityDeniedError, match="authority-bearing"):
        worker._normalize_json({"owner_key": "x"}, path="root")
    assert worker._normalize_json({"summary": "ok"}, path="root") == {"summary": "ok"}


def test_normalize_rejects_depth_and_non_json() -> None:
    nested: object = 1
    for _ in range(worker._MAX_JSON_DEPTH + 2):
        nested = {"x": nested}
    with pytest.raises(worker._MessageDeniedError, match="depth"):
        worker._normalize_json(nested, path="root")
    with pytest.raises(worker._MessageDeniedError, match="non-JSON"):
        worker._normalize_json(object(), path="root")


def test_projection_requires_exact_payload_and_handles() -> None:
    good = {
        "task_id": "task:demo.one",
        "handle_ids": ["artifact:file-1"],
        "model_context": {"messages": ["hello"]},
        "safe_projection": {"status": "ok", "summary": "done"},
    }
    assert worker._normalize_projection(good)["task_id"] == "task:demo.one"
    with pytest.raises(worker._MessageDeniedError, match="four exact fields"):
        worker._normalize_projection({**good, "extra": 1})
    with pytest.raises(worker._MessageDeniedError, match="task_id"):
        worker._normalize_projection({**good, "task_id": "not-a-task"})
    with pytest.raises(worker._MessageDeniedError, match="duplicates"):
        worker._normalize_projection({**good, "handle_ids": ["artifact:file-1", "artifact:file-1"]})
    with pytest.raises(worker._MessageDeniedError, match="allowlist"):
        worker._normalize_safe_projection({"secret": "nope"})


def test_bootstrap_and_request_are_mac_bound() -> None:
    key = b"s" * 32
    nonce = "ab" * 16
    bootstrap = json.dumps(
        {
            "schema": worker._BOOTSTRAP_SCHEMA,
            "session_key": base64.b64encode(key).decode("ascii"),
            "nonce": nonce,
        }
    )
    parsed_key, parsed_nonce = worker._parse_bootstrap(bootstrap)
    assert parsed_key == key
    assert parsed_nonce == nonce
    with pytest.raises(worker._MessageDeniedError, match="schema"):
        worker._parse_bootstrap(json.dumps({"schema": "nope", "session_key": "x", "nonce": nonce}))

    payload = {
        "task_id": "task:demo.one",
        "handle_ids": ["artifact:file-1"],
        "model_context": {"messages": ["hello"]},
        "safe_projection": {"status": "ok"},
    }
    request = {
        "schema": worker._REQUEST_SCHEMA,
        "seq": 1,
        "nonce": nonce,
        "payload": payload,
    }
    request["mac"] = worker._compute_mac(key, request)
    seq, projection = worker._parse_request(
        json.dumps(request),
        session_key=key,
        nonce=nonce,
    )
    assert seq == 1
    assert projection["task_id"] == "task:demo.one"
    request["mac"] = worker._MAC_PREFIX + "0" * 64
    with pytest.raises(worker._MessageDeniedError, match="MAC"):
        worker._parse_request(json.dumps(request), session_key=key, nonce=nonce)
