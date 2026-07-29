from __future__ import annotations

import hmac
import json
from typing import Any

from js.echo.primitives import stable_payload_hash


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def stable_hash(value: Any) -> str:
    return stable_payload_hash(value)


def stable_hmac(key: bytes, value: Any) -> bytes:
    payload = canonical_json(value).encode("utf-8")
    return hmac.new(key, payload, digestmod="sha256").digest()


def hmac_matches(key: bytes, value: Any, mac: bytes) -> bool:
    return hmac.compare_digest(stable_hmac(key, value), mac)
