"""orin/v1 protocol unit tests: framing, MAC, strict parsing, semantics."""

from __future__ import annotations

import secrets

import pytest

from js.orin import protocol as p


@pytest.fixture()
def session_key() -> bytes:
    return secrets.token_bytes(32)


def _envelope(message_type: str, seq: int, session_key: bytes | None, **fields: object) -> dict:
    return p.make_envelope(
        message_type, seq=seq, nonce=secrets.token_hex(16), session_key=session_key, **fields
    )


class TestFraming:
    def test_round_trip(self, session_key: bytes) -> None:
        env = _envelope("heartbeat", seq=1, session_key=session_key)
        frame = p.encode_frame(env)
        assert len(frame) == 4 + len(p.canonical_json(env).encode())
        parsed = p.parse_frame(frame[4:])
        assert parsed["type"] == "heartbeat"
        assert p.verify_mac(session_key, parsed)

    def test_oversize_frame_rejected(self) -> None:
        with pytest.raises(p.ProtocolError, match="64KiB"):
            p.encode_frame({"v": 1, "type": "heartbeat", "seq": 1, "nonce": "n" * 16,
                            "x": "y" * 70_000})

    def test_bad_json_rejected(self) -> None:
        with pytest.raises(p.ProtocolError):
            p.parse_frame(b"{not json")

    def test_non_object_rejected(self) -> None:
        with pytest.raises(p.ProtocolError):
            p.parse_frame(b"[1,2,3]")

    def test_depth_cap(self, session_key: bytes) -> None:
        nested: object = "x"
        for _ in range(20):
            nested = [nested]
        env = _envelope("hello", seq=1, session_key=None)
        env["caps"] = [nested]
        with pytest.raises(p.ProtocolError, match="depth"):
            p.parse_frame(p.canonical_json(env).encode())

    def test_bad_mac_fails_verify(self, session_key: bytes) -> None:
        env = _envelope("heartbeat", seq=1, session_key=session_key)
        env["mac"] = p.MAC_PREFIX + "0" * 64
        assert not p.verify_mac(session_key, env)


class TestStrictParsing:
    def test_unknown_field_rejected(self, session_key: bytes) -> None:
        env = _envelope("heartbeat", seq=1, session_key=session_key)
        env["extra"] = "boom"
        with pytest.raises(p.ProtocolError, match="unknown field"):
            p.parse_frame(p.canonical_json(env).encode())

    def test_unknown_type_rejected(self, session_key: bytes) -> None:
        with pytest.raises(p.ProtocolError, match="unknown message type"):
            _envelope("explode", seq=1, session_key=session_key)

    def test_seventh_message_type_rejected(self, session_key: bytes) -> None:
        env = {
            "v": 1,
            "type": "sign",  # not one of the six frozen types
            "seq": 1,
            "nonce": secrets.token_hex(16),
            "mac": p.compute_mac(session_key, {
                "v": 1, "type": "sign", "seq": 1, "nonce": "n",
            }),
        }
        with pytest.raises(p.ProtocolError):
            p.parse_frame(p.canonical_json(env).encode())

    def test_missing_mac_rejected(self, session_key: bytes) -> None:
        env = _envelope("heartbeat", seq=1, session_key=session_key)
        del env["mac"]
        with pytest.raises(p.ProtocolError, match="requires a mac"):
            p.parse_frame(p.canonical_json(env).encode())

    def test_hello_with_mac_rejected(self, session_key: bytes) -> None:
        with pytest.raises(p.ProtocolError, match="must not carry a mac"):
            _envelope("hello", seq=1, session_key=session_key)

    def test_string_length_cap(self, session_key: bytes) -> None:
        with pytest.raises(p.ProtocolError, match="length cap"):
            _envelope("revoke", seq=1, session_key=session_key, op="lease",
                      lease_id="x" * 200)

    def test_version_rejected_when_future(self, session_key: bytes) -> None:
        env = _envelope("heartbeat", seq=1, session_key=session_key)
        env["v"] = 2
        with pytest.raises(p.ProtocolError):
            p.parse_frame(p.canonical_json(env).encode())


class TestAckSemantics:
    def test_error_ack_requires_known_code(self, session_key: bytes) -> None:
        with pytest.raises(p.ProtocolError, match="unknown error code"):
            _envelope("consume_ack", seq=1, session_key=session_key,
                      ok=False, code="bogus")

    def test_error_ack_requires_code(self, session_key: bytes) -> None:
        with pytest.raises(p.ProtocolError, match="require a 'code'"):
            _envelope("consume_ack", seq=1, session_key=session_key, ok=False)

    def test_success_ack_rejects_code(self, session_key: bytes) -> None:
        with pytest.raises(p.ProtocolError, match="must be absent"):
            _envelope("consume_ack", seq=1, session_key=session_key,
                      ok=True, code="denied", verdict="allow")

    def test_success_consume_ack_requires_verdict(self, session_key: bytes) -> None:
        with pytest.raises(p.ProtocolError, match="verdict"):
            _envelope("consume_ack", seq=1, session_key=session_key, ok=True)

    def test_all_error_codes_are_in_vocabulary(self) -> None:
        for code in p.ERROR_CODES:
            assert isinstance(code, str) and code


class TestRevokeOps:
    @pytest.mark.parametrize(
        ("op", "fields"),
        [
            ("lease", {"lease_id": "x" * 32}),
            ("session", {"owner_key_hash": "o", "session_id": "s"}),
            ("active_sessions", {"owner_key_hash": "o"}),
            ("is_revoked", {"lease_id": "x" * 32}),
        ],
    )
    def test_ops_accepted(self, session_key: bytes, op: str, fields: dict) -> None:
        env = _envelope("revoke", seq=1, session_key=session_key, op=op, **fields)
        assert p.parse_frame(p.encode_frame(env)[4:])["op"] == op

    def test_unknown_op_rejected(self, session_key: bytes) -> None:
        with pytest.raises(p.ProtocolError, match="unknown revoke op"):
            _envelope("revoke", seq=1, session_key=session_key, op="nuke",
                      lease_id="x" * 32)

    def test_op_requires_fields(self, session_key: bytes) -> None:
        with pytest.raises(p.ProtocolError):
            _envelope("revoke", seq=1, session_key=session_key, op="is_revoked")


class TestConsumeModes:
    def _lease_dict(self) -> dict:
        return {
            "lease_id": "l", "owner_key_hash": "o", "run_id": "r",
            "tool_name": "t", "args_schema": "a", "resource_scope": "s",
            "nonce": "n", "mac": "0" * 64, "max_bytes": 1,
            "max_duration_ms": 1, "max_invocations": 1, "expires_at": 99,
        }

    def test_verify_mode_expected_shape(self, session_key: bytes) -> None:
        env = _envelope("consume", seq=1, session_key=session_key, mode="verify",
                        lease=self._lease_dict(),
                        expected={"owner": "o", "tool": "t", "scope": "s"})
        assert p.parse_frame(p.encode_frame(env)[4:])["mode"] == "verify"

    def test_consume_mode_allows_missing_expected(self, session_key: bytes) -> None:
        env = _envelope("consume", seq=1, session_key=session_key, mode="consume",
                        lease=self._lease_dict())
        assert p.parse_frame(p.encode_frame(env)[4:])

    def test_preflight_requires_full_expected(self, session_key: bytes) -> None:
        with pytest.raises(p.ProtocolError):
            _envelope("consume", seq=1, session_key=session_key, mode="preflight",
                      lease=self._lease_dict())

    def test_unknown_mode_rejected(self, session_key: bytes) -> None:
        with pytest.raises(p.ProtocolError, match="unknown consume mode"):
            _envelope("consume", seq=1, session_key=session_key, mode="explode",
                      lease=self._lease_dict())

    def test_lease_mac_must_be_hex(self, session_key: bytes) -> None:
        lease = self._lease_dict()
        lease["mac"] = "authority-hmac-sha256:" + "0" * 64
        with pytest.raises(p.ProtocolError):
            _envelope("consume", seq=1, session_key=session_key, mode="consume",
                      lease=lease)
