"""R5 Mobile gateway and pairing protocol tests."""

from __future__ import annotations

import time

import pytest

from js.mobile import (
    MobileGateway,
    MobileMessage,
    MobileMessageKind,
    MobileRequest,
    MobileResponse,
    PairingStatus,
)
from js.mobile.protocol import (
    generate_device_id,
    generate_pairing_code,
    hash_device_fingerprint,
    verify_pairing_code,
)


class TestPairingProtocol:
    """Pairing code generation and verification."""

    def test_pairing_code_is_6_digits(self) -> None:
        code = generate_pairing_code()
        assert len(code) == 6
        assert code.isdigit()

    def test_verify_valid_pairing_code(self) -> None:
        assert verify_pairing_code("123456") is True

    def test_verify_invalid_pairing_code(self) -> None:
        assert verify_pairing_code("abc123") is False
        assert verify_pairing_code("12345") is False
        assert verify_pairing_code("1234567") is False
        assert verify_pairing_code("") is False

    def test_device_id_is_64_hex(self) -> None:
        device_id = generate_device_id()
        assert len(device_id) == 64
        int(device_id, 16)

    def test_device_fingerprint_hash(self) -> None:
        fp = hash_device_fingerprint("abc123", "salt")
        assert len(fp) == 64
        fp2 = hash_device_fingerprint("abc123", "salt")
        assert fp == fp2
        fp3 = hash_device_fingerprint("abc123", "different")
        assert fp != fp3


class TestMobileGateway:
    """Pairing lifecycle and session management."""

    def test_create_pairing(self) -> None:
        gw = MobileGateway(salt="test-salt")
        session = gw.create_pairing()
        assert session.status == PairingStatus.PENDING
        assert len(session.code) == 6
        assert session.device_name == "iPhone"

    def test_confirm_pairing_success(self) -> None:
        gw = MobileGateway(salt="test-salt")
        pairing = gw.create_pairing()
        fp = hash_device_fingerprint(pairing.device_id, "test-salt")
        confirmed = gw.confirm_pairing(
            pairing.code,
            device_fingerprint=fp,
            owner_hash="owner-hash",
        )
        assert confirmed.status == PairingStatus.CONFIRMED
        assert confirmed.session_token is not None

    def test_confirm_pairing_wrong_fingerprint(self) -> None:
        gw = MobileGateway(salt="test-salt")
        pairing = gw.create_pairing()
        with pytest.raises(ValueError, match="fingerprint"):
            gw.confirm_pairing(
                pairing.code,
                device_fingerprint="wrong",
                owner_hash="owner-hash",
            )

    def test_confirm_pairing_expired(self) -> None:
        gw = MobileGateway(salt="test-salt")
        pairing = gw.create_pairing()
        pairing.expires_at = time.time() - 1
        fp = hash_device_fingerprint(pairing.device_id, "test-salt")
        with pytest.raises(ValueError, match="expired"):
            gw.confirm_pairing(
                pairing.code,
                device_fingerprint=fp,
                owner_hash="owner-hash",
            )

    def test_confirm_pairing_unknown_code(self) -> None:
        gw = MobileGateway(salt="test-salt")
        with pytest.raises(ValueError, match="not found"):
            gw.confirm_pairing(
                "999999",
                device_fingerprint="fp",
                owner_hash="owner-hash",
            )

    def test_verify_session(self) -> None:
        gw = MobileGateway(salt="test-salt")
        pairing = gw.create_pairing()
        fp = hash_device_fingerprint(pairing.device_id, "test-salt")
        gw.confirm_pairing(
            pairing.code,
            device_fingerprint=fp,
            owner_hash="owner-hash",
        )
        token = pairing.session_token
        assert token is not None
        session = gw.verify_session(token)
        assert session.device_name == "iPhone"

    def test_verify_session_invalid_token(self) -> None:
        gw = MobileGateway(salt="test-salt")
        with pytest.raises(ValueError, match="invalid"):
            gw.verify_session("nonexistent-token")

    def test_revoke_session(self) -> None:
        gw = MobileGateway(salt="test-salt")
        pairing = gw.create_pairing()
        fp = hash_device_fingerprint(pairing.device_id, "test-salt")
        gw.confirm_pairing(
            pairing.code,
            device_fingerprint=fp,
            owner_hash="owner-hash",
        )
        token = pairing.session_token
        assert token is not None
        assert gw.revoke_session(token) is True
        with pytest.raises(ValueError):
            gw.verify_session(token)

    def test_revoke_device(self) -> None:
        gw = MobileGateway(salt="test-salt")
        pairing = gw.create_pairing()
        fp = hash_device_fingerprint(pairing.device_id, "test-salt")
        gw.confirm_pairing(
            pairing.code,
            device_fingerprint=fp,
            owner_hash="owner-hash",
        )
        assert gw.revoke_device(pairing.device_id) is True
        assert gw.active_session_count == 0

    def test_max_sessions(self) -> None:
        gw = MobileGateway(salt="test-salt")
        for _ in range(4):
            pairing = gw.create_pairing()
            fp = hash_device_fingerprint(pairing.device_id, "test-salt")
            gw.confirm_pairing(
                pairing.code,
                device_fingerprint=fp,
                owner_hash="owner-hash",
            )
        pairing5 = gw.create_pairing()
        fp5 = hash_device_fingerprint(pairing5.device_id, "test-salt")
        with pytest.raises(RuntimeError, match="max"):
            gw.confirm_pairing(
                pairing5.code,
                device_fingerprint=fp5,
                owner_hash="owner-hash",
            )

    def test_list_sessions_no_tokens(self) -> None:
        gw = MobileGateway(salt="test-salt")
        pairing = gw.create_pairing()
        fp = hash_device_fingerprint(pairing.device_id, "test-salt")
        gw.confirm_pairing(
            pairing.code,
            device_fingerprint=fp,
            owner_hash="owner-hash",
        )
        sessions = gw.list_sessions()
        assert len(sessions) == 1
        assert "session_token" not in sessions[0]
        assert "device_name" in sessions[0]

    def test_cleanup_expired(self) -> None:
        gw = MobileGateway(salt="test-salt")
        pairing = gw.create_pairing()
        pairing.expires_at = time.time() - 1
        removed = gw.cleanup_expired()
        assert removed >= 1

    def test_session_allows_personal_chat(self) -> None:
        gw = MobileGateway(salt="test-salt")
        pairing = gw.create_pairing()
        fp = hash_device_fingerprint(pairing.device_id, "test-salt")
        gw.confirm_pairing(
            pairing.code,
            device_fingerprint=fp,
            owner_hash="owner-hash",
        )
        token = pairing.session_token
        assert token is not None
        session = gw.verify_session(token)
        assert session.allows("personal_chat")
        assert session.allows("work_status")
        assert not session.allows("shell")
        assert not session.allows("python")
        assert not session.allows("fleet")
        assert not session.allows("file_write")
        assert not session.allows("network")


class TestMobileMessages:
    """Mobile message protocol contracts."""

    def test_text_message_round_trip(self) -> None:
        msg = MobileMessage(
            message_id="msg-1",
            kind=MobileMessageKind.TEXT,
            payload={"text": "hello"},
        )
        d = msg.as_dict()
        msg2 = MobileMessage.from_dict(d)
        assert msg2.kind == MobileMessageKind.TEXT
        assert msg2.payload["text"] == "hello"

    def test_text_message_rejects_too_long(self) -> None:
        with pytest.raises(ValueError, match="too long"):
            MobileMessage.from_dict({
                "message_id": "msg-1",
                "kind": "text",
                "payload": {"text": "x" * 10001},
            })

    def test_cancel_message(self) -> None:
        msg = MobileMessage(
            message_id="msg-2",
            kind=MobileMessageKind.CANCEL,
        )
        assert msg.kind == MobileMessageKind.CANCEL

    def test_request_response_round_trip(self) -> None:
        req = MobileRequest(
            request_id="req-1",
            action="personal_chat",
            params={"text": "hello"},
        )
        resp = MobileResponse(
            request_id="req-1",
            success=True,
            data={"reply": "hi"},
        )
        assert req.as_dict()["action"] == "personal_chat"
        assert resp.as_dict()["success"] is True
