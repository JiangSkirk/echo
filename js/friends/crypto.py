"""X25519 + ChaCha20-Poly1305 for friend payloads. Private keys stay in secrets."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def generate_keypair() -> tuple[str, str]:
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private.private_bytes_raw().hex(), public.hex()


def fingerprint(public_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()


def derive_shared_key(private_hex: str, peer_public_hex: str, epoch: int) -> bytes:
    private = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    peer = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_public_hex))
    shared = private.exchange(peer)
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=f"js-friends-v1:{epoch}".encode(),
    ).derive(shared)


def encrypt_text(key: bytes, plaintext: str, *, aad: bytes) -> str:
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    token = cipher.encrypt(nonce, plaintext.encode("utf-8"), aad)
    return base64.urlsafe_b64encode(nonce + token).decode("ascii")


def decrypt_text(key: bytes, payload: str, *, aad: bytes) -> str:
    raw = base64.urlsafe_b64decode(payload.encode("ascii"))
    if len(raw) < 13:
        raise ValueError("ciphertext is truncated")
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(raw[:12], raw[12:], aad).decode("utf-8")


def sign_body(key: bytes, timestamp: str, body: bytes) -> str:
    mac = hmac.new(key, f"{timestamp}.".encode("ascii") + body, hashlib.sha256)
    return mac.hexdigest()


def verify_signature(key: bytes, timestamp: str, body: bytes, signature: str) -> bool:
    expected = sign_body(key, timestamp, body)
    return hmac.compare_digest(expected, signature)


def encode_invite(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(blob.encode("utf-8")).decode("ascii")


def decode_invite(code: str) -> dict[str, Any]:
    raw = json.loads(base64.urlsafe_b64decode(code.encode("ascii")).decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("invite is not an object")
    return raw
