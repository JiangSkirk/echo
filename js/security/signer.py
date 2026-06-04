"""Ed25519 digital signature system for skills, plugins, and Hermes bridge.

Provides cryptographic proof of authorship and integrity that replaces
the current trust model based on self-declared YAML fields and unsigned
JSON lock files.

Key management:
- The signing key is generated once and stored at ``state_dir/.signing_key``
  with ``0o600`` permissions.
- The public key is embedded in signed manifests for verification.
- Built-in skills use a hardcoded public-key whitelist.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Whitelist of public keys for built-in skills shipped with JS Agent.
# These keys are trusted to sign BUILTIN-level manifests.
_BUILTIN_PUBLIC_KEYS: frozenset[str] = frozenset()


def _key_path(state_dir: Path) -> Path:
    return state_dir / ".signing_key"


def _pubkey_path(state_dir: Path) -> Path:
    return state_dir / ".signing_key.pub"


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


def generate_signing_key(state_dir: Path) -> ed25519.Ed25519PrivateKey:
    """Generate a new Ed25519 signing key and persist it to disk.

    The key file is created with ``0o600`` permissions.
    If a key already exists, it is NOT overwritten.
    """
    key_path = _key_path(state_dir)
    pub_path = _pubkey_path(state_dir)

    if key_path.exists():
        return load_signing_key(state_dir)  # type: ignore[return-value]

    state_dir.mkdir(parents=True, exist_ok=True)
    private_key = ed25519.Ed25519PrivateKey.generate()

    # Write private key with atomic O_EXCL
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(str(key_path), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    try:
        os.write(fd, priv_bytes)
    finally:
        os.close(fd)

    # Write public key
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_path.write_bytes(pub_bytes)

    return private_key


def load_signing_key(state_dir: Path) -> ed25519.Ed25519PrivateKey | None:
    """Load the signing key from disk, or None if not found."""
    key_path = _key_path(state_dir)
    if not key_path.exists():
        return None
    priv_bytes = key_path.read_bytes()
    return ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)


def get_public_key(state_dir: Path) -> str:
    """Return the public key as a base64-encoded string."""
    pub_path = _pubkey_path(state_dir)
    if pub_path.exists():
        return base64.b64encode(pub_path.read_bytes()).decode("ascii")
    key = load_signing_key(state_dir)
    if key is not None:
        pub_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(pub_bytes).decode("ascii")
    return ""


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------


def sign_content(content: str, state_dir: Path) -> str:
    """Sign a string payload with the local signing key.

    Returns the base64-encoded Ed25519 signature.
    Raises ``RuntimeError`` if no signing key exists.
    """
    key = load_signing_key(state_dir)
    if key is None:
        raise RuntimeError(
            "No signing key found.  Run generate_signing_key() first."
        )
    signature = key.sign(content.encode("utf-8"))
    return base64.b64encode(signature).decode("ascii")


def verify_signature(
    content: str,
    signature_b64: str,
    public_key_b64: str,
) -> bool:
    """Verify an Ed25519 signature for a content string.

    Returns ``True`` if the signature is valid, ``False`` otherwise.
    Also accepts built-in public keys from the whitelist.
    """
    try:
        signature = base64.b64decode(signature_b64)
        public_key_bytes = base64.b64decode(public_key_b64)
    except Exception:
        return False

    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, content.encode("utf-8"))
        return True
    except Exception:
        # Also check against the built-in whitelist
        if public_key_b64 in _BUILTIN_PUBLIC_KEYS:
            # Re-try with each whitelisted key as a fallback
            for pk_b64 in _BUILTIN_PUBLIC_KEYS:
                try:
                    pk = ed25519.Ed25519PublicKey.from_public_bytes(
                        base64.b64decode(pk_b64),
                    )
                    pk.verify(signature, content.encode("utf-8"))
                    return True
                except Exception:
                    continue
        return False


# ---------------------------------------------------------------------------
# Skill / Plugin manifest signing helpers
# ---------------------------------------------------------------------------


def sign_skill_manifest(manifest_path: Path, state_dir: Path) -> tuple[str, str]:
    """Sign a SKILL.md manifest file.

    Returns ``(signature, public_key)`` as base64 strings.
    The content being signed is the SHA-256 hash of the manifest file
    and all code files in the skill directory (same scope as
    ``SkillSpec.compute_hash()``).

    This MUST be called after ``generate_signing_key()``.
    """
    content_hash = _compute_skill_content_hash(manifest_path)
    signature = sign_content(content_hash, state_dir)
    public_key = get_public_key(state_dir)
    return signature, public_key


def verify_skill_manifest(
    manifest_path: Path, signature: str, public_key: str,
) -> bool:
    """Verify a skill manifest signature.

    Returns ``True`` if the signature is valid for the current content
    of the skill directory.
    """
    if not signature or not public_key:
        return False
    content_hash = _compute_skill_content_hash(manifest_path)
    return verify_signature(content_hash, signature, public_key)


def _compute_skill_content_hash(manifest_path: Path) -> str:
    """Compute a SHA-256 hash of the skill manifest + all code files."""
    h = hashlib.sha256()
    skill_dir = manifest_path.parent

    # Hash manifest
    if manifest_path.exists():
        h.update(manifest_path.read_bytes())

    # Hash code files
    for pattern in ("*.py", "*.sh", "*.bash", "*.js", "*.json", "*.yaml", "*.yml", "*.toml", "requirements.txt"):
        for f in sorted(skill_dir.glob(pattern)):
            if not f.is_symlink() and f.is_file():
                h.update(f.read_bytes())

    # Hash scripts/ directory
    scripts_dir = skill_dir / "scripts"
    if scripts_dir.exists():
        for f in sorted(scripts_dir.rglob("*")):
            if f.is_file() and not f.is_symlink():
                h.update(f.read_bytes())

    return h.hexdigest()


def is_builtin_public_key(public_key_b64: str) -> bool:
    """Check whether a public key belongs to the built-in whitelist."""
    return public_key_b64 in _BUILTIN_PUBLIC_KEYS
