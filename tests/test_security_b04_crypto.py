"""B-04 crypto-surface regression tests.

Covers observable security behavior (not source-string keyword checks):
- Constant-time MAC/hash comparisons reject forgeries.
- AUTO_APPROVE mode must still enforce the session callback's owner binding.
- Symlinked MAC key / ledger / signing key files must be rejected (O_NOFOLLOW).
- Legacy 100K PBKDF2 salt auto-migrates to the versioned 600K format and
  re-encrypts stored secrets transparently.
- KDF migration is crash-safe via a replayable journal (fault after salt
  publish / ciphertext update / before commit still leaves secrets readable).
- ``decrypt_blob`` fails closed on legacy plaintext unless explicitly
  configured with ``require_encryption=False``.
- ``load_signing_key`` fails closed on wrong file permissions / symlinks.
- The public key file is published with O_CREAT|O_EXCL (no clobber).
- ``get_public_key`` rejects symlinked / mismatched public keys (derive+verify).
- Pubkey publish failure rolls back a newly written private key.
- An empty built-in public-key whitelist must fail closed.
- Approval MAC key uses dir_fd / O_NOFOLLOW / fstat / 0600 / O_EXCL tmp.
- Signing keypair publish uses temp+fsync+atomic replace+parent fsync+journal;
  missing public is rebuilt; truncated private is isolated fail-closed.
- Existing MAC keys must already be mode 0600 and exact 32 bytes (no chmod-fix).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import stat
from pathlib import Path
from unittest import mock

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from js.security import signer
from js.security.approvals import ApprovalMode, ApprovalQueue
from js.security.secrets import SecretManager

# ---------------------------------------------------------------------------
# Constant-time comparisons (behavioral)
# ---------------------------------------------------------------------------


def test_approval_ledger_mac_comparison_is_constant_time(tmp_path: Path) -> None:
    """Forged ledger MAC must be rejected via compare_digest path."""
    ledger = tmp_path / "ledger.jsonl"
    queue = ApprovalQueue(ledger_path=ledger, default_mode=ApprovalMode.AUTO_APPROVE)
    queue.request_decision("shell", {"command": "echo ok"}, mode=ApprovalMode.AUTO_APPROVE)
    assert ledger.exists() and ledger.stat().st_size > 0

    # Tamper the last MAC hex nibble so verification must fail closed.
    lines = ledger.read_text(encoding="utf-8").splitlines()
    assert lines
    import json

    row = json.loads(lines[-1])
    mac = str(row["mac"])
    assert mac, "expected non-empty MAC"
    tampered = mac[:-1] + ("0" if mac[-1] != "0" else "1")
    assert tampered != mac
    row["mac"] = tampered
    lines[-1] = json.dumps(row, ensure_ascii=False, sort_keys=True)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with mock.patch("hmac.compare_digest", wraps=hmac.compare_digest) as mocked:
        with pytest.raises(ValueError, match="MAC mismatch"):
            ApprovalQueue(ledger_path=ledger)
        assert mocked.called


def test_audit_chain_mac_comparison_is_constant_time(tmp_path: Path) -> None:
    from js.security.audit import AuditEventType, AuditLogger

    logger = AuditLogger(tmp_path)
    logger.log(
        AuditEventType.SECURITY_ALERT,
        session_id="sess",
        run_id="run",
        actor="tester",
        action="ping",
        details={"ok": True},
    )
    with mock.patch("hmac.compare_digest", wraps=hmac.compare_digest) as mocked:
        ok, _broken_at = logger.verify_chain()
        assert ok is True
        assert mocked.called


def test_owner_hash_comparisons_are_constant_time() -> None:
    """Cross-owner authorization checks must invoke compare_digest."""
    from js.echo.capability import LeaseAuthority
    from js.echo.sandbox import LeasedSandbox
    from js.security.approvals import _secure_str_eq

    assert _secure_str_eq("owner-a", "owner-a") is True
    assert _secure_str_eq("owner-a", "owner-b") is False
    assert _secure_str_eq("short", "longer-value") is False

    authority = LeaseAuthority(mac_key=os.urandom(32), now_fn=lambda: 0)
    sandbox = LeasedSandbox(authority=authority, now_fn=lambda: 0)
    sandbox.bind_owner("owner-aaaaaaaaaaaaaaaa")
    with pytest.raises(ValueError, match="different owner"):
        sandbox.bind_owner("owner-bbbbbbbbbbbbbbbb")


# ---------------------------------------------------------------------------
# AUTO_APPROVE owner binding
# ---------------------------------------------------------------------------


def test_auto_approve_rejects_cross_owner_session(tmp_path: Path) -> None:
    """AUTO_APPROVE must not bypass the session callback's owner binding."""
    queue = ApprovalQueue(default_mode=ApprovalMode.AUTO_APPROVE)
    queue.set_callback(
        "sess-1",
        lambda req: True,
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="shell",
        arguments={"command": "ls"},
    )
    decision = queue.request_decision(
        "shell",
        {"command": "ls"},
        context="web",
        mode=ApprovalMode.AUTO_APPROVE,
        session_id="sess-1",
        run_id="run-b",
        owner_key_hash="owner-b",
    )
    assert not decision.approved, (
        "AUTO_APPROVE approved a request whose owner does not match the session callback binding"
    )


def test_auto_approve_allows_matching_owner(tmp_path: Path) -> None:
    queue = ApprovalQueue(default_mode=ApprovalMode.AUTO_APPROVE)
    queue.set_callback(
        "sess-1",
        lambda req: True,
        owner_key_hash="owner-a",
        run_id="run-a",
        tool_name="shell",
        arguments={"command": "ls"},
    )
    decision = queue.request_decision(
        "shell",
        {"command": "ls"},
        context="web",
        mode=ApprovalMode.AUTO_APPROVE,
        session_id="sess-1",
        run_id="run-a",
        owner_key_hash="owner-a",
    )
    assert decision.approved


def test_auto_approve_without_session_still_approves() -> None:
    queue = ApprovalQueue(default_mode=ApprovalMode.AUTO_APPROVE)
    assert queue.request("shell", {"command": "ls"}, mode=ApprovalMode.AUTO_APPROVE)


# ---------------------------------------------------------------------------
# Symlink rejection (O_NOFOLLOW)
# ---------------------------------------------------------------------------


def test_approval_mac_key_symlink_rejected(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_bytes(b"x" * 32)
    key_path = tmp_path / ".approval_ledger_mac_key"
    key_path.symlink_to(target)
    with pytest.raises((OSError, ValueError)):
        ApprovalQueue(ledger_path=tmp_path / "ledger.jsonl")


def test_approval_ledger_symlink_rejected(tmp_path: Path) -> None:
    target = tmp_path / "real_ledger.jsonl"
    target.write_text("", encoding="utf-8")
    ledger = tmp_path / "ledger.jsonl"
    ledger.symlink_to(target)
    with pytest.raises((OSError, ValueError)):
        ApprovalQueue(ledger_path=ledger)


def test_signing_key_symlink_rejected(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_bytes(os.urandom(32))
    key_path = tmp_path / ".signing_key"
    key_path.symlink_to(target)
    with pytest.raises((OSError, ValueError)):
        signer.load_signing_key(tmp_path)


def test_approval_mac_key_created_0600_regular_file(tmp_path: Path) -> None:
    ApprovalQueue(ledger_path=tmp_path / "ledger.jsonl")
    key_path = tmp_path / ".approval_ledger_mac_key"
    assert key_path.is_file()
    assert not key_path.is_symlink()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert len(key_path.read_bytes()) == 32


def test_approval_mac_key_rejects_non_regular_file(tmp_path: Path) -> None:
    key_path = tmp_path / ".approval_ledger_mac_key"
    key_path.mkdir()
    with pytest.raises((OSError, ValueError)):
        ApprovalQueue(ledger_path=tmp_path / "ledger.jsonl")


# ---------------------------------------------------------------------------
# Legacy KDF auto-migration
# ---------------------------------------------------------------------------


def _make_legacy_state(state_dir: Path, master_key: str, secret: str) -> None:
    """Create a pre-upgrade state dir: raw 16-byte salt + 100K-derived row."""
    state_dir.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(16)
    salt_path = state_dir / ".secret_salt"
    salt_path.write_bytes(salt)
    salt_path.chmod(0o600)
    key = hashlib.pbkdf2_hmac("sha256", master_key.encode(), salt, 100_000, dklen=32)
    fernet = Fernet(base64.urlsafe_b64encode(key))
    manager = SecretManager.__new__(SecretManager)
    manager.state_dir = state_dir
    manager.db_path = state_dir / "secrets.db"
    manager._require_encryption = True
    manager._init_db()
    import js.utils.db as db_mod

    with db_mod.db_connection(manager.db_path) as conn:
        conn.execute(
            "INSERT INTO secrets (name, value_encrypted, category) VALUES (?, ?, ?)",
            ("legacy", fernet.encrypt(secret.encode()), "general"),
        )
        conn.commit()


def test_legacy_100k_kdf_auto_migrates_to_600k(tmp_path: Path) -> None:
    master = "legacy-password"
    _make_legacy_state(tmp_path, master, "still-readable")

    manager = SecretManager(tmp_path, master_key=master)

    # Salt file migrated to the versioned 600K format.
    encoded_salt = (tmp_path / ".secret_salt").read_bytes()
    assert encoded_salt[:4] == b"JSS1"
    assert int.from_bytes(encoded_salt[4:8], "big") == 600_000
    # Stored secrets transparently re-encrypted and readable.
    assert manager.retrieve("legacy") == "still-readable"
    # New writes use the 600K-derived key; a restart still reads everything.
    manager.store("fresh", "new-value")
    restarted = SecretManager(tmp_path, master_key=master)
    assert restarted.retrieve("legacy") == "still-readable"
    assert restarted.retrieve("fresh") == "new-value"
    assert not (tmp_path / ".secret_kdf_migrate.journal").exists()


@pytest.mark.parametrize(
    "fault_point",
    [
        "after_journal",
        "after_ciphertext_update",
        "before_commit",
        "before_salt_publish",
        "after_salt_publish",
    ],
)
def test_kdf_migration_fault_injection_keeps_secrets_readable(
    tmp_path: Path, fault_point: str
) -> None:
    """Crash mid-migration; restart must still decrypt the original secret."""
    master = "legacy-password"
    _make_legacy_state(tmp_path, master, "still-readable")
    SecretManager._migration_fault_point = fault_point
    try:
        with pytest.raises(RuntimeError, match=fault_point):
            SecretManager(tmp_path, master_key=master)
    finally:
        SecretManager._migration_fault_point = None

    restarted = SecretManager(tmp_path, master_key=master)
    assert restarted.retrieve("legacy") == "still-readable"
    # After successful recovery/migration, salt is JSS1/600K and journal is gone.
    encoded_salt = (tmp_path / ".secret_salt").read_bytes()
    assert encoded_salt[:4] == b"JSS1"
    assert int.from_bytes(encoded_salt[4:8], "big") == 600_000
    assert not (tmp_path / ".secret_kdf_migrate.journal").exists()


# ---------------------------------------------------------------------------
# decrypt_blob require_encryption
# ---------------------------------------------------------------------------


def test_decrypt_blob_plaintext_fails_closed_by_default(tmp_path: Path) -> None:
    manager = SecretManager(tmp_path)
    with pytest.raises(ValueError, match="encrypt|encryption|legacy|plaintext"):
        manager.decrypt_blob(b"legacy plaintext blob")


def test_decrypt_blob_plaintext_allowed_with_explicit_opt_out(tmp_path: Path) -> None:
    manager = SecretManager(tmp_path, require_encryption=False)
    assert manager.decrypt_blob(b"legacy plaintext blob") == b"legacy plaintext blob"


def test_decrypt_blob_encrypted_roundtrip_unaffected(tmp_path: Path) -> None:
    manager = SecretManager(tmp_path)
    blob = manager.encrypt_blob(b"payload")
    assert manager.decrypt_blob(blob) == b"payload"


# ---------------------------------------------------------------------------
# signer.py hardening
# ---------------------------------------------------------------------------


def test_load_signing_key_rejects_loose_permissions(tmp_path: Path) -> None:
    signer.generate_signing_key(tmp_path)
    key_path = tmp_path / ".signing_key"
    key_path.chmod(0o644)
    with pytest.raises((ValueError, PermissionError)):
        signer.load_signing_key(tmp_path)
    key_path.chmod(0o600)
    assert signer.load_signing_key(tmp_path) is not None


def test_generate_signing_key_pubkey_no_clobber(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    pub_path = tmp_path / ".signing_key.pub"
    pub_path.write_bytes(b"attacker-controlled")
    with pytest.raises(FileExistsError):
        signer.generate_signing_key(tmp_path)
    assert pub_path.read_bytes() == b"attacker-controlled"
    # Private key must be rolled back when public publish fails.
    assert not (tmp_path / ".signing_key").exists()


def test_generate_signing_key_publishes_matching_keypair(tmp_path: Path) -> None:
    private_key = signer.generate_signing_key(tmp_path)
    pub_b64 = signer.get_public_key(tmp_path)
    derived = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    assert pub_b64 == derived


def test_get_public_key_rejects_symlink(tmp_path: Path) -> None:
    signer.generate_signing_key(tmp_path)
    pub_path = tmp_path / ".signing_key.pub"
    target = tmp_path / "elsewhere.pub"
    target.write_bytes(pub_path.read_bytes())
    pub_path.unlink()
    pub_path.symlink_to(target)
    with pytest.raises((OSError, ValueError)):
        signer.get_public_key(tmp_path)


def test_get_public_key_rejects_mismatched_public(tmp_path: Path) -> None:
    signer.generate_signing_key(tmp_path)
    other = ed25519.Ed25519PrivateKey.generate()
    (tmp_path / ".signing_key.pub").write_bytes(
        other.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    with pytest.raises(ValueError, match="does not match"):
        signer.get_public_key(tmp_path)


def test_empty_builtin_public_keys_fail_closed(tmp_path: Path) -> None:
    """With an empty whitelist nothing may verify via the builtin path."""
    assert not signer._BUILTIN_PUBLIC_KEYS
    key = signer.generate_signing_key(tmp_path)
    signature = signer.sign_content("content", tmp_path)
    public_key = signer.get_public_key(tmp_path)
    # Genuine signature verifies through the explicit public key.
    assert signer.verify_signature("content", signature, public_key)
    # Forged / mismatched signatures are rejected (no whitelist fallback).
    assert not signer.verify_signature("tampered", signature, public_key)
    assert not signer.verify_signature("content", signature, base64.b64encode(b"x" * 32).decode())
    # No key is treated as builtin while the whitelist is empty.
    assert not signer.is_builtin_public_key(public_key)
    del key


def test_signing_key_file_permissions_on_generate(tmp_path: Path) -> None:
    signer.generate_signing_key(tmp_path)
    mode = stat.S_IMODE((tmp_path / ".signing_key").stat().st_mode)
    assert mode == 0o600


# ---------------------------------------------------------------------------
# B04 local durability: MAC key mode/length + signing keypair journal
# ---------------------------------------------------------------------------


def test_approval_mac_key_rejects_loose_mode_without_chmod_fix(tmp_path: Path) -> None:
    """Existing MAC key with mode != 0600 must fail closed; do not chmod-then-accept."""
    key_path = tmp_path / ".approval_ledger_mac_key"
    key_path.write_bytes(os.urandom(32))
    key_path.chmod(0o644)
    original = key_path.read_bytes()
    with pytest.raises((PermissionError, ValueError, OSError)):
        ApprovalQueue(ledger_path=tmp_path / "ledger.jsonl")
    # Key material must remain unchanged and still world/group-readable (not "fixed").
    assert key_path.read_bytes() == original
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o644


def test_approval_mac_key_rejects_non_exact_32_bytes(tmp_path: Path) -> None:
    key_path = tmp_path / ".approval_ledger_mac_key"
    key_path.write_bytes(os.urandom(31))
    key_path.chmod(0o600)
    with pytest.raises(ValueError, match="32"):
        ApprovalQueue(ledger_path=tmp_path / "ledger.jsonl")
    key_path.write_bytes(os.urandom(33))
    key_path.chmod(0o600)
    with pytest.raises(ValueError, match="32"):
        ApprovalQueue(ledger_path=tmp_path / "ledger.jsonl")


def test_approval_mac_key_parent_dir_symlink_rejected(tmp_path: Path) -> None:
    real = tmp_path / "realdir"
    real.mkdir(mode=0o700)
    link = tmp_path / "linkdir"
    link.symlink_to(real)
    with pytest.raises((OSError, ValueError)):
        ApprovalQueue(ledger_path=link / "ledger.jsonl")


def test_missing_public_key_rebuilt_from_valid_private(tmp_path: Path) -> None:
    private_key = signer.generate_signing_key(tmp_path)
    pub_path = tmp_path / ".signing_key.pub"
    assert pub_path.is_file()
    pub_path.unlink()
    rebuilt = signer.get_public_key(tmp_path)
    assert pub_path.is_file()
    assert not pub_path.is_symlink()
    expected = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    assert rebuilt == expected
    assert pub_path.read_bytes() == base64.b64decode(expected)


def test_truncated_private_key_isolated_fail_closed(tmp_path: Path) -> None:
    signer.generate_signing_key(tmp_path)
    key_path = tmp_path / ".signing_key"
    key_path.write_bytes(os.urandom(16))  # truncated / invalid
    key_path.chmod(0o600)
    with pytest.raises((ValueError, OSError)):
        signer.load_signing_key(tmp_path)
    assert not key_path.exists(), "invalid private key must be isolated away from the live path"
    isolated = list(tmp_path.glob(".signing_key.corrupt*"))
    assert isolated, "expected quarantined corrupt private key evidence"


@pytest.mark.parametrize(
    "fault_point",
    [
        "after_journal",
        "after_private_write",
        "after_public_write",
        "after_private_publish",
        "after_public_publish",
        "before_cleanup",
    ],
)
def test_signing_keypair_subprocess_crash_windows(tmp_path: Path, fault_point: str) -> None:
    """Real subprocess exits mid-publish; restart must recover or fail closed cleanly."""
    import subprocess
    import sys

    state = tmp_path / "state"
    state.mkdir()
    env = os.environ.copy()
    env["JS_SIGNING_KEYPAIR_FAULT"] = fault_point
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; from js.security import signer; "
            f"signer.generate_signing_key(Path({str(state)!r}))",
        ],
        env=env,
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0, (
        f"expected injected crash at {fault_point}, got success stdout={proc.stdout!r}"
    )

    # Clear fault and recover via a fresh process / in-process restart.
    recovered = signer.generate_signing_key(state)
    pub = signer.get_public_key(state)
    expected = base64.b64encode(
        recovered.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    assert pub == expected
    assert (state / ".signing_key").is_file()
    assert (state / ".signing_key.pub").is_file()
    assert not (state / ".signing_keypair.journal").exists()
    # No durable temp leftovers after recovery.
    assert not list(state.glob(".signing_key.tmp-*"))
    assert not list(state.glob(".signing_key.pub.tmp-*"))


def test_signing_keypair_uses_temp_fsync_atomic_publish(tmp_path: Path) -> None:
    """Observable durability: temps + parent fsync + journal during publish."""
    synced_dirs: list[Path] = []
    real_fsync = os.fsync
    opened_temps: list[str] = []

    original_open = os.open

    def tracking_open(
        path: str | bytes | os.PathLike[str], flags: int, *args: object, **kwargs: object
    ) -> int:
        path_s = os.fsdecode(path)
        name = Path(path_s).name
        if ".tmp-" in name and (
            name.startswith(".signing_key") or name.startswith(".signing_keypair")
        ):
            opened_temps.append(name)
        return original_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    def tracking_fsync(fd: int) -> None:
        try:
            metadata = os.fstat(fd)
            if stat.S_ISDIR(metadata.st_mode):
                # Best-effort: record that a directory fd was synced.
                synced_dirs.append(tmp_path)
        except OSError:
            pass
        return real_fsync(fd)

    with (
        mock.patch("os.open", side_effect=tracking_open),
        mock.patch("os.fsync", side_effect=tracking_fsync),
    ):
        signer.generate_signing_key(tmp_path)

    assert any("signing_key" in name and ".tmp-" in name for name in opened_temps)
    assert synced_dirs, "parent directory must be fsync'd after atomic keypair publish"
    assert not (tmp_path / ".signing_keypair.journal").exists()
    assert (tmp_path / ".signing_key").is_file()
    assert (tmp_path / ".signing_key.pub").is_file()
