"""Sanitized evidence export + privacy scan (Round 8.11).

Layered layout (no self-hash cycles)::

    <out>/
      sanitized-export/
        ... allowlisted content ...
        MANIFEST.sha256
        archive_scan.receipt.json
      MANIFEST.envelope.json
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import tempfile
import zipfile
import zlib
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from js.echo.ledger.strict_json import (
    StrictJSONError,
    strict_load_object,
    strict_load_object_bytes,
    strict_load_path,
)

MANIFEST_NAME = "MANIFEST.sha256"
ENVELOPE_NAME = "MANIFEST.envelope.json"
EXPORT_DIR_NAME = "sanitized-export"
ARCHIVE_SCAN_RECEIPT_NAME = "archive_scan.receipt.json"
ARCHIVE_SCAN_SCHEMA = "js-agent-archive-scan-receipt-v1"
ARCHIVE_SCAN_RULE_VERSION = "archive-scan-rules-v9"
MANIFEST_SCHEMA = "js-agent-evidence-manifest-v2"
ENVELOPE_SCHEMA = "js-agent-evidence-envelope-v1"
DESKTOP_DESCRIPTOR_RELATIVE = "desktop-build/sanitized-descriptor.json"
DESKTOP_DESCRIPTOR_SCHEMA = "js-agent-sanitized-desktop-descriptor-v1"
DESKTOP_SUMMARY_BINDING_SCHEMA = "js-agent-sanitized-desktop-summary-binding-v1"
SUPERVISED_SOAK_COMBINED_RELATIVE = "soak/supervised_soak.combined.json"
SUPERVISED_SOAK_SCHEMA = "js-agent-supervised-soak-v1"
SUPERVISED_SOAK_SUMMARY_BINDING_SCHEMA = (
    "js-agent-sanitized-supervised-soak-summary-binding-v1"
)
_ORIGINAL_DESKTOP_MANIFEST_RELATIVE = Path("desktop-build/manifest.json")
_ORIGINAL_DESKTOP_MANIFEST_SCHEMA = "JSAgentDesktopProvenanceV4"
_MANIFEST_HEADER_KEYS: tuple[str, ...] = ("schema", "generated_utc", "entry_count")
_MANIFEST_HEADER_SCHEMA = f"# schema={MANIFEST_SCHEMA}"

_ALLOWLIST_GLOBS: tuple[str, ...] = (
    "gate_run_summary.json",
    "final_validator.receipt.json",
    "validator_inputs/*",
    "final/*.receipt.json",
    "gates/*.stdout.txt",
    "gates/*.stderr.txt",
    "slo/slo_run_*.json",
    "soak/ECHO_LIVE_ACCEPTANCE.json",
    SUPERVISED_SOAK_COMBINED_RELATIVE,
    "e2e/ECHO_ISOLATED_VENV_E2E.json",
    "e2e/*.receipt.json",
    "e2e/artifacts/*",
    "e2e/artifacts/**/*",
    "e2e/keys/*.public.b64",
    "e2e/keys/*.fingerprint",
    "e2e/E2E_KEY_PROVENANCE.json",
    "TOOLCHAIN.lock.json",
    "docs_promoted/*",
    "pack/JS_AGENT_FINAL_OPTIMIZATION_REPORT.md",
    "pack/JS_AGENT_FINAL_EVIDENCE.json",
    "pack/ECHO_10_ROUND_AUDIT.md",
    "pack/ECHO_FINAL_REPLACEMENT_REPORT.md",
    "ROUND89_FINAL.md",
    "ROUND810_FINAL.md",
    "ROUND811_FINAL.md",
    "FROZEN_DIGEST.txt",
    "FREEZE_META.txt",
    "archive_scan.receipt.json",
)

_EXCLUDE_NAME_MARKERS: frozenset[str] = frozenset(
    {
        "secrets.db",
        "api_keys.db",
        "ledger.ed25519.private",
        ".private",
        ".private_key_env_path",
        "mac_key",
        "permit.key",
        "lease.key",
        "journal.key",
    }
)

_EXCLUDE_DIR_NAMES: frozenset[str] = frozenset(
    {
        "runtime",
        "venv",
        "__pycache__",
        ".venv",
        "wheelhouse",
        "pre_fix",
        "failure",
        "failures",
        "failed",
        "historical",
        "cache",
        ".cache",
    }
)

# Generic home-path rules (no hardcoded real usernames).
_HOME_PATH_RE = re.compile(
    r"(?:"
    r"/Users/[^/\s\"']+"
    r"|/home/[^/\s\"']+"
    r"|C:\\\\Users\\\\[^\\\s\"']+"
    r")"
)

_PRIVACY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("absolute_home_path", _HOME_PATH_RE),
    ("pem_private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*")),
    (
        "provider_api_key",
        re.compile(r"(?i)\b(?:sk|xai|api)[_-]?(?:key|token)[_=:\s-]+[A-Za-z0-9]{16,}"),
    ),
    ("ed25519_private_file", re.compile(r"ledger\.ed25519\.private")),
)

# Exact, versioned allowlist entries for regex source / fixtures (no secret echo).
_PRIVACY_ALLOWLIST_RELATIVE: frozenset[str] = frozenset(
    {
        # Pattern definitions themselves are not findings when scanned as source in tests.
    }
)

_ARCHIVE_MAX_MEMBERS = 5000
_ARCHIVE_MAX_UNCOMPRESSED = 200 * 1024 * 1024
_ARCHIVE_MAX_RATIO = 200.0
_ARCHIVE_MAX_DEPTH = 4
_ARCHIVE_IO_CHUNK = 1024 * 1024
_ZIP_EOCD_MAX_TAIL = 22 + 0xFFFF
_ALLOWLIST_SOURCE_MAX_BYTES = 512 * 1024 * 1024
_SUPERVISED_SOAK_COUNTER_KEYS = frozenset(
    {
        "mode_switches",
        "app_restarts",
        "sidecar_recoveries",
        "ws_cancel_cycles",
        "r4_ops",
        "r6_ops",
    }
)
_SUPERVISED_SOAK_FIELDS = frozenset(
    {
        "schema_version",
        "ok",
        "started_utc",
        "finished_utc",
        "duration_seconds",
        "elapsed_seconds",
        "source_digest",
        "metadata_fingerprint",
        "core",
        "overlay",
        "combined_sha256",
    }
)
_SUPERVISED_SOAK_CORE_FIELDS = frozenset({"exit_code", "raw_sha256", "ok"})
_SUPERVISED_SOAK_OVERLAY_FIELDS = frozenset(
    {
        "exit_code",
        "raw_sha256",
        "ok",
        "targets",
        "counters",
        "targets_met",
        "cycles",
        "heartbeat_count",
        "max_heartbeat_gap_s",
        "max_heartbeat_gap_limit_s",
        "chain_root",
        "desktop_manifest_sha256",
        "app_tree_sha256",
        "app_sha256",
    }
)

_ARCHIVE_SCAN_RULE_IDS: frozenset[str] = frozenset(
    {
        "archive_absolute_home_path",
        "archive_bearer_token",
        "archive_compression_ratio",
        "archive_current_home",
        "archive_depth_limit",
        "archive_duplicate_member",
        "archive_ed25519_private_file",
        "archive_encrypted_member",
        "archive_hardlink",
        "archive_identity_changed",
        "archive_member_limit",
        "archive_member_name_absolute_home_path",
        "archive_member_name_bearer_token",
        "archive_member_name_current_home",
        "archive_member_name_ed25519_private_file",
        "archive_member_name_pem_private_key",
        "archive_member_name_private_name",
        "archive_member_name_provider_api_key",
        "archive_member_size_mismatch",
        "archive_metadata_forbidden",
        "archive_name_absolute_home_path",
        "archive_name_bearer_token",
        "archive_name_current_home",
        "archive_name_ed25519_private_file",
        "archive_name_pem_private_key",
        "archive_name_private_name",
        "archive_name_provider_api_key",
        "archive_non_utf8_member",
        "archive_path_escape",
        "archive_pem_private",
        "archive_private_name",
        "archive_provider_api_key",
        "archive_size_limit",
        "archive_special_file",
        "archive_special_member",
        "archive_symlink",
        "archive_unreadable",
        "archive_unreadable_member",
        "archive_unsupported_flags",
    }
)
_ARCHIVE_RULE_ID_RE = re.compile(r"archive_[a-z0-9]+(?:_[a-z0-9]+)*\Z")

_ZIP_ARCHIVE_SUFFIXES: tuple[str, ...] = (".whl", ".zip", ".xlsx", ".docx", ".pptx")
_ALLOWED_TEXT_FILE_SUFFIXES: frozenset[str] = frozenset(
    {
        ".b64",
        ".csv",
        ".fingerprint",
        ".html",
        ".json",
        ".log",
        ".md",
        ".py",
        ".sha256",
        ".toml",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)

_USERS_PATTERN_LITERAL = "/Users/" + "[^"
_HOME_PATTERN_LITERAL = "/home/" + "[^"
_PRIVATE_BASENAME_LITERAL = "ledger.ed25519." + "private"
_BEARER_AUTH_LITERAL = "Bearer " + "authorization"
_BEARER_JWT_LITERAL = "Bearer " + "abc.def.ghi"
_BEARER_ABC_LITERAL = "Bearer " + "abc"
_LOWER_BEARER_TOKEN_LITERAL = "bearer " + "token"
_BEARER_TOKEN_LITERAL = "Bearer " + "token"
_HOME_PARENT_LITERAL = "/home/" + ".."

_ARCHIVE_LITERAL_ALLOWANCES: dict[tuple[str, str, str], int] = {
    (
        "js/echo/ledger/evidence_export.py",
        "absolute_home_path",
        _USERS_PATTERN_LITERAL,
    ): 1,
    (
        "js/echo/ledger/evidence_export.py",
        "absolute_home_path",
        _HOME_PATTERN_LITERAL,
    ): 1,
    (
        "js/echo/ledger/evidence_export.py",
        "ed25519_private_file",
        _PRIVATE_BASENAME_LITERAL,
    ): 1,
    (
        "js/echo/ledger/e2e_signing.py",
        "ed25519_private_file",
        _PRIVATE_BASENAME_LITERAL,
    ): 1,
    ("js/echo/ledger/security_matrix.py", "bearer_token", _BEARER_AUTH_LITERAL): 1,
    ("js/echo/ledger/security_matrix.py", "bearer_token", _BEARER_JWT_LITERAL): 1,
    ("js/echo/ledger/security_matrix.py", "bearer_token", _BEARER_ABC_LITERAL): 1,
    ("js/models/capability.py", "bearer_token", _LOWER_BEARER_TOKEN_LITERAL): 1,
    ("js/models/providers.py", "bearer_token", _BEARER_TOKEN_LITERAL): 1,
    ("js/security/strategies.py", "absolute_home_path", _HOME_PARENT_LITERAL): 1,
}

_ARCHIVE_FONT_SHA256: dict[str, str] = {
    "js/web/static/vendor/fontawesome/webfonts/fa-brands-400.ttf": (
        "808443ae6c8204395add8543da8a90a6" + "0b9376fb0f87ed8e8ea37d109596d805"
    ),
    "js/web/static/vendor/fontawesome/webfonts/fa-brands-400.woff2": (
        "d7236a19bf23cbb2027280e8f51dc99d" + "6c45976a2ed60de73382b034b18a2b68"
    ),
    "js/web/static/vendor/fontawesome/webfonts/fa-regular-400.ttf": (
        "54cf6086f7bb21f9d072ad494a19b468" + "1fa516dd0a14cee52da01d3651a913a3"
    ),
    "js/web/static/vendor/fontawesome/webfonts/fa-regular-400.woff2": (
        "e3456d1283b9d75337a773dfd147bf90" + "8fd02c01b4bf48576d8603a69b13cbe5"
    ),
    "js/web/static/vendor/fontawesome/webfonts/fa-solid-900.ttf": (
        "d2f0593540b0e33ba6de255a54f272d" + "466e31144806956bea8cfdbf7edffc9bd"
    ),
    "js/web/static/vendor/fontawesome/webfonts/fa-solid-900.woff2": (
        "aa75998623a391e61c6901794ace832e" + "3ecdd288b56d608f21bea0411acc0b8e"
    ),
    "js/web/static/vendor/fontawesome/webfonts/fa-v4compatibility.ttf": (
        "30f6abf6baa425825828793d6dfad1fb" + "63765d0e5abaa7af6feafb9bfcece5a0"
    ),
    "js/web/static/vendor/fontawesome/webfonts/fa-v4compatibility.woff2": (
        "0ce9033c69dc714f5f45ef9bf17d55e" + "4c46bcdfad6799a4e92b38e7781bf86bd"
    ),
}


@dataclass(frozen=True)
class PrivacyHit:
    """Privacy finding without secret excerpts."""

    rule_id: str
    relative_path: str
    count: int


@dataclass(frozen=True)
class ExportResult:
    export_dir: Path
    manifest_path: Path
    envelope_path: Path
    entry_count: int
    total_bytes: int
    manifest_file_sha256: str
    envelope_file_sha256: str
    envelope_manifest_sha256: str
    validation_ok: bool = False
    passed_gates: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()

    @property
    def manifest_sha256(self) -> str:
        """Alias for manifest_file_sha256 (legacy field name)."""
        return self.manifest_file_sha256

    @property
    def envelope_sha256(self) -> str:
        """Alias for envelope_file_sha256 (legacy field name)."""
        return self.envelope_file_sha256


class _SanitizedExportRollbackError(RuntimeError):
    """Rollback failed; staging must remain available for manual recovery."""


def redact_text(
    text: str,
    *,
    repo_root: Path,
    evidence_root: Path,
    home: Path | None = None,
) -> str:
    """Normalize absolute paths before writing formal evidence copies."""
    replacements: list[tuple[str, str]] = []
    for path, token in (
        (evidence_root.resolve(), "<EVIDENCE_ROOT>"),
        (repo_root.resolve(), "<REPO_ROOT>"),
        ((home or Path.home()).resolve(), "<HOME>"),
    ):
        replacements.append((str(path), token))
        replacements.append((os.path.abspath(str(path)), token))
    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    out = text
    for raw, token in replacements:
        if raw:
            out = out.replace(raw, token)
    # Generic leftover home-style paths.
    out = _HOME_PATH_RE.sub("<HOME>", out)
    return out


def privacy_scan(root: Path) -> list[PrivacyHit]:
    """Fail-closed scan; hits never include matched secret text."""
    hits: list[PrivacyHit] = []
    resolved = root.resolve()
    for path in sorted(resolved.rglob("*")):
        if path.is_symlink():
            hits.append(
                PrivacyHit(rule_id="symlink_forbidden", relative_path=_rel(path, resolved), count=1)
            )
            continue
        if not path.is_file():
            continue
        mode = path.stat().st_mode
        if not stat.S_ISREG(mode):
            hits.append(
                PrivacyHit(rule_id="non_regular_file", relative_path=_rel(path, resolved), count=1)
            )
            continue
        relative = _rel(path, resolved)
        if relative in _PRIVACY_ALLOWLIST_RELATIVE:
            continue
        name_lower = path.name.lower()
        if any(marker in name_lower for marker in _EXCLUDE_NAME_MARKERS):
            hits.append(PrivacyHit(rule_id="excluded_name_marker", relative_path=relative, count=1))
        if _classify_scannable_archive_name(path.name) is not None:
            continue
        if path.suffix.lower() not in _ALLOWED_TEXT_FILE_SUFFIXES:
            hits.append(PrivacyHit(rule_id="unknown_file_type", relative_path=relative, count=1))
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            hits.append(PrivacyHit(rule_id="non_utf8_forbidden", relative_path=relative, count=1))
            continue
        except OSError:
            hits.append(PrivacyHit(rule_id="unreadable", relative_path=relative, count=1))
            continue
        for rule_id, pattern in _PRIVACY_PATTERNS:
            count = len(pattern.findall(text))
            if count:
                hits.append(PrivacyHit(rule_id=rule_id, relative_path=relative, count=count))
    return hits


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def privacy_scan_file(path: Path) -> list[PrivacyHit]:
    if not path.is_file():
        return [PrivacyHit(rule_id="missing", relative_path=path.name, count=1)]
    hits: list[PrivacyHit] = []
    if (
        _classify_scannable_archive_name(path.name) is None
        and path.suffix.lower() not in _ALLOWED_TEXT_FILE_SUFFIXES
    ):
        hits.append(PrivacyHit(rule_id="unknown_file_type", relative_path=path.name, count=1))
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        hits.append(PrivacyHit(rule_id="non_utf8_forbidden", relative_path=path.name, count=1))
        return hits
    for rule_id, pattern in _PRIVACY_PATTERNS:
        count = len(pattern.findall(text))
        if count:
            hits.append(PrivacyHit(rule_id=rule_id, relative_path=path.name, count=count))
    return hits


def format_privacy_hits(hits: Iterable[PrivacyHit]) -> str:
    """Render hits without secret excerpts."""
    parts = [f"{hit.rule_id}@{hit.relative_path}×{hit.count}" for hit in hits]
    return "; ".join(parts)


def _is_excluded(relative: Path) -> bool:
    parts_lower = {part.lower() for part in relative.parts}
    if parts_lower & _EXCLUDE_DIR_NAMES:
        return True
    name_lower = relative.name.lower()
    if any(marker in name_lower for marker in _EXCLUDE_NAME_MARKERS):
        return True
    return name_lower.endswith(".private") or name_lower.endswith("_private.pem")


@dataclass(frozen=True)
class _AllowlistedSource:
    relative: Path
    parent_identity: tuple[int, int]
    source_identity: tuple[int, int, int, int, int, int]
    parent_is_validator_inputs: bool = False


@dataclass
class _AllowlistedSources:
    values: list[_AllowlistedSource]
    validator_inputs_fd: int | None = None

    def __iter__(self) -> Iterator[_AllowlistedSource]:
        return iter(self.values)

    def close(self) -> None:
        if self.validator_inputs_fd is not None:
            os.close(self.validator_inputs_fd)
            self.validator_inputs_fd = None


def _directory_open_flags() -> int:
    if not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")):
        raise RuntimeError("safe allowlisted source open unsupported")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _source_open_flags() -> int:
    if not all(hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")):
        raise RuntimeError("safe allowlisted source open unsupported")
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def _source_identity(st: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def _require_safe_source_file(st: os.stat_result) -> None:
    if not stat.S_ISREG(st.st_mode):
        raise RuntimeError("non-regular file forbidden in allowlisted source")
    if st.st_nlink != 1:
        raise RuntimeError("hardlink forbidden in allowlisted source")
    if st.st_size < 0 or st.st_size > _ALLOWLIST_SOURCE_MAX_BYTES:
        raise RuntimeError("allowlisted source size invalid")


def _open_evidence_root(evidence_root: Path) -> int:
    try:
        fd = os.open(evidence_root, _directory_open_flags())
    except OSError:
        raise RuntimeError("allowlisted evidence root unreadable") from None
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise RuntimeError("allowlisted evidence root is not a directory")
    except Exception:
        os.close(fd)
        raise
    return fd


def _open_relative_directory(root_fd: int, relative: Path) -> int:
    current_fd = os.dup(root_fd)
    try:
        for part in relative.parts:
            try:
                st = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode):
                    raise RuntimeError("symlink forbidden in allowlisted source")
                if not stat.S_ISDIR(st.st_mode):
                    raise RuntimeError("allowlisted source has non-directory ancestor")
                next_fd = os.open(part, _directory_open_flags(), dir_fd=current_fd)
            except RuntimeError:
                raise
            except OSError:
                raise RuntimeError("allowlisted source unreadable") from None
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _validate_validator_inputs_ancestor(root_fd: int) -> tuple[int, tuple[int, int]] | None:
    try:
        st = os.stat("validator_inputs", dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise RuntimeError("validator_inputs ancestor unreadable") from None
    if stat.S_ISLNK(st.st_mode):
        raise RuntimeError("validator_inputs ancestor symlink forbidden")
    if not stat.S_ISDIR(st.st_mode):
        raise RuntimeError("validator_inputs ancestor must be a directory")
    fd = _open_relative_directory(root_fd, Path("validator_inputs"))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            st.st_dev,
            st.st_ino,
        ):
            raise RuntimeError("validator_inputs ancestor identity drift")
        return fd, (opened.st_dev, opened.st_ino)
    except Exception:
        os.close(fd)
        raise


def _capture_allowlisted_source(
    relative: Path,
    *,
    parent_fd: int,
    parent_identity: tuple[int, int],
    parent_is_validator_inputs: bool = False,
) -> _AllowlistedSource:
    try:
        source = os.stat(relative.name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise RuntimeError("allowlisted source unreadable") from None
    if stat.S_ISLNK(source.st_mode):
        raise RuntimeError("symlink forbidden in allowlisted source")
    _require_safe_source_file(source)
    return _AllowlistedSource(
        relative=relative,
        parent_identity=parent_identity,
        source_identity=_source_identity(source),
        parent_is_validator_inputs=parent_is_validator_inputs,
    )


def _allowlisted_relative(
    path: Path,
    *,
    evidence_root: Path,
    evidence_root_fd: int | None = None,
) -> _AllowlistedSource:
    """Capture a lexical source identity without following source path links."""
    try:
        relative = path.relative_to(evidence_root)
    except ValueError as exc:
        raise RuntimeError("allowlisted source path escape") from exc
    if not relative.parts or relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError("allowlisted source path escape")

    owns_root_fd = evidence_root_fd is None
    root_fd = (
        evidence_root_fd if evidence_root_fd is not None else _open_evidence_root(evidence_root)
    )
    parent_fd = -1
    try:
        parent_fd = _open_relative_directory(root_fd, relative.parent)
        parent = os.fstat(parent_fd)
        return _capture_allowlisted_source(
            relative,
            parent_fd=parent_fd,
            parent_identity=(parent.st_dev, parent.st_ino),
        )
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
        if owns_root_fd:
            os.close(root_fd)


def _iter_allowlisted_sources(
    evidence_root: Path, *, evidence_root_fd: int | None = None
) -> _AllowlistedSources:
    owns_root_fd = evidence_root_fd is None
    root_fd = (
        evidence_root_fd if evidence_root_fd is not None else _open_evidence_root(evidence_root)
    )
    validator_inputs_fd: int | None = None
    try:
        validator_inputs = _validate_validator_inputs_ancestor(root_fd)
        if validator_inputs is not None:
            validator_inputs_fd, validator_inputs_identity = validator_inputs
        found: dict[Path, _AllowlistedSource] = {}
        for pattern in _ALLOWLIST_GLOBS:
            if pattern == "validator_inputs/*":
                continue
            for path in evidence_root.glob(pattern):
                source = _allowlisted_relative(
                    path, evidence_root=evidence_root, evidence_root_fd=root_fd
                )
                if _is_excluded(source.relative):
                    continue
                found[source.relative] = source
        if validator_inputs_fd is not None:
            try:
                with os.scandir(validator_inputs_fd) as entries:
                    for entry in entries:
                        relative = Path("validator_inputs") / entry.name
                        source = _capture_allowlisted_source(
                            relative,
                            parent_fd=validator_inputs_fd,
                            parent_identity=validator_inputs_identity,
                            parent_is_validator_inputs=True,
                        )
                        if _is_excluded(source.relative):
                            continue
                        found[source.relative] = source
            except OSError:
                raise RuntimeError("validator_inputs ancestor unreadable") from None
        return _AllowlistedSources(
            values=[found[relative] for relative in sorted(found)],
            validator_inputs_fd=validator_inputs_fd,
        )
    except Exception:
        if validator_inputs_fd is not None:
            os.close(validator_inputs_fd)
        raise
    finally:
        if owns_root_fd:
            os.close(root_fd)


def _iter_allowlisted(evidence_root: Path) -> list[Path]:
    sources = _iter_allowlisted_sources(evidence_root)
    try:
        return [evidence_root / source.relative for source in sources]
    finally:
        sources.close()


def _assert_safe_member(path: Path, *, export_root: Path) -> os.stat_result:
    """lstat-only membership check; reject symlink/FIFO/device/hardlink/escape."""
    export_root = export_root.resolve()
    try:
        relative = path.relative_to(export_root)
    except ValueError:
        raise RuntimeError("path escape in export") from None
    if ".." in relative.parts or relative.is_absolute():
        raise RuntimeError("path escape component in export")
    # Do not Path.resolve() the member (would follow symlinks).
    try:
        st = path.lstat()
    except OSError:
        raise RuntimeError("unreadable export member") from None
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        raise RuntimeError("symlink forbidden in export")
    if not stat.S_ISREG(mode):
        raise RuntimeError("non-regular file forbidden in export")
    if st.st_nlink != 1:
        raise RuntimeError("hardlink forbidden in export")
    return st


def enumerate_export_regular_files(export_dir: Path) -> dict[str, os.stat_result]:
    """Shared safe tree walk for builder and verifier (lstat, regular files only)."""
    export_dir = export_dir.resolve()
    found: dict[str, os.stat_result] = {}

    def walk_error(_error: OSError) -> None:
        raise RuntimeError("unreadable export tree")

    for dirpath, dirnames, filenames in os.walk(
        export_dir,
        followlinks=False,
        onerror=walk_error,
    ):
        base = Path(dirpath)
        # Refuse directory symlinks in the walk frontier.
        for name in list(dirnames):
            child = base / name
            try:
                child_st = child.lstat()
            except OSError:
                raise RuntimeError("unreadable export dirent") from None
            if stat.S_ISLNK(child_st.st_mode):
                raise RuntimeError("directory symlink forbidden in export")
            if not stat.S_ISDIR(child_st.st_mode):
                raise RuntimeError("non-directory child in export tree")
        for name in filenames:
            path = base / name
            try:
                st = path.lstat()
                relative = path.relative_to(export_dir).as_posix()
            except OSError:
                raise RuntimeError("unreadable export member") from None
            except ValueError:
                raise RuntimeError("path escape in export") from None
            if relative == MANIFEST_NAME:
                # Manifest is the only intentional self-exclusion; still must be regular.
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise RuntimeError("MANIFEST.sha256 must be a regular nlink==1 file")
                continue
            if stat.S_ISLNK(st.st_mode):
                raise RuntimeError("symlink forbidden in export")
            if (
                stat.S_ISFIFO(st.st_mode)
                or stat.S_ISSOCK(st.st_mode)
                or stat.S_ISCHR(st.st_mode)
                or stat.S_ISBLK(st.st_mode)
            ):
                raise RuntimeError("forbidden special file in export")
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError("non-regular file forbidden in export")
            if st.st_nlink != 1:
                raise RuntimeError("hardlink/nlink forbidden in export")
            if ".." in Path(relative).parts:
                raise RuntimeError("path escape component in export")
            found[relative] = st
    return found


def _manifest_line(*, digest: str, file_type: str, mode: int, size: int, relative: str) -> str:
    mode_oct = f"{stat.S_IMODE(mode):04o}"
    return f"{digest}  {file_type}  {mode_oct}  {size}  {relative}"


def build_manifest_v2(export_dir: Path) -> tuple[Path, int, int]:
    export_dir = export_dir.resolve()
    members = enumerate_export_regular_files(export_dir)
    entries: list[tuple[str, str, int, int, str]] = []
    total_bytes = 0
    for relative in sorted(members):
        path = export_dir / relative
        st = _assert_safe_member(path, export_root=export_dir)
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        size = len(data)
        if size != st.st_size:
            raise RuntimeError(f"size drift while hashing {relative}")
        total_bytes += size
        entries.append((digest, "file", st.st_mode, size, relative))
    generated = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        _MANIFEST_HEADER_SCHEMA,
        f"# generated_utc={generated}",
        f"# entry_count={len(entries)}",
    ]
    for digest, file_type, mode, size, relative in entries:
        lines.append(
            _manifest_line(
                digest=digest, file_type=file_type, mode=mode, size=size, relative=relative
            )
        )
    manifest_path = export_dir / MANIFEST_NAME
    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest_path, len(entries), total_bytes


def verify_manifest_v2(export_dir: Path) -> None:
    """Strict Manifest v2 verification with exact headers and set closure."""
    export_dir = export_dir.resolve()
    manifest_path = export_dir / MANIFEST_NAME
    try:
        manifest_st = manifest_path.lstat()
    except OSError as exc:
        raise RuntimeError("MANIFEST.sha256 missing") from exc
    if (
        stat.S_ISLNK(manifest_st.st_mode)
        or not stat.S_ISREG(manifest_st.st_mode)
        or manifest_st.st_nlink != 1
    ):
        raise RuntimeError("MANIFEST.sha256 must be a regular nlink==1 file")
    lines = manifest_path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 3:
        raise RuntimeError("MANIFEST missing required headers")
    if lines[0] != _MANIFEST_HEADER_SCHEMA:
        raise RuntimeError("MANIFEST schema header mismatch")
    header_keys: list[str] = ["schema"]
    declared_count: int | None = None
    generated_utc: str | None = None
    for index, expected_key in enumerate(_MANIFEST_HEADER_KEYS[1:], start=1):
        line = lines[index]
        if not line.startswith("#") or "=" not in line:
            raise RuntimeError(f"bad MANIFEST header: {line!r}")
        key, value = line[1:].strip().split("=", 1)
        if key != expected_key:
            raise RuntimeError(f"MANIFEST header order/key mismatch: {key!r}!={expected_key!r}")
        if key in header_keys:
            raise RuntimeError(f"duplicate MANIFEST header: {key}")
        header_keys.append(key)
        if key == "generated_utc":
            generated_utc = value
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
                raise RuntimeError("MANIFEST generated_utc format invalid")
        elif key == "entry_count":
            try:
                declared_count = int(value)
            except ValueError as exc:
                raise RuntimeError("MANIFEST entry_count invalid") from exc
    listed: dict[str, tuple[str, str, int]] = {}
    for line in lines[len(_MANIFEST_HEADER_KEYS) :]:
        if line.startswith("#"):
            raise RuntimeError(f"unknown or trailing MANIFEST header: {line!r}")
        if not line:
            continue
        parts = line.split()
        if len(parts) != 5:
            raise RuntimeError(f"bad MANIFEST line: {line!r}")
        digest, file_type, mode_oct, size_s, relative = parts
        if file_type != "file":
            raise RuntimeError(f"unsupported type {file_type}")
        if not re.fullmatch(r"[0-7]{4}", mode_oct):
            raise RuntimeError(f"bad mode octal: {mode_oct}")
        if ".." in Path(relative).parts or relative.startswith("/"):
            raise RuntimeError(f"path escape in MANIFEST: {relative}")
        if relative == MANIFEST_NAME:
            raise RuntimeError("MANIFEST must not list itself")
        if relative in listed:
            raise RuntimeError(f"duplicate MANIFEST path: {relative}")
        listed[relative] = (digest, mode_oct, int(size_s))
    if generated_utc is None or declared_count is None:
        raise RuntimeError("MANIFEST missing required headers")
    if tuple(header_keys) != _MANIFEST_HEADER_KEYS:
        raise RuntimeError(f"MANIFEST headers must be exactly {_MANIFEST_HEADER_KEYS}")
    if declared_count != len(listed):
        raise RuntimeError("MANIFEST entry_count mismatch")

    actual_files = enumerate_export_regular_files(export_dir)
    if set(listed) != set(actual_files):
        missing = sorted(set(listed) - set(actual_files))
        extra = sorted(set(actual_files) - set(listed))
        raise RuntimeError(f"manifest set mismatch missing={missing[:5]} extra={extra[:5]}")

    for relative, (digest, mode_oct, size) in listed.items():
        path = export_dir / relative
        st = _assert_safe_member(path, export_root=export_dir)
        actual_mode = f"{stat.S_IMODE(st.st_mode):04o}"
        if actual_mode != mode_oct:
            raise RuntimeError(f"mode mismatch for {relative}: {actual_mode}!={mode_oct}")
        data = path.read_bytes()
        if len(data) != size:
            raise RuntimeError(f"size mismatch for {relative}")
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError(f"sha256 mismatch for {relative}")


def write_envelope(
    *,
    out_root: Path,
    manifest_path: Path,
    source_digest: str,
    entry_count: int,
) -> tuple[Path, str]:
    """Write envelope; return (path, payload manifest_sha256)."""
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    payload = {
        "schema_version": ENVELOPE_SCHEMA,
        "source_digest": source_digest,
        "manifest_sha256": manifest_sha,
        "manifest_relative": f"{EXPORT_DIR_NAME}/{MANIFEST_NAME}",
        "entry_count": entry_count,
        "generated_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_a_third_party_signature": True,
        "notes": (
            "Envelope sits outside the MANIFEST self-reference loop. "
            "Hashes prove local packaging consistency only. "
            "Report manifest_file_sha256 / envelope_file_sha256 / "
            "envelope_manifest_sha256 separately."
        ),
    }
    envelope_path = out_root / ENVELOPE_NAME
    envelope_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return envelope_path, manifest_sha


def _read_allowlisted_source(
    source: _AllowlistedSource,
    *,
    evidence_root_fd: int,
    validator_inputs_fd: int | None,
) -> tuple[bytes, os.stat_result, int]:
    """Read exactly one snapshot-bound source from descriptor-relative handles."""
    parent_fd = -1
    descriptor = -1
    try:
        if source.parent_is_validator_inputs:
            if validator_inputs_fd is None:
                raise RuntimeError("validator_inputs ancestor unavailable")
            parent_fd = os.dup(validator_inputs_fd)
            current_parent_fd = _open_relative_directory(evidence_root_fd, Path("validator_inputs"))
            try:
                current_parent = os.fstat(current_parent_fd)
                if (current_parent.st_dev, current_parent.st_ino) != source.parent_identity:
                    raise RuntimeError("validator_inputs ancestor identity drift")
            finally:
                os.close(current_parent_fd)
        else:
            parent_fd = _open_relative_directory(evidence_root_fd, source.relative.parent)

        parent = os.fstat(parent_fd)
        if (parent.st_dev, parent.st_ino) != source.parent_identity:
            raise RuntimeError("allowlisted source parent identity drift")
        try:
            descriptor = os.open(source.relative.name, _source_open_flags(), dir_fd=parent_fd)
        except OSError:
            descriptor = -1
        if descriptor < 0:
            raise RuntimeError("allowlisted source unreadable")
        before = os.fstat(descriptor)
        _require_safe_source_file(before)
        if _source_identity(before) != source.source_identity:
            raise RuntimeError("allowlisted source identity drift")

        payload = bytearray()
        while len(payload) <= _ALLOWLIST_SOURCE_MAX_BYTES:
            chunk = os.read(
                descriptor, min(1024 * 1024, _ALLOWLIST_SOURCE_MAX_BYTES + 1 - len(payload))
            )
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            _source_identity(after) != source.source_identity
            or len(payload) != before.st_size
            or len(payload) > _ALLOWLIST_SOURCE_MAX_BYTES
        ):
            raise RuntimeError("allowlisted source identity drift")

        current_parent_fd = _open_relative_directory(
            evidence_root_fd,
            Path("validator_inputs")
            if source.parent_is_validator_inputs
            else source.relative.parent,
        )
        try:
            current_parent = os.fstat(current_parent_fd)
            if (current_parent.st_dev, current_parent.st_ino) != source.parent_identity:
                if source.parent_is_validator_inputs:
                    raise RuntimeError("validator_inputs ancestor identity drift")
                raise RuntimeError("allowlisted source parent identity drift")
            try:
                current = os.stat(
                    source.relative.name, dir_fd=current_parent_fd, follow_symlinks=False
                )
            except OSError:
                raise RuntimeError("allowlisted source identity drift") from None
            if stat.S_ISLNK(current.st_mode) or _source_identity(current) != source.source_identity:
                raise RuntimeError("allowlisted source identity drift")
        finally:
            os.close(current_parent_fd)
        return bytes(payload), before, descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def _verify_allowlisted_source_after_copy(
    source: _AllowlistedSource,
    *,
    evidence_root_fd: int,
    validator_inputs_fd: int | None,
    descriptor: int,
) -> None:
    try:
        after = os.fstat(descriptor)
        _require_safe_source_file(after)
        if _source_identity(after) != source.source_identity:
            raise RuntimeError("allowlisted source identity drift")
        if source.parent_is_validator_inputs:
            if validator_inputs_fd is None:
                raise RuntimeError("validator_inputs ancestor unavailable")
            held_parent = os.fstat(validator_inputs_fd)
            if (held_parent.st_dev, held_parent.st_ino) != source.parent_identity:
                raise RuntimeError("validator_inputs ancestor identity drift")
            parent_path = Path("validator_inputs")
        else:
            parent_path = source.relative.parent
        parent_fd = _open_relative_directory(evidence_root_fd, parent_path)
        try:
            parent = os.fstat(parent_fd)
            if (parent.st_dev, parent.st_ino) != source.parent_identity:
                if source.parent_is_validator_inputs:
                    raise RuntimeError("validator_inputs ancestor identity drift")
                raise RuntimeError("allowlisted source parent identity drift")
            current = os.stat(source.relative.name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(current.st_mode) or _source_identity(current) != source.source_identity:
                raise RuntimeError("allowlisted source identity drift")
        finally:
            os.close(parent_fd)
    except OSError:
        raise RuntimeError("allowlisted source identity drift") from None


def _write_new_export_member(dest: Path, payload: bytes, *, mode: int) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = -1
    try:
        descriptor = os.open(dest, flags, stat.S_IMODE(mode))
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise RuntimeError("export destination unsafe")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short export write")
            offset += written
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _copy_allowlisted_source(
    source: _AllowlistedSource,
    dest: Path,
    *,
    evidence_root_fd: int,
    validator_inputs_fd: int | None,
    repo_root: Path,
    evidence_root: Path,
) -> None:
    payload, source_stat, source_fd = _read_allowlisted_source(
        source,
        evidence_root_fd=evidence_root_fd,
        validator_inputs_fd=validator_inputs_fd,
    )
    created = False
    try:
        if source.relative.suffix.lower() not in {
            ".whl",
            ".gz",
            ".zip",
            ".png",
            ".jpg",
            ".jpeg",
            ".xlsx",
        }:
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                pass
            else:
                payload = redact_text(
                    text, repo_root=repo_root, evidence_root=evidence_root
                ).encode("utf-8")
        _write_new_export_member(dest, payload, mode=source_stat.st_mode)
        created = True
        _verify_allowlisted_source_after_copy(
            source,
            evidence_root_fd=evidence_root_fd,
            validator_inputs_fd=validator_inputs_fd,
            descriptor=source_fd,
        )
    except Exception:
        if created:
            try:
                dest.unlink()
            except OSError:
                pass
        raise
    finally:
        os.close(source_fd)


def _copy_redacted(
    src: Path,
    dest: Path,
    *,
    repo_root: Path,
    evidence_root: Path,
) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if src.suffix.lower() in {".whl", ".gz", ".zip", ".png", ".jpg", ".jpeg", ".xlsx"}:
        shutil.copy2(src, dest)
        return
    try:
        text = src.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        shutil.copy2(src, dest)
        return
    redacted = redact_text(text, repo_root=repo_root, evidence_root=evidence_root)
    dest.write_text(redacted, encoding="utf-8")


def _normalize_export_log_relative(raw: str, *, gate_name: str, kind: str) -> str:
    """Require exact gates/<gate_name>.{stdout,stderr}.txt after token strip."""
    cleaned = raw.replace("<EVIDENCE_ROOT>/", "").replace("<REPO_ROOT>/", "").lstrip("/")
    expected = f"gates/{gate_name}.{kind}.txt"
    if cleaned != expected:
        raise RuntimeError(
            f"log path must be exactly {expected}, got {cleaned!r} for gate {gate_name}"
        )
    return expected


def _portable_gate_artifact_relative(gate_name: str) -> str | None:
    if gate_name == "soak_3600":
        return SUPERVISED_SOAK_COMBINED_RELATIVE
    if gate_name == "isolated_venv_e2e":
        return "e2e/ECHO_ISOLATED_VENV_E2E.json"
    if re.fullmatch(r"slo_run_[1-5]", gate_name) is not None:
        return f"slo/{gate_name}.json"
    if gate_name == "echo_full_audit":
        return "pack/ECHO_10_ROUND_AUDIT.md"
    return None


def _verify_export_receipt_artifact_closure(
    *,
    export_dir: Path,
    gate_name: str,
    receipt: Mapping[str, object],
) -> None:
    relative = _portable_gate_artifact_relative(gate_name)
    claimed = receipt.get("artifact_sha256")
    if relative is None:
        if claimed is not None:
            raise RuntimeError(f"unexpected artifact_sha256 for {gate_name}")
        return
    if not _is_lower_sha256(claimed):
        raise RuntimeError(f"artifact_sha256 missing or invalid for {gate_name}")
    artifact = export_dir / relative
    _assert_safe_member(artifact, export_root=export_dir)
    if hashlib.sha256(artifact.read_bytes()).hexdigest() != claimed:
        raise RuntimeError(f"artifact sha mismatch for {gate_name}")


def verify_export_receipt_log_closure(
    *,
    export_dir: Path,
    expected_source_digest: str,
    required_gates: Sequence[str] | None = None,
    min_receipts: int | None = None,
) -> None:
    """Independently re-verify every final receipt against exported stdout/stderr."""
    from js.echo.ledger.release_gates import REQUIRED_FINAL_LOCAL_GATES, parse_gate_stdout

    expected_gates = (
        tuple(required_gates) if required_gates is not None else REQUIRED_FINAL_LOCAL_GATES
    )
    if min_receipts is not None and min_receipts != len(expected_gates):
        raise RuntimeError(
            f"min_receipts={min_receipts} conflicts with required_gates count={len(expected_gates)}"
        )
    final_dir = export_dir / "final"
    if not final_dir.is_dir():
        raise RuntimeError("export missing final/")
    gates_dir = export_dir / "gates"
    if not gates_dir.is_dir():
        raise RuntimeError("export missing gates/")

    # Exact gates/ file set: 2 regular files per required gate, no extras/aliases.
    expected_log_relatives = {f"gates/{gate}.stdout.txt" for gate in expected_gates} | {
        f"gates/{gate}.stderr.txt" for gate in expected_gates
    }
    actual_gate_files: set[str] = set()
    for path in gates_dir.iterdir():
        st = path.lstat()
        if stat.S_ISDIR(st.st_mode):
            raise RuntimeError(f"unexpected directory under gates/: {path.name}")
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise RuntimeError(f"gates/ member must be regular nlink==1: {path.name}")
        actual_gate_files.add(f"gates/{path.name}")
    if actual_gate_files != expected_log_relatives:
        missing = sorted(expected_log_relatives - actual_gate_files)
        extra = sorted(actual_gate_files - expected_log_relatives)
        raise RuntimeError(f"gates/ set mismatch missing={missing[:5]} extra={extra[:5]}")

    receipts_by_gate: dict[str, dict[str, object]] = {}
    for receipt_path in sorted(final_dir.iterdir()):
        if not receipt_path.name.endswith(".receipt.json"):
            continue
        st = receipt_path.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise RuntimeError(f"receipt must be regular nlink==1: {receipt_path.name}")
        try:
            receipt = strict_load_path(receipt_path)
        except StrictJSONError as exc:
            raise RuntimeError(f"receipt JSON invalid: {receipt_path.name}") from exc
        if not isinstance(receipt, dict):
            raise RuntimeError(f"receipt not object: {receipt_path.name}")
        gate_name = receipt.get("gate_name")
        if not isinstance(gate_name, str) or not gate_name:
            raise RuntimeError(f"receipt missing gate_name: {receipt_path.name}")
        if receipt_path.name != f"{gate_name}.receipt.json":
            raise RuntimeError(f"receipt filename mismatch: {receipt_path.name}")
        if gate_name in receipts_by_gate:
            raise RuntimeError(f"duplicate receipt for gate: {gate_name}")
        receipts_by_gate[gate_name] = receipt

    if set(receipts_by_gate) != set(expected_gates):
        missing = sorted(set(expected_gates) - set(receipts_by_gate))
        extra = sorted(set(receipts_by_gate) - set(expected_gates))
        raise RuntimeError(f"receipt gate set mismatch missing={missing[:5]} extra={extra[:5]}")

    for gate_name in expected_gates:
        receipt = receipts_by_gate[gate_name]
        for field in ("stdout_path", "stderr_path", "stdout_sha256", "stderr_sha256"):
            if field not in receipt:
                raise RuntimeError(f"receipt missing {field}: {gate_name}")
        stdout_rel = _normalize_export_log_relative(
            str(receipt["stdout_path"]), gate_name=gate_name, kind="stdout"
        )
        stderr_rel = _normalize_export_log_relative(
            str(receipt["stderr_path"]), gate_name=gate_name, kind="stderr"
        )
        for relative, digest_field in (
            (stdout_rel, "stdout_sha256"),
            (stderr_rel, "stderr_sha256"),
        ):
            log_path = export_dir / relative
            digest = hashlib.sha256(log_path.read_bytes()).hexdigest()
            if digest != receipt[digest_field]:
                raise RuntimeError(f"log sha mismatch for {gate_name}:{relative}")
        stdout_text = (export_dir / stdout_rel).read_text(encoding="utf-8")
        output_parse = receipt.get("output_parse")
        if not isinstance(output_parse, dict):
            raise RuntimeError(f"receipt missing output_parse: {gate_name}")
        parser = output_parse.get("parser")
        if not isinstance(parser, str):
            raise RuntimeError(f"receipt missing parser: {gate_name}")
        exit_code = receipt.get("exit_code")
        if not isinstance(exit_code, int) or isinstance(exit_code, bool):
            raise RuntimeError(f"receipt bad exit_code: {gate_name}")
        require_zero = bool(output_parse.get("require_exit_code_zero", True))

        parsed = parse_gate_stdout(
            parser,
            stdout_text,
            exit_code=exit_code,
            require_exit_code_zero=require_zero,
            expected_gate=gate_name,
        )
        if parsed != receipt.get("parse_result"):
            raise RuntimeError(f"parse_result mismatch for {gate_name}")
        if parsed.get("ok") is not True:
            raise RuntimeError(f"reparsed stdout not ok for {gate_name}")
        if parser == "release_markers":
            payload_obj = parsed.get("payload")
            if not isinstance(payload_obj, dict) or payload_obj.get("gate") != gate_name:
                raise RuntimeError(f"release marker gate identity mismatch for {gate_name}")
        for digest_field in ("source_digest_before", "source_digest_after"):
            digest_value = receipt.get(digest_field)
            if digest_value != expected_source_digest:
                raise RuntimeError(f"{digest_field} mismatch for {gate_name}")
        _verify_export_receipt_artifact_closure(
            export_dir=export_dir,
            gate_name=gate_name,
            receipt=receipt,
        )


def _classify_release_archive_name(name: str) -> str | None:
    """Classify canonical release archives and reject mixed-case suspects."""
    lower = name.lower()
    if lower.endswith(".whl"):
        if not name.endswith(".whl"):
            raise RuntimeError("archive extension must use canonical lowercase")
        return "wheel"
    if lower.endswith(".tar.gz"):
        if not name.endswith(".tar.gz"):
            raise RuntimeError("archive extension must use canonical lowercase")
        return "sdist"
    return None


def _classify_scannable_archive_name(name: str) -> str | None:
    """Return the closed-set archive type accepted in sanitized evidence."""
    lower = name.lower()
    if lower.endswith(".tar.gz"):
        if not name.endswith(".tar.gz"):
            raise RuntimeError("archive extension must use canonical lowercase")
        return "tar_gz"
    for suffix in _ZIP_ARCHIVE_SUFFIXES:
        if lower.endswith(suffix):
            if not name.endswith(suffix):
                raise RuntimeError("archive extension must use canonical lowercase")
            return "zip"
    return None


def _collect_export_archives(export_dir: Path) -> list[Path]:
    """lstat-safe full-tree enumeration of *.whl / *.tar.gz under export_dir.

    Builder and readonly verifier share this function. Every archive anywhere in
    the sanitized-export tree is visible; refusing to copy dist/ is not a
    substitute for verifier closure. Symlinks, hardlinks (nlink!=1), FIFOs,
    sockets, device nodes, and path escapes are rejected.
    """
    if not export_dir.is_dir():
        return []
    try:
        root_resolved = export_dir.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("export dir unreadable for archive enumeration") from exc

    archives: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(export_dir, topdown=True, followlinks=False):
        current = Path(dirpath)
        try:
            current.resolve(strict=True).relative_to(root_resolved)
        except (OSError, ValueError) as exc:
            raise RuntimeError("export tree path escape detected") from exc

        kept_dirs: list[str] = []
        for name in sorted(dirnames):
            child = current / name
            try:
                st = child.lstat()
            except OSError as exc:
                raise RuntimeError("export tree directory entry unreadable") from exc
            if stat.S_ISLNK(st.st_mode):
                raise RuntimeError("export tree refuses symlink directory")
            if not stat.S_ISDIR(st.st_mode):
                raise RuntimeError("export tree refuses non-directory walk entry")
            kept_dirs.append(name)
        dirnames[:] = kept_dirs

        for name in sorted(filenames):
            if _classify_release_archive_name(name) is None:
                continue
            path = current / name
            try:
                st = path.lstat()
            except OSError as exc:
                raise RuntimeError("archive entry unreadable") from exc
            rel = path.relative_to(export_dir).as_posix()
            if ".." in Path(rel).parts:
                raise RuntimeError("archive path escape")
            if stat.S_ISLNK(st.st_mode):
                raise RuntimeError("archive must not be symlink")
            if (
                stat.S_ISFIFO(st.st_mode)
                or stat.S_ISSOCK(st.st_mode)
                or stat.S_ISCHR(st.st_mode)
                or stat.S_ISBLK(st.st_mode)
            ):
                raise RuntimeError("archive must not be special file")
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError("archive must be regular file")
            if int(st.st_nlink) != 1:
                raise RuntimeError("archive must have nlink==1")
            try:
                path.resolve(strict=False).relative_to(root_resolved)
            except ValueError as exc:
                raise RuntimeError("archive path escape") from exc
            archives.append(path)

    basenames = [path.name for path in archives]
    if len(basenames) != len(set(basenames)):
        raise RuntimeError("export archives have duplicate basenames")
    return archives


def _collect_scannable_archives(export_dir: Path) -> list[Path]:
    """Enumerate every accepted binary archive in the export tree safely."""
    members = enumerate_export_regular_files(export_dir)
    return [
        export_dir / relative
        for relative in sorted(members)
        if _classify_scannable_archive_name(Path(relative).name) is not None
    ]


def write_archive_scan_receipt(
    export_dir: Path,
    *,
    source_digest: str,
    hits: Sequence[PrivacyHit],
) -> Path:
    """Bind archive scan results to frozen digest + per-artifact identity."""
    if any(not _archive_rule_id_safe(hit.rule_id) for hit in hits):
        raise RuntimeError("archive scan rule_id rejected")
    if any(not _archive_artifact_identity_safe(hit.relative_path) for hit in hits):
        raise RuntimeError("archive scan hit identity rejected")
    canonical_hits = _canonical_hit_tuples_from_objects(hits)
    if len(canonical_hits) != len(set(canonical_hits)):
        raise RuntimeError("archive scan hits contain duplicate hit entries")
    artifacts: list[dict[str, object]] = []
    for path in _collect_scannable_archives(export_dir):
        relative = path.relative_to(export_dir).as_posix()
        if not _archive_artifact_identity_safe(relative) or not _archive_artifact_identity_safe(
            path.name
        ):
            raise RuntimeError("archive artifact path rejected")
        data = path.read_bytes()
        artifacts.append(
            {
                "relative_path": relative,
                "filename": path.name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    payload = {
        "schema_version": ARCHIVE_SCAN_SCHEMA,
        "rule_version": ARCHIVE_SCAN_RULE_VERSION,
        "source_digest": source_digest,
        "artifacts": artifacts,
        "hit_count": len(hits),
        "hits": [
            {"rule_id": hit.rule_id, "relative_path": hit.relative_path, "count": hit.count}
            for hit in hits
        ],
        "ok": len(hits) == 0,
        "generated_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    path = export_dir / ARCHIVE_SCAN_RECEIPT_NAME
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _canonical_hit_tuples_from_objects(hits: Sequence[PrivacyHit]) -> list[tuple[str, str, int]]:
    return sorted((hit.rule_id, hit.relative_path, int(hit.count)) for hit in hits)


def _canonical_hit_tuples_from_dicts(hits: object) -> list[tuple[str, str, int]]:
    if not isinstance(hits, list):
        raise RuntimeError("archive scan hits must be a list")
    out: list[tuple[str, str, int]] = []
    for item in hits:
        if not isinstance(item, dict):
            raise RuntimeError("archive scan hit entry invalid")
        rule_id = item.get("rule_id")
        relative_path = item.get("relative_path")
        count = item.get("count")
        if (
            not isinstance(rule_id, str)
            or not isinstance(relative_path, str)
            or not isinstance(count, int)
            or isinstance(count, bool)
        ):
            raise RuntimeError("archive scan hit identity invalid")
        if not _archive_rule_id_safe(rule_id):
            raise RuntimeError("archive scan rule_id rejected")
        if not _archive_artifact_identity_safe(relative_path):
            raise RuntimeError("archive scan hit identity rejected")
        out.append((rule_id, relative_path, int(count)))
    return sorted(out)


def _parse_e2e_declared_artifacts(e2e: object) -> dict[str, tuple[str, int, str]]:
    """Extract {relative_path: (filename, size, sha256)} from E2E JSON artifacts.

    A valid final E2E result explicitly reports success and declares exactly one
    canonical wheel plus one canonical sdist under e2e/artifacts/.
    """
    declared: dict[str, tuple[str, int, str]] = {}
    if not isinstance(e2e, dict):
        raise RuntimeError("e2e artifact declaration invalid")
    if e2e.get("ok") is not True:
        raise RuntimeError("e2e artifact declaration not successful")
    artifacts = e2e.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise RuntimeError("e2e artifact declaration missing artifacts")
    expected_kinds = {"wheel", "sdist"}
    if set(artifacts) != expected_kinds:
        raise RuntimeError(
            "e2e artifact declaration closure mismatch "
            f"expected_count={len(expected_kinds)} actual_count={len(artifacts)}"
        )
    for kind in ("wheel", "sdist"):
        meta = artifacts[kind]
        if not isinstance(meta, dict):
            raise RuntimeError("e2e artifact meta invalid")
        relative = meta.get("path")
        size = meta.get("bytes") if "bytes" in meta else meta.get("size")
        digest = meta.get("sha256")
        if not isinstance(relative, str) or not isinstance(digest, str):
            raise RuntimeError("e2e artifact meta incomplete")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise RuntimeError("e2e artifact size invalid")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise RuntimeError("e2e artifact digest invalid")
        pure = PurePosixPath(relative)
        if (
            not relative
            or "\\" in relative
            or pure.is_absolute()
            or pure.as_posix() != relative
            or len(pure.parts) != 3
            or pure.parts[:2] != ("e2e", "artifacts")
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            raise RuntimeError("e2e artifact declaration path invalid")
        filename = pure.name
        if not _archive_artifact_identity_safe(
            relative
        ) or not _archive_artifact_identity_safe(filename):
            raise RuntimeError("e2e artifact path rejected")
        archive_kind = _classify_release_archive_name(filename)
        if archive_kind != kind:
            raise RuntimeError("e2e artifact declaration format invalid")
        if relative in declared:
            raise RuntimeError("duplicate e2e declared artifact path")
        declared[relative] = (filename, int(size), digest)
    return declared


def verify_archive_scan_receipt(
    export_dir: Path,
    *,
    source_digest: str,
    e2e_artifact_json: Path | None = None,
) -> None:
    """Re-verify archive scan by rescanning current bytes; never trust receipt hits.

    Recomputes the archive file set, per-artifact identity (relative path,
    filename, size, SHA-256), scan rule version, canonical hits, hit_count and
    ok from the actual on-disk archives, then compares to the receipt. Rejects
    missed hits, forged hits, hit_count mismatch, duplicate hits, stale rule
    version, extra/missing/duplicate-basename archives, and dist/+e2e/
    coexistence. The current HOME is held in memory only for the rescan and is
    never written to the receipt, logs, or export.
    """
    receipt_path = export_dir / ARCHIVE_SCAN_RECEIPT_NAME
    try:
        payload = strict_load_object(receipt_path)
    except (OSError, StrictJSONError, ValueError) as exc:
        raise RuntimeError("archive_scan.receipt.json missing or invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("archive_scan.receipt.json not an object")
    if payload.get("schema_version") != ARCHIVE_SCAN_SCHEMA:
        raise RuntimeError("archive scan schema mismatch")
    if payload.get("rule_version") != ARCHIVE_SCAN_RULE_VERSION:
        raise RuntimeError("archive scan rule_version mismatch (stale or forged)")
    if payload.get("source_digest") != source_digest:
        raise RuntimeError("archive scan source_digest mismatch")

    # --- Recompute actual archive set from export dir (lstat-safe). ---
    actual_archives: dict[str, Path] = {}
    for path in _collect_scannable_archives(export_dir):
        relative = path.relative_to(export_dir).as_posix()
        if not _archive_artifact_identity_safe(relative):
            raise RuntimeError("archive artifact path rejected")
        actual_archives[relative] = path
    release_archives: dict[str, Path] = {}
    for path in _collect_export_archives(export_dir):
        relative = path.relative_to(export_dir).as_posix()
        if not _archive_artifact_identity_safe(relative):
            raise RuntimeError("release archive path rejected")
        release_archives[relative] = path

    # --- Parse receipt artifacts and require exact set + identity match. ---
    receipt_artifacts: dict[str, tuple[str, int, str]] = {}
    listed = payload.get("artifacts")
    if not isinstance(listed, list):
        raise RuntimeError("archive scan artifacts missing")
    for item in listed:
        if not isinstance(item, dict):
            raise RuntimeError("archive scan artifact entry invalid")
        receipt_relative = item.get("relative_path")
        filename = item.get("filename")
        size = item.get("size")
        digest = item.get("sha256")
        if (
            not isinstance(receipt_relative, str)
            or not isinstance(filename, str)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not isinstance(digest, str)
            or Path(receipt_relative).name != filename
        ):
            raise RuntimeError("archive scan artifact identity invalid")
        if not _archive_artifact_identity_safe(
            receipt_relative
        ) or not _archive_artifact_identity_safe(filename):
            raise RuntimeError("archive scan artifact identity rejected")
        if receipt_relative in receipt_artifacts:
            raise RuntimeError("duplicate archive scan artifact path")
        receipt_artifacts[receipt_relative] = (filename, int(size), digest)

    if set(receipt_artifacts) != set(actual_archives):
        missing_count = len(set(receipt_artifacts) - set(actual_archives))
        extra_count = len(set(actual_archives) - set(receipt_artifacts))
        raise RuntimeError(
            f"archive set mismatch missing_count={missing_count} extra_count={extra_count}"
        )
    for relative, (filename, size, digest) in receipt_artifacts.items():
        path = actual_archives[relative]
        if path.name != filename:
            raise RuntimeError("archive filename mismatch")
        data = path.read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError("archive identity drift")

    # --- Task D: exact closure against E2E JSON declared artifacts. ---
    declared: dict[str, tuple[str, int, str]] | None = None
    if e2e_artifact_json is not None:
        try:
            e2e_stat = e2e_artifact_json.lstat()
        except OSError:
            raise RuntimeError("e2e artifact JSON missing or invalid") from None
        if stat.S_ISLNK(e2e_stat.st_mode) or not stat.S_ISREG(e2e_stat.st_mode):
            raise RuntimeError("e2e artifact JSON must be a regular non-symlink file")
        try:
            e2e = strict_load_object(e2e_artifact_json)
        except (OSError, StrictJSONError, ValueError):
            raise RuntimeError("e2e artifact JSON missing or invalid") from None
        declared = _parse_e2e_declared_artifacts(e2e)
        # Exact equality: exported archive paths == E2E declared paths (not subset).
        if set(release_archives) != set(declared):
            raise RuntimeError(
                "e2e artifact closure mismatch "
                f"missing_count={len(set(declared) - set(release_archives))} "
                f"extra_count={len(set(release_archives) - set(declared))}"
            )
        for relative, (filename, size, digest) in declared.items():
            path = release_archives[relative]
            if path.name != filename:
                raise RuntimeError("e2e artifact filename mismatch")
            data = path.read_bytes()
            if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError("e2e artifact identity drift")
        if declared:
            # Reject duplicate basenames among declared artifacts.
            basenames = [Path(r).name for r in declared]
            if len(basenames) != len(set(basenames)):
                raise RuntimeError("e2e declared artifacts have duplicate basenames")
            # Reject dist/+e2e/ coexistence: declared paths must all live under one root.
            roots = {Path(r).parts[0] for r in declared}
            if len(roots) != 1:
                raise RuntimeError("e2e declared artifacts span multiple roots")
    # --- Task C: rescan current bytes; recompute canonical hits/hit_count/ok. ---
    current_home = str(Path.home().resolve())  # in memory only; never persisted.
    recomputed_hits: list[PrivacyHit] = []
    for relative in sorted(actual_archives):
        recomputed_hits.extend(
            scan_archive_members(actual_archives[relative], current_home=current_home)
        )
    canonical_recomputed = _canonical_hit_tuples_from_objects(recomputed_hits)

    receipt_hits = payload.get("hits", [])
    canonical_receipt = _canonical_hit_tuples_from_dicts(receipt_hits)
    if len(canonical_receipt) != len(set(canonical_receipt)):
        raise RuntimeError("archive scan receipt has duplicate hit entries")

    receipt_hit_count = payload.get("hit_count")
    if not isinstance(receipt_hit_count, int) or isinstance(receipt_hit_count, bool):
        raise RuntimeError("archive scan hit_count invalid")
    receipt_ok = payload.get("ok")

    if canonical_recomputed != canonical_receipt:
        raise RuntimeError("archive scan hit forgery: rescanned hits differ from receipt")
    if len(canonical_recomputed) != receipt_hit_count:
        raise RuntimeError(
            f"archive scan hit_count mismatch: receipt={receipt_hit_count} "
            f"rescanned={len(canonical_recomputed)}"
        )
    recomputed_ok = len(canonical_recomputed) == 0
    if receipt_ok is not True:
        raise RuntimeError("archive scan receipt ok is not true")
    if not recomputed_ok:
        raise RuntimeError(
            f"archive scan fail-closed: {len(canonical_recomputed)} privacy/safety hit(s)"
        )


def _archive_member_path_safe(name: str) -> bool:
    pure = PurePosixPath(name)
    return bool(
        name
        and "\\" not in name
        and not pure.is_absolute()
        and all(part not in {"", ".", ".."} for part in pure.parts)
    )


def _allowed_archive_binary(
    member_name: str,
    data: bytes,
    *,
    allow_member_exceptions: bool,
) -> bool:
    if not allow_member_exceptions:
        return False
    expected_sha256 = _ARCHIVE_FONT_SHA256.get(member_name)
    if expected_sha256 is None or hashlib.sha256(data).hexdigest() != expected_sha256:
        return False
    if member_name.endswith(".woff2"):
        return data.startswith(b"wOF2")
    return data.startswith((b"\x00\x01\x00\x00", b"OTTO"))


def _archive_member_identity(parent: str, member_name: str, ordinal: int) -> str:
    digest = hashlib.sha256(member_name.encode("utf-8", errors="surrogatepass")).hexdigest()[:12]
    return f"{parent}!member-{ordinal:04d}-{digest}"


def _archive_top_level_identity(name: str) -> str:
    digest = hashlib.sha256(name.encode("utf-8", errors="surrogatepass")).hexdigest()[:12]
    return f"archive-{digest}"


def _archive_name_privacy_hits(
    value: str,
    *,
    relative: str,
    current_home: str,
    scope: str,
) -> list[PrivacyHit]:
    hits: list[PrivacyHit] = []
    if current_home and current_home in value:
        hits.append(PrivacyHit(f"archive_{scope}_current_home", relative, 1))
    for rule_id, pattern in _PRIVACY_PATTERNS:
        count = len(pattern.findall(value))
        if count:
            hits.append(PrivacyHit(f"archive_{scope}_{rule_id}", relative, count))
    lowered = value.lower()
    private_count = sum(lowered.count(marker.lower()) for marker in _EXCLUDE_NAME_MARKERS)
    if private_count:
        hits.append(PrivacyHit(f"archive_{scope}_private_name", relative, private_count))
    return hits


def _archive_artifact_identity_safe(value: str) -> bool:
    lowered = value.lower()
    return all(
        pattern.search(value) is None for _rule_id, pattern in _PRIVACY_PATTERNS
    ) and all(marker.lower() not in lowered for marker in _EXCLUDE_NAME_MARKERS)


def _archive_rule_id_safe(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) <= 96
        and _ARCHIVE_RULE_ID_RE.fullmatch(value) is not None
        and value in _ARCHIVE_SCAN_RULE_IDS
    )


def _normalized_archive_member_name(member_name: str) -> str:
    return PurePosixPath(member_name).as_posix()


class _ArchivePreflightError(RuntimeError):
    def __init__(self, rule_id: str, relative_path: str | None = None) -> None:
        super().__init__(rule_id)
        self.rule_id = rule_id
        self.relative_path = relative_path


@dataclass(frozen=True)
class _ZipCentralEntry:
    member_name: str
    name_bytes: bytes
    flags: int
    method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    local_offset: int
    data_start: int = -1
    data_end: int = -1


def _little_endian(data: bytes | memoryview, offset: int, width: int) -> int:
    if offset < 0 or width < 1 or offset + width > len(data):
        raise _ArchivePreflightError("archive_unreadable")
    return int.from_bytes(data[offset : offset + width], "little")


def _zip_preflight(
    payload: bytes,
    *,
    relative: str,
) -> tuple[list[_ZipCentralEntry], list[PrivacyHit]]:
    """Validate bounded ZIP metadata before any member decompression."""
    tail_start = max(0, len(payload) - _ZIP_EOCD_MAX_TAIL)
    eocd = payload.rfind(b"PK\x05\x06", tail_start)
    if eocd < 0 or eocd + 22 > len(payload):
        raise _ArchivePreflightError("archive_unreadable")
    comment_size = _little_endian(payload, eocd + 20, 2)
    if comment_size != 0 or eocd + 22 != len(payload):
        raise _ArchivePreflightError("archive_unreadable")

    disk_number = _little_endian(payload, eocd + 4, 2)
    central_disk = _little_endian(payload, eocd + 6, 2)
    legacy_disk_entries = _little_endian(payload, eocd + 8, 2)
    legacy_entry_count = _little_endian(payload, eocd + 10, 2)
    legacy_central_size = _little_endian(payload, eocd + 12, 4)
    legacy_central_offset = _little_endian(payload, eocd + 16, 4)
    if disk_number != 0 or central_disk != 0:
        raise _ArchivePreflightError("archive_unreadable")

    sentinel = (
        legacy_disk_entries == 0xFFFF
        or legacy_entry_count == 0xFFFF
        or legacy_central_size == 0xFFFFFFFF
        or legacy_central_offset == 0xFFFFFFFF
    )
    central_boundary = eocd
    locator = eocd - 20
    if sentinel:
        if locator < 0 or payload[locator : locator + 4] != b"PK\x06\x07":
            raise _ArchivePreflightError("archive_unreadable")
        zip64_disk = _little_endian(payload, locator + 4, 4)
        zip64_offset = _little_endian(payload, locator + 8, 8)
        total_disks = _little_endian(payload, locator + 16, 4)
        if zip64_disk != 0 or total_disks != 1:
            raise _ArchivePreflightError("archive_unreadable")
        if zip64_offset + 56 > locator or payload[zip64_offset : zip64_offset + 4] != b"PK\x06\x06":
            raise _ArchivePreflightError("archive_unreadable")
        zip64_size = _little_endian(payload, zip64_offset + 4, 8)
        if zip64_size != 44 or zip64_offset + 12 + zip64_size != locator:
            raise _ArchivePreflightError("archive_unreadable")
        if _little_endian(payload, zip64_offset + 16, 4) != 0:
            raise _ArchivePreflightError("archive_unreadable")
        if _little_endian(payload, zip64_offset + 20, 4) != 0:
            raise _ArchivePreflightError("archive_unreadable")
        disk_entries = _little_endian(payload, zip64_offset + 24, 8)
        entry_count = _little_endian(payload, zip64_offset + 32, 8)
        central_size = _little_endian(payload, zip64_offset + 40, 8)
        central_offset = _little_endian(payload, zip64_offset + 48, 8)
        if disk_entries != entry_count:
            raise _ArchivePreflightError("archive_unreadable")
        legacy_pairs = (
            (legacy_disk_entries, 0xFFFF, disk_entries),
            (legacy_entry_count, 0xFFFF, entry_count),
            (legacy_central_size, 0xFFFFFFFF, central_size),
            (legacy_central_offset, 0xFFFFFFFF, central_offset),
        )
        if any(
            legacy != sentinel_value and legacy != zip64_value
            for legacy, sentinel_value, zip64_value in legacy_pairs
        ):
            raise _ArchivePreflightError("archive_unreadable")
        central_boundary = zip64_offset
    elif locator >= 0 and payload[locator : locator + 4] == b"PK\x06\x07":
        raise _ArchivePreflightError("archive_unreadable")
    else:
        disk_entries = legacy_disk_entries
        entry_count = legacy_entry_count
        central_size = legacy_central_size
        central_offset = legacy_central_offset
        if disk_entries != entry_count:
            raise _ArchivePreflightError("archive_unreadable")

    if entry_count > _ARCHIVE_MAX_MEMBERS:
        raise _ArchivePreflightError("archive_member_limit")
    if central_size > _ARCHIVE_MAX_UNCOMPRESSED:
        raise _ArchivePreflightError("archive_size_limit")
    if central_offset > central_boundary or central_size > central_boundary - central_offset:
        raise _ArchivePreflightError("archive_unreadable")
    if central_offset + central_size != central_boundary:
        raise _ArchivePreflightError("archive_unreadable")

    cursor = central_offset
    parsed_entries = 0
    central_end = central_offset + central_size
    hits: list[PrivacyHit] = []
    entries: list[_ZipCentralEntry] = []
    seen_raw: set[str] = set()
    seen_normalized: set[str] = set()
    while cursor < central_end:
        if cursor + 46 > central_end or payload[cursor : cursor + 4] != b"PK\x01\x02":
            raise _ArchivePreflightError("archive_unreadable")
        flags = _little_endian(payload, cursor + 8, 2)
        method = _little_endian(payload, cursor + 10, 2)
        crc32 = _little_endian(payload, cursor + 16, 4)
        compressed_size = _little_endian(payload, cursor + 20, 4)
        uncompressed_size = _little_endian(payload, cursor + 24, 4)
        if _little_endian(payload, cursor + 34, 2) != 0:
            raise _ArchivePreflightError("archive_unreadable")
        name_size = _little_endian(payload, cursor + 28, 2)
        extra_size = _little_endian(payload, cursor + 30, 2)
        member_comment_size = _little_endian(payload, cursor + 32, 2)
        local_offset = _little_endian(payload, cursor + 42, 4)
        if extra_size != 0 or member_comment_size != 0:
            raise _ArchivePreflightError("archive_unreadable")
        if method not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise _ArchivePreflightError("archive_unreadable")
        if 0xFFFFFFFF in {compressed_size, uncompressed_size, local_offset}:
            raise _ArchivePreflightError("archive_unreadable")
        record_size = 46 + name_size + extra_size + member_comment_size
        if record_size < 46 or cursor + record_size > central_end:
            raise _ArchivePreflightError("archive_unreadable")
        parsed_entries += 1
        if parsed_entries > _ARCHIVE_MAX_MEMBERS:
            raise _ArchivePreflightError("archive_member_limit")
        name_start = cursor + 46
        name_bytes = payload[name_start : name_start + name_size]
        try:
            member_name = name_bytes.decode("utf-8" if flags & 0x800 else "cp437")
        except UnicodeDecodeError:
            raise _ArchivePreflightError("archive_unreadable") from None
        if "\x00" in member_name:
            raise _ArchivePreflightError("archive_unreadable")
        member_relative = _archive_member_identity(relative, member_name, parsed_entries)
        normalized_name = _normalized_archive_member_name(member_name)
        if member_name in seen_raw or normalized_name in seen_normalized:
            hits.append(PrivacyHit("archive_duplicate_member", member_relative, 1))
        seen_raw.add(member_name)
        seen_normalized.add(normalized_name)
        if not _archive_member_path_safe(member_name):
            hits.append(PrivacyHit("archive_path_escape", member_relative, 1))
        if flags & 0x1:
            hits.append(PrivacyHit("archive_encrypted_member", member_relative, 1))
        elif flags != 0:
            hits.append(PrivacyHit("archive_unsupported_flags", member_relative, 1))
        if stat.S_ISLNK(_little_endian(payload, cursor + 38, 4) >> 16):
            hits.append(PrivacyHit("archive_symlink", member_relative, 1))
        if member_name.endswith((".private", "_private.pem")):
            hits.append(PrivacyHit("archive_private_name", member_relative, 1))
        entries.append(
            _ZipCentralEntry(
                member_name=member_name,
                name_bytes=name_bytes,
                flags=flags,
                method=method,
                crc32=crc32,
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                local_offset=local_offset,
            )
        )
        cursor += record_size
    if cursor != central_end or parsed_entries != entry_count:
        raise _ArchivePreflightError("archive_unreadable")

    local_cursor = 0
    validated_entries: list[_ZipCentralEntry] = []
    for entry in entries:
        if entry.local_offset != local_cursor:
            raise _ArchivePreflightError("archive_unreadable")
        if local_cursor + 30 > central_offset:
            raise _ArchivePreflightError("archive_unreadable")
        if payload[local_cursor : local_cursor + 4] != b"PK\x03\x04":
            raise _ArchivePreflightError("archive_unreadable")
        local_flags = _little_endian(payload, local_cursor + 6, 2)
        local_method = _little_endian(payload, local_cursor + 8, 2)
        local_crc32 = _little_endian(payload, local_cursor + 14, 4)
        local_compressed_size = _little_endian(payload, local_cursor + 18, 4)
        local_uncompressed_size = _little_endian(payload, local_cursor + 22, 4)
        local_name_size = _little_endian(payload, local_cursor + 26, 2)
        local_extra_size = _little_endian(payload, local_cursor + 28, 2)
        if local_extra_size != 0:
            raise _ArchivePreflightError("archive_unreadable")
        name_start = local_cursor + 30
        name_end = name_start + local_name_size
        data_end = name_end + entry.compressed_size
        if data_end > central_offset:
            raise _ArchivePreflightError("archive_unreadable")
        if payload[name_start:name_end] != entry.name_bytes:
            raise _ArchivePreflightError("archive_unreadable")
        if (
            local_flags != entry.flags
            or local_method != entry.method
            or local_crc32 != entry.crc32
            or local_compressed_size != entry.compressed_size
            or local_uncompressed_size != entry.uncompressed_size
        ):
            raise _ArchivePreflightError("archive_unreadable")
        validated_entries.append(
            _ZipCentralEntry(
                member_name=entry.member_name,
                name_bytes=entry.name_bytes,
                flags=entry.flags,
                method=entry.method,
                crc32=entry.crc32,
                compressed_size=entry.compressed_size,
                uncompressed_size=entry.uncompressed_size,
                local_offset=entry.local_offset,
                data_start=name_end,
                data_end=data_end,
            )
        )
        local_cursor = data_end
    if local_cursor != central_offset:
        raise _ArchivePreflightError("archive_unreadable")
    return validated_entries, hits


def _archive_rule_match_count(
    text: str,
    *,
    member_name: str,
    rule_id: str,
    pattern: re.Pattern[str],
) -> int:
    matches = [match.group(0) for match in pattern.finditer(text)]
    if not matches:
        return 0
    for (allowed_path, allowed_rule, literal), maximum in _ARCHIVE_LITERAL_ALLOWANCES.items():
        if allowed_path != member_name or allowed_rule != rule_id:
            continue
        remaining = min(matches.count(literal), maximum)
        for _index in range(remaining):
            matches.remove(literal)
    return len(matches)


def _canonical_sdist_members(
    archive_name: str,
    member_names: Sequence[str],
) -> dict[str, str]:
    basename = PurePosixPath(archive_name).name
    if not basename.endswith(".tar.gz"):
        return {}
    expected_root = basename.removesuffix(".tar.gz")
    paths = [PurePosixPath(member_name) for member_name in member_names if member_name]
    if not paths or {path.parts[0] for path in paths if path.parts} != {expected_root}:
        return {}
    canonical: dict[str, str] = {}
    for path in paths:
        if len(path.parts) < 2:
            continue
        canonical[path.as_posix()] = PurePosixPath(*path.parts[1:]).as_posix()
    return canonical


@dataclass(frozen=True)
class _RawTarEntry:
    member_name: str
    data_start: int
    data_end: int
    is_file: bool
    relative_path: str
    duplicate: bool


def _decompress_raw_deflate_bounded(
    payload: bytes | memoryview,
    *,
    limit: int,
    overflow_rule: str,
) -> bytes:
    if limit < 0 or limit > _ARCHIVE_MAX_UNCOMPRESSED:
        raise _ArchivePreflightError(overflow_rule)
    try:
        decompressor = zlib.decompressobj(wbits=-15)
        chunks: list[bytes] = []
        output_size = 0
        cursor = 0
        while cursor < len(payload):
            block = payload[cursor : cursor + _ARCHIVE_IO_CHUNK]
            cursor += len(block)
            remaining = limit + 1 - output_size
            if remaining <= 0:
                raise _ArchivePreflightError(overflow_rule)
            decoded = decompressor.decompress(block, remaining)
            chunks.append(decoded)
            output_size += len(decoded)
            if output_size > limit or decompressor.unconsumed_tail:
                raise _ArchivePreflightError(overflow_rule)
            if decompressor.unused_data or (decompressor.eof and cursor != len(payload)):
                raise _ArchivePreflightError("archive_unreadable")
        if (
            not decompressor.eof
            or decompressor.unused_data
            or decompressor.unconsumed_tail
        ):
            raise _ArchivePreflightError("archive_unreadable")
        remaining = limit + 1 - output_size
        decoded = decompressor.flush(remaining)
        chunks.append(decoded)
        output_size += len(decoded)
    except _ArchivePreflightError:
        raise
    except zlib.error:
        raise _ArchivePreflightError("archive_unreadable") from None
    if output_size > limit:
        raise _ArchivePreflightError(overflow_rule)
    return b"".join(chunks)


def _gzip_decompress_bounded(
    payload: bytes | memoryview,
    *,
    state: dict[str, int],
) -> bytes:
    if (
        len(payload) < 18
        or bytes(payload[:3]) != b"\x1f\x8b\x08"
        or payload[3] != 0
    ):
        raise _ArchivePreflightError("archive_unreadable")
    expected_crc32 = _little_endian(payload, len(payload) - 8, 4)
    expected_size = _little_endian(payload, len(payload) - 4, 4)
    expanded = state.get("expanded", 0)
    if expanded < 0 or expected_size > _ARCHIVE_MAX_UNCOMPRESSED - expanded:
        raise _ArchivePreflightError("archive_size_limit")
    state["expanded"] = expanded + expected_size
    compressed = memoryview(payload)[10:-8]
    data = _decompress_raw_deflate_bounded(
        compressed,
        limit=expected_size,
        overflow_rule="archive_size_limit",
    )
    if zlib.crc32(data) & 0xFFFFFFFF != expected_crc32 or len(data) != expected_size:
        raise _ArchivePreflightError("archive_unreadable")
    if len(data) / max(len(payload), 1) > _ARCHIVE_MAX_RATIO:
        raise _ArchivePreflightError("archive_compression_ratio")
    return data


def _tar_octal(field: bytes) -> int:
    if not field or field[0] & 0x80:
        raise _ArchivePreflightError("archive_unreadable")
    if field == b"\0" * len(field):
        return 0
    if field[-1:] != b"\0":
        raise _ArchivePreflightError("archive_unreadable")
    digits = field[:-1]
    if not digits or any(byte < ord("0") or byte > ord("7") for byte in digits):
        raise _ArchivePreflightError("archive_unreadable")
    return int(digits, 8)


def _tar_checksum_octal(field: bytes) -> int:
    if len(field) != 8 or field[6:] != b"\0 ":
        raise _ArchivePreflightError("archive_unreadable")
    digits = field[:6]
    if any(byte < ord("0") or byte > ord("7") for byte in digits):
        raise _ArchivePreflightError("archive_unreadable")
    return int(digits, 8)


def _tar_text(field: bytes) -> str:
    zero = field.find(b"\0")
    if zero >= 0:
        if any(field[zero:]):
            raise _ArchivePreflightError("archive_unreadable")
        field = field[:zero]
    try:
        return field.decode("utf-8")
    except UnicodeDecodeError:
        raise _ArchivePreflightError("archive_unreadable") from None


def _parse_raw_tar(
    data: bytes,
    *,
    relative: str,
    state: dict[str, int],
) -> tuple[list[_RawTarEntry], list[PrivacyHit]]:
    entries: list[_RawTarEntry] = []
    hits: list[PrivacyHit] = []
    seen_raw: set[str] = set()
    seen_normalized: set[str] = set()
    offset = 0
    ordinal = 0
    while True:
        if offset + 1024 > len(data):
            raise _ArchivePreflightError("archive_unreadable")
        header = data[offset : offset + 512]
        if header == b"\0" * 512:
            if data[offset + 512 : offset + 1024] != b"\0" * 512:
                raise _ArchivePreflightError("archive_unreadable")
            if any(memoryview(data)[offset + 1024 :]):
                raise _ArchivePreflightError("archive_unreadable")
            break

        ordinal += 1
        state["members"] += 1
        if state["members"] > _ARCHIVE_MAX_MEMBERS:
            raise _ArchivePreflightError("archive_member_limit")
        stored_checksum = _tar_checksum_octal(header[148:156])
        computed_checksum = sum(header[:148]) + sum(b" " * 8) + sum(header[156:])
        if stored_checksum != computed_checksum:
            raise _ArchivePreflightError("archive_unreadable")
        _tar_octal(header[100:108])
        _tar_octal(header[108:116])
        _tar_octal(header[116:124])
        size = _tar_octal(header[124:136])
        _tar_octal(header[136:148])
        devmajor = _tar_octal(header[329:337])
        devminor = _tar_octal(header[337:345])
        state["bytes"] += size
        if state["bytes"] > _ARCHIVE_MAX_UNCOMPRESSED:
            raise _ArchivePreflightError("archive_size_limit")
        typeflag = header[156:157]
        raw_name = _tar_text(header[:100])
        prefix = _tar_text(header[345:500])
        member_name = f"{prefix}/{raw_name}" if prefix else raw_name
        member_relative = _archive_member_identity(relative, member_name, ordinal)
        if typeflag in {b"x", b"g", b"L", b"K"}:
            return entries, [PrivacyHit("archive_metadata_forbidden", member_relative, 1)]
        if header[257:263] != b"ustar\0" or header[263:265] != b"00":
            raise _ArchivePreflightError("archive_unreadable")
        if any(header[157:257]) or any(header[265:329]) or any(header[500:512]):
            return entries, [PrivacyHit("archive_metadata_forbidden", member_relative, 1)]
        if typeflag not in {b"\0", b"0", b"5"}:
            return entries, [PrivacyHit("archive_special_member", member_relative, 1)]
        if devmajor != 0 or devminor != 0:
            raise _ArchivePreflightError("archive_unreadable")
        if not member_name:
            raise _ArchivePreflightError("archive_unreadable")
        normalized_name = _normalized_archive_member_name(member_name)
        duplicate = member_name in seen_raw or normalized_name in seen_normalized
        if duplicate:
            hits.append(PrivacyHit("archive_duplicate_member", member_relative, 1))
        seen_raw.add(member_name)
        seen_normalized.add(normalized_name)
        if not _archive_member_path_safe(member_name):
            hits.append(PrivacyHit("archive_path_escape", member_relative, 1))
        if typeflag == b"5" and size != 0:
            raise _ArchivePreflightError("archive_unreadable")
        data_start = offset + 512
        data_end = data_start + size
        padded_end = data_start + ((size + 511) // 512) * 512
        if data_end > len(data) or padded_end > len(data):
            raise _ArchivePreflightError("archive_unreadable")
        if any(data[data_end:padded_end]):
            raise _ArchivePreflightError("archive_unreadable")
        entries.append(
            _RawTarEntry(
                member_name=member_name,
                data_start=data_start,
                data_end=data_end,
                is_file=typeflag in {b"\0", b"0"},
                relative_path=member_relative,
                duplicate=duplicate,
            )
        )
        offset = padded_end
    return entries, hits


def _scan_archive_text(
    data: bytes | memoryview,
    *,
    member_name: str,
    relative: str,
    current_home: str,
    allow_member_exceptions: bool,
) -> list[PrivacyHit]:
    raw_data = data if isinstance(data, bytes) else data.tobytes()
    if _allowed_archive_binary(
        member_name,
        raw_data,
        allow_member_exceptions=allow_member_exceptions,
    ):
        return []
    if member_name.lower().endswith((".ttf", ".woff2")):
        return [PrivacyHit("archive_non_utf8_member", relative, 1)]
    try:
        text = raw_data.decode("utf-8")
    except UnicodeDecodeError:
        return [PrivacyHit("archive_non_utf8_member", relative, 1)]
    hits: list[PrivacyHit] = []
    if current_home and current_home in text:
        hits.append(PrivacyHit("archive_current_home", relative, 1))
    for rule_id, pattern in _PRIVACY_PATTERNS:
        count = len(pattern.findall(text))
        if allow_member_exceptions:
            count = _archive_rule_match_count(
                text,
                member_name=member_name,
                rule_id=rule_id,
                pattern=pattern,
            )
        if count:
            archive_rule = (
                "archive_pem_private" if rule_id == "pem_private_key" else f"archive_{rule_id}"
            )
            hits.append(PrivacyHit(archive_rule, relative, count))
    return hits


def _scan_archive_payload(
    payload: bytes | memoryview,
    *,
    name: str,
    scan_name: str | None,
    relative: str,
    current_home: str,
    depth: int,
    state: dict[str, int],
    allow_member_exceptions: bool,
) -> list[PrivacyHit]:
    hits: list[PrivacyHit] = []
    if len(payload) > _ARCHIVE_MAX_UNCOMPRESSED:
        return [PrivacyHit("archive_size_limit", relative, 1)]
    kind = _classify_scannable_archive_name(name)
    if kind is None:
        return _scan_archive_text(
            payload,
            member_name=scan_name or name,
            relative=relative,
            current_home=current_home,
            allow_member_exceptions=allow_member_exceptions,
        )
    if depth > _ARCHIVE_MAX_DEPTH:
        return [PrivacyHit("archive_depth_limit", relative, 1)]

    if kind == "zip":
        zip_payload = payload if isinstance(payload, bytes) else payload.tobytes()
        try:
            entries, preflight_hits = _zip_preflight(zip_payload, relative=relative)
        except _ArchivePreflightError as exc:
            return [PrivacyHit(exc.rule_id, exc.relative_path or relative, 1)]
        name_hits: list[PrivacyHit] = []
        for ordinal, entry in enumerate(entries, start=1):
            member_relative = _archive_member_identity(
                relative,
                entry.member_name,
                ordinal,
            )
            name_hits.extend(
                _archive_name_privacy_hits(
                    entry.member_name,
                    relative=member_relative,
                    current_home=current_home,
                    scope="member_name",
                )
            )
        if preflight_hits or name_hits:
            return preflight_hits + name_hits
        if state["members"] + len(entries) > _ARCHIVE_MAX_MEMBERS:
            return [PrivacyHit("archive_member_limit", relative, 1)]
        state["members"] += len(entries)
        for ordinal, entry in enumerate(entries, start=1):
            member_relative = _archive_member_identity(
                relative,
                entry.member_name,
                ordinal,
            )
            state["bytes"] += entry.uncompressed_size
            if state["bytes"] > _ARCHIVE_MAX_UNCOMPRESSED:
                return hits + [PrivacyHit("archive_size_limit", member_relative, 1)]
            if (
                entry.uncompressed_size / max(entry.compressed_size, 1)
                > _ARCHIVE_MAX_RATIO
            ):
                hits.append(PrivacyHit("archive_compression_ratio", member_relative, 1))
                continue
            compressed = memoryview(zip_payload)[entry.data_start : entry.data_end]
            member_payload: bytes | memoryview
            try:
                if entry.method == zipfile.ZIP_STORED:
                    if entry.compressed_size != entry.uncompressed_size:
                        raise _ArchivePreflightError("archive_member_size_mismatch")
                    member_payload = compressed
                else:
                    member_payload = _decompress_raw_deflate_bounded(
                        compressed,
                        limit=entry.uncompressed_size,
                        overflow_rule="archive_member_size_mismatch",
                    )
            except _ArchivePreflightError as exc:
                rule_id = (
                    exc.rule_id
                    if exc.rule_id == "archive_member_size_mismatch"
                    else "archive_unreadable_member"
                )
                hits.append(PrivacyHit(rule_id, member_relative, 1))
                continue
            if len(member_payload) != entry.uncompressed_size:
                hits.append(PrivacyHit("archive_member_size_mismatch", member_relative, 1))
                continue
            if zlib.crc32(member_payload) & 0xFFFFFFFF != entry.crc32:
                hits.append(PrivacyHit("archive_unreadable_member", member_relative, 1))
                continue
            if entry.member_name.endswith("/"):
                if member_payload:
                    hits.append(PrivacyHit("archive_unreadable_member", member_relative, 1))
                continue
            hits.extend(
                _scan_archive_payload(
                    member_payload,
                    name=entry.member_name,
                    scan_name=entry.member_name,
                    relative=member_relative,
                    current_home=current_home,
                    depth=depth + 1,
                    state=state,
                    allow_member_exceptions=depth == 0,
                )
            )
        return hits

    try:
        tar_data = _gzip_decompress_bounded(payload, state=state)
        tar_entries, structural_hits = _parse_raw_tar(
            tar_data,
            relative=relative,
            state=state,
        )
    except _ArchivePreflightError as exc:
        return [PrivacyHit(exc.rule_id, exc.relative_path or relative, 1)]
    name_hits = []
    for tar_entry in tar_entries:
        name_hits.extend(
            _archive_name_privacy_hits(
                tar_entry.member_name,
                relative=tar_entry.relative_path,
                current_home=current_home,
                scope="member_name",
            )
        )
    if structural_hits or name_hits:
        return structural_hits + name_hits
    canonical_members = _canonical_sdist_members(
        name,
        [tar_entry.member_name for tar_entry in tar_entries],
    )
    for tar_entry in tar_entries:
        if not tar_entry.is_file:
            continue
        if tar_entry.member_name.endswith((".private", "_private.pem")):
            hits.append(PrivacyHit("archive_private_name", tar_entry.relative_path, 1))
        member_payload = memoryview(tar_data)[tar_entry.data_start : tar_entry.data_end]
        hits.extend(
            _scan_archive_payload(
                member_payload,
                name=tar_entry.member_name,
                scan_name=canonical_members.get(
                    tar_entry.member_name,
                    tar_entry.member_name,
                ),
                relative=tar_entry.relative_path,
                current_home=current_home,
                depth=depth + 1,
                state=state,
                allow_member_exceptions=(
                    depth == 0
                    and not tar_entry.duplicate
                    and tar_entry.member_name in canonical_members
                ),
            )
        )
    return hits


def _archive_open_flags() -> int:
    required = ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if not all(hasattr(os, flag) for flag in required):
        raise _ArchivePreflightError("archive_unreadable")
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def _read_archive_fd_bounded(fd: int) -> bytes:
    remaining = _ARCHIVE_MAX_UNCOMPRESSED + 1
    chunks: list[bytes] = []
    while remaining:
        chunk = os.read(fd, min(remaining, _ARCHIVE_IO_CHUNK))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_top_level_archive(path: Path) -> bytes | PrivacyHit:
    relative = path.name
    try:
        before = path.lstat()
    except OSError:
        return PrivacyHit("archive_unreadable", relative, 1)
    if stat.S_ISLNK(before.st_mode):
        return PrivacyHit("archive_symlink", relative, 1)
    if not stat.S_ISREG(before.st_mode):
        return PrivacyHit("archive_special_file", relative, 1)
    if before.st_nlink != 1:
        return PrivacyHit("archive_hardlink", relative, 1)
    if before.st_size < 0 or before.st_size > _ARCHIVE_MAX_UNCOMPRESSED:
        return PrivacyHit("archive_size_limit", relative, 1)

    try:
        flags = _archive_open_flags()
        fd = os.open(path, flags)
    except (OSError, _ArchivePreflightError):
        return PrivacyHit("archive_unreadable", relative, 1)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            return PrivacyHit("archive_special_file", relative, 1)
        if opened.st_nlink != 1:
            return PrivacyHit("archive_hardlink", relative, 1)
        if _source_identity(opened) != _source_identity(before):
            return PrivacyHit("archive_identity_changed", relative, 1)
        if opened.st_size < 0 or opened.st_size > _ARCHIVE_MAX_UNCOMPRESSED:
            return PrivacyHit("archive_size_limit", relative, 1)
        payload = _read_archive_fd_bounded(fd)
        after = os.fstat(fd)
        if _source_identity(after) != _source_identity(opened) or len(payload) != opened.st_size:
            return PrivacyHit("archive_identity_changed", relative, 1)
        if len(payload) > _ARCHIVE_MAX_UNCOMPRESSED:
            return PrivacyHit("archive_size_limit", relative, 1)
        return payload
    except OSError:
        return PrivacyHit("archive_unreadable", relative, 1)
    finally:
        os.close(fd)


def scan_archive_members(path: Path, *, current_home: str) -> list[PrivacyHit]:
    """Recursively scan the closed archive family with global resource limits."""
    if _classify_scannable_archive_name(path.name) is None:
        raise RuntimeError("unsupported evidence archive format")
    name_hits = _archive_name_privacy_hits(
        path.name,
        relative=_archive_top_level_identity(path.name),
        current_home=current_home,
        scope="name",
    )
    if name_hits:
        return name_hits
    payload = _read_top_level_archive(path)
    if isinstance(payload, PrivacyHit):
        return [payload]
    return _scan_archive_payload(
        payload,
        name=path.name,
        scan_name=None,
        relative=path.name,
        current_home=current_home,
        depth=0,
        state={"members": 0, "bytes": 0, "expanded": 0},
        allow_member_exceptions=False,
    )


def archive_scan_scope_notes() -> str:
    """Document bounded archive scan scope for reports (no blanket zero claims)."""
    return (
        "Archive scan recursively covers wheel/tar.gz/zip/xlsx/docx/pptx members. ZIP "
        "requires empty comments/extras, safe flags, exact ZIP64/central/local coverage, and "
        "bounded raw-DEFLATE length/EOF/CRC validation; tar.gz requires an FLG=0 single raw "
        "DEFLATE stream, verified trailer, shared expansion budget, and canonical USTAR "
        "regular/directory headers without PAX/GNU or identity metadata. Artifact/member "
        "names and content apply fail-closed path, type, size/count/ratio/depth, non-UTF8, "
        "HOME, token, and private-key checks with opaque unsafe-name identities. Safe source "
        "literals use exact path/rule/literal/count allowances; Font Awesome requires "
        "top-level exact paths, SHA-256, and format magic."
    )


def _canonical_json_sha256(payload: Mapping[str, object]) -> str:
    body = json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _is_lower_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _sanitized_desktop_artifact(value: object, *, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise RuntimeError(f"desktop descriptor {label} binding invalid")
    relative = value.get("path")
    digest = value.get("sha256")
    if not isinstance(relative, str) or not _is_lower_sha256(digest):
        raise RuntimeError(f"desktop descriptor {label} binding invalid")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise RuntimeError(f"desktop descriptor {label} path invalid")
    return {"path": relative, "sha256": str(digest)}


def _validate_sanitized_desktop_descriptor(
    payload: object,
    *,
    expected_source_digest: str,
) -> dict[str, object]:
    expected_fields = {
        "schema_version",
        "original_manifest_schema",
        "original_manifest_sha256",
        "source_digest",
        "arch",
        "product_version",
        "build_number",
        "app_tree",
        "app_binary",
        "zip",
    }
    if not isinstance(payload, dict) or set(payload) != expected_fields:
        raise RuntimeError("desktop descriptor schema is not closed")
    try:
        from desktop.build_driver import PRODUCT_VERSION, TARGET_TRIPLE, validate_build_number

        validated_build_number = validate_build_number(payload.get("build_number"))
    except (ImportError, RuntimeError, TypeError, ValueError):
        raise RuntimeError("desktop descriptor identity invalid") from None
    if (
        payload.get("schema_version") != DESKTOP_DESCRIPTOR_SCHEMA
        or payload.get("original_manifest_schema") != _ORIGINAL_DESKTOP_MANIFEST_SCHEMA
        or payload.get("source_digest") != expected_source_digest
        or not _is_lower_sha256(payload.get("original_manifest_sha256"))
        or payload.get("arch") != TARGET_TRIPLE
        or payload.get("product_version") != PRODUCT_VERSION
        or payload.get("build_number") != validated_build_number
    ):
        raise RuntimeError("desktop descriptor identity invalid")
    app_tree = _sanitized_desktop_artifact(payload["app_tree"], label="app_tree")
    app_binary = _sanitized_desktop_artifact(payload["app_binary"], label="app_binary")
    zip_artifact = _sanitized_desktop_artifact(payload["zip"], label="zip")
    descriptor: dict[str, object] = {
        "schema_version": DESKTOP_DESCRIPTOR_SCHEMA,
        "original_manifest_schema": _ORIGINAL_DESKTOP_MANIFEST_SCHEMA,
        "original_manifest_sha256": str(payload["original_manifest_sha256"]),
        "source_digest": expected_source_digest,
        "arch": str(payload["arch"]),
        "product_version": str(payload["product_version"]),
        "build_number": str(payload["build_number"]),
        "app_tree": app_tree,
        "app_binary": app_binary,
        "zip": zip_artifact,
    }
    expected_paths = {
        "app_tree": "artifacts/JS Agent.app",
        "app_binary": "artifacts/JS Agent.app/Contents/MacOS/js-agent-desktop",
        "zip": (
            f"artifacts/JS-Agent-{PRODUCT_VERSION}-macos-arm64-unsigned-"
            f"{expected_source_digest[:16]}.zip"
        ),
    }
    artifacts = {"app_tree": app_tree, "app_binary": app_binary, "zip": zip_artifact}
    if any(artifacts[name]["path"] != path for name, path in expected_paths.items()):
        raise RuntimeError("desktop descriptor artifact path binding invalid")
    return descriptor


def _load_verified_original_desktop_manifest(
    *,
    evidence_root: Path,
    repo_root: Path,
    expected_source_digest: str,
) -> tuple[dict[str, object], str]:
    """Read and verify private V4 bytes without copying or redacting them."""
    manifest_path = evidence_root / _ORIGINAL_DESKTOP_MANIFEST_RELATIVE
    root_fd = _open_evidence_root(evidence_root)
    descriptor = -1
    try:
        source = _allowlisted_relative(
            manifest_path,
            evidence_root=evidence_root,
            evidence_root_fd=root_fd,
        )
        raw, _source_stat, descriptor = _read_allowlisted_source(
            source,
            evidence_root_fd=root_fd,
            validator_inputs_fd=None,
        )
        try:
            from desktop.build_driver import verify_manifest

            verification_errors = verify_manifest(manifest_path, repo_root=repo_root)
        except (ImportError, OSError, RuntimeError, TypeError, ValueError):
            raise RuntimeError("original desktop manifest V4 verification failed") from None
        if verification_errors != []:
            raise RuntimeError("original desktop manifest V4 verification failed")
        _verify_allowlisted_source_after_copy(
            source,
            evidence_root_fd=root_fd,
            validator_inputs_fd=None,
            descriptor=descriptor,
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(root_fd)
    try:
        manifest = strict_load_object_bytes(raw)
    except (StrictJSONError, UnicodeDecodeError, ValueError):
        raise RuntimeError("original desktop manifest V4 JSON invalid") from None
    if (
        manifest.get("schema") != _ORIGINAL_DESKTOP_MANIFEST_SCHEMA
        or manifest.get("source_digest") != expected_source_digest
    ):
        raise RuntimeError("original desktop manifest V4 identity invalid")
    return manifest, hashlib.sha256(raw).hexdigest()


def _exported_desktop_release_bindings(export_dir: Path, *, gate_name: str) -> dict[str, str]:
    receipt_path = export_dir / "final" / f"{gate_name}.receipt.json"
    try:
        receipt = strict_load_object(receipt_path)
    except (OSError, StrictJSONError, ValueError):
        raise RuntimeError("desktop formal receipt missing or invalid") from None
    parse_result = receipt.get("parse_result")
    if (
        receipt.get("gate_name") != gate_name
        or receipt.get("passed") is not True
        or not isinstance(parse_result, dict)
        or parse_result.get("parser") != "release_markers"
        or parse_result.get("ok") is not True
    ):
        raise RuntimeError("desktop formal receipt marker invalid")
    marker = parse_result.get("payload")
    if not isinstance(marker, dict) or marker.get("gate") != gate_name or marker.get("ok") is not True:
        raise RuntimeError("desktop formal receipt marker invalid")
    bindings = marker.get("bindings")
    expected = {"desktop_manifest_sha256", "app_tree_sha256", "app_sha256"}
    if gate_name == "tauri_webview_lifecycle":
        expected |= {"result_sha256", "harness_sha256"}
    if (
        not isinstance(bindings, dict)
        or set(bindings) != expected
        or any(not _is_lower_sha256(value) for value in bindings.values())
    ):
        raise RuntimeError("desktop formal receipt bindings invalid")
    return {key: str(value) for key, value in bindings.items()}


def _verify_exported_final_desktop_summaries(
    export_dir: Path,
    *,
    expected_original_manifest_sha256: str | None,
) -> None:
    for relative in (
        "pack/JS_AGENT_FINAL_EVIDENCE.json",
        "docs/JS_AGENT_FINAL_EVIDENCE.json",
    ):
        path = export_dir / relative
        if not path.exists():
            continue
        _assert_safe_member(path, export_root=export_dir)
        try:
            payload = strict_load_object(path)
        except (OSError, StrictJSONError, ValueError):
            raise RuntimeError("exported final desktop summary invalid") from None
        claimed = payload.get("desktop_manifest_digest")
        if claimed is None:
            if expected_original_manifest_sha256 is not None:
                raise RuntimeError("exported final desktop summary binding missing")
            continue
        if (
            expected_original_manifest_sha256 is None
            or not _is_lower_sha256(claimed)
            or claimed != expected_original_manifest_sha256
        ):
            raise RuntimeError("exported final desktop summary binding mismatch")


def _desktop_summary_binding(
    descriptor: Mapping[str, object],
    *,
    descriptor_sha256: str,
) -> dict[str, object]:
    app_tree = descriptor.get("app_tree")
    app_binary = descriptor.get("app_binary")
    zip_artifact = descriptor.get("zip")
    if not all(isinstance(value, dict) for value in (app_tree, app_binary, zip_artifact)):
        raise RuntimeError("desktop descriptor artifact bindings invalid")
    assert isinstance(app_tree, dict)
    assert isinstance(app_binary, dict)
    assert isinstance(zip_artifact, dict)
    return {
        "schema_version": DESKTOP_SUMMARY_BINDING_SCHEMA,
        "descriptor_relative_path": DESKTOP_DESCRIPTOR_RELATIVE,
        "descriptor_sha256": descriptor_sha256,
        "original_manifest_sha256": descriptor["original_manifest_sha256"],
        "app_tree_sha256": app_tree["sha256"],
        "app_sha256": app_binary["sha256"],
        "zip_sha256": zip_artifact["sha256"],
    }


def verify_sanitized_desktop_binding(
    export_dir: Path,
    *,
    expected_source_digest: str,
    passed_gates: Sequence[str],
) -> dict[str, object] | None:
    """Verify descriptor -> marker receipts -> final summaries without private V4 bytes."""
    original_export = export_dir / _ORIGINAL_DESKTOP_MANIFEST_RELATIVE
    if original_export.exists():
        raise RuntimeError("original desktop manifest V4 must not be exported")
    descriptor_path = export_dir / DESKTOP_DESCRIPTOR_RELATIVE
    desktop_passed = "desktop_build" in passed_gates
    tauri_passed = "tauri_webview_lifecycle" in passed_gates
    if tauri_passed and not desktop_passed:
        raise RuntimeError("desktop formal gate ordering invalid")
    if not desktop_passed:
        if descriptor_path.exists():
            raise RuntimeError("desktop descriptor exists without formal desktop gate")
        _verify_exported_final_desktop_summaries(
            export_dir,
            expected_original_manifest_sha256=None,
        )
        return None
    _assert_safe_member(descriptor_path, export_root=export_dir)
    try:
        raw_descriptor = descriptor_path.read_bytes()
        loaded_descriptor = strict_load_object_bytes(raw_descriptor)
    except (OSError, StrictJSONError, UnicodeDecodeError, ValueError):
        raise RuntimeError("desktop descriptor missing or invalid") from None
    descriptor = _validate_sanitized_desktop_descriptor(
        loaded_descriptor,
        expected_source_digest=expected_source_digest,
    )
    desktop_marker = _exported_desktop_release_bindings(
        export_dir,
        gate_name="desktop_build",
    )
    app_tree = descriptor["app_tree"]
    app_binary = descriptor["app_binary"]
    if not isinstance(app_tree, dict) or not isinstance(app_binary, dict):
        raise RuntimeError("desktop descriptor artifact bindings invalid")
    expected_marker: dict[str, str] = {
        "desktop_manifest_sha256": str(descriptor["original_manifest_sha256"]),
        "app_tree_sha256": str(app_tree["sha256"]),
        "app_sha256": str(app_binary["sha256"]),
    }
    if desktop_marker != expected_marker:
        raise RuntimeError("desktop descriptor/formal receipt binding mismatch")
    if tauri_passed:
        tauri_marker = _exported_desktop_release_bindings(
            export_dir,
            gate_name="tauri_webview_lifecycle",
        )
        if any(tauri_marker[key] != value for key, value in expected_marker.items()):
            raise RuntimeError("desktop descriptor/Tauri receipt binding mismatch")
    _verify_exported_final_desktop_summaries(
        export_dir,
        expected_original_manifest_sha256=str(descriptor["original_manifest_sha256"]),
    )
    return _desktop_summary_binding(
        descriptor,
        descriptor_sha256=hashlib.sha256(raw_descriptor).hexdigest(),
    )


def _write_sanitized_desktop_descriptor(
    *,
    evidence_root: Path,
    export_dir: Path,
    repo_root: Path,
    source_digest: str,
    passed_gates: Sequence[str],
) -> dict[str, object] | None:
    if "desktop_build" not in passed_gates:
        return verify_sanitized_desktop_binding(
            export_dir,
            expected_source_digest=source_digest,
            passed_gates=passed_gates,
        )
    manifest, original_sha256 = _load_verified_original_desktop_manifest(
        evidence_root=evidence_root,
        repo_root=repo_root,
        expected_source_digest=source_digest,
    )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise RuntimeError("original desktop manifest V4 artifacts invalid")
    descriptor = _validate_sanitized_desktop_descriptor(
        {
            "schema_version": DESKTOP_DESCRIPTOR_SCHEMA,
            "original_manifest_schema": manifest.get("schema"),
            "original_manifest_sha256": original_sha256,
            "source_digest": manifest.get("source_digest"),
            "arch": manifest.get("arch"),
            "product_version": manifest.get("product_version"),
            "build_number": manifest.get("build_number"),
            "app_tree": artifacts.get("app_tree"),
            "app_binary": artifacts.get("rust_main"),
            "zip": artifacts.get("zip"),
        },
        expected_source_digest=source_digest,
    )
    payload = (json.dumps(descriptor, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_new_export_member(
        export_dir / DESKTOP_DESCRIPTOR_RELATIVE,
        payload,
        mode=0o644,
    )
    return verify_sanitized_desktop_binding(
        export_dir,
        expected_source_digest=source_digest,
        passed_gates=passed_gates,
    )


def _finite_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) else None


def _parse_export_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.utcoffset() == UTC.utcoffset(parsed) else None


def _valid_supervised_soak_counters(value: object, *, positive: bool) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value) == _SUPERVISED_SOAK_COUNTER_KEYS
        and all(
            isinstance(item, int)
            and not isinstance(item, bool)
            and (item > 0 if positive else item >= 0)
            for item in value.values()
        )
    )


def _validate_portable_supervised_soak(
    payload: object,
    *,
    expected_source_digest: str,
) -> dict[str, object]:
    if not isinstance(payload, dict) or set(payload) != _SUPERVISED_SOAK_FIELDS:
        raise RuntimeError("supervised soak portable schema is not closed")
    claimed_combined = payload.get("combined_sha256")
    unsigned = {key: value for key, value in payload.items() if key != "combined_sha256"}
    actual_combined = _canonical_json_sha256(unsigned)
    started = _parse_export_utc(payload.get("started_utc"))
    finished = _parse_export_utc(payload.get("finished_utc"))
    duration = _finite_number(payload.get("duration_seconds"))
    elapsed = _finite_number(payload.get("elapsed_seconds"))
    if (
        payload.get("schema_version") != SUPERVISED_SOAK_SCHEMA
        or payload.get("ok") is not True
        or payload.get("source_digest") != expected_source_digest
        or not _is_lower_sha256(payload.get("metadata_fingerprint"))
        or not _is_lower_sha256(claimed_combined)
        or claimed_combined != actual_combined
        or started is None
        or finished is None
        or finished < started
        or duration != 3600.0
        or elapsed is None
        or elapsed < 3585.0
        or (finished - started).total_seconds() < 3585.0
    ):
        raise RuntimeError("supervised soak portable identity invalid")
    core = payload.get("core")
    overlay = payload.get("overlay")
    if (
        not isinstance(core, dict)
        or set(core) != _SUPERVISED_SOAK_CORE_FIELDS
        or core.get("exit_code") != 0
        or core.get("ok") is not True
        or not _is_lower_sha256(core.get("raw_sha256"))
        or not isinstance(overlay, dict)
        or set(overlay) != _SUPERVISED_SOAK_OVERLAY_FIELDS
        or overlay.get("exit_code") != 0
        or overlay.get("ok") is not True
        or overlay.get("targets_met") is not True
        or not _is_lower_sha256(overlay.get("raw_sha256"))
        or not _is_lower_sha256(overlay.get("chain_root"))
        or not _is_lower_sha256(overlay.get("desktop_manifest_sha256"))
        or not _is_lower_sha256(overlay.get("app_tree_sha256"))
        or not _is_lower_sha256(overlay.get("app_sha256"))
        or not _valid_supervised_soak_counters(overlay.get("targets"), positive=True)
        or not _valid_supervised_soak_counters(overlay.get("counters"), positive=False)
    ):
        raise RuntimeError("supervised soak portable binding invalid")
    targets = overlay["targets"]
    counters = overlay["counters"]
    assert isinstance(targets, dict)
    assert isinstance(counters, dict)
    cycles = overlay.get("cycles")
    heartbeat_count = overlay.get("heartbeat_count")
    max_gap = _finite_number(overlay.get("max_heartbeat_gap_s"))
    gap_limit = _finite_number(overlay.get("max_heartbeat_gap_limit_s"))
    if (
        any(counters[key] < targets[key] for key in _SUPERVISED_SOAK_COUNTER_KEYS)
        or not isinstance(cycles, int)
        or isinstance(cycles, bool)
        or cycles < 1
        or not isinstance(heartbeat_count, int)
        or isinstance(heartbeat_count, bool)
        or heartbeat_count < 2
        or max_gap is None
        or gap_limit is None
        or max_gap < 0
        or max_gap > gap_limit
    ):
        raise RuntimeError("supervised soak portable counters invalid")
    return payload


def _verify_exported_final_soak_summaries(
    export_dir: Path,
    *,
    expected_artifact_sha256: str | None,
) -> None:
    for relative in (
        "pack/JS_AGENT_FINAL_EVIDENCE.json",
        "docs/JS_AGENT_FINAL_EVIDENCE.json",
    ):
        path = export_dir / relative
        if not path.exists():
            continue
        _assert_safe_member(path, export_root=export_dir)
        try:
            payload = strict_load_object(path)
        except (OSError, StrictJSONError, ValueError):
            raise RuntimeError("exported final soak summary invalid") from None
        receipts = payload.get("gate_receipts")
        soak_receipt = receipts.get("soak_3600") if isinstance(receipts, dict) else None
        claimed = soak_receipt.get("artifact_sha256") if isinstance(soak_receipt, dict) else None
        if expected_artifact_sha256 is None:
            if claimed is not None:
                raise RuntimeError("exported final soak summary binding mismatch")
            continue
        if claimed != expected_artifact_sha256:
            raise RuntimeError("exported final soak summary binding missing or mismatched")


def verify_sanitized_supervised_soak_binding(
    export_dir: Path,
    *,
    expected_source_digest: str,
    passed_gates: Sequence[str],
    desktop_binding: Mapping[str, object] | None,
) -> dict[str, object] | None:
    """Verify the portable combined summary; private raw soak reports stay excluded."""
    for relative in ("soak/echo_core_soak.raw.json", "soak/tauri_overlay.raw.json"):
        if (export_dir / relative).exists():
            raise RuntimeError("private supervised soak raw artifact must not be exported")
    combined_path = export_dir / SUPERVISED_SOAK_COMBINED_RELATIVE
    soak_passed = "soak_3600" in passed_gates
    if not soak_passed:
        if combined_path.exists():
            raise RuntimeError("supervised soak summary exists without formal gate")
        _verify_exported_final_soak_summaries(
            export_dir,
            expected_artifact_sha256=None,
        )
        return None
    if desktop_binding is None:
        raise RuntimeError("supervised soak desktop descriptor binding missing")
    _assert_safe_member(combined_path, export_root=export_dir)
    try:
        raw = combined_path.read_bytes()
        loaded = strict_load_object_bytes(raw)
    except (OSError, StrictJSONError, UnicodeDecodeError, ValueError):
        raise RuntimeError("supervised soak portable summary missing or invalid") from None
    combined = _validate_portable_supervised_soak(
        loaded,
        expected_source_digest=expected_source_digest,
    )
    artifact_sha = hashlib.sha256(raw).hexdigest()
    receipt_path = export_dir / "final/soak_3600.receipt.json"
    try:
        receipt = strict_load_object(receipt_path)
    except (OSError, StrictJSONError, ValueError):
        raise RuntimeError("supervised soak formal receipt missing or invalid") from None
    if receipt.get("gate_name") != "soak_3600" or receipt.get("passed") is not True:
        raise RuntimeError("supervised soak formal receipt invalid")
    if receipt.get("artifact_sha256") != artifact_sha:
        raise RuntimeError("supervised soak receipt artifact binding mismatch")
    overlay = combined.get("overlay")
    core = combined.get("core")
    if not isinstance(overlay, dict) or not isinstance(core, dict):
        raise RuntimeError("supervised soak portable binding invalid")
    expected_desktop = {
        "desktop_manifest_sha256": desktop_binding.get("original_manifest_sha256"),
        "app_tree_sha256": desktop_binding.get("app_tree_sha256"),
        "app_sha256": desktop_binding.get("app_sha256"),
    }
    if any(overlay.get(key) != value for key, value in expected_desktop.items()):
        raise RuntimeError("supervised soak/desktop descriptor binding mismatch")
    _verify_exported_final_soak_summaries(
        export_dir,
        expected_artifact_sha256=artifact_sha,
    )
    return {
        "schema_version": SUPERVISED_SOAK_SUMMARY_BINDING_SCHEMA,
        "combined_relative_path": SUPERVISED_SOAK_COMBINED_RELATIVE,
        "artifact_sha256": artifact_sha,
        "combined_sha256": combined["combined_sha256"],
        "core_raw_sha256": core["raw_sha256"],
        "overlay_raw_sha256": overlay["raw_sha256"],
        "metadata_fingerprint": combined["metadata_fingerprint"],
        "overlay_chain_root": overlay["chain_root"],
        **expected_desktop,
    }


def _formal_report_core(
    report: object,
    *,
    source_digest: str,
) -> dict[str, object]:
    from js.echo.ledger.release_gates import REQUIRED_FINAL_LOCAL_GATES

    raw_passed = getattr(report, "passed_gates", ())
    raw_blockers = getattr(report, "blockers", ())
    if not isinstance(raw_passed, tuple) or not all(isinstance(item, str) for item in raw_passed):
        raise RuntimeError("formal validator report passed_gates invalid")
    if not isinstance(raw_blockers, tuple) or not all(
        isinstance(item, str) for item in raw_blockers
    ):
        raise RuntimeError("formal validator report blockers invalid")
    unknown = set(raw_passed) - set(REQUIRED_FINAL_LOCAL_GATES)
    if unknown:
        raise RuntimeError("formal validator report contains unknown passed gate")
    passed = [gate for gate in REQUIRED_FINAL_LOCAL_GATES if gate in set(raw_passed)]
    all_passed = getattr(report, "all_local_gates_passed", None)
    product_ready = getattr(report, "product_internal_ready", None)
    if not isinstance(all_passed, bool) or not isinstance(product_ready, bool):
        raise RuntimeError("formal validator report readiness invalid")
    if all_passed != (passed == list(REQUIRED_FINAL_LOCAL_GATES) and not raw_blockers):
        raise RuntimeError("formal validator report gate closure inconsistent")
    if product_ready and not all_passed:
        raise RuntimeError("formal validator report product readiness inconsistent")
    return {
        "source_digest": source_digest,
        "required_gates": list(REQUIRED_FINAL_LOCAL_GATES),
        "passed_gates": passed,
        "blockers": list(raw_blockers),
        "all_local_gates_passed": all_passed,
        "product_internal_ready": product_ready,
    }


def _core_string_tuple(core: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = core.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError(f"formal validator report {key} invalid")
    return tuple(value)


def _write_export_validator_binding(
    export_dir: Path,
    *,
    source_digest: str,
    report: object,
    desktop_binding: Mapping[str, object] | None,
    soak_binding: Mapping[str, object] | None,
) -> None:
    core = _formal_report_core(report, source_digest=source_digest)
    generated_utc = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    report_sha = _canonical_json_sha256(core)
    summary: dict[str, object] = {
        "schema_version": "js-agent-gate-run-summary-v5",
        "generated_utc": generated_utc,
        **core,
        "formal_validator": "validate_final_local_gate_evidence",
        "validation_report_sha256": report_sha,
        "desktop_binding": dict(desktop_binding) if desktop_binding is not None else None,
        "supervised_soak_binding": dict(soak_binding) if soak_binding is not None else None,
    }
    validator: dict[str, object] = {
        "schema_version": "js-agent-final-validator-receipt-v4",
        "generated_utc": generated_utc,
        "validator": "validate_final_local_gate_evidence",
        "writer": "build_sanitized_export",
        "source_digest": source_digest,
        "gate_run_summary_sha256": _canonical_json_sha256(summary),
        "validation_report_sha256": report_sha,
        "ok": core["all_local_gates_passed"],
        "blockers": core["blockers"],
        "desktop_binding": dict(desktop_binding) if desktop_binding is not None else None,
        "supervised_soak_binding": dict(soak_binding) if soak_binding is not None else None,
    }
    (export_dir / "gate_run_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (export_dir / "final_validator.receipt.json").write_text(
        json.dumps(validator, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def verify_export_validator_binding(
    export_dir: Path,
    *,
    expected_source_digest: str,
    report: object | None = None,
) -> None:
    """Verify the exported summary is derived from and bound to the formal report."""
    try:
        summary = strict_load_object(export_dir / "gate_run_summary.json")
        validator = strict_load_object(export_dir / "final_validator.receipt.json")
    except (OSError, StrictJSONError, ValueError) as exc:
        raise RuntimeError("formal validator summary/receipt missing or invalid") from exc
    if not isinstance(summary, dict) or not isinstance(validator, dict):
        raise RuntimeError("formal validator summary/receipt must be objects")
    if summary.get("schema_version") != "js-agent-gate-run-summary-v5":
        raise RuntimeError("formal validator summary schema mismatch")
    if validator.get("schema_version") != "js-agent-final-validator-receipt-v4":
        raise RuntimeError("formal validator receipt schema mismatch")
    if summary.get("source_digest") != expected_source_digest:
        raise RuntimeError("formal validator summary source digest mismatch")
    if validator.get("source_digest") != expected_source_digest:
        raise RuntimeError("formal validator receipt source digest mismatch")
    if validator.get("validator") != "validate_final_local_gate_evidence":
        raise RuntimeError("formal validator identity mismatch")
    if validator.get("gate_run_summary_sha256") != _canonical_json_sha256(summary):
        raise RuntimeError("formal validator summary hash mismatch")
    core = {
        key: summary.get(key)
        for key in (
            "source_digest",
            "required_gates",
            "passed_gates",
            "blockers",
            "all_local_gates_passed",
            "product_internal_ready",
        )
    }
    report_sha = _canonical_json_sha256(core)
    if summary.get("validation_report_sha256") != report_sha:
        raise RuntimeError("formal validator summary report hash mismatch")
    if validator.get("validation_report_sha256") != report_sha:
        raise RuntimeError("formal validator receipt report hash mismatch")
    if validator.get("ok") is not summary.get("all_local_gates_passed"):
        raise RuntimeError("formal validator readiness mismatch")
    if validator.get("blockers") != summary.get("blockers"):
        raise RuntimeError("formal validator blockers mismatch")
    passed_gates = _core_string_tuple(core, "passed_gates")
    desktop_binding = verify_sanitized_desktop_binding(
        export_dir,
        expected_source_digest=expected_source_digest,
        passed_gates=passed_gates,
    )
    if summary.get("desktop_binding") != desktop_binding:
        raise RuntimeError("formal validator desktop summary binding mismatch")
    if validator.get("desktop_binding") != desktop_binding:
        raise RuntimeError("formal validator desktop receipt binding mismatch")
    soak_binding = verify_sanitized_supervised_soak_binding(
        export_dir,
        expected_source_digest=expected_source_digest,
        passed_gates=passed_gates,
        desktop_binding=desktop_binding,
    )
    if summary.get("supervised_soak_binding") != soak_binding:
        raise RuntimeError("formal validator supervised soak summary binding mismatch")
    if validator.get("supervised_soak_binding") != soak_binding:
        raise RuntimeError("formal validator supervised soak receipt binding mismatch")
    if report is not None:
        expected_core = _formal_report_core(report, source_digest=expected_source_digest)
        if core != expected_core:
            raise RuntimeError("formal validator passed_gates/report mismatch")


def _prune_unvalidated_gate_material(export_dir: Path, *, passed_gates: Sequence[str]) -> None:
    allowed = set(passed_gates)
    final_dir = export_dir / "final"
    gates_dir = export_dir / "gates"
    final_dir.mkdir(parents=True, exist_ok=True)
    gates_dir.mkdir(parents=True, exist_ok=True)
    for path in final_dir.iterdir():
        gate_name = path.name.removesuffix(".receipt.json")
        if not path.name.endswith(".receipt.json") or gate_name not in allowed:
            _remove_path_no_follow(path)
    for path in gates_dir.iterdir():
        name = path.name
        gate_name = name.removesuffix(".stdout.txt").removesuffix(".stderr.txt")
        if (
            not name.endswith((".stdout.txt", ".stderr.txt"))
            or gate_name not in allowed
        ):
            _remove_path_no_follow(path)
    if "soak_3600" not in allowed:
        combined = export_dir / SUPERVISED_SOAK_COMBINED_RELATIVE
        if combined.exists():
            _remove_path_no_follow(combined)


def _path_exists_no_follow(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _remove_path_no_follow(path: Path) -> None:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(path)
    else:
        path.unlink()


def _remove_private_staging_tree(path: Path) -> None:
    """Remove our mode-0700 staging tree without following symlinks."""
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(st.st_mode):
        path.unlink()
        return
    with os.scandir(path) as entries:
        for entry in entries:
            _remove_private_staging_tree(Path(entry.path))
    path.rmdir()


def _publish_staged_export(*, staging_root: Path, out_root: Path) -> None:
    staged_export = staging_root / EXPORT_DIR_NAME
    staged_envelope = staging_root / ENVELOPE_NAME
    final_export = out_root / EXPORT_DIR_NAME
    final_envelope = out_root / ENVELOPE_NAME
    previous_export = staging_root / f".previous-{EXPORT_DIR_NAME}"
    previous_envelope = staging_root / f".previous-{ENVELOPE_NAME}"

    backed_up_export = False
    backed_up_envelope = False
    published_export = False
    published_envelope = False
    try:
        if _path_exists_no_follow(final_export):
            os.replace(final_export, previous_export)
            backed_up_export = True
        if _path_exists_no_follow(final_envelope):
            os.replace(final_envelope, previous_envelope)
            backed_up_envelope = True
        os.replace(staged_export, final_export)
        published_export = True
        os.replace(staged_envelope, final_envelope)
        published_envelope = True
    except BaseException as publish_error:
        rollback_errors: list[BaseException] = []

        def attempt(action: Callable[[], None]) -> None:
            try:
                action()
            except BaseException as exc:
                rollback_errors.append(exc)

        if published_envelope:
            attempt(lambda: _remove_path_no_follow(final_envelope))
        if published_export:
            attempt(lambda: _remove_path_no_follow(final_export))
        if backed_up_export:
            attempt(lambda: os.replace(previous_export, final_export))
        if backed_up_envelope:
            attempt(lambda: os.replace(previous_envelope, final_envelope))
        if rollback_errors:
            kinds = ", ".join(type(exc).__name__ for exc in rollback_errors)
            raise _SanitizedExportRollbackError(
                "sanitized export rollback failed "
                f"({kinds}); recovery backup retained in .{EXPORT_DIR_NAME}.staging-*"
            ) from publish_error
        raise


def build_sanitized_export(
    *,
    evidence_root: Path,
    repo_root: Path,
    source_digest: str,
    out_root: Path | None = None,
    top_level_docs: Iterable[Path] | None = None,
    required_gates: Sequence[str] | None = None,
    min_receipts: int | None = None,
) -> ExportResult:
    from js.echo.ledger.release_gates import (
        release_source_digest,
        validate_final_local_gate_evidence,
    )

    evidence_root = evidence_root.resolve()
    repo_root = repo_root.resolve()
    out_root = (out_root or evidence_root).resolve()
    live_digest = release_source_digest(repo_root)
    if source_digest != live_digest:
        raise RuntimeError("formal validator source digest does not match current source")
    report = validate_final_local_gate_evidence(
        repo_root,
        final_dir=evidence_root / "final",
        evidence_dir=evidence_root,
        expected_source_digest=source_digest,
    )
    report_core = _formal_report_core(report, source_digest=source_digest)
    passed_gates = _core_string_tuple(report_core, "passed_gates")
    if required_gates is not None and tuple(required_gates) != passed_gates:
        raise RuntimeError("requested gate subset must match formal validator passed_gates")
    if min_receipts is not None and min_receipts != len(passed_gates):
        raise RuntimeError("min_receipts must match formal validator passed_gates")
    out_root.mkdir(parents=True, exist_ok=True)
    staging_root = Path(
        tempfile.mkdtemp(prefix=f".{EXPORT_DIR_NAME}.staging-", dir=out_root)
    )
    cleanup_staging = True
    try:
        staged = _build_sanitized_export_staged(
            evidence_root=evidence_root,
            repo_root=repo_root,
            source_digest=source_digest,
            out_root=staging_root,
            top_level_docs=top_level_docs,
            report=report,
        )
        result = ExportResult(
            export_dir=out_root / EXPORT_DIR_NAME,
            manifest_path=out_root / EXPORT_DIR_NAME / MANIFEST_NAME,
            envelope_path=out_root / ENVELOPE_NAME,
            entry_count=staged.entry_count,
            total_bytes=staged.total_bytes,
            manifest_file_sha256=staged.manifest_file_sha256,
            envelope_file_sha256=staged.envelope_file_sha256,
            envelope_manifest_sha256=staged.envelope_manifest_sha256,
            validation_ok=bool(report_core["all_local_gates_passed"]),
            passed_gates=passed_gates,
            blockers=_core_string_tuple(report_core, "blockers"),
        )
        final_report = validate_final_local_gate_evidence(
            repo_root,
            final_dir=evidence_root / "final",
            evidence_dir=evidence_root,
            expected_source_digest=source_digest,
        )
        if _formal_report_core(final_report, source_digest=source_digest) != report_core:
            raise RuntimeError("formal validator report changed while building export")
        _publish_staged_export(staging_root=staging_root, out_root=out_root)
        return result
    except _SanitizedExportRollbackError:
        cleanup_staging = False
        raise
    finally:
        if cleanup_staging:
            _remove_private_staging_tree(staging_root)


def _build_sanitized_export_staged(
    *,
    evidence_root: Path,
    repo_root: Path,
    source_digest: str,
    out_root: Path,
    top_level_docs: Iterable[Path] | None,
    report: object,
) -> ExportResult:
    export_dir = out_root / EXPORT_DIR_NAME
    export_dir.mkdir(parents=True, exist_ok=True)

    evidence_root_fd = _open_evidence_root(evidence_root)
    try:
        sources = _iter_allowlisted_sources(evidence_root, evidence_root_fd=evidence_root_fd)
        try:
            for source in sources:
                dest = export_dir / source.relative
                _copy_allowlisted_source(
                    source,
                    dest,
                    evidence_root_fd=evidence_root_fd,
                    validator_inputs_fd=sources.validator_inputs_fd,
                    repo_root=repo_root,
                    evidence_root=evidence_root,
                )
        finally:
            sources.close()
    finally:
        os.close(evidence_root_fd)

    for doc in top_level_docs or ():
        if not doc.is_file():
            continue
        dest = export_dir / "docs" / doc.name
        _copy_redacted(doc, dest, repo_root=repo_root, evidence_root=evidence_root)

    report_core = _formal_report_core(report, source_digest=source_digest)
    expected_gates = _core_string_tuple(report_core, "passed_gates")
    _prune_unvalidated_gate_material(export_dir, passed_gates=expected_gates)
    # Copy exact receipt-referenced logs: gates/<gate>.stdout.txt / .stderr.txt only.
    for gate_name in expected_gates:
        for kind in ("stdout", "stderr"):
            src = evidence_root / "gates" / f"{gate_name}.{kind}.txt"
            if not src.is_file():
                continue
            dest = export_dir / "gates" / f"{gate_name}.{kind}.txt"
            if not dest.exists():
                _copy_redacted(src, dest, repo_root=repo_root, evidence_root=evidence_root)

    # Update receipt SHA-256 digests to match the redacted gate logs in the export.
    export_final_dir = export_dir / "final"
    if export_final_dir.is_dir():
        for gate_name in expected_gates:
            receipt_path = export_final_dir / f"{gate_name}.receipt.json"
            if not receipt_path.is_file():
                continue
            try:
                receipt = strict_load_path(receipt_path)
            except (OSError, StrictJSONError, ValueError):
                continue
            if not isinstance(receipt, dict):
                continue
            updated = False
            for kind, digest_field, bytes_field in (
                ("stdout", "stdout_sha256", "stdout_bytes"),
                ("stderr", "stderr_sha256", "stderr_bytes"),
            ):
                log_file = export_dir / "gates" / f"{gate_name}.{kind}.txt"
                if not log_file.is_file():
                    continue
                raw = log_file.read_bytes()
                new_sha = hashlib.sha256(raw).hexdigest()
                if receipt.get(digest_field) != new_sha:
                    receipt[digest_field] = new_sha
                    receipt[bytes_field] = len(raw)
                    updated = True
            if updated:
                receipt_path.write_text(
                    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )

    desktop_binding = _write_sanitized_desktop_descriptor(
        evidence_root=evidence_root,
        export_dir=export_dir,
        repo_root=repo_root,
        source_digest=source_digest,
        passed_gates=expected_gates,
    )
    soak_binding = verify_sanitized_supervised_soak_binding(
        export_dir,
        expected_source_digest=source_digest,
        passed_gates=expected_gates,
        desktop_binding=desktop_binding,
    )
    _write_export_validator_binding(
        export_dir,
        source_digest=source_digest,
        report=report,
        desktop_binding=desktop_binding,
        soak_binding=soak_binding,
    )
    verify_export_validator_binding(
        export_dir,
        expected_source_digest=source_digest,
        report=report,
    )

    current_home = str(Path.home().resolve())
    export_archives = _collect_scannable_archives(export_dir)
    archive_hits: list[PrivacyHit] = []
    for archive in export_archives:
        archive_hits.extend(scan_archive_members(archive, current_home=current_home))
    write_archive_scan_receipt(export_dir, source_digest=source_digest, hits=archive_hits)

    manifest_path, entry_count, total_bytes = build_manifest_v2(export_dir)
    verify_manifest_v2(export_dir)
    verify_export_receipt_log_closure(
        export_dir=export_dir,
        expected_source_digest=source_digest,
        required_gates=expected_gates,
        min_receipts=len(expected_gates),
    )
    e2e_candidate = evidence_root / "e2e" / "ECHO_ISOLATED_VENV_E2E.json"
    verify_archive_scan_receipt(
        export_dir,
        source_digest=source_digest,
        e2e_artifact_json=e2e_candidate if e2e_candidate.is_file() else None,
    )
    envelope_path, envelope_manifest_sha256 = write_envelope(
        out_root=out_root,
        manifest_path=manifest_path,
        source_digest=source_digest,
        entry_count=entry_count,
    )
    hits = privacy_scan(export_dir)
    hits.extend(privacy_scan_file(envelope_path))
    hits.extend(archive_hits)
    if hits:
        raise RuntimeError(f"privacy_scan fail-closed: {format_privacy_hits(hits[:5])}")

    return ExportResult(
        export_dir=export_dir,
        manifest_path=manifest_path,
        envelope_path=envelope_path,
        entry_count=entry_count,
        total_bytes=total_bytes,
        manifest_file_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        envelope_file_sha256=hashlib.sha256(envelope_path.read_bytes()).hexdigest(),
        envelope_manifest_sha256=envelope_manifest_sha256,
        validation_ok=bool(report_core["all_local_gates_passed"]),
        passed_gates=expected_gates,
        blockers=_core_string_tuple(report_core, "blockers"),
    )


def assert_docs_byte_identical(top_level: Path, export_copy: Path) -> None:
    if top_level.read_bytes() != export_copy.read_bytes():
        raise RuntimeError(f"top-level/export docs diverge: {top_level.name}")


def assert_no_self_hash_fields(payload: object) -> None:
    forbidden = {
        "self_sha256",
        "own_sha256",
        "document_sha256",
        "this_file_sha256",
        "final_evidence_sha256",
    }
    if isinstance(payload, dict):
        bad = forbidden & set(payload)
        if bad:
            raise RuntimeError(f"self-hash fields forbidden: {sorted(bad)}")
        for key, value in payload.items():
            if key == "manifest_sha256" and "envelope" not in str(
                payload.get("schema_version", "")
            ):
                raise RuntimeError("content JSON must not embed manifest_sha256; use envelope")
            assert_no_self_hash_fields(value)
    elif isinstance(payload, list):
        for item in payload:
            assert_no_self_hash_fields(item)
