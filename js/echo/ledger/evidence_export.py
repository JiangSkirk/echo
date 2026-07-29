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
import os
import re
import shutil
import stat
import tarfile
import zipfile
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from js.echo.ledger.strict_json import StrictJSONError, strict_load_object, strict_load_path

MANIFEST_NAME = "MANIFEST.sha256"
ENVELOPE_NAME = "MANIFEST.envelope.json"
EXPORT_DIR_NAME = "sanitized-export"
ARCHIVE_SCAN_RECEIPT_NAME = "archive_scan.receipt.json"
ARCHIVE_SCAN_SCHEMA = "js-agent-archive-scan-receipt-v1"
ARCHIVE_SCAN_RULE_VERSION = "archive-scan-rules-v3"
MANIFEST_SCHEMA = "js-agent-evidence-manifest-v2"
ENVELOPE_SCHEMA = "js-agent-evidence-envelope-v1"
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
_ALLOWLIST_SOURCE_MAX_BYTES = 512 * 1024 * 1024

# Versioned allowlist for archive members that define privacy regexes (not secrets).
# Scan reports must name this scope; do not claim "whole archive 0 hits" when used.
_ARCHIVE_PATTERN_SOURCE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "js/echo/ledger/evidence_export.py",
        "js/echo/ledger/privacy.py",
    }
)
_ARCHIVE_PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n")


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

    @property
    def manifest_sha256(self) -> str:
        """Alias for manifest_file_sha256 (legacy field name)."""
        return self.manifest_file_sha256

    @property
    def envelope_sha256(self) -> str:
        """Alias for envelope_file_sha256 (legacy field name)."""
        return self.envelope_file_sha256


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
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
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
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    hits: list[PrivacyHit] = []
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
    except ValueError as exc:
        raise RuntimeError(f"path escape in export: {path}") from exc
    if ".." in relative.parts or relative.is_absolute():
        raise RuntimeError(f"path escape component in export: {path}")
    # Do not Path.resolve() the member (would follow symlinks).
    st = path.lstat()
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        raise RuntimeError(f"symlink forbidden in export: {relative.as_posix()}")
    if not stat.S_ISREG(mode):
        raise RuntimeError(f"non-regular file forbidden in export: {relative.as_posix()}")
    if st.st_nlink != 1:
        raise RuntimeError(f"hardlink forbidden in export: {relative.as_posix()}")
    return st


def enumerate_export_regular_files(export_dir: Path) -> dict[str, os.stat_result]:
    """Shared safe tree walk for builder and verifier (lstat, regular files only)."""
    export_dir = export_dir.resolve()
    found: dict[str, os.stat_result] = {}
    for dirpath, dirnames, filenames in os.walk(export_dir, followlinks=False):
        base = Path(dirpath)
        # Refuse directory symlinks in the walk frontier.
        for name in list(dirnames):
            child = base / name
            try:
                child_st = child.lstat()
            except OSError as exc:
                raise RuntimeError(f"unreadable export dirent: {child}") from exc
            if stat.S_ISLNK(child_st.st_mode):
                raise RuntimeError(f"directory symlink forbidden in export: {child}")
            if not stat.S_ISDIR(child_st.st_mode):
                raise RuntimeError(f"non-directory child in dirnames: {child}")
        for name in filenames:
            path = base / name
            st = path.lstat()
            relative = path.relative_to(export_dir).as_posix()
            if relative == MANIFEST_NAME:
                # Manifest is the only intentional self-exclusion; still must be regular.
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise RuntimeError("MANIFEST.sha256 must be a regular nlink==1 file")
                continue
            if (
                stat.S_ISLNK(st.st_mode)
                or stat.S_ISFIFO(st.st_mode)
                or stat.S_ISSOCK(st.st_mode)
                or stat.S_ISCHR(st.st_mode)
                or stat.S_ISBLK(st.st_mode)
            ):
                raise RuntimeError(f"forbidden special file in export: {relative}")
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError(f"non-regular file forbidden in export: {relative}")
            if st.st_nlink != 1:
                raise RuntimeError(f"hardlink forbidden in export: {relative}")
            if ".." in Path(relative).parts:
                raise RuntimeError(f"path escape component in export: {relative}")
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
                raise RuntimeError(f"archive path escape: {rel}")
            if stat.S_ISLNK(st.st_mode):
                raise RuntimeError(f"archive must not be symlink: {rel}")
            if (
                stat.S_ISFIFO(st.st_mode)
                or stat.S_ISSOCK(st.st_mode)
                or stat.S_ISCHR(st.st_mode)
                or stat.S_ISBLK(st.st_mode)
            ):
                raise RuntimeError(f"archive must not be special file: {rel}")
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError(f"archive must be regular file: {rel}")
            if int(st.st_nlink) != 1:
                raise RuntimeError(f"archive must have nlink==1: {rel}")
            try:
                path.resolve(strict=False).relative_to(root_resolved)
            except ValueError as exc:
                raise RuntimeError(f"archive path escape: {rel}") from exc
            archives.append(path)

    basenames = [path.name for path in archives]
    if len(basenames) != len(set(basenames)):
        raise RuntimeError("export archives have duplicate basenames")
    return archives


def write_archive_scan_receipt(
    export_dir: Path,
    *,
    source_digest: str,
    hits: Sequence[PrivacyHit],
) -> Path:
    """Bind archive scan results to frozen digest + per-artifact identity."""
    artifacts: list[dict[str, object]] = []
    for path in _collect_export_archives(export_dir):
        data = path.read_bytes()
        artifacts.append(
            {
                "relative_path": path.relative_to(export_dir).as_posix(),
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
    actual_archives: dict[str, Path] = {
        path.relative_to(export_dir).as_posix(): path
        for path in _collect_export_archives(export_dir)
    }

    # --- Parse receipt artifacts and require exact set + identity match. ---
    receipt_artifacts: dict[str, tuple[str, int, str]] = {}
    listed = payload.get("artifacts")
    if not isinstance(listed, list):
        raise RuntimeError("archive scan artifacts missing")
    for item in listed:
        if not isinstance(item, dict):
            raise RuntimeError("archive scan artifact entry invalid")
        relative = item.get("relative_path")
        filename = item.get("filename")
        size = item.get("size")
        digest = item.get("sha256")
        if (
            not isinstance(relative, str)
            or not isinstance(filename, str)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not isinstance(digest, str)
            or Path(relative).name != filename
        ):
            raise RuntimeError("archive scan artifact identity invalid")
        if relative in receipt_artifacts:
            raise RuntimeError(f"duplicate archive scan artifact path: {relative}")
        receipt_artifacts[relative] = (filename, int(size), digest)

    if set(receipt_artifacts) != set(actual_archives):
        missing = sorted(set(receipt_artifacts) - set(actual_archives))
        extra = sorted(set(actual_archives) - set(receipt_artifacts))
        raise RuntimeError(f"archive set mismatch missing={missing[:5]} extra={extra[:5]}")
    for relative, (filename, size, digest) in receipt_artifacts.items():
        path = actual_archives[relative]
        if path.name != filename:
            raise RuntimeError(f"archive filename mismatch: {relative}")
        data = path.read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError(f"archive identity drift: {relative}")

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
        if set(actual_archives) != set(declared):
            raise RuntimeError(
                "e2e artifact closure mismatch "
                f"missing_count={len(set(declared) - set(actual_archives))} "
                f"extra_count={len(set(actual_archives) - set(declared))}"
            )
        for relative, (filename, size, digest) in declared.items():
            path = actual_archives[relative]
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
    if len(canonical_receipt) != len(receipt_hits):
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


def scan_archive_members(path: Path, *, current_home: str) -> list[PrivacyHit]:
    """Bounded wheel/sdist member privacy scan."""
    hits: list[PrivacyHit] = []
    relative = path.name
    archive_kind = _classify_release_archive_name(path.name)
    if archive_kind is None:
        raise RuntimeError("unsupported release archive format")
    if archive_kind == "wheel":
        try:
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()
                if len(infos) > _ARCHIVE_MAX_MEMBERS:
                    hits.append(PrivacyHit("archive_member_limit", relative, len(infos)))
                    return hits
                total = 0
                for info in infos:
                    if info.is_dir():
                        continue
                    name = info.filename
                    if ".." in Path(name).parts or name.startswith("/"):
                        hits.append(PrivacyHit("archive_path_escape", relative, 1))
                    if info.external_attr and (stat.S_ISLNK(info.external_attr >> 16)):
                        hits.append(PrivacyHit("archive_symlink", relative, 1))
                    if name.endswith(".private") or name.endswith("_private.pem"):
                        hits.append(PrivacyHit("archive_private_name", relative, 1))
                    total += int(info.file_size)
                    if total > _ARCHIVE_MAX_UNCOMPRESSED:
                        hits.append(PrivacyHit("archive_size_limit", relative, 1))
                        return hits
                    if info.file_size and info.compress_size:
                        ratio = info.file_size / max(info.compress_size, 1)
                        if ratio > _ARCHIVE_MAX_RATIO:
                            hits.append(PrivacyHit("archive_compression_ratio", relative, 1))
                    # Sample text members for HOME / PEM (bounded).
                    if info.file_size <= 256_000 and name.endswith((".py", ".txt", ".md", ".json")):
                        if name in _ARCHIVE_PATTERN_SOURCE_ALLOWLIST:
                            continue
                        data = archive.read(info)
                        try:
                            text = data.decode("utf-8")
                        except UnicodeDecodeError:
                            continue
                        if current_home and current_home in text:
                            hits.append(PrivacyHit("archive_current_home", relative, 1))
                        if _ARCHIVE_PEM_RE.search(text):
                            hits.append(PrivacyHit("archive_pem_private", relative, 1))
        except zipfile.BadZipFile:
            hits.append(PrivacyHit("archive_unreadable", relative, 1))
        return hits

    if archive_kind == "sdist":
        try:
            with tarfile.open(path, "r:gz") as archive:
                members = archive.getmembers()
                if len(members) > _ARCHIVE_MAX_MEMBERS:
                    hits.append(PrivacyHit("archive_member_limit", relative, len(members)))
                    return hits
                total = 0
                for member in members:
                    name = member.name
                    if ".." in Path(name).parts or name.startswith("/"):
                        hits.append(PrivacyHit("archive_path_escape", relative, 1))
                    if member.issym() or member.islnk() or member.isdev():
                        hits.append(PrivacyHit("archive_special_member", relative, 1))
                    if name.endswith(".private") or name.endswith("_private.pem"):
                        hits.append(PrivacyHit("archive_private_name", relative, 1))
                    total += int(member.size)
                    if total > _ARCHIVE_MAX_UNCOMPRESSED:
                        hits.append(PrivacyHit("archive_size_limit", relative, 1))
                        return hits
                    if (
                        member.isfile()
                        and member.size <= 256_000
                        and name.endswith((".py", ".txt", ".md", ".json"))
                    ):
                        if name in _ARCHIVE_PATTERN_SOURCE_ALLOWLIST:
                            continue
                        handle = archive.extractfile(member)
                        if handle is None:
                            continue
                        data = handle.read()
                        try:
                            text = data.decode("utf-8")
                        except UnicodeDecodeError:
                            continue
                        if current_home and current_home in text:
                            hits.append(PrivacyHit("archive_current_home", relative, 1))
                        if _ARCHIVE_PEM_RE.search(text):
                            hits.append(PrivacyHit("archive_pem_private", relative, 1))
        except tarfile.TarError:
            hits.append(PrivacyHit("archive_unreadable", relative, 1))
    return hits


def archive_scan_scope_notes() -> str:
    """Document bounded archive scan scope for reports (no blanket zero claims)."""
    allow = ", ".join(sorted(_ARCHIVE_PATTERN_SOURCE_ALLOWLIST))
    return (
        "Archive scan covers path-escape/symlink/special/private-name/size/ratio, "
        "literal current HOME, and PEM private headers in text members "
        f"<=256KiB (.py/.txt/.md/.json). Pattern-source allowlist: {allow}."
    )


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
    from js.echo.ledger.release_gates import REQUIRED_FINAL_LOCAL_GATES

    evidence_root = evidence_root.resolve()
    repo_root = repo_root.resolve()
    out_root = (out_root or evidence_root).resolve()
    export_dir = out_root / EXPORT_DIR_NAME
    if export_dir.exists():
        shutil.rmtree(export_dir)
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

    expected_gates = (
        tuple(required_gates) if required_gates is not None else REQUIRED_FINAL_LOCAL_GATES
    )
    # Copy exact receipt-referenced logs: gates/<gate>.stdout.txt / .stderr.txt only.
    for gate_name in expected_gates:
        for kind in ("stdout", "stderr"):
            src = evidence_root / "gates" / f"{gate_name}.{kind}.txt"
            if not src.is_file():
                continue
            dest = export_dir / "gates" / f"{gate_name}.{kind}.txt"
            if not dest.exists():
                _copy_redacted(src, dest, repo_root=repo_root, evidence_root=evidence_root)

    current_home = str(Path.home().resolve())
    export_archives = _collect_export_archives(export_dir)
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
        min_receipts=min_receipts,
    )
    e2e_candidate = evidence_root / "e2e" / "ECHO_ISOLATED_VENV_E2E.json"
    verify_archive_scan_receipt(
        export_dir,
        source_digest=source_digest,
        e2e_artifact_json=e2e_candidate,
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
