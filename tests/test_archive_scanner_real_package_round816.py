from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
import warnings
import zipfile
import zlib
from pathlib import Path

import pytest

import js.echo.ledger.evidence_export as evidence_export
import js.echo.ledger.release_gates as release_gates
from js.echo.ledger.evidence_export import (
    ARCHIVE_SCAN_RECEIPT_NAME,
    PrivacyHit,
    build_sanitized_export,
    scan_archive_members,
    verify_archive_scan_receipt,
    write_archive_scan_receipt,
)
from scripts import build_sanitized_evidence_export

_DIGEST = "8" * 64
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SDIST_ROOT = "js_agent-0.1.5"
_WHEEL_NAME = "js_agent-0.1.5-py3-none-any.whl"
_SDIST_NAME = f"{_SDIST_ROOT}.tar.gz"

_SAFE_SOURCE_MEMBERS: dict[str, bytes] = {
    "js/echo/ledger/evidence_export.py": (
        b'users_pattern = r"/Users/[^"\n'
        b'home_pattern = r"/home/[^"\n'
        b'private_basename = "ledger.ed25519.private"\n'
    ),
    "js/echo/ledger/e2e_signing.py": b'private_basename = "ledger.ed25519.private"\n',
    "js/echo/ledger/security_matrix.py": (
        b'case = "Bearer authorization"\n'
        b'header = "Bearer abc.def.ghi"\n'
        b'assert "Bearer abc" not in header\n'
    ),
    "js/models/capability.py": b'note = "bearer token"\n',
    "js/models/providers.py": b'note = "Bearer token"\n',
    "js/security/strategies.py": b'note = "/home/.."\n',
}

_FONT_MEMBERS = (
    "js/web/static/vendor/fontawesome/webfonts/fa-brands-400.ttf",
    "js/web/static/vendor/fontawesome/webfonts/fa-brands-400.woff2",
    "js/web/static/vendor/fontawesome/webfonts/fa-regular-400.ttf",
    "js/web/static/vendor/fontawesome/webfonts/fa-regular-400.woff2",
    "js/web/static/vendor/fontawesome/webfonts/fa-solid-900.ttf",
    "js/web/static/vendor/fontawesome/webfonts/fa-solid-900.woff2",
    "js/web/static/vendor/fontawesome/webfonts/fa-v4compatibility.ttf",
    "js/web/static/vendor/fontawesome/webfonts/fa-v4compatibility.woff2",
)


def _real_package_members() -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    for root_name in ("js", "js_work", "resources"):
        root = _REPO_ROOT / root_name
        for path in sorted(root.rglob("*")):
            if (
                not path.is_file()
                or path.is_symlink()
                or "__pycache__" in path.parts
                or path.name.startswith(".")
                or path.suffix == ".pyc"
            ):
                continue
            members[path.relative_to(_REPO_ROOT).as_posix()] = path.read_bytes()
    return members


def _zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w") as archive:
            for member, payload in entries:
                archive.writestr(member, payload)
    return stream.getvalue()


def _tar_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for member, payload in entries:
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


def _eocd_offset(payload: bytes) -> int:
    offset = payload.rfind(b"PK\x05\x06")
    assert offset >= 0
    return offset


def _mutate_eocd_u16(payload: bytes, relative_offset: int, value: int) -> bytes:
    body = bytearray(payload)
    offset = _eocd_offset(payload) + relative_offset
    body[offset : offset + 2] = value.to_bytes(2, "little")
    return bytes(body)


def _mutate_eocd_u32(payload: bytes, relative_offset: int, value: int) -> bytes:
    body = bytearray(payload)
    offset = _eocd_offset(payload) + relative_offset
    body[offset : offset + 4] = value.to_bytes(4, "little")
    return bytes(body)


def _hundred_thousand_member_zip() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for index in range(100_000):
            archive.writestr(f"empty/{index:06d}", b"")
    return stream.getvalue()


def _hundred_thousand_member_tar_gz() -> bytes:
    header = tarfile.TarInfo("empty").tobuf()
    return gzip.compress(header * 100_000 + b"\0" * 1024, compresslevel=1, mtime=0)


def _zip64_archive(
    *,
    extensible_sector: bytes = b"",
    legacy_mutation: str | None = None,
) -> bytes:
    base = _zip_bytes([("pkg/clean.py", b"clean = True\n")])
    eocd = _eocd_offset(base)
    entry_count = int.from_bytes(base[eocd + 10 : eocd + 12], "little")
    central_size = int.from_bytes(base[eocd + 12 : eocd + 16], "little")
    central_offset = int.from_bytes(base[eocd + 16 : eocd + 20], "little")
    assert entry_count == 1
    assert central_offset + central_size == eocd

    zip64_record = (
        b"PK\x06\x06"
        + (44 + len(extensible_sector)).to_bytes(8, "little")
        + (45).to_bytes(2, "little")
        + (45).to_bytes(2, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + entry_count.to_bytes(8, "little")
        + entry_count.to_bytes(8, "little")
        + central_size.to_bytes(8, "little")
        + central_offset.to_bytes(8, "little")
        + extensible_sector
    )
    locator = (
        b"PK\x06\x07"
        + (0).to_bytes(4, "little")
        + eocd.to_bytes(8, "little")
        + (1).to_bytes(4, "little")
    )
    final_eocd = bytearray(base[eocd:])
    final_eocd[8:12] = b"\xff" * 4
    final_eocd[12:20] = b"\xff" * 8
    if legacy_mutation == "disk_entries_conflict":
        final_eocd[8:10] = (entry_count + 1).to_bytes(2, "little")
        final_eocd[10:12] = entry_count.to_bytes(2, "little")
    elif legacy_mutation == "entry_count_conflict":
        final_eocd[8:10] = entry_count.to_bytes(2, "little")
        final_eocd[10:12] = (entry_count + 1).to_bytes(2, "little")
    elif legacy_mutation == "central_size_conflict":
        final_eocd[12:16] = (central_size + 1).to_bytes(4, "little")
    elif legacy_mutation == "central_offset_conflict":
        final_eocd[16:20] = (central_offset + 1).to_bytes(4, "little")
    elif legacy_mutation == "disk_entries_consistent":
        final_eocd[8:10] = entry_count.to_bytes(2, "little")
    elif legacy_mutation == "entry_count_consistent":
        final_eocd[10:12] = entry_count.to_bytes(2, "little")
    elif legacy_mutation is not None:
        raise AssertionError(f"unknown ZIP64 legacy mutation: {legacy_mutation}")
    return base[:eocd] + zip64_record + locator + bytes(final_eocd)


def _zip64_with_extensible_sector(marker: bytes) -> bytes:
    return _zip64_archive(extensible_sector=marker)


def _zip_with_deflate_trailing_data(marker: bytes) -> bytes:
    base = _zip_with_metadata("none", b"")
    local = base.find(b"PK\x03\x04")
    central = base.find(b"PK\x01\x02")
    eocd = _eocd_offset(base)
    assert local == 0 and 0 < central < eocd
    compressed_size = int.from_bytes(base[local + 18 : local + 22], "little")
    name_size = int.from_bytes(base[local + 26 : local + 28], "little")
    extra_size = int.from_bytes(base[local + 28 : local + 30], "little")
    data_end = local + 30 + name_size + extra_size + compressed_size
    assert data_end == central

    body = bytearray(base[:data_end] + marker + base[data_end:])
    shifted_central = central + len(marker)
    shifted_eocd = eocd + len(marker)
    expanded_size = compressed_size + len(marker)
    body[local + 18 : local + 22] = expanded_size.to_bytes(4, "little")
    body[shifted_central + 20 : shifted_central + 24] = expanded_size.to_bytes(4, "little")
    body[shifted_eocd + 16 : shifted_eocd + 20] = shifted_central.to_bytes(4, "little")
    return bytes(body)


def _gzip_with_optional_header(payload: bytes, kind: str, marker: bytes) -> bytes:
    assert payload[:3] == b"\x1f\x8b\x08"
    header = bytearray(payload[:10])
    optional = b""
    if kind == "extra":
        header[3] = 0x04
        optional = len(marker).to_bytes(2, "little") + marker
    elif kind == "name":
        header[3] = 0x08
        optional = marker + b"\0"
    elif kind == "comment":
        header[3] = 0x10
        optional = marker + b"\0"
    elif kind == "header_crc":
        header[3] = 0x02
        checksum = zlib.crc32(header) & 0xFFFF
        optional = checksum.to_bytes(2, "little")
    elif kind == "unknown_flag":
        header[3] = 0x20
    else:
        raise AssertionError(f"unknown gzip header kind: {kind}")
    return bytes(header) + optional + payload[10:]


def _zip_with_metadata(kind: str, marker: bytes) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("pkg/clean.py")
        info.compress_type = zipfile.ZIP_DEFLATED
        if kind == "member_comment":
            info.comment = marker
        elif kind == "member_extra":
            info.extra = b"\xfe\xca" + len(marker).to_bytes(2, "little") + marker
        archive.writestr(info, b"clean = True\n")
        if kind == "archive_comment":
            archive.comment = marker
    return stream.getvalue()


def _mutate_zip_layout(payload: bytes, mutation: str, marker: bytes) -> bytes:
    local = payload.find(b"PK\x03\x04")
    central = payload.find(b"PK\x01\x02")
    eocd = _eocd_offset(payload)
    assert local == 0 and 0 < central < eocd
    body = bytearray(payload)
    if mutation == "local_crc":
        body[local + 14] ^= 1
        return bytes(body)
    if mutation == "local_flags":
        flags = int.from_bytes(body[local + 6 : local + 8], "little")
        body[local + 6 : local + 8] = (flags | 0x8).to_bytes(2, "little")
        return bytes(body)
    if mutation == "local_method":
        method = int.from_bytes(body[local + 8 : local + 10], "little")
        body[local + 8 : local + 10] = (0 if method else 8).to_bytes(2, "little")
        return bytes(body)
    if mutation == "local_size":
        size = int.from_bytes(body[local + 18 : local + 22], "little")
        body[local + 18 : local + 22] = (size + 1).to_bytes(4, "little")
        return bytes(body)
    if mutation == "local_name":
        name_start = local + 30
        body[name_start] ^= 1
        return bytes(body)
    if mutation == "gap":
        mutated = bytearray(payload[:central] + marker + payload[central:])
        new_eocd = eocd + len(marker)
        old_offset = int.from_bytes(payload[eocd + 16 : eocd + 20], "little")
        mutated[new_eocd + 16 : new_eocd + 20] = (old_offset + len(marker)).to_bytes(
            4, "little"
        )
        return bytes(mutated)
    if mutation == "prefix":
        mutated = bytearray(marker + payload)
        new_central = central + len(marker)
        new_eocd = eocd + len(marker)
        old_cd_offset = int.from_bytes(payload[eocd + 16 : eocd + 20], "little")
        old_local_offset = int.from_bytes(payload[central + 42 : central + 46], "little")
        mutated[new_eocd + 16 : new_eocd + 20] = (old_cd_offset + len(marker)).to_bytes(
            4, "little"
        )
        mutated[new_central + 42 : new_central + 46] = (
            old_local_offset + len(marker)
        ).to_bytes(4, "little")
        return bytes(mutated)
    if mutation == "trailing":
        return payload + marker
    raise AssertionError(f"unknown mutation: {mutation}")


def _mutate_tar_header(payload: bytes, mutation: str) -> bytes:
    raw = bytearray(gzip.decompress(payload))
    if mutation == "checksum":
        raw[0] ^= 1
    else:
        raw[124:136] = b"99999999999\0"
        raw[148:156] = b" " * 8
        checksum = sum(raw[:512])
        raw[148:156] = f"{checksum:06o}\0 ".encode()
    return gzip.compress(bytes(raw), mtime=0)


_TAR_NUMERIC_FIELDS: dict[str, tuple[int, int]] = {
    "mode": (100, 108),
    "uid": (108, 116),
    "gid": (116, 124),
    "size": (124, 136),
    "mtime": (136, 148),
    "devmajor": (329, 337),
    "devminor": (337, 345),
}


def _mutate_tar_numeric_field(payload: bytes, field_name: str, replacement: bytes) -> bytes:
    raw = bytearray(gzip.decompress(payload))
    start, end = _TAR_NUMERIC_FIELDS[field_name]
    assert len(replacement) == end - start
    raw[start:end] = replacement
    raw[148:156] = b" " * 8
    checksum = sum(raw[:512])
    raw[148:156] = f"{checksum:06o}\0 ".encode()
    return gzip.compress(bytes(raw), mtime=0)


def _pax_tar_gz(marker: str) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("pkg/clean.py")
        info.size = len(b"clean\n")
        info.pax_headers = {"comment": marker}
        archive.addfile(info, io.BytesIO(b"clean\n"))
    return stream.getvalue()


def _tar_with_header_metadata(marker: str) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("pkg/clean.py")
        info.size = len(b"clean\n")
        info.uname = marker
        info.gname = marker
        info.linkname = marker
        archive.addfile(info, io.BytesIO(b"clean\n"))
    return stream.getvalue()


def _global_pax_tar_gz(marker: str) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(
        fileobj=stream,
        mode="w:gz",
        format=tarfile.PAX_FORMAT,
        pax_headers={"comment": marker},
    ) as archive:
        info = tarfile.TarInfo("pkg/clean.py")
        info.size = len(b"clean\n")
        archive.addfile(info, io.BytesIO(b"clean\n"))
    return stream.getvalue()


def _gnu_extension_tar_gz(kind: str, marker: str) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.GNU_FORMAT) as archive:
        if kind == "long_name":
            info = tarfile.TarInfo(f"pkg/{marker}/" + "n" * 180)
            info.size = len(b"clean\n")
            archive.addfile(info, io.BytesIO(b"clean\n"))
        else:
            info = tarfile.TarInfo("pkg/link")
            info.type = tarfile.SYMTYPE
            info.linkname = f"{marker}/" + "l" * 180
            archive.addfile(info)
    return stream.getvalue()


def _write_wheel(path: Path, members: dict[str, bytes]) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for member, payload in members.items():
            archive.writestr(member, payload)
    return path.read_bytes()


def _write_sdist(
    path: Path,
    members: dict[str, bytes],
    *,
    dist_root: str | None = _SDIST_ROOT,
) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for member, payload in members.items():
            archived_name = f"{dist_root}/{member}" if dist_root is not None else member
            info = tarfile.TarInfo(archived_name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    payload = stream.getvalue()
    path.write_bytes(payload)
    return payload


def _make_sensitive_unsafe_export_entry(
    export: Path,
    *,
    kind: str,
    marker: str,
) -> None:
    export.mkdir(parents=True, exist_ok=True)
    sensitive = f"Bearer {marker}"
    if kind == "directory_symlink":
        target_dir = export.parent / "safe-directory-target"
        target_dir.mkdir()
        (export / sensitive).symlink_to(target_dir, target_is_directory=True)
        return

    target = export.parent / "safe-target.whl"
    _write_wheel(target, {"pkg/clean.py": b"clean = True\n"})
    unsafe = export / f"{sensitive}.whl"
    if kind == "symlink":
        unsafe.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, unsafe)
    elif kind == "special":
        os.mkfifo(unsafe)
    else:
        raise AssertionError(f"unknown unsafe export entry kind: {kind}")


def _write_e2e_declaration(evidence: Path, wheel: bytes, sdist: bytes) -> Path:
    path = evidence / "e2e" / "ECHO_ISOLATED_VENV_E2E.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "ok": True,
                "artifacts": {
                    "wheel": {
                        "path": f"e2e/artifacts/{_WHEEL_NAME}",
                        "bytes": len(wheel),
                        "sha256": hashlib.sha256(wheel).hexdigest(),
                    },
                    "sdist": {
                        "path": f"e2e/artifacts/{_SDIST_NAME}",
                        "bytes": len(sdist),
                        "sha256": hashlib.sha256(sdist).hexdigest(),
                    },
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _seed_real_package_evidence(evidence: Path) -> tuple[Path, Path]:
    artifacts = evidence / "e2e" / "artifacts"
    wheel = artifacts / _WHEEL_NAME
    sdist = artifacts / _SDIST_NAME
    members = _real_package_members()
    wheel_payload = _write_wheel(wheel, members)
    sdist_payload = _write_sdist(sdist, members)
    _write_e2e_declaration(evidence, wheel_payload, sdist_payload)
    (evidence / "TOOLCHAIN.lock.json").write_text("{}\n", encoding="utf-8")
    return wheel, sdist


def _partial_report() -> release_gates.FinalLocalGateEvidenceReport:
    return release_gates.FinalLocalGateEvidenceReport(
        all_local_gates_passed=False,
        passed_gates=(),
        blockers=("required_gates_not_complete",),
        product_internal_ready=False,
    )


def test_real_package_wheel_and_canonical_sdist_have_no_false_positive_hits(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / _WHEEL_NAME
    sdist = tmp_path / _SDIST_NAME
    members = _real_package_members()
    _write_wheel(wheel, members)
    _write_sdist(sdist, members)

    wheel_hits = scan_archive_members(wheel, current_home="/Users/runtime-account")
    sdist_hits = scan_archive_members(sdist, current_home="/Users/runtime-account")

    assert wheel_hits == []
    assert sdist_hits == []


def test_current_evidence_export_source_is_safe_in_direct_wheel_and_sdist_members(
    tmp_path: Path,
) -> None:
    source = (_REPO_ROOT / "js/echo/ledger/evidence_export.py").read_bytes()
    wheel = tmp_path / _WHEEL_NAME
    sdist = tmp_path / _SDIST_NAME
    _write_wheel(wheel, {"js/echo/ledger/evidence_export.py": source})
    _write_sdist(sdist, {"js/echo/ledger/evidence_export.py": source})

    assert scan_archive_members(wheel, current_home="/Users/runtime-account") == []
    assert scan_archive_members(sdist, current_home="/Users/runtime-account") == []


@pytest.mark.parametrize(
    ("member", "payload", "expected_rule"),
    [
        (
            "js/echo/ledger/evidence_export.py",
            _SAFE_SOURCE_MEMBERS["js/echo/ledger/evidence_export.py"]
            + b'real_home = "/Users/private-account/work"\n',
            "archive_absolute_home_path",
        ),
        (
            "js/echo/ledger/evidence_export.py",
            _SAFE_SOURCE_MEMBERS["js/echo/ledger/evidence_export.py"]
            + b"-----BEGIN PRIVATE KEY-----\n",
            "archive_pem_private",
        ),
        (
            "js/echo/ledger/e2e_signing.py",
            _SAFE_SOURCE_MEMBERS["js/echo/ledger/e2e_signing.py"]
            + b'copy = "ledger.ed25519.private"\n',
            "archive_ed25519_private_file",
        ),
        (
            "js/echo/ledger/security_matrix.py",
            _SAFE_SOURCE_MEMBERS["js/echo/ledger/security_matrix.py"]
            + b'extra = "Bearer abc"\n',
            "archive_bearer_token",
        ),
    ],
)
def test_exact_source_literal_allowances_are_count_bounded_and_fail_closed(
    tmp_path: Path,
    member: str,
    payload: bytes,
    expected_rule: str,
) -> None:
    wheel = tmp_path / _WHEEL_NAME
    _write_wheel(wheel, {member: payload})

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert any(hit.rule_id == expected_rule and hit.count >= 1 for hit in hits)


@pytest.mark.parametrize(
    ("dist_root", "member"),
    [
        ("lookalike-0.1.5", "js/echo/ledger/e2e_signing.py"),
        (_SDIST_ROOT, "extra/js/echo/ledger/e2e_signing.py"),
    ],
)
def test_noncanonical_or_multilayer_sdist_path_does_not_receive_source_allowance(
    tmp_path: Path,
    dist_root: str,
    member: str,
) -> None:
    sdist = tmp_path / _SDIST_NAME
    _write_sdist(
        sdist,
        {member: b'private_basename = "ledger.ed25519.private"\n'},
        dist_root=dist_root,
    )

    hits = scan_archive_members(sdist, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_ed25519_private_file" for hit in hits)


def test_lookalike_wheel_member_path_does_not_receive_source_allowance(tmp_path: Path) -> None:
    wheel = tmp_path / _WHEEL_NAME
    _write_wheel(
        wheel,
        {
            "prefix/js/echo/ledger/e2e_signing.py": (
                b'private_basename = "ledger.ed25519.private"\n'
            )
        },
    )

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_ed25519_private_file" for hit in hits)


def test_nested_archive_cannot_reset_source_literal_allowance(tmp_path: Path) -> None:
    wheel = tmp_path / _WHEEL_NAME
    inner = _zip_bytes(
        [
            (
                "js/echo/ledger/e2e_signing.py",
                _SAFE_SOURCE_MEMBERS["js/echo/ledger/e2e_signing.py"],
            )
        ]
    )
    _write_wheel(wheel, {"nested/inner.zip": inner})

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_ed25519_private_file" for hit in hits)


@pytest.mark.parametrize(
    "entries",
    [
        [("pkg/repeated.py", b"one\n"), ("pkg/repeated.py", b"two\n")],
        [("pkg/./normalized.py", b"one\n"), ("pkg/normalized.py", b"two\n")],
    ],
)
def test_zip_rejects_duplicate_raw_or_normalized_member_paths(
    tmp_path: Path,
    entries: list[tuple[str, bytes]],
) -> None:
    wheel = tmp_path / _WHEEL_NAME
    wheel.write_bytes(_zip_bytes(entries))

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_duplicate_member" for hit in hits)


@pytest.mark.parametrize(
    "entries",
    [
        [
            (f"{_SDIST_ROOT}/pkg/repeated.py", b"one\n"),
            (f"{_SDIST_ROOT}/pkg/repeated.py", b"two\n"),
        ],
        [
            (f"{_SDIST_ROOT}/pkg/./normalized.py", b"one\n"),
            (f"{_SDIST_ROOT}/pkg/normalized.py", b"two\n"),
        ],
    ],
)
def test_sdist_rejects_duplicate_raw_or_normalized_member_paths(
    tmp_path: Path,
    entries: list[tuple[str, bytes]],
) -> None:
    sdist = tmp_path / _SDIST_NAME
    sdist.write_bytes(_tar_bytes(entries))

    hits = scan_archive_members(sdist, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_duplicate_member" for hit in hits)


def test_only_exact_fontawesome_paths_with_valid_magic_are_binary_safe(tmp_path: Path) -> None:
    wheel = tmp_path / _WHEEL_NAME
    _write_wheel(
        wheel,
        {member: (_REPO_ROOT / member).read_bytes() for member in _FONT_MEMBERS},
    )

    assert scan_archive_members(wheel, current_home="/Users/runtime-account") == []


def test_nested_archive_cannot_reset_font_hash_allowance(tmp_path: Path) -> None:
    wheel = tmp_path / _WHEEL_NAME
    member = _FONT_MEMBERS[0]
    inner = _zip_bytes([(member, (_REPO_ROOT / member).read_bytes())])
    _write_wheel(wheel, {"nested/fonts.zip": inner})

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_non_utf8_member" for hit in hits)


@pytest.mark.parametrize("mutation", ["append_secret", "flip_byte", "plain_text"])
def test_exact_font_path_rejects_injected_or_modified_vendored_bytes(
    tmp_path: Path,
    mutation: str,
) -> None:
    wheel = tmp_path / _WHEEL_NAME
    member = _FONT_MEMBERS[0]
    payload = bytearray((_REPO_ROOT / member).read_bytes())
    if mutation == "plain_text":
        payload = bytearray(b"not a font\n")
    elif mutation == "append_secret":
        payload.extend(b"\n-----BEGIN PRIVATE KEY-----\n")
    else:
        payload[-1] ^= 1
    _write_wheel(wheel, {member: bytes(payload)})

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_non_utf8_member" for hit in hits)


@pytest.mark.parametrize(
    ("member", "payload"),
    [
        (_FONT_MEMBERS[0], b"bad!\xfffont"),
        (_FONT_MEMBERS[1], b"\x00\x01\x00\x00\xfffont"),
        (
            "js/web/static/vendor/fontawesome2/webfonts/fa-brands-400.ttf",
            b"\x00\x01\x00\x00\xfffont",
        ),
        (f"{_FONT_MEMBERS[0]}.bin", b"\x00\x01\x00\x00\xfffont"),
        ("js/package-data.bin", b"\x00\x01\x00\x00\xfffont"),
    ],
)
def test_corrupt_lookalike_or_unknown_binary_remains_fail_closed(
    tmp_path: Path,
    member: str,
    payload: bytes,
) -> None:
    wheel = tmp_path / _WHEEL_NAME
    _write_wheel(wheel, {member: payload})

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    member_hash = hashlib.sha256(member.encode("utf-8")).hexdigest()[:12]
    assert hits == [
        PrivacyHit(
            rule_id="archive_non_utf8_member",
            relative_path=f"{_WHEEL_NAME}!member-0001-{member_hash}",
            count=1,
        )
    ]


def test_hit_identity_binds_archive_and_exact_member_without_match_content(tmp_path: Path) -> None:
    marker = "/Users/receipt-private-marker"
    wheel = tmp_path / _WHEEL_NAME
    _write_wheel(
        wheel,
        {
            "pkg/first.py": f'home = "{marker}/first"\n'.encode(),
            "pkg/second.py": f'home = "{marker}/second"\n'.encode(),
        },
    )

    hits = scan_archive_members(wheel, current_home=marker)

    identities = {hit.relative_path for hit in hits}
    assert len(identities) == 2
    assert all(identity.startswith(f"{_WHEEL_NAME}!member-") for identity in identities)
    assert all("pkg/" not in identity for identity in identities)
    assert marker not in evidence_export.format_privacy_hits(hits)


def test_sensitive_member_name_never_enters_hit_receipt_or_verifier_error(tmp_path: Path) -> None:
    marker = "round816-private-member-marker"
    member = f"records/Users/{marker}/ledger.ed25519.private"
    export = tmp_path / "sanitized-export"
    wheel = export / "e2e" / "artifacts" / _WHEEL_NAME
    _write_wheel(wheel, {member: b"clean payload\n"})

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")
    assert hits
    assert marker not in evidence_export.format_privacy_hits(hits)
    receipt = write_archive_scan_receipt(export, source_digest=_DIGEST, hits=hits)
    assert marker not in receipt.read_text(encoding="utf-8")

    with pytest.raises(RuntimeError) as caught:
        verify_archive_scan_receipt(export, source_digest=_DIGEST)

    assert marker not in str(caught.value)


@pytest.mark.parametrize("archive_kind", ["wheel", "sdist"])
def test_sensitive_ordinary_member_name_is_scanned_without_identity_leak(
    tmp_path: Path,
    archive_kind: str,
) -> None:
    marker = "round816-ordinary-member-name-private"
    member = f"pkg/Bearer {marker}.txt"
    export = tmp_path / "sanitized-export"
    artifacts = export / "e2e" / "artifacts"
    if archive_kind == "wheel":
        archive = artifacts / _WHEEL_NAME
        _write_wheel(archive, {member: b"clean payload\n"})
    else:
        archive = artifacts / _SDIST_NAME
        _write_sdist(archive, {member: b"clean payload\n"})

    hits = scan_archive_members(archive, current_home="/Users/runtime-account")

    assert hits
    assert marker not in evidence_export.format_privacy_hits(hits)
    receipt = write_archive_scan_receipt(export, source_digest=_DIGEST, hits=hits)
    assert marker not in receipt.read_text(encoding="utf-8")
    with pytest.raises(RuntimeError) as caught:
        verify_archive_scan_receipt(export, source_digest=_DIGEST)
    assert marker not in str(caught.value)


def test_sensitive_top_level_archive_name_is_rejected_without_leak(tmp_path: Path) -> None:
    marker = "round816-top-name-private"
    export = tmp_path / "sanitized-export"
    wheel = export / "e2e" / "artifacts" / f"Bearer {marker}.whl"
    _write_wheel(wheel, {"pkg/clean.py": b"clean = True\n"})

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert hits
    assert marker not in evidence_export.format_privacy_hits(hits)
    with pytest.raises(RuntimeError) as caught:
        write_archive_scan_receipt(export, source_digest=_DIGEST, hits=hits)
    assert marker not in str(caught.value)
    receipt = export / ARCHIVE_SCAN_RECEIPT_NAME
    assert not receipt.exists() or marker not in receipt.read_text(encoding="utf-8")


def test_sensitive_archive_relative_directory_is_rejected_without_leak(tmp_path: Path) -> None:
    marker = "round816-relative-dir-private"
    export = tmp_path / "sanitized-export"
    wheel = export / f"Bearer {marker}" / _WHEEL_NAME
    _write_wheel(wheel, {"pkg/clean.py": b"clean = True\n"})
    assert scan_archive_members(wheel, current_home="/Users/runtime-account") == []

    with pytest.raises(RuntimeError) as caught:
        write_archive_scan_receipt(export, source_digest=_DIGEST, hits=[])

    assert marker not in str(caught.value)
    receipt = export / ARCHIVE_SCAN_RECEIPT_NAME
    assert not receipt.exists() or marker not in receipt.read_text(encoding="utf-8")


def test_nested_tar_high_compression_ratio_fails_closed(tmp_path: Path) -> None:
    wheel = tmp_path / _WHEEL_NAME
    inner = _tar_bytes([("nested-1.0/payload.txt", b"0" * (2 * 1024 * 1024))])
    assert (2 * 1024 * 1024) / len(inner) > 200
    _write_wheel(wheel, {"nested/nested-1.0.tar.gz": inner})

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_compression_ratio" for hit in hits)


def test_nested_tar_zero_padding_uses_shared_expansion_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inner = _tar_bytes([("nested-1.0/clean.txt", b"clean\n")])
    outer = _tar_bytes([(f"{_SDIST_ROOT}/nested-1.0.tar.gz", inner)])
    assert len(gzip.decompress(inner)) == 10 * 1024
    assert len(gzip.decompress(outer)) == 10 * 1024
    monkeypatch.setattr(evidence_export, "_ARCHIVE_MAX_UNCOMPRESSED", 15 * 1024)
    sdist = tmp_path / _SDIST_NAME
    sdist.write_bytes(outer)

    hits = scan_archive_members(sdist, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_size_limit" for hit in hits)


def test_oversized_top_level_archive_is_rejected_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / _WHEEL_NAME
    with wheel.open("wb") as handle:
        handle.truncate(200 * 1024 * 1024 + 1)

    def forbidden_read_bytes(_path: Path) -> bytes:
        raise AssertionError("oversized archive payload must not be read")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert hits == [PrivacyHit("archive_size_limit", _WHEEL_NAME, 1)]


def test_zip_entry_limit_preflight_runs_before_zipfile_constructor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / _WHEEL_NAME
    wheel.write_bytes(_hundred_thousand_member_zip())

    class ForbiddenZipFile:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("ZipFile must not run before entry-count preflight")

    monkeypatch.setattr(evidence_export.zipfile, "ZipFile", ForbiddenZipFile)

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_member_limit" for hit in hits)


@pytest.mark.parametrize(
    "mutation",
    ["truncated", "multi_disk", "bad_cd_offset", "zip64_missing", "zip64_forged"],
)
def test_zip_eocd_and_zip64_anomalies_fail_before_zipfile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    base = _zip_bytes([("pkg/clean.py", b"clean = True\n")])
    if mutation == "truncated":
        payload = base[:-10]
    elif mutation == "multi_disk":
        payload = _mutate_eocd_u16(base, 4, 1)
    elif mutation == "bad_cd_offset":
        payload = _mutate_eocd_u32(base, 16, len(base) + 1)
    elif mutation == "zip64_missing":
        payload = _mutate_eocd_u16(_mutate_eocd_u16(base, 8, 0xFFFF), 10, 0xFFFF)
    else:
        eocd = _eocd_offset(base)
        sentinel = _mutate_eocd_u32(
            _mutate_eocd_u32(
                _mutate_eocd_u16(_mutate_eocd_u16(base, 8, 0xFFFF), 10, 0xFFFF),
                12,
                0xFFFFFFFF,
            ),
            16,
            0xFFFFFFFF,
        )
        locator = b"PK\x06\x07" + (0).to_bytes(4, "little")
        locator += (len(base) + 4096).to_bytes(8, "little") + (1).to_bytes(4, "little")
        payload = sentinel[:eocd] + locator + sentinel[eocd:]

    wheel = tmp_path / _WHEEL_NAME
    wheel.write_bytes(payload)

    class ForbiddenZipFile:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("malformed EOCD must fail before ZipFile")

    monkeypatch.setattr(evidence_export.zipfile, "ZipFile", ForbiddenZipFile)

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert hits == [PrivacyHit("archive_unreadable", _WHEEL_NAME, 1)]


def test_zip64_extensible_sector_is_rejected_without_secret_leak(tmp_path: Path) -> None:
    marker = b"/Users/round816-zip64-private Bearer hidden"
    export = tmp_path / "sanitized-export"
    wheel = export / "e2e" / "artifacts" / _WHEEL_NAME
    wheel.parent.mkdir(parents=True)
    wheel.write_bytes(_zip64_with_extensible_sector(marker))

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert hits
    formatted = evidence_export.format_privacy_hits(hits)
    assert "round816-zip64-private" not in formatted
    receipt = write_archive_scan_receipt(export, source_digest=_DIGEST, hits=hits)
    assert "round816-zip64-private" not in receipt.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "legacy_mutation",
    [
        "disk_entries_conflict",
        "entry_count_conflict",
        "central_size_conflict",
        "central_offset_conflict",
    ],
)
def test_zip64_rejects_each_conflicting_legacy_eocd_value(
    tmp_path: Path,
    legacy_mutation: str,
) -> None:
    wheel = tmp_path / _WHEEL_NAME
    wheel.write_bytes(_zip64_archive(legacy_mutation=legacy_mutation))

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert hits == [PrivacyHit("archive_unreadable", _WHEEL_NAME, 1)]


@pytest.mark.parametrize(
    "legacy_mutation",
    ["disk_entries_consistent", "entry_count_consistent"],
)
def test_zip64_accepts_each_consistent_non_sentinel_legacy_count(
    tmp_path: Path,
    legacy_mutation: str,
) -> None:
    wheel = tmp_path / _WHEEL_NAME
    wheel.write_bytes(_zip64_archive(legacy_mutation=legacy_mutation))

    assert scan_archive_members(wheel, current_home="/Users/runtime-account") == []


@pytest.mark.parametrize("kind", ["archive_comment", "member_comment", "member_extra"])
def test_zip_comments_and_member_extra_are_closed_and_never_leak(
    tmp_path: Path,
    kind: str,
) -> None:
    marker = "round816-zip-private-Bearer-marker"
    export = tmp_path / "sanitized-export"
    wheel = export / "e2e" / "artifacts" / _WHEEL_NAME
    wheel.parent.mkdir(parents=True)
    wheel.write_bytes(_zip_with_metadata(kind, marker.encode()))

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert hits
    assert marker not in evidence_export.format_privacy_hits(hits)
    receipt = write_archive_scan_receipt(export, source_digest=_DIGEST, hits=hits)
    assert marker not in receipt.read_text(encoding="utf-8")


@pytest.mark.parametrize("flag", [0x8, 0x40])
def test_zip_rejects_nonzero_general_purpose_flags(tmp_path: Path, flag: int) -> None:
    payload = bytearray(_zip_with_metadata("none", b""))
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        position = payload.find(signature)
        assert position >= 0
        payload[position + offset : position + offset + 2] = flag.to_bytes(2, "little")
    wheel = tmp_path / _WHEEL_NAME
    wheel.write_bytes(payload)

    assert scan_archive_members(wheel, current_home="/Users/runtime-account")


@pytest.mark.parametrize(
    "mutation",
    [
        "local_crc",
        "local_flags",
        "local_method",
        "local_size",
        "local_name",
        "gap",
        "prefix",
        "trailing",
    ],
)
def test_zip_local_central_or_byte_coverage_mismatch_fails_closed_without_leak(
    tmp_path: Path,
    mutation: str,
) -> None:
    marker = b"round816-zip-layout-private"
    payload = _mutate_zip_layout(_zip_with_metadata("none", b""), mutation, marker)
    wheel = tmp_path / _WHEEL_NAME
    wheel.write_bytes(payload)

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert hits
    assert marker.decode() not in evidence_export.format_privacy_hits(hits)


def test_deflated_zip_member_rejects_bytes_after_raw_stream_without_leak(
    tmp_path: Path,
) -> None:
    marker = b"/Users/round816-deflate-tail Bearer hidden"
    export = tmp_path / "sanitized-export"
    wheel = export / "e2e" / "artifacts" / _WHEEL_NAME
    wheel.parent.mkdir(parents=True)
    wheel.write_bytes(_zip_with_deflate_trailing_data(marker))

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert hits
    formatted = evidence_export.format_privacy_hits(hits)
    assert "round816-deflate-tail" not in formatted
    receipt = write_archive_scan_receipt(export, source_digest=_DIGEST, hits=hits)
    assert "round816-deflate-tail" not in receipt.read_text(encoding="utf-8")


def test_tar_member_limit_streams_without_getmembers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdist = tmp_path / _SDIST_NAME
    sdist.write_bytes(_hundred_thousand_member_tar_gz())

    def forbidden_getmembers(_archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
        raise AssertionError("tar preflight must not materialize all members")

    monkeypatch.setattr(tarfile.TarFile, "getmembers", forbidden_getmembers)

    hits = scan_archive_members(sdist, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_member_limit" for hit in hits)


def test_large_amplified_pax_header_fails_closed_without_allocated_metadata_leak(
    tmp_path: Path,
) -> None:
    marker = "/Users/round816-pax-private Bearer hidden -----BEGIN PRIVATE KEY-----"
    pax_value = marker + "x" * (8 * 1024 * 1024)
    payload = _pax_tar_gz(pax_value)
    assert len(payload) < 128 * 1024
    export = tmp_path / "sanitized-export"
    sdist = export / "e2e" / "artifacts" / _SDIST_NAME
    sdist.parent.mkdir(parents=True)
    sdist.write_bytes(payload)

    hits = scan_archive_members(sdist, current_home="/Users/runtime-account")

    assert hits
    assert "round816-pax-private" not in evidence_export.format_privacy_hits(hits)
    receipt = write_archive_scan_receipt(export, source_digest=_DIGEST, hits=hits)
    assert "round816-pax-private" not in receipt.read_text(encoding="utf-8")
    with pytest.raises(RuntimeError) as caught:
        verify_archive_scan_receipt(export, source_digest=_DIGEST)
    assert "round816-pax-private" not in str(caught.value)


@pytest.mark.parametrize("kind", ["pax_global", "gnu_long_name", "gnu_long_link"])
def test_pax_and_gnu_extension_headers_are_outside_release_closure(
    tmp_path: Path,
    kind: str,
) -> None:
    marker = "round816-extension-private"
    if kind == "pax_global":
        payload = _global_pax_tar_gz(marker)
    elif kind == "gnu_long_name":
        payload = _gnu_extension_tar_gz("long_name", marker)
    else:
        payload = _gnu_extension_tar_gz("long_link", marker)
    sdist = tmp_path / _SDIST_NAME
    sdist.write_bytes(payload)

    hits = scan_archive_members(sdist, current_home="/Users/runtime-account")

    assert hits
    assert marker not in evidence_export.format_privacy_hits(hits)


def test_tar_header_user_group_and_link_metadata_is_rejected_without_leak(
    tmp_path: Path,
) -> None:
    marker = "round816-header-private"
    sdist = tmp_path / _SDIST_NAME
    sdist.write_bytes(_tar_with_header_metadata(marker))

    hits = scan_archive_members(sdist, current_home="/Users/runtime-account")

    assert hits
    assert marker not in evidence_export.format_privacy_hits(hits)


def test_second_gzip_stream_with_secret_is_rejected_without_leak(tmp_path: Path) -> None:
    marker = "/Users/round816-second-stream -----BEGIN PRIVATE KEY-----"
    payload = _tar_bytes([(f"{_SDIST_ROOT}/clean.txt", b"clean\n")])
    payload += gzip.compress(marker.encode(), mtime=0)
    sdist = tmp_path / _SDIST_NAME
    sdist.write_bytes(payload)

    hits = scan_archive_members(sdist, current_home="/Users/runtime-account")

    assert hits
    assert "round816-second-stream" not in evidence_export.format_privacy_hits(hits)


@pytest.mark.parametrize(
    "kind",
    ["extra", "name", "comment", "header_crc", "unknown_flag"],
)
def test_gzip_optional_or_unknown_header_fields_are_rejected_without_leak(
    tmp_path: Path,
    kind: str,
) -> None:
    marker = b"round816-gzip-header-private"
    clean = _tar_bytes([(f"{_SDIST_ROOT}/clean.txt", b"clean\n")])
    sdist = tmp_path / _SDIST_NAME
    sdist.write_bytes(_gzip_with_optional_header(clean, kind, marker))

    hits = scan_archive_members(sdist, current_home="/Users/runtime-account")

    assert hits
    assert marker.decode() not in evidence_export.format_privacy_hits(hits)


def test_nonzero_bytes_after_tar_eof_blocks_are_rejected_without_leak(tmp_path: Path) -> None:
    marker = b"round816-after-eof-private"
    raw = gzip.decompress(_tar_bytes([(f"{_SDIST_ROOT}/clean.txt", b"clean\n")]))
    sdist = tmp_path / _SDIST_NAME
    sdist.write_bytes(gzip.compress(raw + marker, mtime=0))

    hits = scan_archive_members(sdist, current_home="/Users/runtime-account")

    assert hits
    assert marker.decode() not in evidence_export.format_privacy_hits(hits)


@pytest.mark.parametrize("mutation", ["checksum", "size_octal"])
def test_tar_checksum_and_octal_size_are_strictly_validated(
    tmp_path: Path,
    mutation: str,
) -> None:
    payload = _tar_bytes([(f"{_SDIST_ROOT}/clean.txt", b"clean\n")])
    sdist = tmp_path / _SDIST_NAME
    sdist.write_bytes(_mutate_tar_header(payload, mutation))

    assert scan_archive_members(sdist, current_home="/Users/runtime-account")


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("mode", b"Bearer!\0"),
        ("uid", b"Bearer!\0"),
        ("gid", b"Bearer!\0"),
        ("mtime", b"Bearer!\0\0\0\0\0"),
        ("devmajor", b"Bearer!\0"),
        ("devminor", b"Bearer!\0"),
    ],
)
def test_all_ustar_numeric_fields_reject_nonoctal_secret_without_leak(
    tmp_path: Path,
    field_name: str,
    replacement: bytes,
) -> None:
    clean = _tar_bytes([(f"{_SDIST_ROOT}/clean.txt", b"clean\n")])
    sdist = tmp_path / _SDIST_NAME
    sdist.write_bytes(_mutate_tar_numeric_field(clean, field_name, replacement))

    hits = scan_archive_members(sdist, current_home="/Users/runtime-account")

    assert hits
    assert "Bearer" not in evidence_export.format_privacy_hits(hits)


@pytest.mark.parametrize("field_name", ["devmajor", "devminor"])
def test_regular_ustar_member_rejects_nonzero_device_numbers(
    tmp_path: Path,
    field_name: str,
) -> None:
    clean = _tar_bytes([(f"{_SDIST_ROOT}/clean.txt", b"clean\n")])
    sdist = tmp_path / _SDIST_NAME
    sdist.write_bytes(
        _mutate_tar_numeric_field(clean, field_name, b"0000001\0")
    )

    assert scan_archive_members(sdist, current_home="/Users/runtime-account")


def test_top_level_clean_archive_uses_fd_instead_of_path_read_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / _WHEEL_NAME
    _write_wheel(wheel, {"pkg/clean.py": b"clean = True\n"})

    def forbidden_read_bytes(_path: Path) -> bytes:
        raise AssertionError("scanner must read the already-validated fd")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)

    assert scan_archive_members(wheel, current_home="/Users/runtime-account") == []


def test_top_level_open_swap_is_rejected_by_fd_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / _WHEEL_NAME
    replacement = tmp_path / "replacement.whl"
    _write_wheel(wheel, {"pkg/clean.py": b"clean = True\n"})
    _write_wheel(replacement, {"pkg/other.py": b"other = True\n"})
    real_open = os.open
    swapped = False

    def swapping_open(path: os.PathLike[str] | str, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal swapped
        if not swapped and os.fspath(path) == os.fspath(wheel):
            os.replace(replacement, wheel)
            swapped = True
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(evidence_export.os, "open", swapping_open)

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_identity_changed" for hit in hits)


def test_top_level_growth_during_fd_read_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / _WHEEL_NAME
    _write_wheel(wheel, {"pkg/clean.py": b"clean = True\n"})
    real_read = os.read
    grown = False

    def growing_read(fd: int, size: int) -> bytes:
        nonlocal grown
        if not grown:
            with wheel.open("ab") as handle:
                handle.write(b"growth")
            grown = True
        return real_read(fd, size)

    monkeypatch.setattr(evidence_export.os, "read", growing_read)

    hits = scan_archive_members(wheel, current_home="/Users/runtime-account")

    assert any(hit.rule_id == "archive_identity_changed" for hit in hits)


def test_top_level_symlink_hardlink_and_fifo_fail_before_content_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target.whl"
    _write_wheel(target, {"pkg/clean.py": b"clean = True\n"})
    symlink = tmp_path / "symlink.whl"
    symlink.symlink_to(target)
    hardlink = tmp_path / "hardlink.whl"
    os.link(target, hardlink)
    fifo = tmp_path / "special.whl"
    os.mkfifo(fifo)

    def forbidden_read_bytes(_path: Path) -> bytes:
        raise AssertionError("unsafe top-level entry must fail before content read")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)

    for path in (symlink, hardlink, fifo):
        assert scan_archive_members(path, current_home="/Users/runtime-account")


@pytest.mark.parametrize(
    "kind",
    ["symlink", "hardlink", "special", "directory_symlink"],
)
def test_sensitive_unsafe_export_entry_never_leaks_through_receipt_or_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    kind: str,
) -> None:
    marker = f"round816-{kind}-path-private"
    export = tmp_path / "sanitized-export"
    _make_sensitive_unsafe_export_entry(export, kind=kind, marker=marker)

    with pytest.raises(RuntimeError) as direct_error:
        write_archive_scan_receipt(export, source_digest=_DIGEST, hits=[])
    assert marker not in str(direct_error.value)
    receipt = export / ARCHIVE_SCAN_RECEIPT_NAME
    assert not receipt.exists() or marker not in receipt.read_text(encoding="utf-8")

    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    evidence.mkdir()
    monkeypatch.setattr(build_sanitized_evidence_export, "release_source_digest", lambda _r: _DIGEST)

    def fail_during_real_enumeration(**_kwargs: object) -> object:
        return write_archive_scan_receipt(export, source_digest=_DIGEST, hits=[])

    monkeypatch.setattr(
        build_sanitized_evidence_export,
        "build_sanitized_export",
        fail_during_real_enumeration,
    )
    code = build_sanitized_evidence_export.main(
        [
            "--evidence-root",
            str(evidence),
            "--repo-root",
            str(repo),
            "--source-digest",
            _DIGEST,
        ]
    )
    captured = capsys.readouterr()

    assert code == 1
    assert marker not in captured.err
    assert marker not in captured.out


@pytest.mark.parametrize(
    "rule_id",
    [
        "Bearer round816-rule-id-private",
        "/Users/round816-rule-id-private",
        "archive_safe\nround816-rule-id-private",
        "not_archive_round816-rule-id-private",
        "archive_future_rule",
    ],
)
def test_receipt_writer_rejects_unsafe_rule_id_without_leak(
    tmp_path: Path,
    rule_id: str,
) -> None:
    marker = "round816-rule-id-private"
    export = tmp_path / "sanitized-export"
    wheel = export / "e2e" / "artifacts" / _WHEEL_NAME
    _write_wheel(wheel, {"pkg/clean.py": b"clean = True\n"})
    hit = PrivacyHit(
        rule_id=rule_id,
        relative_path=f"{_WHEEL_NAME}!member-0001-aaaaaaaaaaaa",
        count=1,
    )

    with pytest.raises(RuntimeError) as caught:
        write_archive_scan_receipt(export, source_digest=_DIGEST, hits=[hit])

    assert marker not in str(caught.value)
    receipt = export / ARCHIVE_SCAN_RECEIPT_NAME
    assert not receipt.exists() or marker not in receipt.read_text(encoding="utf-8")


def test_receipt_verifier_rejects_unsafe_rule_id_without_error_leak(tmp_path: Path) -> None:
    marker = "round816-forged-rule-id-private"
    export = tmp_path / "sanitized-export"
    wheel = export / "e2e" / "artifacts" / _WHEEL_NAME
    _write_wheel(wheel, {"pkg/clean.py": b"clean = True\n"})
    receipt = write_archive_scan_receipt(export, source_digest=_DIGEST, hits=[])
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["hits"] = [
        {
            "rule_id": f"Bearer {marker}",
            "relative_path": f"{_WHEEL_NAME}!member-0001-aaaaaaaaaaaa",
            "count": 1,
        }
    ]
    payload["hit_count"] = 1
    payload["ok"] = False
    receipt.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="rule_id") as caught:
        verify_archive_scan_receipt(export, source_digest=_DIGEST)

    assert marker not in str(caught.value)


def test_receipt_verifier_rejects_duplicate_hit_tuple_via_set(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    wheel = export / "e2e" / "artifacts" / _WHEEL_NAME
    _write_wheel(wheel, {"pkg/clean.py": b"clean = True\n"})
    receipt = write_archive_scan_receipt(export, source_digest=_DIGEST, hits=[])
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    duplicate = {
        "rule_id": "archive_bearer_token",
        "relative_path": f"{_WHEEL_NAME}!pkg/clean.py",
        "count": 1,
    }
    payload["hits"] = [duplicate, duplicate]
    payload["hit_count"] = 2
    payload["ok"] = False
    receipt.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="duplicate hit"):
        verify_archive_scan_receipt(export, source_digest=_DIGEST)


def test_previous_rule_version_is_stale_after_precise_scanner_upgrade(tmp_path: Path) -> None:
    export = tmp_path / "sanitized-export"
    wheel = export / "e2e" / "artifacts" / _WHEEL_NAME
    _write_wheel(wheel, {"pkg/clean.py": b"clean = True\n"})
    receipt = write_archive_scan_receipt(export, source_digest=_DIGEST, hits=[])
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["rule_version"] = "archive-scan-rules-v8"
    receipt.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="rule_version"):
        verify_archive_scan_receipt(export, source_digest=_DIGEST)


def test_real_package_partial_export_builds_clean_receipt_and_cli_exits_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    evidence = tmp_path / "evidence"
    repo.mkdir()
    _seed_real_package_evidence(evidence)
    report = _partial_report()
    monkeypatch.setattr(release_gates, "release_source_digest", lambda _root: _DIGEST)
    monkeypatch.setattr(
        release_gates,
        "validate_final_local_gate_evidence",
        lambda *_args, **_kwargs: report,
    )
    monkeypatch.setattr(build_sanitized_evidence_export, "release_source_digest", lambda _r: _DIGEST)

    result = build_sanitized_export(
        evidence_root=evidence,
        repo_root=repo,
        source_digest=_DIGEST,
        out_root=evidence / "direct",
    )

    receipt = json.loads(
        (result.export_dir / ARCHIVE_SCAN_RECEIPT_NAME).read_text(encoding="utf-8")
    )
    assert result.validation_ok is False
    assert receipt["ok"] is True
    assert receipt["hit_count"] == 0

    code = build_sanitized_evidence_export.main(
        [
            "--evidence-root",
            str(evidence),
            "--repo-root",
            str(repo),
            "--source-digest",
            _DIGEST,
            "--out-root",
            str(evidence / "cli"),
        ]
    )

    summaries = [line for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    assert code == 2
    assert json.loads(summaries[-1])["ok"] is False
