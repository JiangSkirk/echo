"""Trusted skill key registry: self-sign is COMMUNITY, registry grants TRUSTED."""

from __future__ import annotations

from pathlib import Path

from js.security import signer
from js.skills.key_registry import load_registry
from js.skills.security import scan_skill
from js.skills.spec import TrustLevel, parse_skill_manifest


def _signed_skill(tmp_path: Path) -> Path:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    manifest = skill_dir / "SKILL.md"
    manifest.write_text("---\nid: demo\nname: Demo\ntype: prompt\n---\nhello\n", encoding="utf-8")
    signer.generate_signing_key(tmp_path)
    signature, public_key = signer.sign_skill_manifest(manifest, tmp_path)
    manifest.write_text(
        "---\n"
        "id: demo\n"
        "name: Demo\n"
        "type: prompt\n"
        f"signature: {signature}\n"
        f"public_key: {public_key}\n"
        "---\nhello\n",
        encoding="utf-8",
    )
    return skill_dir


def test_self_signed_skill_is_community(tmp_path: Path) -> None:
    skill_dir = _signed_skill(tmp_path)
    spec = parse_skill_manifest(skill_dir / "SKILL.md")
    result = scan_skill(spec)
    assert result.trust_level == TrustLevel.COMMUNITY


def test_registry_key_grants_trusted(tmp_path: Path) -> None:
    skill_dir = _signed_skill(tmp_path)
    spec = parse_skill_manifest(skill_dir / "SKILL.md")
    assert spec.public_key
    load_registry(tmp_path).register(spec.public_key, name="operator")
    result = scan_skill(spec)
    assert result.trust_level == TrustLevel.TRUSTED


def test_revoked_registry_key_is_community(tmp_path: Path) -> None:
    skill_dir = _signed_skill(tmp_path)
    spec = parse_skill_manifest(skill_dir / "SKILL.md")
    assert spec.public_key
    registry = load_registry(tmp_path)
    registry.register(spec.public_key, name="operator")
    registry.revoke(spec.public_key)
    result = scan_skill(spec)
    assert result.trust_level == TrustLevel.COMMUNITY
