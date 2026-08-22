"""Regression tests for skill content-hash coverage.

``SkillSpec.compute_hash`` previously covered only top-level code/config files
plus scripts/**, so editing lib/helper.py or references/ left the integrity
hash unchanged and verify_integrity() passed tampered skills. The hash now
covers every regular file in the skill directory (minus volatile directories
and symlinks), and the Ed25519 signer shares the same implementation.
"""

from __future__ import annotations

import os
from pathlib import Path

from js.security.signer import _compute_skill_content_hash
from js.skills.spec import SkillSpec, SkillType, compute_skill_dir_hash


def _make_skill(root: Path) -> SkillSpec:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text("---\nid: demo\n---\n")
    (root / "main.py").write_text("print('v1')\n")
    (root / "lib").mkdir()
    (root / "lib" / "helper.py").write_text("X = 1\n")
    (root / "references").mkdir()
    (root / "references" / "notes.md").write_text("# notes v1\n")
    return SkillSpec(id="demo", name="demo", type=SkillType.CODE, path=root)


def test_hash_changes_when_lib_file_changes(tmp_path: Path) -> None:
    spec = _make_skill(tmp_path / "skill")
    before = spec.compute_hash()
    assert before
    assert spec.path is not None
    (spec.path / "lib" / "helper.py").write_text("X = 2\n")
    assert spec.compute_hash() != before


def test_hash_changes_when_reference_file_changes(tmp_path: Path) -> None:
    spec = _make_skill(tmp_path / "skill")
    before = spec.compute_hash()
    assert spec.path is not None
    (spec.path / "references" / "notes.md").write_text("# notes v2\n")
    assert spec.compute_hash() != before


def test_hash_changes_when_nested_file_added(tmp_path: Path) -> None:
    spec = _make_skill(tmp_path / "skill")
    before = spec.compute_hash()
    assert spec.path is not None
    (spec.path / "lib" / "extra.py").write_text("Y = 1\n")
    assert spec.compute_hash() != before


def test_hash_is_stable_and_creation_order_independent(tmp_path: Path) -> None:
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "SKILL.md").write_text("x")
    (dir_a / "main.py").write_text("y")
    (dir_a / "lib").mkdir()
    (dir_a / "lib" / "h.py").write_text("z")
    # Same content, different creation order.
    (dir_b / "lib").mkdir()
    (dir_b / "lib" / "h.py").write_text("z")
    (dir_b / "main.py").write_text("y")
    (dir_b / "SKILL.md").write_text("x")
    assert compute_skill_dir_hash(dir_a) == compute_skill_dir_hash(dir_b)
    assert compute_skill_dir_hash(dir_a) == compute_skill_dir_hash(dir_a)


def test_volatile_dirs_and_symlinked_files_excluded(tmp_path: Path) -> None:
    spec = _make_skill(tmp_path / "skill")
    assert spec.path is not None
    before = spec.compute_hash()

    (spec.path / "__pycache__").mkdir()
    (spec.path / "__pycache__" / "main.cpython-312.pyc").write_bytes(b"\x00\x01")
    (spec.path / ".venv" / "bin").mkdir(parents=True)
    (spec.path / ".venv" / "bin" / "python").write_text("fake")
    (spec.path / ".git").mkdir()
    (spec.path / ".git" / "config").write_text("[core]\n")
    outside = tmp_path / "outside.txt"
    outside.write_text("external content")
    os.symlink(outside, spec.path / "linked.txt")

    assert spec.compute_hash() == before
    # Sanity: a real change still flips the hash.
    (spec.path / "main.py").write_text("print('v2')\n")
    assert spec.compute_hash() != before


def test_symlinked_directory_not_traversed(tmp_path: Path) -> None:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nid: demo\n---\n")
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "data.txt").write_text("v1")
    os.symlink(outside_dir, skill_dir / "linked_dir")

    before = compute_skill_dir_hash(skill_dir)
    (outside_dir / "data.txt").write_text("v2")
    assert compute_skill_dir_hash(skill_dir) == before


def test_signer_hash_shares_spec_coverage(tmp_path: Path) -> None:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nid: demo\n---\n")
    (skill_dir / "lib").mkdir()
    (skill_dir / "lib" / "helper.py").write_text("X = 1\n")
    manifest = skill_dir / "SKILL.md"

    # Same file set, same digest (signer keeps the full 64-char hexdigest).
    assert _compute_skill_content_hash(manifest) == compute_skill_dir_hash(skill_dir)
    before = _compute_skill_content_hash(manifest)
    (skill_dir / "lib" / "helper.py").write_text("X = 2\n")
    assert _compute_skill_content_hash(manifest) != before
