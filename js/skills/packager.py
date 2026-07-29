"""Skill packaging and publishing toolkit.

Supports:
- Packaging a skill directory into a distributable archive
- Generating ClawHub-compatible manifest entries
- Ed25519 package signing for integrity and authenticity verification
- Git-based publishing workflow
"""

from __future__ import annotations

import hashlib
import hmac
import json
import tarfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from js.skills.spec import parse_skill_manifest
from js.utils.log import get_logger

logger = get_logger("js.skills.packager")


@dataclass
class PackageManifest:
    """Manifest for a packaged skill."""

    skill_id: str
    name: str
    version: str
    author: str
    description: str
    type: str
    category: str
    tags: list[str] = field(default_factory=list)
    license: str = "MIT"  # noqa: A002
    content_hash: str = ""
    archive_hash: str = ""
    file_count: int = 0
    size_bytes: int = 0
    packaged_at: float = 0.0
    packager_version: str = "0.1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.skill_id,
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "type": self.type,
            "category": self.category,
            "tags": self.tags,
            "license": self.license,
            "content_hash": self.content_hash,
            "archive_hash": self.archive_hash,
            "file_count": self.file_count,
            "size_bytes": self.size_bytes,
            "packaged_at": self.packaged_at,
            "packager_version": self.packager_version,
        }


@dataclass
class PackageResult:
    """Result of a packaging operation."""

    success: bool
    archive_path: Path | None = None
    manifest: PackageManifest | None = None
    clawhub_entry: dict[str, Any] | None = None
    error: str = ""


# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------


def package_skill(
    skill_dir: Path,
    output_dir: Path | None = None,
    *,
    format: str = "tar.gz",  # noqa: A002
    include_gitignore: bool = True,
) -> PackageResult:
    """Package a skill directory into a distributable archive.

    Args:
        skill_dir: Path to the skill directory
        output_dir: Where to write the archive (default: skill_dir.parent)
        format: "tar.gz" or "zip"
        include_gitignore: Add a .gitignore if none exists

    Returns:
        PackageResult with archive path and manifest.
    """
    manifest_path = skill_dir / "SKILL.md"
    if not manifest_path.exists():
        return PackageResult(success=False, error="SKILL.md not found")

    try:
        spec = parse_skill_manifest(manifest_path)
    except Exception as e:
        return PackageResult(success=False, error=f"Failed to parse SKILL.md: {e}")

    out_dir = output_dir or skill_dir.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    archive_name = f"{spec.id}-{spec.version}"
    if format == "tar.gz":
        archive_path = out_dir / f"{archive_name}.tar.gz"
    else:
        archive_path = out_dir / f"{archive_name}.zip"

    # Collect files
    files_to_pack: list[Path] = []
    for item in skill_dir.rglob("*"):
        if item.is_file():
            # Skip common junk
            if any(
                part.startswith(".") and part not in {".gitkeep", ".gitignore"}
                for part in item.relative_to(skill_dir).parts
            ):
                continue
            if item.suffix in (".pyc", ".pyo", ".egg-info"):
                continue
            if item.name == "__pycache__":
                continue
            files_to_pack.append(item)

    # Add .gitignore if requested
    gitignore_path = skill_dir / ".gitignore"
    if include_gitignore and not gitignore_path.exists():
        gitignore_content = "__pycache__/\n*.pyc\n*.egg-info/\n.pytest_cache/\n"
        gitignore_path.write_text(gitignore_content, encoding="utf-8")
        files_to_pack.append(gitignore_path)

    # Compute content hash (SHA-256 of all file contents, sorted)
    hasher = hashlib.sha256()
    for f in sorted(files_to_pack, key=lambda p: str(p.relative_to(skill_dir))):
        hasher.update(f.relative_to(skill_dir).as_posix().encode())
        hasher.update(f.read_bytes())
    content_hash = hasher.hexdigest()[:16]

    # Create archive
    try:
        if format == "tar.gz":
            with tarfile.open(archive_path, "w:gz") as tar:
                for f in files_to_pack:
                    arcname = f"{spec.id}/{f.relative_to(skill_dir).as_posix()}"
                    tar.add(f, arcname=arcname)
        else:
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for f in files_to_pack:
                    arcname = f"{spec.id}/{f.relative_to(skill_dir).as_posix()}"
                    zf.write(f, arcname=arcname)
    except Exception as e:
        return PackageResult(success=False, error=f"Archive creation failed: {e}")

    # Compute archive hash
    archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()[:16]

    pkg_manifest = PackageManifest(
        skill_id=spec.id,
        name=spec.name,
        version=spec.version,
        author=spec.author,
        description=spec.description,
        type=spec.type.value,
        category=spec.category,
        tags=spec.tags,
        license=spec.license,
        content_hash=content_hash,
        archive_hash=archive_hash,
        file_count=len(files_to_pack),
        size_bytes=archive_path.stat().st_size,
        packaged_at=time.time(),
    )

    # Write manifest alongside archive
    manifest_json = out_dir / f"{archive_name}.manifest.json"
    manifest_json.write_text(json.dumps(pkg_manifest.to_dict(), indent=2), encoding="utf-8")

    # Generate ClawHub entry
    clawhub_entry = {
        "id": spec.id,
        "name": spec.name,
        "description": spec.description,
        "version": spec.version,
        "author": spec.author,
        "license": spec.license,
        "type": spec.type.value,
        "category": spec.category,
        "tags": spec.tags,
        "source": f"https://github.com/user/skills/{spec.id}",  # placeholder
        "content_hash": content_hash,
        "archive_hash": archive_hash,
    }

    clawhub_path = out_dir / f"{archive_name}.clawhub.json"
    clawhub_path.write_text(json.dumps(clawhub_entry, indent=2), encoding="utf-8")

    logger.info(
        f"Packaged {spec.id}: {archive_path} ({pkg_manifest.size_bytes} bytes, {pkg_manifest.file_count} files)"
    )

    return PackageResult(
        success=True,
        archive_path=archive_path,
        manifest=pkg_manifest,
        clawhub_entry=clawhub_entry,
    )


# ---------------------------------------------------------------------------
# Signing / verification
# ---------------------------------------------------------------------------


def sign_package(archive_path: Path, state_dir: Path | None = None) -> Path | None:
    """Sign a package archive with the local Ed25519 signing key.

    The signature file is a JSON document containing the archive SHA-256
    digest, the Ed25519 signature over that digest, and the signer's
    public key.  Keyless content hashes are NOT signatures — they prove
    nothing about authorship and are trivially re-computable by an
    attacker, so signing without a key fails closed (returns None).

    Returns the path to the signature file, or None on failure.
    """
    if not archive_path.exists():
        return None
    if state_dir is None:
        logger.error(f"Refusing to sign {archive_path}: no signing-key state directory given")
        return None

    from js.security.signer import get_public_key, sign_content

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    try:
        signature = sign_content(digest, state_dir)
        public_key = get_public_key(state_dir)
    except RuntimeError:
        logger.error(f"Cannot sign {archive_path}: no Ed25519 signing key in {state_dir}")
        return None
    if not signature or not public_key:
        logger.error(f"Cannot sign {archive_path}: signing key unavailable")
        return None

    sig_payload = {
        "algorithm": "ed25519",
        "archive_sha256": digest,
        "signature": signature,
        "public_key": public_key,
    }
    sig_path = archive_path.with_suffix(archive_path.suffix + ".sig")
    sig_path.write_text(json.dumps(sig_payload, indent=2), encoding="utf-8")
    logger.info(f"Signed {archive_path}: {sig_path}")
    return sig_path


def verify_package(archive_path: Path, signature_path: Path | None = None) -> bool:
    """Verify a package signature (fail-closed).

    Only Ed25519 signatures produced by ``sign_package`` are accepted.
    Legacy keyless SHA-256 digest files, missing signatures, tampered
    archives, and forged signature blobs are all rejected.
    """
    if not archive_path.exists():
        return False

    sig_path = signature_path or archive_path.with_suffix(archive_path.suffix + ".sig")
    if not sig_path.exists():
        logger.warning(f"No signature found for {archive_path}")
        return False

    try:
        payload = json.loads(sig_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Legacy bare-hex keyless digests are forgeable — reject them.
        logger.warning(f"Rejecting unparseable/legacy signature for {archive_path}")
        return False
    if not isinstance(payload, dict) or payload.get("algorithm") != "ed25519":
        logger.warning(f"Unsupported signature format for {archive_path}")
        return False

    stored_digest = payload.get("archive_sha256")
    signature = payload.get("signature")
    public_key = payload.get("public_key")
    if not all(
        isinstance(value, str) and value for value in (stored_digest, signature, public_key)
    ):
        logger.warning(f"Incomplete signature payload for {archive_path}")
        return False

    actual_digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    # Constant-time comparison; also short-circuits before the costly verify.
    assert isinstance(stored_digest, str)
    assert isinstance(signature, str)
    assert isinstance(public_key, str)
    if not hmac.compare_digest(stored_digest, actual_digest):
        logger.warning(f"Package digest mismatch for {archive_path} — archive tampered")
        return False

    from js.security.signer import verify_signature

    if not verify_signature(actual_digest, signature, public_key):
        logger.warning(f"Invalid Ed25519 signature for {archive_path}")
        return False
    return True


# ---------------------------------------------------------------------------
# Publishing helpers
# ---------------------------------------------------------------------------


def generate_clawhub_json(skills: list[Path], output: Path) -> Path:
    """Generate a ClawHub-compatible index from a list of skill directories.

    Args:
        skills: List of skill directory paths
        output: Path to write the clawhub.json

    Returns:
        Path to the generated index file.
    """
    entries: list[dict[str, Any]] = []
    for skill_dir in skills:
        manifest = skill_dir / "SKILL.md"
        if not manifest.exists():
            continue
        try:
            spec = parse_skill_manifest(manifest)
            entries.append(
                {
                    "id": spec.id,
                    "name": spec.name,
                    "description": spec.description,
                    "version": spec.version,
                    "author": spec.author,
                    "license": spec.license,
                    "type": spec.type.value,
                    "category": spec.category,
                    "tags": spec.tags,
                    "source": f"git+https://github.com/user/skills.git#{spec.id}",
                }
            )
        except Exception as e:
            logger.warning(f"Failed to parse {skill_dir}: {e}")

    index = {"skills": entries, "generated_at": time.time(), "version": "1.0"}
    output.write_text(json.dumps(index, indent=2), encoding="utf-8")
    logger.info(f"Generated ClawHub index: {output} ({len(entries)} skills)")
    return output


def publish_to_git(skill_dir: Path, repo_url: str, branch: str = "main") -> dict[str, Any]:
    """Publish a skill to a git repository.

    This is a helper that stages the skill directory and prints
    the commands the user should run. Does not actually push
    to avoid accidental commits.
    """
    import subprocess

    result: dict[str, Any] = {"commands": [], "success": True}

    # Verify git is available
    if not shutil_which("git"):
        return {"success": False, "error": "git command not found"}

    # Check if skill_dir is in a git repo
    try:
        git_root = subprocess.run(
            ["git", "-C", str(skill_dir), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if git_root.returncode != 0:
            result["commands"].append(f"cd {skill_dir.parent}")
            result["commands"].append("git init")
            result["commands"].append(f"git remote add origin {repo_url}")
    except Exception as e:
        return {"success": False, "error": str(e)}

    result["commands"].append(f"cd {skill_dir}")
    result["commands"].append("git add -A")
    result["commands"].append(f"git commit -m 'Publish skill: {skill_dir.name}'")
    result["commands"].append(f"git push origin {branch}")

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def shutil_which(cmd: str) -> str | None:
    import shutil

    return shutil.which(cmd)
