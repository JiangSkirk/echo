"""Fail-closed storage separation for Personal and Work modes."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StorageRoots:
    """The three persistent roots that must remain product-disjoint."""

    config_path: Path
    workspace: Path
    state_dir: Path


class StorageOverlapError(ValueError):
    """Raised before I/O when Personal and Work storage roots overlap."""


def canonical_for_compare(
    path: Path | str,
    *,
    case_insensitive: bool | None = None,
) -> tuple[str, ...]:
    """Return a symlink-aware, prefix-comparable path key."""
    resolved = Path(path).expanduser().resolve(strict=False)
    fold = sys.platform == "darwin" if case_insensitive is None else case_insensitive
    return tuple(part.casefold() if fold else part for part in resolved.parts)


def _is_prefix(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    return len(left) <= len(right) and right[: len(left)] == left


def assert_disjoint(*, personal: StorageRoots, work: StorageRoots) -> None:
    """Reject every equal, ancestor, or descendant cross-product overlap."""
    for personal_kind in ("config_path", "workspace", "state_dir"):
        personal_key = canonical_for_compare(getattr(personal, personal_kind))
        for work_kind in ("config_path", "workspace", "state_dir"):
            work_key = canonical_for_compare(getattr(work, work_kind))
            if _is_prefix(personal_key, work_key) or _is_prefix(work_key, personal_key):
                raise StorageOverlapError(
                    f"Personal.{personal_kind} {personal_key!r} overlaps "
                    f"Work.{work_kind} {work_key!r}"
                )


def _contains_parts(path: Path | str, needle: tuple[str, ...]) -> bool:
    parts = canonical_for_compare(path, case_insensitive=sys.platform == "darwin")
    folded_needle = tuple(part.casefold() if sys.platform == "darwin" else part for part in needle)
    width = len(folded_needle)
    return any(parts[index : index + width] == folded_needle for index in range(len(parts) - width + 1))


def assert_personal_path_not_in_work_namespace(path: Path | str) -> None:
    """Reserve both Work config and Work data namespaces from Personal."""
    if _contains_parts(path, (".js-work",)) or _contains_parts(path, (".config", "js-work")):
        raise ValueError(f"Personal path is inside reserved Work namespace: {Path(path)}")


def assert_work_path_not_in_personal_namespace(path: Path | str) -> None:
    """Reserve the Personal data namespace from Work."""
    if _contains_parts(path, (".js",)) or _contains_parts(path, (".config", "js")):
        raise ValueError(f"Work path is inside reserved Personal namespace: {Path(path)}")
