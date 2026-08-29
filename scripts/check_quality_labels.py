#!/usr/bin/env python3
"""Fail-closed quality-label checker.

Later “is quality at peak?” questions must run this script. Criteria that are
not registered in quality/rubric.yaml are RUBRIC_DRIFT (exit 2), not a reason
to invent a new bar in chat.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

EXIT_OK = 0
EXIT_NOT_PEAK = 1
EXIT_RUBRIC_DRIFT = 2

ALLOWED_LABELS = frozenset({"OPEN", "PEAK", "FROZEN", "WONT_FIX", "REGRESSED"})
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUBRIC = REPO_ROOT / "quality" / "rubric.yaml"
DEFAULT_LABELS = REPO_ROOT / "quality" / "labels.yaml"


@dataclass
class Issue:
    code: str
    message: str


@dataclass
class Evaluation:
    issues: list[Issue] = field(default_factory=list)
    rows: list[dict[str, str]] = field(default_factory=list)

    @property
    def drift(self) -> bool:
        return any(issue.code == "RUBRIC_DRIFT" for issue in self.issues)

    @property
    def ok(self) -> bool:
        return not self.issues

    def add(self, code: str, message: str) -> None:
        self.issues.append(Issue(code, message))


def load_yaml(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must be a mapping")
    return raw


def _criteria_for_scopes(rubric: dict[str, Any], scope_ids: list[str]) -> dict[str, dict[str, Any]]:
    scopes = rubric.get("scopes")
    if not isinstance(scopes, dict):
        return {}
    found: dict[str, dict[str, Any]] = {}
    for scope_id in scope_ids:
        scope = scopes.get(scope_id)
        if not isinstance(scope, dict):
            continue
        for item in scope.get("criteria") or []:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                found[str(item["id"])] = item
    return found


def _as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def evaluate(
    rubric: dict[str, Any],
    labels_doc: dict[str, Any],
    *,
    peak: bool = False,
    verify: bool = False,
    repo_root: Path = REPO_ROOT,
) -> Evaluation:
    result = Evaluation()
    rubric_version = str(rubric.get("rubric_version") or "")
    inventory = rubric.get("inventory_units")
    if not isinstance(inventory, dict) or not inventory:
        result.add("RUBRIC_DRIFT", "rubric.inventory_units is missing")
        return result

    expected_units = [str(name) for name in inventory]
    labels = labels_doc.get("labels")
    if not isinstance(labels, list):
        result.add("NOT_PEAK", "labels.yaml has no labels list")
        return result

    seen: dict[str, dict[str, Any]] = {}
    for entry in labels:
        if not isinstance(entry, dict):
            result.add("NOT_PEAK", "label entry is not a mapping")
            continue
        unit = str(entry.get("unit") or "")
        if not unit:
            result.add("NOT_PEAK", "label entry missing unit")
            continue
        if unit in seen:
            result.add("NOT_PEAK", f"duplicate label for {unit}")
            continue
        if unit not in inventory:
            result.add("RUBRIC_DRIFT", f"invented unit {unit!r} is not in rubric inventory")
            continue
        seen[unit] = entry

    for unit in expected_units:
        if unit not in seen:
            result.add("NOT_PEAK", f"missing label for {unit}")

    for unit, spec in inventory.items():
        entry = seen.get(str(unit))
        if entry is None:
            continue
        unit_name = str(unit)
        label = str(entry.get("label") or "")
        result.rows.append(
            {
                "unit": unit_name,
                "label": label,
                "wave": str(entry.get("next_wave") or entry.get("debt_ref") or ""),
            }
        )
        if label not in ALLOWED_LABELS:
            result.add("RUBRIC_DRIFT", f"{unit_name}: unknown label {label!r}")
            continue

        stamp_version = str(entry.get("rubric_version") or "")
        if peak and stamp_version != rubric_version:
            result.add(
                "NOT_PEAK",
                f"{unit_name}: stamp {stamp_version!r} != rubric {rubric_version!r}; re-stamp",
            )

        spec_map = spec if isinstance(spec, dict) else {}
        scope_ids = _as_str_list(spec_map.get("scopes"))
        allowed_criteria = _criteria_for_scopes(rubric, scope_ids)
        evidence = entry.get("evidence") or []
        if not isinstance(evidence, list):
            result.add("NOT_PEAK", f"{unit_name}: evidence must be a list")
            continue
        seen_ids: set[str] = set()
        for item in evidence:
            if not isinstance(item, dict):
                result.add("NOT_PEAK", f"{unit_name}: evidence item must be a mapping")
                continue
            criterion_id = str(item.get("criterion_id") or "")
            if criterion_id not in allowed_criteria:
                result.add(
                    "RUBRIC_DRIFT",
                    f"{unit_name}: criterion {criterion_id!r} is not in scopes {scope_ids}",
                )
                continue
            seen_ids.add(criterion_id)
            if verify:
                _verify_criterion(result, unit_name, allowed_criteria[criterion_id], repo_root)

        if peak:
            if label in {"OPEN", "REGRESSED"}:
                result.add("NOT_PEAK", f"{unit_name}: {label} is not a terminal peak label")
            elif label == "FROZEN":
                if not str(entry.get("freeze_reason") or "").strip():
                    result.add("NOT_PEAK", f"{unit_name}: FROZEN requires freeze_reason")
                if not str(entry.get("next_wave") or "").strip():
                    result.add("NOT_PEAK", f"{unit_name}: FROZEN requires next_wave")
            elif label == "WONT_FIX":
                if not str(entry.get("debt_ref") or "").strip():
                    result.add("NOT_PEAK", f"{unit_name}: WONT_FIX requires debt_ref")
            elif label == "PEAK":
                missing = sorted(set(allowed_criteria) - seen_ids)
                if missing:
                    result.add(
                        "NOT_PEAK",
                        f"{unit_name}: PEAK missing evidence {missing}",
                    )
                for item in evidence:
                    if isinstance(item, dict) and str(item.get("status") or "") != "pass":
                        result.add(
                            "NOT_PEAK",
                            f"{unit_name}: evidence {item.get('criterion_id')} is not pass",
                        )

    return result


def _verify_criterion(
    result: Evaluation,
    unit: str,
    criterion: dict[str, Any],
    repo_root: Path,
) -> None:
    kind = str(criterion.get("evidence_kind") or "")
    if kind == "command":
        command = criterion.get("command")
        if not isinstance(command, list) or not command:
            result.add("NOT_PEAK", f"{unit}: command criterion has no command")
            return
        completed = subprocess.run(
            [str(part) for part in command],
            cwd=repo_root,
            check=False,
        )
        if completed.returncode != 0:
            result.add("NOT_PEAK", f"{unit}: command failed: {command}")
        return
    if kind == "pytest_node":
        nodeid = str(criterion.get("nodeid") or "")
        target = repo_root / nodeid.split("::", 1)[0]
        if not target.is_file():
            result.add("NOT_PEAK", f"{unit}: pytest node file missing: {nodeid}")
            return
        completed = subprocess.run(
            ["uv", "run", "pytest", nodeid, "-q"],
            cwd=repo_root,
            check=False,
        )
        if completed.returncode != 0:
            result.add("NOT_PEAK", f"{unit}: pytest node failed: {nodeid}")
        return
    if kind == "recorded":
        return
    result.add("RUBRIC_DRIFT", f"{unit}: unknown evidence_kind {kind!r}")


def format_report(evaluation: Evaluation) -> str:
    lines = ["unit                 label      wave/debt", "-" * 56]
    for row in evaluation.rows:
        lines.append(f"{row['unit']:<20} {row['label']:<10} {row['wave']}")
    if evaluation.issues:
        lines.append("")
        for issue in evaluation.issues:
            lines.append(f"{issue.code}: {issue.message}")
    elif not evaluation.rows:
        lines.append("no units")
    return "\n".join(lines)


def exit_code(evaluation: Evaluation) -> int:
    if evaluation.drift:
        return EXIT_RUBRIC_DRIFT
    if evaluation.issues:
        return EXIT_NOT_PEAK
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check quality labels against the locked rubric")
    parser.add_argument("--peak", action="store_true", help="require zero OPEN/REGRESSED")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="re-run command and pytest_node evidence (not recorded full pytest)",
    )
    parser.add_argument("--rubric", type=Path, default=DEFAULT_RUBRIC)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    args = parser.parse_args(argv)
    evaluation = evaluate(
        load_yaml(args.rubric),
        load_yaml(args.labels),
        peak=args.peak,
        verify=args.verify,
    )
    print(format_report(evaluation))
    if args.peak and evaluation.ok:
        print("PEAK: yes")
    elif args.peak:
        print("PEAK: no")
    return exit_code(evaluation)


if __name__ == "__main__":
    sys.exit(main())
