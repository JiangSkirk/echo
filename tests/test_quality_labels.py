"""Anti-drift tests for the quality-label checker."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load_checker() -> Any:
    path = ROOT / "scripts" / "check_quality_labels.py"
    spec = importlib.util.spec_from_file_location("check_quality_labels", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_checker()


def _rubric() -> dict[str, Any]:
    return {
        "rubric_version": "2026.08.1",
        "inventory_units": {
            "demo.unit": {"paths": ["js/demo/"], "scopes": ["repo.default"]},
        },
        "scopes": {
            "repo.default": {
                "criteria": [
                    {"id": "gate.ruff", "evidence_kind": "recorded"},
                ]
            }
        },
    }


def _label(
    *,
    label: str,
    criterion_id: str = "gate.ruff",
    rubric_version: str = "2026.08.1",
    freeze_reason: str = "",
    next_wave: str = "",
    debt_ref: str = "",
    evidence: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "unit": "demo.unit",
        "paths": ["js/demo/"],
        "label": label,
        "rubric_version": rubric_version,
        "stamped_at": "2026-08-26",
        "reviewer": "test",
        "evidence": evidence
        if evidence is not None
        else [{"criterion_id": criterion_id, "status": "pass"}],
    }
    if freeze_reason:
        entry["freeze_reason"] = freeze_reason
    if next_wave:
        entry["next_wave"] = next_wave
    if debt_ref:
        entry["debt_ref"] = debt_ref
    return {"rubric_version": rubric_version, "labels": [entry]}


def test_unknown_criterion_is_rubric_drift() -> None:
    evaluation = checker.evaluate(
        _rubric(),
        _label(label="PEAK", criterion_id="invented.bar"),
        peak=True,
    )
    assert evaluation.drift
    assert checker.exit_code(evaluation) == checker.EXIT_RUBRIC_DRIFT
    assert any("invented.bar" in issue.message for issue in evaluation.issues)


def test_open_unit_fails_peak() -> None:
    evaluation = checker.evaluate(
        _rubric(),
        _label(label="OPEN", evidence=[]),
        peak=True,
    )
    assert not evaluation.drift
    assert checker.exit_code(evaluation) == checker.EXIT_NOT_PEAK
    assert any("OPEN" in issue.message for issue in evaluation.issues)


def test_frozen_counts_as_closed_peak() -> None:
    evaluation = checker.evaluate(
        _rubric(),
        _label(
            label="FROZEN",
            evidence=[],
            freeze_reason="monolith_split_later",
            next_wave="M3",
        ),
        peak=True,
    )
    assert evaluation.ok
    assert checker.exit_code(evaluation) == checker.EXIT_OK


def test_rubric_version_mismatch_not_peak() -> None:
    evaluation = checker.evaluate(
        _rubric(),
        _label(label="PEAK", rubric_version="2026.08.0"),
        peak=True,
    )
    assert not evaluation.drift
    assert checker.exit_code(evaluation) == checker.EXIT_NOT_PEAK
    assert any("re-stamp" in issue.message for issue in evaluation.issues)


def test_wont_fix_requires_debt_ref() -> None:
    evaluation = checker.evaluate(
        _rubric(),
        _label(label="WONT_FIX", evidence=[]),
        peak=True,
    )
    assert checker.exit_code(evaluation) == checker.EXIT_NOT_PEAK
    assert any("debt_ref" in issue.message for issue in evaluation.issues)


def test_frozen_requires_reason_and_wave() -> None:
    evaluation = checker.evaluate(
        _rubric(),
        _label(label="FROZEN", evidence=[]),
        peak=True,
    )
    assert checker.exit_code(evaluation) == checker.EXIT_NOT_PEAK
    messages = " ".join(issue.message for issue in evaluation.issues)
    assert "freeze_reason" in messages
    assert "next_wave" in messages


def test_extra_unit_is_rubric_drift() -> None:
    labels = _label(
        label="FROZEN",
        evidence=[],
        freeze_reason="later",
        next_wave="M1",
    )
    labels["labels"].append(
        {
            "unit": "invented.unit",
            "label": "PEAK",
            "rubric_version": "2026.08.1",
            "evidence": [],
        }
    )
    evaluation = checker.evaluate(_rubric(), labels, peak=True)
    assert evaluation.drift
    assert checker.exit_code(evaluation) == checker.EXIT_RUBRIC_DRIFT


def test_repo_yaml_is_loadable(tmp_path: Path) -> None:
    rubric = yaml.safe_load((ROOT / "quality" / "rubric.yaml").read_text(encoding="utf-8"))
    labels = yaml.safe_load((ROOT / "quality" / "labels.yaml").read_text(encoding="utf-8"))
    assert rubric["rubric_version"] == labels["rubric_version"]
    evaluation = checker.evaluate(rubric, labels, peak=False)
    assert not evaluation.drift
    copied = tmp_path / "labels.yaml"
    copied.write_text(yaml.safe_dump(labels), encoding="utf-8")
    assert copied.is_file()


def test_repo_labels_have_no_drift() -> None:
    rubric = yaml.safe_load((ROOT / "quality" / "rubric.yaml").read_text(encoding="utf-8"))
    labels = yaml.safe_load((ROOT / "quality" / "labels.yaml").read_text(encoding="utf-8"))
    evaluation = checker.evaluate(rubric, labels, peak=False)
    assert not evaluation.drift
    assert rubric["rubric_version"] == labels["rubric_version"]
