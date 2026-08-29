"""C6/C7 evidence and closeout stay honest: no Stage C implemented claim."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from js.config import OrinConfig
from js.orin.stage_c import (
    CLOSEOUT_IMPLEMENTED_CANDIDATE,
    CLOSEOUT_NOT_IMPLEMENTED,
    StageCEvidence,
    evaluate_stage_c_conjunction,
    stage_c_closeout_declaration,
)


def test_c6c7_evidence_doc_forbids_false_claims() -> None:
    text = Path("docs/security/orin/ORIN_STAGE_C_C6C7_EVIDENCE.md").read_text(encoding="utf-8")
    assert "Stage C is not implemented" in text
    assert "external-pending" in text
    assert "blocked" in text
    assert "orin.enforce" in text
    assert "ORIN_STAGE_C_CLOSEOUT.md" in text


def test_closeout_doc_is_not_an_implemented_claim() -> None:
    text = Path("docs/security/orin/ORIN_STAGE_C_CLOSEOUT.md").read_text(encoding="utf-8")
    assert "Stage C is not implemented" in text
    assert "Echo RCE is not closed" in text
    assert "not_implemented" in text
    assert "未实施" in text
    assert "不得" in text


def test_conjunction_still_missing_external_gates() -> None:
    evidence = StageCEvidence.observed()
    assert evidence.official_tcc_packaging is False
    assert evidence.k156_8_real_model_e2e is False
    assert evidence.k156_9_independent_red_team is False
    report = evaluate_stage_c_conjunction(OrinConfig())
    assert report.ok is False
    assert "official_tcc_packaging" in report.missing


def test_production_closeout_verdict_is_not_implemented() -> None:
    declaration = stage_c_closeout_declaration()
    assert declaration.verdict == CLOSEOUT_NOT_IMPLEMENTED
    assert declaration.conjunction_ok is False
    assert OrinConfig().enforce is False
    assert "official_tcc_packaging" in declaration.external_gates_missing
    assert "k156_8_real_model_e2e" in declaration.external_gates_missing
    assert "k156_9_independent_red_team" in declaration.external_gates_missing
    assert "Stage C is implemented" in declaration.forbidden_claims
    assert "Stage C is not implemented" in declaration.statement
    assert declaration.to_public_dict()["verdict"] == CLOSEOUT_NOT_IMPLEMENTED


def test_software_flags_alone_cannot_make_closeout_implemented() -> None:
    config = SimpleNamespace(
        enabled=True,
        stage_b=True,
        cell_build=True,
        cell_secret=True,
        cell_net=True,
        cell_file=True,
        commit_membrane=True,
        cell_desktop=True,
        cell_memory=True,
        cell_identity_enforce=True,
        echo_minimal_os=True,
        enforce=True,
    )
    declaration = stage_c_closeout_declaration(
        config,
        evidence=StageCEvidence(
            appshell_echo_separated=True,
            production_sandbox_carrier=True,
            official_tcc_packaging=False,
            k156_8_real_model_e2e=False,
            k156_9_independent_red_team=False,
            provider_tokens_out_of_echo=True,
            unclassified_exits_denied=True,
            signed_receipt_schema=True,
        ),
    )
    assert declaration.verdict == CLOSEOUT_NOT_IMPLEMENTED
    assert declaration.verdict != CLOSEOUT_IMPLEMENTED_CANDIDATE
    assert declaration.external_gates_missing == (
        "official_tcc_packaging",
        "k156_8_real_model_e2e",
        "k156_9_independent_red_team",
    )
