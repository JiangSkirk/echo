from __future__ import annotations

from pathlib import Path

from js.echo.ledger.release_gates import (
    REQUIRED_FINAL_LOCAL_GATES,
    get_local_gate_spec,
)


def test_round810_gate_still_registered_but_not_required() -> None:
    # Round 8.15 supersedes round813 in REQUIRED_FINAL_LOCAL_GATES.
    assert "pytest_targeted_round810" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round811" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round812" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round815" in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round89" not in REQUIRED_FINAL_LOCAL_GATES
    assert "pytest_targeted_round88" not in REQUIRED_FINAL_LOCAL_GATES
    spec = get_local_gate_spec("pytest_targeted_round810", evidence_dir=Path("/tmp/evidence"))
    assert spec is not None
    joined = " ".join(spec.argv)
    assert "tests/test_strict_json_round810.py" in joined
    assert "tests/test_e2e_key_lifecycle_round810.py" in joined
    assert "tests/test_evidence_export_round810.py" in joined
    # Round 8.13 targeted gate must be registered and cover R8.12 + R8.13 tests.
    spec813 = get_local_gate_spec("pytest_targeted_round813", evidence_dir=Path("/tmp/evidence"))
    assert spec813 is not None
    joined813 = " ".join(spec813.argv)
    assert "tests/test_e2e_key_destroy_race_round812.py" in joined813
    assert "tests/test_e2e_key_prepare_rollback_round812.py" in joined813
    assert "tests/test_archive_verifier_rescan_round812.py" in joined813
    assert "tests/test_archive_artifact_set_round812.py" in joined813
    assert "tests/test_e2e_key_destroy_close_round813.py" in joined813
    assert "tests/test_e2e_key_prepare_rollback_round813.py" in joined813
    assert "tests/test_archive_full_tree_round813.py" in joined813


def test_release_result_sentinel_required_on_smoke_and_audit() -> None:
    for gate_name in ("release_smoke", "echo_full_audit"):
        spec = get_local_gate_spec(gate_name, evidence_dir=Path("/tmp/evidence"))
        assert spec is not None
        assert spec.output_parse.parser == "release_markers"
