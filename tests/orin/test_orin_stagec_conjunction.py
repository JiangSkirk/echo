"""Stage C §6.1 conjunction checker.  Enforce stays fail-closed."""

from __future__ import annotations

from types import SimpleNamespace

from js.config import OrinConfig
from js.orin.stage_c import (
    StageCEvidence,
    echo_may_hold_provider_tokens,
    evaluate_stage_c_conjunction,
    product_desktop_cell_required,
    product_memory_cell_required,
    should_register_product_tool,
)


def test_default_config_conjunction_lists_external_gates() -> None:
    report = evaluate_stage_c_conjunction(OrinConfig())

    assert report.ok is False
    assert "enabled" in report.missing
    assert "echo_minimal_os" in report.missing
    assert "k156_8_real_model_e2e" in report.missing
    assert "k156_9_independent_red_team" in report.missing
    assert "official_tcc_packaging" in report.missing
    assert "appshell_echo_separated" in report.missing
    assert "provider_tokens_out_of_echo" in report.missing
    assert "conjunction incomplete" in report.reject_message()


def test_all_software_flags_still_fail_without_external_evidence() -> None:
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
    report = evaluate_stage_c_conjunction(
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

    assert report.ok is False
    assert report.missing == (
        "official_tcc_packaging",
        "k156_8_real_model_e2e",
        "k156_9_independent_red_team",
    )


def test_product_cell_routes_stay_off_when_enforce_is_off() -> None:
    config = OrinConfig(cell_desktop=True, cell_memory=True)

    assert config.enforce is False
    assert product_desktop_cell_required(config) is False
    assert product_memory_cell_required(config) is False
    assert echo_may_hold_provider_tokens(config) is True
    assert should_register_product_tool("excel_write", enforce=False) is True
    assert should_register_product_tool("excel_write", enforce=True) is False
    assert should_register_product_tool("web_navigate", enforce=True) is False
    assert should_register_product_tool("file_delete", enforce=True) is False
    assert should_register_product_tool("fleet_collaborate", enforce=True) is False
    assert should_register_product_tool("control_memory_mutate", enforce=True) is False
    assert should_register_product_tool("read_file", enforce=True) is True


def test_mock_settings_do_not_enable_product_cell_routes() -> None:
    from unittest.mock import MagicMock

    mock_settings = MagicMock()
    assert product_desktop_cell_required(mock_settings.orin) is False
    assert product_memory_cell_required(mock_settings.orin) is False
    assert echo_may_hold_provider_tokens(mock_settings.orin) is True
