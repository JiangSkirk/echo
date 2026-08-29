"""AppShell/Echo split and provider-token observations stay honest."""

from __future__ import annotations

import pytest

from js.config import OrinConfig
from js.orin.echo_os import restricted_echo_environment
from js.orin.process_split import (
    production_appshell_echo_separated,
    provider_tokens_out_of_echo,
    strip_authority_from_env,
)
from js.orin.stage_c import StageCEvidence, evaluate_stage_c_conjunction


def test_process_split_bits_remain_unobserved() -> None:
    from js.orin.process_split import reset_process_split_observations

    reset_process_split_observations()
    assert production_appshell_echo_separated() is False
    assert provider_tokens_out_of_echo() is False
    evidence = StageCEvidence.observed()
    assert evidence.appshell_echo_separated is False
    assert evidence.provider_tokens_out_of_echo is False
    report = evaluate_stage_c_conjunction(OrinConfig())
    assert "appshell_echo_separated" in report.missing
    assert "provider_tokens_out_of_echo" in report.missing


def test_strip_authority_drops_provider_and_owner_keys() -> None:
    cleaned = strip_authority_from_env(
        {
            "PATH": "/usr/bin",
            "OPENAI_API_KEY": "sk-test",
            "ORIN_OWNER_PRIVATE_KEY": "secret",
            "LC_ALL": "C",
        }
    )
    assert cleaned == {"PATH": "/usr/bin", "LC_ALL": "C"}
    restricted = restricted_echo_environment({"OPENAI_API_KEY": "sk-test", "HOME": "/tmp"})
    assert "OPENAI_API_KEY" not in restricted
    assert restricted["LC_ALL"] == "C"
    assert restricted["HOME"] == "/tmp"


def test_hydrate_refuses_plaintext_tokens_under_product_enforce() -> None:
    from js.models.provider_manager import hydrate_static_provider_api_keys
    from js.orin.stage_c import bind_product_enforce, reset_product_enforce

    token = bind_product_enforce(True)
    try:
        with pytest.raises(RuntimeError, match="provider tokens"):
            hydrate_static_provider_api_keys([], None)  # type: ignore[arg-type]
    finally:
        reset_product_enforce(token)
