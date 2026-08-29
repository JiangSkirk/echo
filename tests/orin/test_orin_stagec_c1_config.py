"""WP-C1 configuration gates: default-off, lazy, and fail-fast."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from js.config import OrinConfig
from js.orin.protocol import ProtocolError, make_envelope
from js.orind.daemon import OrinDaemon, OrinDaemonError


def test_stage_c_switches_default_off() -> None:
    config = OrinConfig()

    assert config.enforce is False
    assert config.cell_identity_enforce is False
    assert config.echo_minimal_os is False


def test_cell_identity_switch_is_accepted_but_lazy_without_enforce() -> None:
    config = OrinConfig(cell_identity_enforce=True)

    assert config.enforce is False
    assert config.cell_identity_enforce is True


def test_product_enforce_config_fails_fast_until_conjunction_is_observed() -> None:
    with pytest.raises(ValidationError, match="conjunction incomplete"):
        OrinConfig(enforce=True)


def test_daemon_enforce_fails_before_creating_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "must-not-be-created"

    with pytest.raises(OrinDaemonError, match="conjunction incomplete"):
        OrinDaemon(state_dir=state_dir, orin_enforce=True)

    assert not state_dir.exists()


def test_non_enforce_hello_schema_still_rejects_c1_only_fields() -> None:
    with pytest.raises(ProtocolError, match="unknown field"):
        make_envelope(
            "hello",
            seq=1,
            nonce="a" * 32,
            session_key=None,
            caps=["lease.v2"],
            pid=123,
            launch_nonce="b" * 32,
        )
