"""K§15.6 #8 real-model observe→act→observe stays blocked by default.

An operator can set JS_K156_8_REAL_MODEL=1 and provide a live provider to
attempt the Calculator scene. Success is harness observation, not official
TCC and not a reason to flip orin.enforce.
"""

from __future__ import annotations

import os

import pytest

from js.config import OrinConfig
from js.orin.stage_c import StageCEvidence


def test_k156_8_evidence_bit_stays_false() -> None:
    evidence = StageCEvidence.observed()
    assert evidence.k156_8_real_model_e2e is False
    assert OrinConfig().enforce is False


@pytest.mark.skipif(
    not os.environ.get("JS_K156_8_REAL_MODEL"),
    reason="K§15.6 #8 blocked: no operator-provided live provider",
)
def test_k156_8_real_model_opt_in_is_operator_only() -> None:
    pytest.fail("live K§15.6 #8 must be recorded as harness observation, not this default")
