"""K§10.4 observations are labeled; they are not a pass."""

from __future__ import annotations

from js.orin.k104 import K104_GOALS, observation_is_not_a_pass, observe_callable_ms


def test_k104_observation_is_not_a_pass() -> None:
    observed = observe_callable_ms("authz_probe", lambda: sum(range(32)), payload_label="1KB-ish")

    assert observed.value_ms >= 0
    assert "非正式 K§10.4" in observed.disclaimer
    assert "harness 观察" in observed.disclaimer
    assert observation_is_not_a_pass(observed) is True
    assert observed.hardware
    assert observed.os_name
    assert "untested" in K104_GOALS["authz_p99_ms"]
