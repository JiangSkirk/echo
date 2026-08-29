"""Name → SOUL compiler. 调查bot must claim investigation duty."""

from __future__ import annotations

from js.bots.identity import awakening_prompt, compile_bot_identity
from js.bots.persona import render_soul_block


def test_investigator_bot_self_model_includes_investigation_duty() -> None:
    compiled = compile_bot_identity("调查bot")
    assert compiled.specialty_key == "investigator"
    assert "调查" in compiled.soul_seed or "搜" in compiled.soul_seed
    assert "证据" in compiled.persona_appendix or "交叉验证" in compiled.persona_appendix
    prompt = awakening_prompt("调查bot", compiled)
    assert "调查bot" in prompt
    assert "不编造" in prompt
    block = render_soul_block(compiled.soul_seed, compiled.persona_appendix)
    assert "SOUL" in block
    assert "调查bot" in block
