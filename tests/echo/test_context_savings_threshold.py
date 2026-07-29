"""T8-S3A dedicated threshold gate.

Runs only when invoked with ``-m t8s3a_gate``. Default
``pytest tests/echo/ -q`` skips this file via
``tests/echo/conftest.py::pytest_ignore_collect``.

fail-closed: when tiktoken is missing, dedicated invocation raises
``pytest.fail`` (NOT ``pytest.skip`` / ``importorskip``).

Threshold formula (locked by T8-S3A plan):

    PASS ≡  aggregate.total_savings_ratio      >= 0.35
        AND aggregate.cross_turn_unsent_ratio  >= 0.35
        AND aggregate.in_call_dedup_ratio      <  aggregate.cross_turn_unsent_ratio

These are offline fixture metrics under a real tokenizer. They are NOT
claims about production savings. Production cutover remains blocked
behind T8-S3B + T9.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.t8s3a_gate


def _require_tiktoken() -> None:
    """Fail (not skip) if tiktoken is unavailable in the current venv."""
    try:
        import tiktoken  # noqa: F401, PLC0415 -- presence probe; test layer is allowed to import tiktoken
    except ImportError:
        pytest.fail(
            "T8-S3A dedicated gate requires tiktoken. "
            "Install with: pip install -e '.[echo-tokenizer]'",
            pytrace=False,
        )


def test_threshold_gate_meets_t8s3a_target() -> None:
    """Main gate: offline 20-turn tool-heavy fixture + real tiktoken
    encoding must meet the locked T8-S3A threshold triple."""
    _require_tiktoken()
    from js.echo.context_savings import ContextBudget
    from js.echo.context_savings_harness import (
        build_tool_heavy_20_turn_fixture,
        run_harness,
    )
    from js.echo.context_tokenizer import tiktoken_counter_factory

    fixture = build_tool_heavy_20_turn_fixture()
    counter = tiktoken_counter_factory("o200k_base")
    aggregate = run_harness(fixture, ContextBudget(max_tokens=10**9), token_counter=counter)

    assert aggregate.total_savings_ratio >= 0.35, (
        f"total_savings_ratio={aggregate.total_savings_ratio:.4f} < 0.35; T8-S3A gate failed."
    )
    assert aggregate.cross_turn_unsent_ratio >= 0.35, (
        f"cross_turn_unsent_ratio={aggregate.cross_turn_unsent_ratio:.4f} < 0.35; "
        "T8-S3A gate failed."
    )
    assert aggregate.in_call_dedup_ratio < aggregate.cross_turn_unsent_ratio, (
        f"in_call_dedup_ratio={aggregate.in_call_dedup_ratio:.4f} >= "
        f"cross_turn_unsent_ratio={aggregate.cross_turn_unsent_ratio:.4f}; "
        "savings must come predominantly from cross-turn CAS, not in-turn dedup."
    )


def test_threshold_gate_uses_real_tokenizer_not_heuristic() -> None:
    """Sanity: with tiktoken, counts must differ from the byte/4
    heuristic on at least one payload -- proves the counter is wired
    through, not silently falling back to the heuristic."""
    _require_tiktoken()
    from js.echo.context_savings import estimate_tokens
    from js.echo.context_tokenizer import (
        heuristic_counter,
        tiktoken_counter_factory,
    )

    counter = tiktoken_counter_factory("o200k_base")
    # A payload where BPE and the 4-byte heuristic must disagree.
    sample = b"the quick brown fox jumps over the lazy dog" * 4
    assert counter(sample) != heuristic_counter(sample), (
        "tiktoken count equals heuristic count -- wiring may be silently "
        "falling back to the heuristic"
    )
    # Core wiring stays live.
    assert estimate_tokens(sample, token_counter=counter) == counter(sample)
