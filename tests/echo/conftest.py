"""Tests-echo conftest.

T8-S3A dedicated gate (``test_context_savings_threshold.py``) is collected
ONLY when ``-m t8s3a_gate`` appears in the invocation. Default collection
(``pytest tests/echo/ -q``) skips it via :func:`pytest_ignore_collect`,
so plain runs see the same 41 T8-S1+T8-S2 tests + the T8-S3A wiring /
isolation units, with no skip on the dedicated gate file at all.

This conftest deliberately does NOT use ``collect_ignore_glob`` (a static
list) because that would also hide the file from explicit dedicated
invocations such as ``pytest tests/echo/test_context_savings_threshold.py``;
``pytest_ignore_collect`` lets the gate be unlocked by:

* ``-m`` selection that mentions ``t8s3a_gate``
* ``-k`` selection that mentions ``threshold``
* an explicit positional path to the file
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pathlib

    import pytest

_GATE_FILE_NAME = "test_context_savings_threshold.py"


def pytest_ignore_collect(collection_path: pathlib.Path, config: pytest.Config) -> bool | None:
    if collection_path.name != _GATE_FILE_NAME:
        return None

    markexpr = config.getoption("-m", default="") or ""
    if "t8s3a_gate" in markexpr:
        return False

    keyword = config.getoption("-k", default="") or ""
    if "threshold" in keyword.lower():
        return False

    return all("test_context_savings_threshold" not in str(arg) for arg in config.args)
