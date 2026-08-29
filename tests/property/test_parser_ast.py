"""Property tests: the shell parser never raises and extracted names stay strings."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from js.security.parser import extract_all_args, extract_command_names, has_subshell, parse
from js.security.rules import evaluate

_SHELLISH = st.text(
    alphabet=st.sampled_from(list("abc012xyz ;|&$()`\\\"'\n\t./-_=*<>")),
    max_size=64,
)


@settings(max_examples=80, deadline=None)
@given(_SHELLISH)
def test_parse_never_raises_and_ast_is_well_typed(command: str) -> None:
    ast = parse(command)
    if ast is None:
        return
    names = extract_command_names(ast)
    assert all(isinstance(name, str) for name in names)
    args = extract_all_args(ast)
    assert all(isinstance(group, list) for group in args)
    assert isinstance(has_subshell(ast), bool)
    verdict = evaluate(ast)
    assert isinstance(verdict.blocked, bool)


@settings(max_examples=40, deadline=None)
@given(st.sampled_from(("echo hi", "ls | wc", "true && false", "cat file > out")))
def test_simple_safe_commands_parse(command: str) -> None:
    ast = parse(command)
    assert ast is not None
    assert extract_command_names(ast)
