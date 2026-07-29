from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ROOTS = (ROOT / "js", ROOT / "js_work")
FORBIDDEN = (
    "js.rivetline",
    "RivetLine",
    "rivetline_engine",
    "JS_RIVETLINE_ENGINE",
    "run_legacy",
)


def test_legacy_rivetline_package_is_physically_absent() -> None:
    assert not (ROOT / "js" / "rivetline").exists()
    assert importlib.util.find_spec("js.rivetline") is None


def test_runtime_source_contains_no_legacy_architecture_symbols() -> None:
    offenders: list[str] = []
    for runtime_root in RUNTIME_ROOTS:
        for path in runtime_root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            for token in FORBIDDEN:
                if token in text:
                    offenders.append(f"{path.relative_to(ROOT)}: {token}")
    assert not offenders, "legacy runtime residues:\n" + "\n".join(offenders)


def test_echo_ledger_is_the_only_persistent_safety_service() -> None:
    from js.echo.ledger.journal import FileEchoLedger
    from js.echo.ledger.service import EchoSafetyService

    assert FileEchoLedger.__module__ == "js.echo.ledger.journal"
    assert EchoSafetyService.__module__ == "js.echo.ledger.service"


def test_agent_runner_contains_only_the_echo_api_facade() -> None:
    source = (ROOT / "js" / "agent" / "runner.py").read_text(encoding="utf-8")
    assert "TurnExecutor" not in source
    assert "EchoTurnLoop" not in source
    assert "inspect.iscoroutinefunction" not in source
    assert "EchoRuntime(self)" not in source
    assert "authoritative_runtime(self)" in source


def test_public_turn_boundary_rejects_runtime_shims_instead_of_replacing_runtime() -> None:
    source = (ROOT / "js" / "echo" / "turn_runtime.py").read_text(encoding="utf-8")
    assert "type(runtime) is not EchoRuntime" in source
    assert "agent.echo_runtime = runtime" not in source
    assert "EchoRuntime.run_agent_turn(" in source
    assert "EchoRuntime.run_turn(" in source


def test_turn_loop_does_not_invoke_model_router_directly() -> None:
    source = (ROOT / "js" / "echo" / "turn_loop.py").read_text(encoding="utf-8")
    assert ".router.chat(" not in source
    assert ".router.chat_stream_events(" not in source
    assert ".provider.chat(" not in source
    assert ".provider.chat_stream_events(" not in source


def test_legacy_smoke_script_is_removed() -> None:
    assert not (ROOT / "scripts" / "rivetline_smoke.py").exists()
    assert (ROOT / "scripts" / "echo_ledger_smoke.py").is_file()


def test_echo2_primitive_compatibility_shells_are_physically_absent() -> None:
    assert not (ROOT / "js" / "echo2_primitives.py").exists()
    assert not (ROOT / "js" / "echo" / "echo2.py").exists()
    assert importlib.util.find_spec("js.echo2_primitives") is None
    assert importlib.util.find_spec("js.echo.echo2") is None
