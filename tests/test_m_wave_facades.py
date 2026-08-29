"""Facade contracts for M1–M3 mechanical splits. Old import paths must keep working."""

from __future__ import annotations


def test_m1_facades() -> None:
    from js.echo.capability import LeaseAuthority, LeaseDenied
    from js.echo.turn_loop import EchoTurnLoop
    from js.memory.enhanced_store import EnhancedMemoryStore, Episode, SemanticMemory
    from js.orchestration.fleet import AgentFleet, AgentRole
    from js.tools.office import OfficeTools, _BinaryIncrementalCSVReader

    assert OfficeTools is not None
    assert _BinaryIncrementalCSVReader is not None
    assert AgentFleet is not None
    assert AgentRole is not None
    assert EnhancedMemoryStore is not None
    assert Episode is not None
    assert SemanticMemory is not None
    assert EchoTurnLoop is not None
    assert LeaseAuthority is not None
    assert LeaseDenied is not None


def test_m2_facades() -> None:
    from js.agent.tool_executor import CONTROL_TASK_MUTATE_TOOL, ToolExecutorMixin
    from js.web.server import create_app, lifespan

    assert callable(create_app)
    assert lifespan is not None
    assert ToolExecutorMixin is not None
    assert CONTROL_TASK_MUTATE_TOOL == "control_task_mutate"


def test_telegram_gateway_facade() -> None:
    from js.gateway.channels.telegram import TelegramBotIntegration as Impl
    from js.integrations.telegram_bot import TelegramBotIntegration as Facade

    assert Facade is Impl


def test_m3_facades() -> None:
    from js.echo.capability import LeaseAuthority
    from js.echo.ledger.service import EchoSafetyService
    from js.echo.ledger.tip_seal import LocalTipSeal, TipSealError
    from js.orind.daemon import OrinDaemon, peer_credentials

    assert EchoSafetyService is not None
    assert OrinDaemon is not None
    assert callable(peer_credentials)
    assert LeaseAuthority.compact is not None
    assert LocalTipSeal is not None
    assert TipSealError is not None
