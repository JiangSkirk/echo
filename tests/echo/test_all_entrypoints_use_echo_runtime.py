from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_ROOTS = (
    ROOT / "js" / "ui",
    ROOT / "js" / "tui",
    ROOT / "js" / "integrations",
    ROOT / "js" / "gateway",
    ROOT / "js" / "orchestration",
    ROOT / "js" / "daemon",
    ROOT / "js" / "web",
    ROOT / "js" / "bots",
    ROOT / "js" / "appshell",
    ROOT / "js_work",
)
# js/agent is intentionally omitted: RunnerMixin.run is an Echo facade and
# contains the token "self.run(". AppShell mounts Host and does not start turns,
# so it is scanned for forbidden calls only — no channel string required.
FORBIDDEN_CALLS = (
    "agent.run(",
    "worker.agent.run(",
    "decision.provider.chat(",
    "registry.get_handler(",
)


def test_production_entrypoints_have_no_direct_agent_provider_or_handler_calls() -> None:
    offenders: list[str] = []
    for production_root in PRODUCTION_ROOTS:
        for path in production_root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for token in FORBIDDEN_CALLS:
                if token in text:
                    offenders.append(f"{path.relative_to(ROOT)}: {token}")
    assert not offenders, "entrypoints bypass EchoRuntime:\n" + "\n".join(offenders)


def test_every_user_surface_names_its_echo_channel() -> None:
    required_channels = {
        "js/ui/cli.py": "cli",
        "js/tui/app.py": "tui",
        "js/integrations/telegram_bot.py": "telegram",
        "js/gateway/channels/telegram.py": "telegram",
        "js/gateway/channels/webhook.py": "webhook",
        "js/gateway/channels/discord.py": "discord",
        "js/orchestration/fleet/agent_fleet.py": "fleet",
        "js/daemon/core.py": "cron",
        "js/bots/service.py": "bots",
        "js_work/cli.py": "js_work_cli",
        "js_work/web.py": "js_work_web",
    }
    missing = [
        f"{relative}: {channel}"
        for relative, channel in required_channels.items()
        if channel not in (ROOT / relative).read_text(encoding="utf-8")
    ]
    assert not missing, "surfaces missing explicit Echo channel:\n" + "\n".join(missing)
