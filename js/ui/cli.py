"""Interactive CLI with rich formatting and command handling."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import click
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from js.agent import JSAgent
from js.config import JSSettings
from js.utils.log import configure_logging, get_logger

console = Console()

PROMPT_STYLE = Style.from_dict({
    "prompt": "#00aa00 bold",
    "": "#ffffff",
})


class JSCLI:
    """Main CLI interface for JS Agent."""

    def __init__(self, settings: JSSettings | None = None) -> None:
        self.settings = settings or JSSettings.from_file()
        self.agent: JSAgent | None = None
        self.session_id: str | None = None
        self.logger = get_logger("js.cli")

    async def init(self) -> None:
        self.agent = JSAgent(self.settings)

    def _get_session(self) -> PromptSession[str]:
        history_path = Path.home() / ".js" / "history"
        history_path.parent.mkdir(parents=True, exist_ok=True)
        return PromptSession(
            history=FileHistory(str(history_path)),
            style=PROMPT_STYLE,
        )

    async def run_interactive(self) -> None:
        """Run interactive chat loop."""
        await self.init()
        session = self._get_session()

        console.print(Panel.fit(
            "[bold cyan]JS Agent[/bold cyan] v0.1.0\n"
            "Type your message or [bold]/help[/bold] for commands, [bold]/quit[/bold] to exit.",
            title="Welcome",
            border_style="cyan",
        ))

        while True:
            try:
                user_input = await session.prompt_async("JS> ")
                user_input = user_input.strip()

                if not user_input:
                    continue

                if user_input.startswith("/"):
                    if await self._handle_command(user_input):
                        break
                    continue

                await self._process_message(user_input)

            except KeyboardInterrupt:
                continue
            except EOFError:
                break

        console.print("\n[dim]Goodbye![/dim]")

    async def _process_message(self, user_input: str) -> None:
        """Process a user message through the agent."""
        if not self.agent:
            console.print("[red]Agent not initialized[/red]")
            return

        with console.status("[bold green]Thinking...", spinner="dots"):
            try:
                state = await self.agent.run(
                    user_input,
                    session_id=self.session_id,
                )
                self.session_id = state.session_id

                if state.status == "error":
                    console.print(f"[red]Error: {state.error_message}[/red]")
                else:
                    # Find last assistant message
                    for msg in reversed(state.messages):
                        if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                            from rich.console import Console
                            from rich.markdown import Markdown
                            Console().print(Markdown(msg.content))
                            break

                    if self.settings.display.show_cost:
                        console.print(
                            f"[dim]Tokens: {state.total_tokens} | Turns: {state.turn_count}[/dim]"
                        )

            except Exception as e:
                console.print(f"[red]Failed: {e}[/red]")
                self.logger.error("Message processing failed", exc_info=True)

    async def _handle_command(self, cmd: str) -> bool:
        """Handle CLI commands. Returns True if should exit."""
        parts = cmd[1:].split()
        if not parts:
            return False

        command = parts[0].lower()

        if command in ("quit", "exit", "q"):
            return True

        elif command == "help":
            self._show_help()

        elif command == "status":
            self._show_status()

        elif command == "memory":
            self._show_memory()

        elif command == "audit":
            self._show_audit()

        elif command == "config":
            self._show_config()

        elif command == "clear":
            console.clear()

        elif command == "new":
            self.session_id = None
            console.print("[dim]Started new session.[/dim]")

        elif command == "skills":
            self._show_skills()

        elif command == "skill":
            if len(parts) < 2:
                console.print("[yellow]Usage: /skill <skill_id>[/yellow]")
            else:
                self._show_skill_detail(parts[1])

        else:
            console.print(f"[yellow]Unknown command: {command}. Type /help for available commands.[/yellow]")

        return False

    def _show_help(self) -> None:
        table = Table(title="Commands")
        table.add_column("Command", style="cyan")
        table.add_column("Description")

        commands = [
            ("/help", "Show this help"),
            ("/status", "Show agent status"),
            ("/memory", "Show memory contents"),
            ("/audit", "Show recent audit events"),
            ("/config", "Show current configuration"),
            ("/skills", "List available skills"),
            ("/skill <id>", "Show skill details"),
            ("/clear", "Clear screen"),
            ("/new", "Start new session"),
            ("/quit", "Exit JS"),
        ]
        for cmd, desc in commands:
            table.add_row(cmd, desc)
        console.print(table)

    def _show_status(self) -> None:
        if not self.agent:
            console.print("[red]Agent not initialized[/red]")
            return

        table = Table(title="Agent Status")
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("Session", self.session_id or "None")
        table.add_row("Workspace", str(self.settings.workspace))
        table.add_row("State Dir", str(self.settings.state_dir))
        table.add_row("Max Turns", str(self.settings.max_turns))
        table.add_row("Defense Mode", self.settings.security.defense_mode.value)

        # Tool stats
        stats = self.agent.registry.get_stats()
        table.add_row("Tool Calls", str(sum(stats.values())))

        # Secret stats
        secret_stats = self.agent.secrets.get_stats()
        table.add_row("Secrets Stored", str(secret_stats["stored_secrets"]))
        table.add_row("Secrets Redacted", str(secret_stats["detected_leaks"]))

        console.print(table)

    def _show_memory(self) -> None:
        if not self.agent:
            return
        context = self.agent.memory.get_context_string(max_chars=2000)
        console.print(Panel(context, title="Memory", border_style="blue"))

    def _show_audit(self) -> None:
        if not self.agent:
            return
        events = self.agent.audit.query(limit=20)
        table = Table(title="Recent Audit Events")
        table.add_column("Time", style="dim")
        table.add_column("Type", style="cyan")
        table.add_column("Actor")
        table.add_column("Action")

        import datetime
        for e in events:
            ts = datetime.datetime.fromtimestamp(e.timestamp).strftime("%H:%M:%S")
            table.add_row(ts, e.event_type.value, e.actor, e.action)

        console.print(table)

    def _show_config(self) -> None:
        import json
        data = self.settings.model_dump(mode="json", exclude={"providers": {"__all__": {"api_key"}}})
        console.print(Panel(json.dumps(data, indent=2, default=str), title="Config"))

    def _show_skills(self) -> None:
        if not self.agent:
            console.print("[red]Agent not initialized[/red]")
            return

        skills = self.agent.skills.list_skills()
        if not skills:
            console.print("[dim]No skills loaded.[/dim]")
            return

        table = Table(title=f"Skills ({len(skills)} loaded)")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Name")
        table.add_column("Type", style="dim")
        table.add_column("Category")
        table.add_column("Trust", style="yellow")
        table.add_column("Compat", style="green")
        table.add_column("Usage", justify="right")

        for s in skills:
            trust_color = f"[{s.get('trust_color', 'gray')}]"
            compat = "[green]✓[/green]" if s["compatible"] else "[red]✗[/red]"
            table.add_row(
                s["id"],
                s["name"],
                s["type"],
                s["category"],
                f"{trust_color}{s['trust_level']}[/]",
                compat,
                str(s["usage_count"]),
            )
        console.print(table)

    def _show_skill_detail(self, skill_id: str) -> None:
        if not self.agent:
            console.print("[red]Agent not initialized[/red]")
            return
        detail = self.agent.skills.view_skill(skill_id)
        if not detail:
            console.print(f"[red]Skill not found: {skill_id}[/red]")
            return
        _print_skill_detail(detail)


def _print_skill_detail(detail: dict[str, Any]) -> None:
    """Print skill detail to console."""
    trust_color = detail.get("trust_color", "gray")

    info = f"""[bold cyan]{detail['name']}[/bold cyan] [dim]v{detail['version']}[/dim]
[bold]ID:[/bold] {detail['id']}
[bold]Type:[/bold] {detail['type']}
[bold]Category:[/bold] {detail['category']}
[bold]Author:[/bold] {detail['author']}
[bold]Trust Level:[/bold] [{trust_color}]{detail['trust_level']}[/{trust_color}]
[bold]Compatible:[/bold] {'Yes' if detail['compatible'] else 'No'}
[bold]Prerequisites OK:[/bold] {'Yes' if detail['prerequisites_ok'] else 'No'}
[bold]Usage:[/bold] {detail['usage_count']} calls | Success: {(detail['success_rate'] * 100):.1f}%
"""
    if detail.get("risk_flags"):
        info += f"[bold red]Risk Flags:[/bold red] {', '.join(detail['risk_flags'])}\n"
    if detail.get("tags"):
        info += f"[bold]Tags:[/bold] {', '.join(detail['tags'])}\n"

    console.print(Panel(info, title="Skill Detail", border_style="cyan"))

    if detail.get("content"):
        console.print(Panel(detail["content"][:2000], title="Content Preview", border_style="blue"))


@click.group(invoke_without_command=True)
@click.option("--config", "-c", type=click.Path(), help="Path to config file")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging")
@click.pass_context
def main(ctx: click.Context, config: str | None, verbose: bool) -> None:
    """JS Agent - A stable, secure, and convenient AI agent."""
    configure_logging("DEBUG" if verbose else "INFO")

    if ctx.invoked_subcommand is None:
        settings = JSSettings.from_file(config)
        cli = JSCLI(settings)
        try:
            asyncio.run(cli.run_interactive())
        except KeyboardInterrupt:
            console.print("\n[dim]Interrupted.[/dim]")


@main.command()
@click.option("--path", "-p", default="~/.config/js/config.yaml", help="Config file path")
def init(path: str) -> None:
    """Initialize JS configuration."""
    target = Path(path).expanduser()
    if target.exists():
        click.confirm(f"Config exists at {target}. Overwrite?", abort=True)

    settings = JSSettings()
    settings.save(target)
    console.print(f"[green]Config initialized at {target}[/green]")


@main.command()
@click.argument("message")
@click.option("--model", "-m", help="Model to use")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def run(message: str, model: str | None, config: str | None) -> None:
    """Run a single message and exit."""
    settings = JSSettings.from_file(config)
    cli = JSCLI(settings)

    async def _run() -> None:
        await cli.init()
        if cli.agent:
            state = await cli.agent.run(message, model=model)
            for msg in reversed(state.messages):
                if msg.role == "assistant" and msg.content:
                    console.print(msg.content)
                    break

    asyncio.run(_run())


@main.command()
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def status(config: str | None) -> None:
    """Show system status."""
    settings = JSSettings.from_file(config)
    cli = JSCLI(settings)
    asyncio.run(cli.init())
    cli._show_status()


@main.command()
@click.option("--host", default="127.0.0.1", help="Bind host")
@click.option("--port", default=8000, help="Bind port")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def web(host: str, port: int, config: str | None) -> None:
    """Launch Web UI."""
    _launch_web(host, port, config, open_browser=False)


@main.command(name="open")
@click.option("--host", default="127.0.0.1", help="Bind host")
@click.option("--port", default=8000, help="Bind port")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def open_cmd(host: str, port: int, config: str | None) -> None:
    """Launch Web UI and open browser."""
    _launch_web(host, port, config, open_browser=True)


def _launch_web(host: str, port: int, config: str | None, open_browser: bool) -> None:
    import threading
    import time
    import webbrowser

    import uvicorn

    from js.web import create_app

    url = f"http://{host}:{port}"
    console.print(f"[green]Starting JS Web UI at {url}[/green]")

    if open_browser:
        def _open() -> None:
            time.sleep(1.5)
            webbrowser.open(url)

        threading.Thread(target=_open, daemon=True).start()

    app = create_app()
    uvicorn.run(app, host=host, port=port)


@main.command()
@click.option("--yes", "-y", is_flag=True, help="Non-interactive mode")
def setup(yes: bool) -> None:
    """Run setup wizard to auto-configure everything."""
    from js.setup_wizard import run_setup

    asyncio.run(run_setup(non_interactive=yes))


@main.command()
@click.argument("query")
@click.option("--engine", "-e", default="auto", help="Search engine")
def search(query: str, engine: str) -> None:
    """Search the web."""
    from js.search.engines import DuckDuckGoEngine, SearchManager

    async def _search() -> None:
        manager = SearchManager()
        manager.register(DuckDuckGoEngine(), default=True)
        try:
            results = await manager.search(query, max_results=5)
            for i, r in enumerate(results, 1):
                console.print(f"\n[bold cyan]{i}. {r.title}[/bold cyan]")
                console.print(f"[dim]{r.url}[/dim]")
                console.print(r.snippet)
        finally:
            await manager.close()

    asyncio.run(_search())


@main.group()
def skill() -> None:
    """Manage skills."""


@skill.command("list")
@click.option("--category", "-c", help="Filter by category")
@click.option("--type", "-t", "skill_type", help="Filter by type (code/prompt/workflow)")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def skill_list(category: str | None, skill_type: str | None, config: str | None) -> None:
    """List available skills."""
    from js.skills.spec import SkillType

    settings = JSSettings.from_file(config)
    # Fast path: only initialize SkillManager, not the full Agent
    from js.skills.manager import SkillManager
    skills_mgr = SkillManager(settings.state_dir, settings.workspace)

    st = SkillType(skill_type) if skill_type else None
    skills = skills_mgr.list_skills(category=category, skill_type=st)

    table = Table(title=f"Skills ({len(skills)} loaded)")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("Type", style="dim")
    table.add_column("Category")
    table.add_column("Trust", style="yellow")
    table.add_column("Usage", justify="right")

    for s in skills:
        trust_color = f"[{s.get('trust_color', 'gray')}]"
        table.add_row(
            s["id"],
            s["name"],
            s["type"],
            s["category"],
            f"{trust_color}{s['trust_level']}[/]",
            str(s["usage_count"]),
        )
    console.print(table)


@skill.command("info")
@click.argument("skill_id")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def skill_info(skill_id: str, config: str | None) -> None:
    """Show detailed information about a skill."""
    settings = JSSettings.from_file(config)
    # Fast path: only initialize SkillManager, not the full Agent
    from js.skills.manager import SkillManager
    skills_mgr = SkillManager(settings.state_dir, settings.workspace)
    if skill_id in skills_mgr._skills:
        detail = skills_mgr.view_skill(skill_id)
        if detail:
            _print_skill_detail(detail)
    else:
        console.print(f"[red]Skill not found: {skill_id}[/red]")


@skill.command("install")
@click.argument("source")
@click.option("--id", "skill_id", help="Override skill ID")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def skill_install(source: str, skill_id: str | None, config: str | None) -> None:
    """Install a skill from a local path or git URL."""
    settings = JSSettings.from_file(config)
    cli = JSCLI(settings)
    asyncio.run(cli.init())
    if not cli.agent:
        console.print("[red]Agent not initialized[/red]")
        return
    async def _do() -> None:
        assert cli.agent is not None
        try:
            spec = await cli.agent.skills.install(source, skill_id)
            console.print(f"[green]Installed skill: {spec.id} (trust={spec.trust_level.value})[/green]")
        except Exception as e:
            console.print(f"[red]Install failed: {e}[/red]")
    asyncio.run(_do())


@skill.command("uninstall")
@click.argument("skill_id")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def skill_uninstall(skill_id: str, yes: bool, config: str | None) -> None:
    """Uninstall a skill."""
    settings = JSSettings.from_file(config)
    cli = JSCLI(settings)
    asyncio.run(cli.init())
    if not cli.agent:
        console.print("[red]Agent not initialized[/red]")
        return
    if not yes:
        click.confirm(f"Uninstall skill '{skill_id}'?", abort=True)

    async def _do() -> None:
        assert cli.agent is not None
        if await cli.agent.skills.uninstall(skill_id):
            console.print(f"[green]Uninstalled skill: {skill_id}[/green]")
        else:
            console.print(f"[red]Skill not found: {skill_id}[/red]")
    asyncio.run(_do())


@skill.command("trust")
@click.argument("skill_id")
@click.argument("level", type=click.Choice(["builtin", "trusted", "community", "quarantine"]))
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def skill_trust(skill_id: str, level: str, config: str | None) -> None:
    """Set trust level for a skill."""
    from js.skills.spec import TrustLevel

    settings = JSSettings.from_file(config)
    cli = JSCLI(settings)
    asyncio.run(cli.init())
    if not cli.agent:
        console.print("[red]Agent not initialized[/red]")
        return
    trust_level = TrustLevel(level)
    if cli.agent.skills.trust_skill(skill_id, trust_level):
        console.print(f"[green]Trust level for {skill_id} set to {level}[/green]")
    else:
        console.print(f"[red]Skill not found: {skill_id}[/red]")


if __name__ == "__main__":
    main()
