"""Interactive CLI with rich formatting and command handling."""

from __future__ import annotations

import asyncio
import json
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
            "[bold cyan]JS Agent[/bold cyan] v0.1.1\n"
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

        # First-run guidance: if no models are configured, prompt for setup
        if not settings.providers:
            console.print(Panel.fit(
                "[bold yellow]Welcome to JS Agent![/bold yellow]\n\n"
                "No model providers are configured yet.\n"
                "Run [bold cyan]js setup[/bold cyan] to auto-detect local models "
                "(LM Studio, Ollama) and configure everything.\n\n"
                "Or initialize a minimal config with:\n"
                "  [bold]js init[/bold]",
                title="First Run",
                border_style="yellow",
            ))
            return

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
@click.option("--reload", is_flag=True, help="Enable auto-reload on code changes (dev mode)")
def web(host: str, port: int, config: str | None, reload: bool) -> None:
    """Launch Web UI."""
    _launch_web(host, port, config, open_browser=False, reload=reload)


@main.command(name="open")
@click.option("--host", default="127.0.0.1", help="Bind host")
@click.option("--port", default=8000, help="Bind port")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def open_cmd(host: str, port: int, config: str | None) -> None:
    """Launch Web UI and open browser."""
    _launch_web(host, port, config, open_browser=True, reload=False)


def _launch_web(host: str, port: int, _config: str | None, open_browser: bool, reload: bool = False) -> None:
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
    uvicorn.run(app, host=host, port=port, reload=reload)


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
@click.option("--category", "-C", help="Filter by category")
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


@skill.command("discover")
@click.argument("query", default="")
@click.option("--install", "-i", help="Install a skill by ID from search results")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def skill_discover(query: str, install: str | None, config: str | None) -> None:
    """Search the ClawHub skill marketplace."""
    import asyncio

    from js.skills.clawhub import ClawHubClient

    settings = JSSettings.from_file(config)
    cli = JSCLI(settings)
    asyncio.run(cli.init())
    if not cli.agent:
        console.print("[red]Agent not initialized[/red]")
        return

    clawhub = ClawHubClient(settings.state_dir)

    if install:
        source = clawhub.get_skill_source(install)
        if not source:
            console.print(f"[red]Skill {install} not found in ClawHub index[/red]")
            return
        try:
            spec = asyncio.run(cli.agent.skills.install(source, install))
            console.print(f"[green]Installed {spec.id} from ClawHub[/green]")
        except Exception as e:
            console.print(f"[red]Install failed: {e}[/red]")
        return

    async def _search() -> None:
        await clawhub.fetch_index()
        results = clawhub.search_index(query) if query else clawhub._index
        if not results:
            console.print("[yellow]No skills found.[/yellow]")
            return
        table = Table(title=f"ClawHub Skills ({len(results)} results)")
        table.add_column("ID", style="cyan")
        table.add_column("Name")
        table.add_column("Description", max_width=40)
        table.add_column("Version")
        table.add_column("Author")
        for sk in results[:20]:
            table.add_row(
                sk.get("id", ""),
                sk.get("name", ""),
                sk.get("description", "")[:40],
                sk.get("version", ""),
                sk.get("author", ""),
            )
        console.print(table)

    asyncio.run(_search())


@skill.command("create")
@click.option("--path", "-p", type=click.Path(), help="Target directory for the new skill")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def skill_create(path: str | None, config: str | None) -> None:
    """Interactively create a new skill from a template wizard."""
    settings = JSSettings.from_file(config)
    target = Path(path).expanduser() if path else settings.state_dir / "skills" / "user"
    target.mkdir(parents=True, exist_ok=True)

    from js.skills.creator import run_interactive_wizard
    try:
        run_interactive_wizard(target)
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Cancelled.[/yellow]")


@skill.command("validate")
@click.argument("skill_path", type=click.Path(exists=True))
def skill_validate(skill_path: str) -> None:
    """Validate a skill directory for correctness and security."""
    from js.skills.validator import validate_skill

    report = validate_skill(Path(skill_path))
    report.print_report()
    if not report.passed:
        raise click.ClickException("Validation failed")


@skill.command("test")
@click.argument("skill_path", type=click.Path(exists=True))
@click.option("--generate", "-g", is_flag=True, help="Generate tests before running")
def skill_test(skill_path: str, generate: bool) -> None:
    """Run tests for a skill. Auto-generates test stubs if none exist."""
    import asyncio

    from js.skills.tester import generate_tests, run_skill_tests

    sdir = Path(skill_path)
    if generate or not list(sdir.glob("test_*.py")):
        try:
            generated = generate_tests(sdir)
            console.print(f"[green]Generated {len(generated)} test file(s)[/green]")
        except Exception as e:
            console.print(f"[yellow]Test generation: {e}[/yellow]")

    report = asyncio.run(run_skill_tests(sdir))
    report.print_report()
    if not report.passed:
        raise click.ClickException("Tests failed")


@skill.command("package")
@click.argument("skill_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.option("--format", "fmt", default="tar.gz", type=click.Choice(["tar.gz", "zip"]))
def skill_package(skill_path: str, output: str | None, fmt: str) -> None:
    """Package a skill into a distributable archive."""
    from js.skills.packager import package_skill

    sdir = Path(skill_path)
    out = Path(output).expanduser() if output else None
    result = package_skill(sdir, out, format=fmt)

    if result.success and result.archive_path and result.manifest:
        console.print(f"[green]Packaged: {result.archive_path}[/green]")
        console.print(f"[dim]Files: {result.manifest.file_count} | Size: {result.manifest.size_bytes} bytes[/dim]")
        if result.clawhub_entry:
            clawhub_path = result.archive_path.with_suffix("").with_suffix(".clawhub.json")
            console.print(f"[dim]ClawHub entry: {clawhub_path}[/dim]")
    else:
        console.print(f"[red]Packaging failed: {result.error}[/red]")
        raise click.ClickException("Packaging failed")


@skill.command("publish")
@click.argument("skill_path", type=click.Path(exists=True))
@click.option("--repo", "-r", help="Git repository URL to publish to")
def skill_publish(skill_path: str, repo: str | None) -> None:
    """Generate publish commands for a skill (dry-run, does not push)."""
    from js.skills.packager import publish_to_git

    sdir = Path(skill_path)
    repo_url = repo or "https://github.com/YOURNAME/skills.git"
    result = publish_to_git(sdir, repo_url)

    if result["success"]:
        console.print(Panel(
            "[bold]Publish your skill with these commands:[/bold]\n\n" +
            "\n".join(f"  {cmd}" for cmd in result["commands"]),
            title="Git Publish Guide", border_style="cyan",
        ))
    else:
        console.print(f"[red]Publish setup failed: {result.get('error')}[/red]")


@main.command()
@click.option("--token", "-t", envvar="TELEGRAM_BOT_TOKEN", help="Telegram Bot Token (or set TELEGRAM_BOT_TOKEN env)")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def telegram(token: str | None, config: str | None) -> None:
    """Run JS Agent as a Telegram Bot (24/7 messaging interface)."""
    if not token:
        console.print("[red]Error: --token required or set TELEGRAM_BOT_TOKEN env var[/red]")
        raise click.ClickException("Telegram bot token is required")

    settings = JSSettings.from_file(config)
    from js.integrations.telegram_bot import TelegramBotIntegration

    bot = TelegramBotIntegration(token=token, settings=settings)
    asyncio.run(bot.start())


@main.command()
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def daemon(config: str | None) -> None:
    """Run JS Agent in background daemon mode with scheduled tasks."""
    settings = JSSettings.from_file(config)
    from js.daemon.core import build_default_daemon

    d = build_default_daemon(settings)
    asyncio.run(d.start())


@main.command()
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def tui(config: str | None) -> None:
    """Launch the Terminal User Interface (Textual-based rich CLI)."""
    settings = JSSettings.from_file(config)
    from js.tui.app import JSTuiApp

    app = JSTuiApp(settings)
    app.run()


@main.group()
def plugin() -> None:
    """Manage plugins (discover, list, enable, disable)."""
    pass


@plugin.command("list")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def plugin_list(config: str | None) -> None:
    """List all discovered plugins and their status."""
    settings = JSSettings.from_file(config)
    from js.agent import JSAgent
    from js.plugins.manager import PluginManager

    agent = JSAgent(settings)
    pm = PluginManager(agent, settings)
    pm.discover()

    table = Table(title="Plugins")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Status", justify="center")
    table.add_column("Tools")
    table.add_column("Categories")

    for p in pm.list_plugins():
        status_color = {
            "enabled": "green",
            "disabled": "yellow",
            "error": "red",
        }.get(p.status, "dim")
        table.add_row(
            p.manifest.id,
            p.manifest.name,
            p.manifest.version,
            f"[{status_color}]{p.status}[/{status_color}]",
            str(len(p._tools)),
            ", ".join(p.manifest.categories),
        )
    console.print(table)


@plugin.command("enable")
@click.argument("plugin_id")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def plugin_enable(plugin_id: str, config: str | None) -> None:
    """Enable a plugin by ID."""
    settings = JSSettings.from_file(config)
    from js.agent import JSAgent
    from js.plugins.manager import PluginManager

    agent = JSAgent(settings)
    pm = PluginManager(agent, settings)
    pm.discover()
    if pm.enable(plugin_id):
        console.print(f"[green]Plugin '{plugin_id}' enabled.[/green]")
    else:
        console.print(f"[red]Failed to enable plugin '{plugin_id}'.[/red]")


@plugin.command("disable")
@click.argument("plugin_id")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
def plugin_disable(plugin_id: str, config: str | None) -> None:
    """Disable a plugin by ID."""
    settings = JSSettings.from_file(config)
    from js.agent import JSAgent
    from js.plugins.manager import PluginManager

    agent = JSAgent(settings)
    pm = PluginManager(agent, settings)
    pm.discover()
    if pm.disable(plugin_id):
        console.print(f"[yellow]Plugin '{plugin_id}' disabled.[/yellow]")
    else:
        console.print(f"[red]Failed to disable plugin '{plugin_id}'.[/red]")


@main.group()
def rl() -> None:
    """Reinforcement Learning: train agent policies in simulated environments."""
    pass


@rl.command("train")
@click.option("--env", "-e", default="code_fix", type=click.Choice(["code_fix"]), help="Environment name")
@click.option("--episodes", "-n", default=5, type=int, help="Number of episodes")
@click.option("--output", "-o", type=click.Path(), help="Trajectory output directory")
def rl_train(env: str, episodes: int, output: str | None) -> None:
    """Run RL training episodes and collect trajectories."""
    from js.rl.code_fix import CodeFixEnv
    from js.rl.trainer import RLTrainer

    out_dir = Path(output).expanduser() if output else None
    environment = CodeFixEnv()
    trainer = RLTrainer(environment, output_dir=out_dir)

    console.print(f"[bold]Training {episodes} episodes on '{env}'...[/bold]")
    report = asyncio.run(trainer.run_episodes(num_episodes=episodes))

    console.print(Panel(
        f"Episodes: {report.num_episodes}\n"
        f"Success rate: {report.success_count / report.num_episodes:.1%}\n"
        f"Avg reward: {report.avg_reward:.2f}\n"
        f"Avg steps: {report.avg_steps:.1f}\n"
        f"Duration: {report.end_time - report.start_time:.1f}s",
        title="Training Report", border_style="green",
    ))


@rl.command("list")
def rl_list() -> None:
    """List saved trajectories."""
    from js.rl.recorder import TrajectoryRecorder

    recorder = TrajectoryRecorder()
    paths = recorder.list_trajectories()
    if not paths:
        console.print("[dim]No trajectories found.[/dim]")
        return

    table = Table(title="Saved Trajectories")
    table.add_column("ID", style="cyan")
    table.add_column("Env")
    table.add_column("Steps")
    table.add_column("Success")
    table.add_column("Size")

    for p in paths[:20]:
        data = json.loads(p.read_text(encoding="utf-8"))
        table.add_row(
            data["trajectory_id"],
            data["env_name"],
            str(len(data.get("steps", []))),
            "✅" if data.get("success") else "❌",
            f"{p.stat().st_size // 1024}KB",
        )
    console.print(table)


if __name__ == "__main__":
    main()
