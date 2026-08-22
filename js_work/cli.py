"""Command line interface for JS Agent Work."""

from __future__ import annotations

import asyncio
import json
import sys
import warnings
from pathlib import Path
from typing import Any

import click
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from js.agent import JSAgent
from js.echo.effect_interpreter import ToolEffect
from js.echo.turn_runtime import run_echo_turn
from js.product_storage import StorageRoots
from js.utils.log import configure_logging, get_logger
from js.web.messages import humanize_error
from js_work.agent_factory import create_work_agent
from js_work.config import default_work_config_path, load_work_settings
from js_work.routines import WorkRoutineStore
from js_work.routines.store import DEFAULT_WORK_OWNER_KEY_HASH
from js_work.tools import WorkToolProfile
from js_work.workflows import WorkIntentRouter

WORK_OWNER_KEY_HASH = DEFAULT_WORK_OWNER_KEY_HASH
WORK_CHANNEL = "js_work_cli"
WORK_ROUTINE_CHANNEL = "js_work_routine_cli"

console = Console()


class WorkCLI:
    """Interactive and one-shot runner for JS Agent Work."""

    def __init__(
        self,
        *,
        config: str | None = None,
        home: Path | None = None,
        profile: WorkToolProfile = WorkToolProfile.EXECUTE,
        personal_roots: StorageRoots | None = None,
    ) -> None:
        self.config = config
        self.home = home
        self.profile = profile
        self.personal_roots = personal_roots
        self.settings = load_work_settings(config, home=home, personal_roots=personal_roots)
        self.agent: JSAgent | None = None
        self._agent_profile: WorkToolProfile | None = None
        self.session_id: str | None = None
        self.intent_router = WorkIntentRouter()
        self.logger = get_logger("js_work.cli")

    async def init(self, *, profile: WorkToolProfile | None = None) -> None:
        selected = profile or self.profile
        if self.agent is not None and self._agent_profile == selected:
            return
        previous = self.agent
        if previous is not None:
            await previous.close()
        self.agent = create_work_agent(
            settings=self.settings,
            profile=selected,
            allow_host_code_tools=True,
        )
        self._agent_profile = selected
        self.agent.start_background_tasks()

    async def close(self) -> None:
        agent, self.agent = self.agent, None
        self._agent_profile = None
        if agent is not None:
            await agent.close()

    def _history_path(self) -> Path:
        base = self.home or Path.home()
        path = base / ".js-work" / "history"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    async def run_message(self, message: str, model: str | None = None) -> None:
        if not self.settings.providers:
            console.print(
                Panel.fit(
                    "No model providers are configured for JS Agent Work.\n"
                    "Run `js work init` and add a provider to the Work config.",
                    title="JS Agent Work",
                    border_style="yellow",
                )
            )
            return
        effective_profile = self._profile_for_message(message)
        await self.init(profile=effective_profile)
        assert self.agent is not None
        prepared = self.intent_router.prepare_message(message)
        try:
            state = await run_echo_turn(
                self.agent,
                prepared,
                channel=WORK_CHANNEL,
                owner_key_hash=WORK_OWNER_KEY_HASH,
                session_id=self.session_id,
                model=model,
                attachments=[],
            )
        except Exception as exc:
            self.logger.error(
                "Work CLI turn failed: %s",
                type(exc).__name__,
            )
            raise click.ClickException(humanize_error(str(exc))) from None
        self.session_id = state.session_id
        if state.status != "completed":
            if state.error_message:
                error_message = humanize_error(state.error_message)
            elif state.status == "cancelled":
                error_message = humanize_error("Echo turn cancelled")
            elif state.status == "error":
                error_message = "Echo turn failed"
            else:
                error_message = f"Echo turn ended with status {state.status}"
            raise click.ClickException(error_message)
        for msg in reversed(state.messages):
            if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                console.print(Markdown(msg.content))
                break

    async def run_interactive(self) -> None:
        if not self.settings.providers:
            console.print(
                Panel.fit(
                    "No model providers are configured for JS Agent Work.\n"
                    "Run `js work init` and add a provider to the Work config.",
                    title="JS Agent Work",
                    border_style="yellow",
                )
            )
            return
        await self.init()
        session: PromptSession[str] = PromptSession(history=FileHistory(str(self._history_path())))
        console.print(
            Panel.fit(
                f"JS Agent Work\nProfile: {self.profile.value}\n"
                "Type /profile safe, /profile execute, /profile office, or /quit.",
                title="Work",
                border_style="cyan",
            )
        )
        try:
            while True:
                try:
                    user_input = (await session.prompt_async("JS Work> ")).strip()
                except (KeyboardInterrupt, EOFError):
                    break
                if not user_input:
                    continue
                if user_input.startswith("/"):
                    if await self._handle_command(user_input):
                        break
                    continue
                await self.run_message(user_input)
        finally:
            await self.close()

    def _profile_for_message(self, message: str) -> WorkToolProfile:
        # Intent detection may tailor the prompt, but it must never widen the
        # capability profile selected by the caller.
        return self.profile

    async def _handle_command(self, command: str) -> bool:
        parts = command[1:].split()
        if not parts:
            return False
        if parts[0] in {"quit", "exit", "q"}:
            return True
        if parts[0] == "profile":
            if len(parts) != 2 or parts[1] not in {p.value for p in WorkToolProfile}:
                console.print("[yellow]Usage: /profile execute|safe|office[/yellow]")
                return False
            self.profile = WorkToolProfile(parts[1])
            await self.init(profile=self.profile)
            console.print(f"[green]Profile switched to {self.profile.value}[/green]")
            return False
        if parts[0] == "routine":
            await self._handle_routine_command(parts[1:])
            return False
        console.print("[yellow]Unknown command[/yellow]")
        return False

    async def _handle_routine_command(self, parts: list[str]) -> None:
        store = WorkRoutineStore(
            self.settings.state_dir,
            owner_key_hash=WORK_OWNER_KEY_HASH,
            session_id="work-routine-cli",
        )
        if not parts or parts[0] == "list":
            console.print_json(data={"routines": [r.to_dict() for r in store.list_routines()]})
            return
        if parts[0] == "approve" and len(parts) == 2:
            routine_id = parts[1]
            result = await _execute_routine_control_effect(
                settings=self.settings,
                tool_name="control_work_routine_approve",
                arguments={"routine_id": routine_id},
            )
            if not result.success:
                raise click.ClickException(result.error or "routine approve failed")
            payload = _parse_routine_payload(result)
            if payload.get("routine_id") != routine_id or payload.get("status") != "enabled":
                raise click.ClickException("routine control returned invalid data")
            console.print_json(data=payload)
            return
        if parts[0] == "inspect" and len(parts) == 2:
            console.print_json(data=store.get(parts[1]).to_dict())
            return
        if parts[0] == "run" and len(parts) == 5:
            if self.profile != WorkToolProfile.OFFICE:
                console.print(
                    "[red]routine run requires the office profile "
                    "(use /profile office or --profile office)[/red]"
                )
                return
            payload = await _execute_routine_tool_effect(
                settings=self.settings,
                routine_id=parts[1],
                source_path=parts[2],
                template_path=parts[3],
                output_path=parts[4],
                dry_run=False,
            )
            console.print_json(data=payload)
            return
        console.print(
            "[yellow]Usage: /routine list | approve <id> | inspect <id> | "
            "run <id> <source.xlsx> <template.xlsx> <output.xlsx>[/yellow]"
        )


@click.group(invoke_without_command=True)
@click.option("--config", "-c", type=click.Path(), help="Path to JS Agent Work config")
@click.option(
    "--profile",
    type=click.Choice([profile.value for profile in WorkToolProfile]),
    default=WorkToolProfile.EXECUTE.value,
    show_default=True,
)
@click.option("--home", type=click.Path(), hidden=True)
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging")
@click.pass_context
def main(
    ctx: click.Context,
    config: str | None,
    profile: str,
    home: str | None,
    verbose: bool,
) -> None:
    """Work mode - the restricted work-focused mode inside JS Agent."""
    configure_logging("DEBUG" if verbose else "INFO")
    root = ctx.find_root()
    root_object = root.obj if isinstance(root.obj, dict) else {}
    ctx.obj = {
        "config": config,
        "profile": WorkToolProfile(profile),
        "home": Path(home).expanduser() if home else None,
        "personal_roots": root_object.get("personal_roots"),
    }
    if ctx.invoked_subcommand is None:
        cli = WorkCLI(**ctx.obj)
        asyncio.run(cli.run_interactive())


@main.command()
@click.option("--path", "-p", type=click.Path(), help="Config file path")
@click.pass_context
def init(ctx: click.Context, path: str | None) -> None:
    """Initialize JS Agent Work configuration."""
    home: Path | None = ctx.obj["home"]
    target = Path(path).expanduser() if path else default_work_config_path(home)
    if target.exists() and not click.confirm(f"Config exists at {target}. Overwrite?"):
        return
    settings = load_work_settings(home=home, personal_roots=ctx.obj["personal_roots"])
    settings.save(target)
    console.print(f"[green]JS Agent Work config initialized at {target}[/green]")


@main.command()
@click.argument("message", nargs=-1, required=True)
@click.option("--model", "-m", help="Model to use")
@click.pass_context
def run(ctx: click.Context, message: tuple[str, ...], model: str | None) -> None:
    """Run one Work task and exit."""
    cli = WorkCLI(**ctx.obj)
    async def _run_once() -> None:
        try:
            await cli.run_message(" ".join(message), model=model)
        finally:
            await cli.close()

    asyncio.run(_run_once())


@main.group()
@click.pass_context
def routine(ctx: click.Context) -> None:
    """Manage JS Agent Work routines."""
    _ = ctx


def _local_store(settings: Any) -> WorkRoutineStore:
    return WorkRoutineStore(
        settings.state_dir,
        owner_key_hash=WORK_OWNER_KEY_HASH,
        session_id="work-routine-cli",
    )


def _parse_routine_payload(result: Any) -> dict[str, Any]:
    """Extract the routine dict from an Echo control tool result."""
    routine = result.metadata.get("routine") if hasattr(result, "metadata") else None
    if not isinstance(routine, dict):
        raise click.ClickException("routine control returned invalid data")
    return routine


async def _execute_routine_control_effect(
    *,
    settings: Any,
    tool_name: str,
    arguments: dict[str, Any],
) -> Any:
    """Run a Work routine control operation (draft/approve/disable) through Echo.

    Control-plane operations must go through ``echo_runtime.execute_tool_effect``
    so the durable ledger records the authorization, mirroring the web API.
    """
    from js_work.agent_factory import create_work_agent
    from js_work.tools import WorkToolProfile

    agent = create_work_agent(settings=settings, profile=WorkToolProfile.OFFICE)
    runtime = agent.echo_runtime
    context = runtime.build_context(
        channel="work-routine-cli-control",
        owner_key_hash=WORK_OWNER_KEY_HASH,
        session_id="work-routine-cli",
        role="local-user",
        capabilities=(tool_name,),
    )
    _message, result = await runtime.execute_tool_effect(
        ToolEffect.from_arguments(
            tool_name,
            arguments,
            allowed_tools=(tool_name,),
            user_input=f"cli {tool_name}",
        ),
        context,
    )
    return result


async def _execute_routine_tool_effect(
    *,
    settings: Any,
    routine_id: str,
    source_path: str,
    template_path: str,
    output_path: str,
    dry_run: bool,
) -> dict[str, Any]:
    """Run work_routine_run/preview through Echo with an office-only capability lease."""
    agent = create_work_agent(settings=settings, profile=WorkToolProfile.OFFICE)
    tool_name = "work_routine_preview" if dry_run else "work_routine_run"
    arguments: dict[str, Any] = {
        "routine_id": routine_id,
        "source_path": source_path,
        "template_path": template_path,
    }
    if not dry_run:
        arguments["output_path"] = output_path
    approval_session = "work-routine-cli"
    try:
        runtime = agent.echo_runtime
        context = runtime.build_context(
            channel=WORK_ROUTINE_CHANNEL,
            owner_key_hash=WORK_OWNER_KEY_HASH,
            session_id=approval_session,
            role="local-user",
            capabilities=(tool_name,),
        )
        if not dry_run:
            agent.approvals.set_callback(
                approval_session,
                lambda _request: True,
                owner_key_hash=WORK_OWNER_KEY_HASH,
                run_id=context.run_id,
                tool_name=tool_name,
                arguments=arguments,
            )
        _message, result = await runtime.execute_tool_effect(
            ToolEffect.from_arguments(
                tool_name,
                arguments,
                allowed_tools=(tool_name,),
                user_input=f"cli {tool_name}",
            ),
            context,
        )
        if not result.success:
            raise click.ClickException(result.error or "routine execution failed")
        try:
            payload = json.loads(result.output or "{}")
        except json.JSONDecodeError as e:
            raise click.ClickException("routine tool returned invalid payload") from e
        if not isinstance(payload, dict):
            raise click.ClickException("routine tool returned invalid payload")
        return payload
    finally:
        if not dry_run:
            agent.approvals.remove_callback(approval_session)
        await agent.close()


@routine.command(name="list")
@click.pass_context
def routine_list(ctx: click.Context) -> None:
    """List Work routines."""
    settings = load_work_settings(
        ctx.obj["config"], home=ctx.obj["home"], personal_roots=ctx.obj["personal_roots"]
    )
    store = _local_store(settings)
    click.echo(json.dumps({"routines": [r.to_dict() for r in store.list_routines()]}, ensure_ascii=False))


@routine.command(name="draft")
@click.option("--name", required=True, help="Routine name")
@click.option("--trigger", multiple=True, required=True, help="Trigger phrase")
@click.option("--routine-type", default="spreadsheet_template", show_default=True, help="Routine type")
@click.option("--mapping", default="{}", help="JSON output-to-source field mapping")
@click.option("--required-field", multiple=True, help="Required output field")
@click.option("--row-filter", multiple=True, help="JSON row filter object")
@click.option("--header-aliases", default="{}", help="JSON header alias object")
@click.option("--aggregation", default="{}", help="JSON aggregation rules object")
@click.option("--source-sheet", default="", help="Source workbook sheet name")
@click.option("--review-policy", default="{}", help="JSON review policy object")
@click.pass_context
def routine_draft(
    ctx: click.Context,
    name: str,
    trigger: tuple[str, ...],
    routine_type: str,
    mapping: str,
    required_field: tuple[str, ...],
    row_filter: tuple[str, ...],
    header_aliases: str,
    aggregation: str,
    source_sheet: str,
    review_policy: str,
) -> None:
    """Create a disabled routine draft through Echo authorization."""
    settings = load_work_settings(
        ctx.obj["config"], home=ctx.obj["home"], personal_roots=ctx.obj["personal_roots"]
    )
    arguments: dict[str, Any] = {
        "name": name,
        "trigger_phrases": list(trigger),
        "routine_type": routine_type,
        "field_mapping": json.loads(mapping),
        "row_filters": [json.loads(item) for item in row_filter],
        "header_aliases": json.loads(header_aliases or "{}"),
        "aggregation_rules": json.loads(aggregation or "{}"),
        "source_sheet": source_sheet,
        "review_policy": json.loads(review_policy or "{}"),
        "validation_rules": {"required_fields": list(required_field)},
    }
    result = asyncio.run(
        _execute_routine_control_effect(
            settings=settings,
            tool_name="control_work_routine_draft",
            arguments=arguments,
        )
    )
    if not result.success:
        raise click.ClickException(result.error or "routine draft failed")
    payload = _parse_routine_payload(result)
    click.echo(json.dumps(payload, ensure_ascii=False))


@routine.command(name="approve")
@click.argument("routine_id")
@click.pass_context
def routine_approve(ctx: click.Context, routine_id: str) -> None:
    """Approve a routine draft through Echo authorization."""
    settings = load_work_settings(
        ctx.obj["config"], home=ctx.obj["home"], personal_roots=ctx.obj["personal_roots"]
    )
    result = asyncio.run(
        _execute_routine_control_effect(
            settings=settings,
            tool_name="control_work_routine_approve",
            arguments={"routine_id": routine_id},
        )
    )
    if not result.success:
        raise click.ClickException(result.error or "routine approve failed")
    payload = _parse_routine_payload(result)
    click.echo(json.dumps(payload, ensure_ascii=False))


@routine.command(name="inspect")
@click.argument("routine_id")
@click.pass_context
def routine_inspect(ctx: click.Context, routine_id: str) -> None:
    """Inspect a routine."""
    settings = load_work_settings(
        ctx.obj["config"], home=ctx.obj["home"], personal_roots=ctx.obj["personal_roots"]
    )
    store = _local_store(settings)
    click.echo(json.dumps(store.get(routine_id).to_dict(), ensure_ascii=False))


@routine.command(name="run")
@click.argument("routine_id")
@click.option("--source", "source_path", required=True, help="Source workbook path")
@click.option("--template", "template_path", required=True, help="Template workbook path")
@click.option("--output", "output_path", required=True, help="Output workbook path")
@click.option("--dry-run", is_flag=True, help="Preview routine extraction without writing output")
@click.pass_context
def routine_run(
    ctx: click.Context,
    routine_id: str,
    source_path: str,
    template_path: str,
    output_path: str,
    dry_run: bool,
) -> None:
    """Run an approved spreadsheet routine."""
    profile = ctx.obj["profile"]
    if profile != WorkToolProfile.OFFICE:
        raise click.ClickException(
            "routine run requires --profile office (capability profile is never auto-widened)"
        )
    settings = load_work_settings(
        ctx.obj["config"], home=ctx.obj["home"], personal_roots=ctx.obj["personal_roots"]
    )
    payload = asyncio.run(
        _execute_routine_tool_effect(
            settings=settings,
            routine_id=routine_id,
            source_path=source_path,
            template_path=template_path,
            output_path=output_path,
            dry_run=dry_run,
        )
    )
    click.echo(json.dumps(payload, ensure_ascii=False))


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host")
@click.option("--port", default=8000, show_default=True, help="Bind parent AppShell port")
@click.option("--reload", is_flag=True, help="Enable auto-reload on code changes")
@click.option("--open-browser", is_flag=True, help="Open the Work Web UI in a browser")
@click.pass_context
def web(
    ctx: click.Context,
    host: str,
    port: int,
    reload: bool,
    open_browser: bool,
) -> None:
    """Run Work through the single parent AppShell host."""
    if reload and ctx.obj["personal_roots"] is not None:
        raise click.ClickException("AppShell object mode does not support --reload")
    personal_roots: StorageRoots | None = ctx.obj["personal_roots"]
    if personal_roots is None:
        # Programmatic/direct Work command compatibility. Public ``js-work``
        # and ``python -m js_work`` shims dispatch through ``js work`` and
        # therefore always carry Personal roots into the parent branch below.
        from js_work.web import serve_work_web

        serve_work_web(
            config=ctx.obj["config"],
            home=ctx.obj["home"],
            personal_roots=None,
            profile=ctx.obj["profile"],
            host=host,
            port=port,
            reload=reload,
            open_browser=open_browser,
        )
        return

    from js.appshell.server import create_appshell_app

    app = create_appshell_app(
        personal_config=str(personal_roots.config_path),
        work_config=ctx.obj["config"],
        work_home=ctx.obj["home"],
        work_profile=ctx.obj["profile"],
        host=host,
        port=port,
    )
    url = f"http://{host}:{port}"
    if open_browser:
        import webbrowser

        webbrowser.open(url)
    console.print(f"[green]Starting JS Agent AppShell at {url}[/green]")
    import uvicorn

    uvicorn.run(app, host=host, port=port, reload=False)


def compat_main() -> None:
    """Translate the deprecated standalone argv and call the canonical dispatcher."""
    warnings.warn(
        "js-work is a compatibility shim; use `js work`.",
        FutureWarning,
        stacklevel=2,
    )
    argv = list(sys.argv[1:])
    personal_config: str | None = None
    translated: list[str] = []
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--personal-config":
            if index + 1 >= len(argv):
                raise click.UsageError("--personal-config requires a path")
            personal_config = argv[index + 1]
            index += 2
            continue
        if item.startswith("--personal-config="):
            personal_config = item.split("=", 1)[1]
            index += 1
            continue
        translated.append(item)
        index += 1
    canonical_args = (["--config", personal_config] if personal_config else [])
    canonical_args.extend(["work", *translated])
    from js.ui.cli import main as canonical_main

    canonical_main(args=canonical_args, prog_name="js", standalone_mode=True)
