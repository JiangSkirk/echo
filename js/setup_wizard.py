"""One-click setup wizard for app-like installation experience."""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from js.config import JSSettings
from js.echo.effect_interpreter import ToolEffect
from js.search.engines import DuckDuckGoEngine, SearchManager, TavilyEngine
from js.utils.log import get_logger

console = Console()
logger = get_logger("js.setup")


class SetupWizard:
    """Interactive setup wizard that auto-configures everything."""

    def __init__(self) -> None:
        self.settings = JSSettings()
        self.config_path = Path(
            os.getenv("JS_CONFIG_PATH", "~/.config/js/config.yaml")
        ).expanduser()

    async def run(self, non_interactive: bool = False) -> None:
        """Run the complete setup flow."""
        console.print(
            Panel.fit(
                "[bold cyan]JS Agent Setup Wizard[/bold cyan]\n"
                "We'll automatically detect your local models and configure everything.",
                title="Welcome",
                border_style="cyan",
            )
        )

        steps = [
            ("Creating directories", self._setup_directories),
            ("Detecting local models", self._detect_models),
            ("Configuring search", self._configure_search),
            ("Saving configuration", self._save_config),
            ("Running health checks", self._health_checks),
            ("Finishing up", self._embedding_hint),
        ]

        failed_steps: list[str] = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            for desc, step_fn in steps:
                task = progress.add_task(description=desc, total=None)
                try:
                    await step_fn(non_interactive=non_interactive)
                    progress.update(task, description=f"[green]✓ {desc}[/green]")
                except Exception as e:
                    progress.update(task, description=f"[red]✗ {desc}: {e}[/red]")
                    logger.error(f"Setup step '{desc}' failed: {e}")
                    failed_steps.append(desc)

        if failed_steps:
            console.print(
                Panel(
                    f"[red]Setup failed: {', '.join(failed_steps)}[/red]\n\n"
                    "Configuration may be incomplete. Re-run setup after fixing "
                    "the errors above.",
                    title="Setup Failed",
                    border_style="red",
                )
            )
            raise SystemExit(1)

        console.print(
            Panel(
                "[green]Setup complete![/green]\n\n"
                f"Config saved to: [cyan]{self.config_path}[/cyan]\n\n"
                "Next steps:\n"
                "  Open the [bold]JS Agent desktop app[/bold]\n"
                "  [bold]js[/bold]          - Start CLI chat\n"
                "  [bold]js appshell[/bold] - Local Host (does not open a browser)\n"
                "  [bold]js status[/bold]   - Check system status",
                border_style="green",
            )
        )

    async def _setup_directories(self, **_kwargs: Any) -> None:
        self.settings.workspace.mkdir(parents=True, exist_ok=True)
        self.settings.state_dir.mkdir(parents=True, exist_ok=True)
        (self.settings.state_dir / "skills").mkdir(exist_ok=True)

    async def _detect_models(self, non_interactive: bool = False, **_kwargs: Any) -> None:
        """Probe two exact local endpoints through the Echo control boundary.

        Does NOT auto-save all discovered models — only the provider endpoint
        and a single default_model chosen by the user (or first loaded model
        in non-interactive mode). Embedding models are left for manual config.
        """
        from js.agent import JSAgent
        from js.config import ModelConfig, ModelProviderConfig

        agent = JSAgent(self.settings)
        discovered: list[tuple[str, str, str, list[dict[str, Any]]]] = []
        try:
            for provider_type, base_url, api_key in (
                ("lmstudio", "http://127.0.0.1:1234/v1", "lm-studio"),
                ("ollama", "http://127.0.0.1:11434/v1", "ollama"),
            ):
                owner = "local-setup-admin"
                session_id = f"setup-provider-{secrets.token_hex(16)}"
                product_id = str(getattr(agent.settings, "product_id", "js-agent"))
                api_key_ref = agent.stage_provider_discovery_key(
                    api_key,
                    owner_key_hash=owner,
                    product_id=product_id,
                    session_id=session_id,
                )
                if not api_key_ref:
                    logger.error("Provider credential admission is unavailable")
                    continue
                arguments = {
                    "base_url": base_url,
                    "api_key_ref": api_key_ref,
                    "allow_private": False,
                }
                context = agent.echo_runtime.build_context(
                    channel="cli_setup_provider_discover",
                    owner_key_hash=owner,
                    session_id=session_id,
                    role="admin",
                    capabilities=("control_provider_discover",),
                    control_arguments=arguments,
                )
                try:
                    _message, result = await agent.echo_runtime.execute_tool_effect(
                        ToolEffect.from_arguments(
                            "control_provider_discover",
                            arguments,
                            user_input=(
                                f"Setup wizard exact local provider discovery: {provider_type}"
                            ),
                            allowed_tools=("control_provider_discover",),
                        ),
                        context,
                    )
                finally:
                    agent.discard_provider_discovery_key(
                        api_key_ref,
                        owner_key_hash=owner,
                        product_id=product_id,
                        session_id=session_id,
                    )
                models = result.metadata.get("models", [])
                if result.success and isinstance(models, list):
                    valid_models = [
                        model
                        for model in models
                        if isinstance(model, dict)
                        and isinstance(model.get("id"), str)
                        and bool(model["id"].strip())
                    ]
                    if valid_models:
                        discovered.append((provider_type, base_url, api_key, valid_models))
        finally:
            await agent.close()

        if not discovered:
            console.print(
                "[yellow]⚠ No local models detected.[/yellow]\n"
                "  Make sure LM Studio or Ollama is running, or configure cloud providers manually."
            )
            return

        existing_names = {p.name for p in self.settings.providers}
        existing_urls = {p.base_url for p in self.settings.providers}

        for provider_type, base_url, api_key, models in discovered:
            if base_url in existing_urls or provider_type in existing_names:
                continue

            # Pick default: first non-embedding model, or first model if all are embedding
            model_ids = [str(model["id"]).strip() for model in models]
            chat_models = [model_id for model_id in model_ids if "embed" not in model_id.lower()]
            default_models = chat_models if chat_models else model_ids
            default_model = default_models[0] if default_models else ""

            if not non_interactive and len(default_models) > 1:
                choices = list(default_models)
                default_model = click.prompt(
                    f"Select default model for {provider_type}",
                    type=click.Choice(choices),
                    default=choices[0],
                )

            cfg = ModelProviderConfig(
                name=provider_type,
                base_url=base_url,
                api_key=api_key,
                timeout=120.0,
                max_retries=3,
                default_model=default_model,
                models=[
                    ModelConfig(
                        id=default_model,
                        name=default_model,
                        provider=provider_type,
                    )
                ],
            )
            self.settings.providers.append(cfg)
            self.settings.models.append(
                ModelConfig(
                    id=default_model,
                    name=default_model,
                    provider=provider_type,
                )
            )
            console.print(f"  [green]+ {provider_type}[/green] → {default_model}")

    async def _configure_search(self, non_interactive: bool = False, **_kwargs: Any) -> None:
        # Always enable DuckDuckGo (free, no API key)
        search_manager = SearchManager()
        search_manager.register(DuckDuckGoEngine(), default=True)

        # Check for Tavily API key
        tavily_key = os.getenv("TAVILY_API_KEY", "")
        if not tavily_key and not non_interactive:
            tavily_key = click.prompt(
                "Tavily API key (optional, press Enter to skip)",
                default="",
                show_default=False,
            )

        if tavily_key:
            search_manager.register(TavilyEngine(tavily_key))
            # Store in secrets
            from js.security.secrets import SecretManager

            secrets = SecretManager(self.settings.state_dir)
            secrets.store("tavily_api_key", tavily_key)

        self.settings.search_configured = True

    async def _save_config(self, **_kwargs: Any) -> None:
        self.settings.save(self.config_path)

    async def _health_checks(self, **_kwargs: Any) -> None:
        from js.models.router import ModelRouter

        router = ModelRouter(self.settings)
        health = await router.health_check()
        for name, status in health.items():
            color = "green" if status else "red"
            console.print(f"  [{color}]{'✓' if status else '✗'} {name}[/{color}]")

    async def _embedding_hint(self, **_kwargs: Any) -> None:
        """Print a hint about embedding models for semantic memory."""
        has_embedding = any(
            "embed" in m.id.lower() or "embedding" in m.id.lower()
            for p in self.settings.providers
            for m in p.models
        )
        if not has_embedding and self.settings.providers:
            console.print(
                "\n[dim]💡 Tip: For full semantic memory (vector search), load an embedding model\n"
                "   in LM Studio → 'Developer' tab → 'Embedding Model', or use an external\n"
                "   embedding provider like OpenAI text-embedding-3-small.[/dim]"
            )


async def run_setup(non_interactive: bool = False) -> None:
    wizard = SetupWizard()
    await wizard.run(non_interactive=non_interactive)
