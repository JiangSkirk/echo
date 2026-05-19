"""One-click setup wizard for app-like installation experience."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from js.config import JSSettings
from js.discovery.local_models import LocalModelDiscovery
from js.search.engines import DuckDuckGoEngine, SearchManager, TavilyEngine
from js.utils.log import get_logger

console = Console()
logger = get_logger("js.setup")


class SetupWizard:
    """Interactive setup wizard that auto-configures everything."""

    def __init__(self) -> None:
        self.settings = JSSettings()
        self.config_path = Path.home() / ".config" / "js" / "config.yaml"

    async def run(self, non_interactive: bool = False) -> None:
        """Run the complete setup flow."""
        console.print(Panel.fit(
            "[bold cyan]JS Agent Setup Wizard[/bold cyan]\n"
            "We'll automatically detect your local models and configure everything.",
            title="Welcome",
            border_style="cyan",
        ))

        steps = [
            ("Creating directories", self._setup_directories),
            ("Detecting local models", self._detect_models),
            ("Configuring search", self._configure_search),
            ("Saving configuration", self._save_config),
            ("Running health checks", self._health_checks),
        ]

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
                    logger.warning(f"Setup step '{desc}' failed: {e}")

        console.print(Panel(
            "[green]Setup complete![/green]\n\n"
            f"Config saved to: [cyan]{self.config_path}[/cyan]\n\n"
            "Next steps:\n"
            "  [bold]js chat[/bold]     - Start CLI chat\n"
            "  [bold]js web[/bold]      - Launch Web UI\n"
            "  [bold]js status[/bold]   - Check system status",
            border_style="green",
        ))

    async def _setup_directories(self, **kwargs: Any) -> None:
        self.settings.workspace.mkdir(parents=True, exist_ok=True)
        self.settings.state_dir.mkdir(parents=True, exist_ok=True)
        (self.settings.state_dir / "skills").mkdir(exist_ok=True)

    async def _detect_models(self, **kwargs: Any) -> None:
        discovery = LocalModelDiscovery(timeout=5.0)
        try:
            self.settings = await discovery.apply_to_settings(self.settings)
        finally:
            await discovery.close()

        if not self.settings.providers:
            console.print(
                "[yellow]⚠ No local models detected.[/yellow]\n"
                "  Make sure LM Studio or Ollama is running, or configure cloud providers manually."
            )

    async def _configure_search(self, non_interactive: bool = False, **kwargs: Any) -> None:
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

    async def _save_config(self, **kwargs: Any) -> None:
        self.settings.save(self.config_path)

    async def _health_checks(self, **kwargs: Any) -> None:
        from js.models.router import ModelRouter
        router = ModelRouter(self.settings)
        health = await router.health_check()
        for name, status in health.items():
            color = "green" if status else "red"
            console.print(f"  [{color}]{'✓' if status else '✗'} {name}[/{color}]")


async def run_setup(non_interactive: bool = False) -> None:
    wizard = SetupWizard()
    await wizard.run(non_interactive=non_interactive)
