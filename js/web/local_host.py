"""Thin uvicorn entry shared by local Host launchers."""

from __future__ import annotations

from typing import Any


def run_local_host(
    app: Any,
    *,
    host: str,
    port: int,
    reload: bool = False,
    title: str = "JS Agent AppShell Host",
    notes: tuple[str, ...] = (),
) -> None:
    """Print a unified banner and serve ``app``. Does not open a browser."""
    import uvicorn
    from rich.console import Console

    url = f"http://{host}:{port}"
    console = Console()
    console.print(f"[green]Starting {title} at {url}[/green]")
    for note in notes:
        console.print(f"[dim]{note}[/dim]")
    uvicorn.run(app, host=host, port=port, reload=reload)
