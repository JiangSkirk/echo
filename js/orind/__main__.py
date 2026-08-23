"""orind entry point: ``python -m js.orind --dev``.

Production deployment wraps this in launchd (KeepAlive); ``--dev`` runs
the daemon in the foreground. The daemon holds the lease MAC key — never
run it with privileges beyond the owning user.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="orind", description="Orin gatekeeper daemon")
    parser.add_argument("--dev", action="store_true", help="Run in the foreground")
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path.home() / ".js" / "state",
        help="State directory (shared with the main process)",
    )
    parser.add_argument(
        "--socket-path",
        type=Path,
        default=None,
        help="Override the Unix domain socket path",
    )
    parser.add_argument(
        "--keybox-tier",
        choices=["dev", "production"],
        default="dev",
        help="Key custody tier (production = macOS Keychain)",
    )
    return parser.parse_args(argv)


@contextmanager
def _graceful_signals(stop: asyncio.Event) -> Iterator[None]:
    loop = asyncio.get_running_loop()
    handlers: list[signal.Signals] = [signal.SIGINT, signal.SIGTERM]
    for sig in handlers:
        with contextlib.suppress(NotImplementedError):  # pragma: no cover - Windows
            loop.add_signal_handler(sig, stop.set)
    try:
        yield
    finally:
        for sig in handlers:
            with contextlib.suppress(NotImplementedError, ValueError):  # pragma: no cover
                loop.remove_signal_handler(sig)


async def _main_async(args: argparse.Namespace) -> int:
    from js.orind.daemon import OrinDaemon

    stop = asyncio.Event()
    daemon = OrinDaemon(
        state_dir=args.state_dir,
        socket_path=args.socket_path,
        keybox_tier=args.keybox_tier,
    )
    await daemon.start()
    print(
        f"orind listening on {daemon.socket_path} (keybox tier: {daemon.keybox_tier})",
        flush=True,
    )
    try:
        with _graceful_signals(stop):
            await stop.wait()
    finally:
        await daemon.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if not args.dev:
        print("orind: only --dev mode exists in Stage A; run with --dev", file=sys.stderr)
        return 2
    try:
        return asyncio.run(_main_async(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
