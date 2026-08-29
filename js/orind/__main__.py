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
    parser.add_argument(
        "--policy-profile",
        choices=["conservative", "compat"],
        default="conservative",
        help="Lease policy table profile",
    )
    stage_b = parser.add_argument_group("Stage B (opt-in)")
    stage_b.add_argument(
        "--stage-b",
        action="store_true",
        help="Enable Stage-B protocol surfaces; Cell features remain opt-in",
    )
    stage_b.add_argument(
        "--cell-build",
        action="store_true",
        help="Enable the legacy-compatible Build Cell",
    )
    stage_b.add_argument(
        "--cell-secret",
        action="store_true",
        help="Enable the Secret Cell service capability",
    )
    stage_b.add_argument(
        "--cell-net",
        action="store_true",
        help="Enable Network and Connector Cell service capabilities",
    )
    stage_b.add_argument(
        "--cell-file",
        action="store_true",
        help="Enable the File Cell",
    )
    stage_b.add_argument(
        "--commit-membrane",
        action="store_true",
        help="Enable the Stage-B durable Commit Membrane",
    )
    stage_c = parser.add_argument_group("Stage C (opt-in, default off)")
    stage_c.add_argument(
        "--cell-identity-enforce",
        action="store_true",
        help="Enable Cell OS/launch/protocol identity without the C1 test harness",
    )
    args = parser.parse_args(argv)
    if not args.stage_b and any(
        (
            args.cell_build,
            args.cell_secret,
            args.cell_net,
            args.cell_file,
            args.commit_membrane,
            args.cell_identity_enforce,
        )
    ):
        parser.error("Stage-B Cell, membrane, and identity switches require --stage-b")
    return args


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
        policy_profile=args.policy_profile,
        stage_b=args.stage_b,
        cell_build=args.cell_build,
        cell_secret=args.cell_secret,
        cell_net=args.cell_net,
        cell_file=args.cell_file,
        commit_membrane=args.commit_membrane,
        cell_identity_enforce=args.cell_identity_enforce,
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
