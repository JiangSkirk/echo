"""In-process orind for tests — no launchd, no separate process.

``TestOrind`` runs the *real* :class:`js.orind.daemon.OrinDaemon` on a
temporary Unix domain socket inside a background thread of the test
process. This exercises the full protocol stack (handshake, session key
file, MAC, seq) exactly as production does.

macOS caps AF_UNIX paths at 104 bytes, and pytest tmp_path trees can
exceed that. When the requested socket path is too long the socket is
relocated to a short temporary directory (``$TMPDIR/orind-*/orind.sock``)
while the ledger/keybox stay in ``state_dir``.
"""

from __future__ import annotations

import asyncio
import tempfile
import threading
from pathlib import Path
from typing import Any

from js.orind.daemon import OrinDaemon

_MAX_UNIX_PATH = 100


def derive_c2_appshell_application_handle(
    *,
    owner_key_hash: str,
    task_id: str,
    principal_owner: str,
    principal_session: str,
    principal_epoch: int,
    bundle_id: str,
    product_id: str = "js-work",
    profile: str = "work",
) -> str:
    """Derive one AppShell ApplicationHandle id for the explicit C2 harness.

    Production ``/intent`` still issues only File DirectoryHandle.  This helper
    mirrors that owner/session/epoch binding for Desktop tests only.
    """

    from js.orin.handles import derive_appshell_application_handle_id

    return derive_appshell_application_handle_id(
        installation_owner_hash=owner_key_hash,
        product_id=product_id,
        task_id=task_id,
        profile=profile,
        principal_owner=principal_owner,
        principal_session=principal_session,
        principal_epoch=principal_epoch,
        bundle_id=bundle_id,
    )


class TestOrind:
    """Real daemon on a temp socket; start/stop from sync test code."""

    def __init__(
        self,
        *,
        state_dir: Path,
        keybox_tier: str = "dev",
        socket_path: Path | None = None,
        policy_profile: str | None = None,
        shadow_mode: bool = False,
        canary_enabled: bool = True,
        responder_lock_l0: bool = False,
        patrol_record_only: bool = False,
        stage_b: bool = False,
        cell_build: bool = False,
        cell_net: bool = False,
        cell_secret: bool = False,
        cell_file: bool = False,
        cell_desktop: bool = False,
        cell_memory: bool = False,
        commit_membrane: bool = False,
        cell_identity_enforce: bool = False,
        c1_test_harness: bool = False,
        desktop_script_path: Path | None = None,
        membrane_fault_hook: Any = None,
        witness_public_keys: tuple[str, ...] = (),
        now_fn: Any = None,
    ) -> None:
        self._state_dir = state_dir
        requested = socket_path or (state_dir / "orin" / "orind.sock")
        if len(str(requested)) > _MAX_UNIX_PATH:
            short_dir = Path(tempfile.mkdtemp(prefix="orind-test-"))
            requested = short_dir / "orind.sock"
        self._socket_path = requested
        self._keybox_tier = keybox_tier
        self._policy_profile = policy_profile
        self._shadow_mode = shadow_mode
        self._canary_enabled = canary_enabled
        self._responder_lock_l0 = responder_lock_l0
        self._patrol_record_only = patrol_record_only
        self._stage_b = stage_b
        self._cell_build = cell_build
        self._cell_net = cell_net
        self._cell_secret = cell_secret
        self._cell_file = cell_file
        self._cell_desktop = cell_desktop
        self._cell_memory = cell_memory
        self._commit_membrane = commit_membrane
        self._cell_identity_enforce = cell_identity_enforce
        self._c1_test_harness = c1_test_harness
        self._desktop_script_path = desktop_script_path
        self._membrane_fault_hook = membrane_fault_hook
        self._witness_public_keys = witness_public_keys
        self._now_fn = now_fn
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._daemon: OrinDaemon | None = None
        self._startup_error: BaseException | None = None

    @property
    def socket_path(self) -> Path:
        return self._socket_path

    @property
    def daemon(self) -> OrinDaemon:
        assert self._daemon is not None, "TestOrind not started"
        return self._daemon

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._ready.clear()
        self._thread = threading.Thread(target=self._run, name="test-orind", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=10.0):
            raise RuntimeError("TestOrind failed to start (timeout)")
        if self._startup_error is not None:
            raise RuntimeError("TestOrind failed to start") from self._startup_error

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._start_daemon())
            self._ready.set()
            self._loop.run_forever()
        except BaseException as exc:  # noqa: BLE001 - surface to start()
            self._startup_error = exc
            self._ready.set()
        finally:
            self._loop.close()

    async def _start_daemon(self) -> None:
        kwargs: dict[str, Any] = {
            "state_dir": self._state_dir,
            "socket_path": self._socket_path,
            "orin_dir": self._state_dir / "orin",
            "keybox_tier": self._keybox_tier,
            "shadow_mode": self._shadow_mode,
            "canary_enabled": self._canary_enabled,
            "responder_lock_l0": self._responder_lock_l0,
            "patrol_record_only": self._patrol_record_only,
        }
        if self._policy_profile is not None:
            kwargs["policy_profile"] = self._policy_profile
        if self._now_fn is not None:
            kwargs["now_fn"] = self._now_fn
        kwargs["stage_b"] = self._stage_b
        kwargs["cell_build"] = self._cell_build
        if self._cell_net:
            kwargs["cell_net"] = True
        if self._cell_secret:
            kwargs["cell_secret"] = True
        if self._cell_file:
            kwargs["cell_file"] = True
        if self._cell_desktop:
            kwargs["cell_desktop"] = True
        if self._cell_memory:
            kwargs["cell_memory"] = True
        if self._commit_membrane:
            kwargs["commit_membrane"] = True
        if self._cell_identity_enforce:
            kwargs["cell_identity_enforce"] = True
        if self._c1_test_harness:
            kwargs["c1_test_harness"] = True
        if self._desktop_script_path is not None:
            kwargs["desktop_script_path"] = self._desktop_script_path
        if self._membrane_fault_hook is not None:
            kwargs["membrane_fault_hook"] = self._membrane_fault_hook
        if self._witness_public_keys:
            kwargs["witness_public_keys"] = self._witness_public_keys
        self._daemon = OrinDaemon(**kwargs)
        await self._daemon.start()
        self._ready.set()

    def stop(self) -> None:
        """Simulate ``kill orind``: stop serving, unlink the socket."""

        loop = self._loop
        daemon = self._daemon
        if loop is not None and not loop.is_closed() and daemon is not None:
            future = asyncio.run_coroutine_threadsafe(daemon.stop(), loop)
            try:
                future.result(timeout=10.0)
            except Exception:  # noqa: BLE001 - teardown must not raise in tests
                pass
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=10.0)

    def __enter__(self) -> TestOrind:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


class C1TestOrind(TestOrind):
    """Explicit WP-C1 identity harness; never used by product launchers."""

    def __init__(self, **kwargs: Any) -> None:
        kwargs["stage_b"] = True
        kwargs["cell_identity_enforce"] = True
        kwargs["c1_test_harness"] = True
        super().__init__(**kwargs)


class C2TestOrind(C1TestOrind):
    """Explicit WP-C2 Desktop Cell harness; never used by product launchers."""

    def __init__(self, **kwargs: Any) -> None:
        kwargs["cell_desktop"] = True
        super().__init__(**kwargs)

    @staticmethod
    def appshell_application_handle(
        *,
        owner_key_hash: str,
        task_id: str,
        principal_owner: str,
        principal_session: str,
        principal_epoch: int,
        bundle_id: str,
        product_id: str = "js-work",
        profile: str = "work",
    ) -> str:
        return derive_c2_appshell_application_handle(
            owner_key_hash=owner_key_hash,
            task_id=task_id,
            principal_owner=principal_owner,
            principal_session=principal_session,
            principal_epoch=principal_epoch,
            bundle_id=bundle_id,
            product_id=product_id,
            profile=profile,
        )


class C3TestOrind(C1TestOrind):
    """Explicit WP-C3 Memory Cell harness; never used by product launchers."""

    def __init__(self, **kwargs: Any) -> None:
        kwargs["cell_memory"] = True
        super().__init__(**kwargs)


__all__ = [
    "C1TestOrind",
    "C2TestOrind",
    "C3TestOrind",
    "TestOrind",
    "derive_c2_appshell_application_handle",
]
