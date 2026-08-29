"""ASGI routing controlled only by the parent AppShell principal."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse

from js.appshell.principal import (
    APPSHELL_SCOPE_MANAGED,
    APPSHELL_SCOPE_PRINCIPAL,
    APPSHELL_SESSION_COOKIE,
    AppShellEpochBindingV1,
    AppShellOperationLimitError,
    AppShellOperationV1,
    AppShellPrincipalV1,
    AppShellSessionConflictError,
    AppShellSessionStore,
    reset_current_appshell_epoch_binding,
    set_current_appshell_epoch_binding,
)
from js.utils.log import get_logger

logger = get_logger("js.appshell.routing")


@dataclass(eq=False)
class _WebSocketBinding:
    send: Any
    revoked: asyncio.Event
    accepted: bool = False
    close_sent: bool = False

    def revoke(self) -> None:
        self.revoked.set()

    async def send_close(self) -> bool:
        if self.accepted and not self.close_sent:
            await self.send({"type": "websocket.close", "code": 1012, "reason": "mode switched"})
            self.close_sent = True
            return True
        return False


class AppShellWebSocketRegistry:
    """Track sockets by parent session so a mode switch invalidates old WS use."""

    def __init__(self) -> None:
        self._bindings: dict[tuple[str, str], set[_WebSocketBinding]] = {}
        self._lock = asyncio.Lock()
        self.close_timeout_seconds = 1.0

    async def register(
        self,
        principal: AppShellPrincipalV1,
        send: Any,
    ) -> _WebSocketBinding:
        binding = _WebSocketBinding(send=send, revoked=asyncio.Event())
        key = (principal.session, principal.active_mode)
        async with self._lock:
            self._bindings.setdefault(key, set()).add(binding)
        return binding

    async def unregister(
        self,
        principal: AppShellPrincipalV1,
        binding: _WebSocketBinding,
    ) -> None:
        key = (principal.session, principal.active_mode)
        async with self._lock:
            values = self._bindings.get(key)
            if values is None:
                return
            values.discard(binding)
            if not values:
                self._bindings.pop(key, None)

    async def close_for_session(self, session: str, mode: str) -> dict[str, Any]:
        key = (session, mode)
        async with self._lock:
            bindings = tuple(self._bindings.get(key, ()))
            # Revocation is the authority boundary. Set every event while still
            # holding the registry lock, before any potentially failing I/O.
            for binding in bindings:
                binding.revoke()
        try:
            async with asyncio.timeout(self.close_timeout_seconds):
                results = await asyncio.gather(
                    *(binding.send_close() for binding in bindings),
                    return_exceptions=True,
                )
        except TimeoutError:
            return {
                "revoked": len(bindings),
                "closed": sum(binding.close_sent for binding in bindings),
                "errors": ["TimeoutError: WebSocket close deadline exceeded"],
                "timed_out": True,
            }
        closed = sum(result is True for result in results)
        errors = [
            f"{type(result).__name__}: {result}"
            for result in results
            if isinstance(result, BaseException)
        ]
        if not errors:
            async with self._lock:
                values = self._bindings.get(key)
                if values is not None:
                    values.difference_update(bindings)
                    if not values:
                        self._bindings.pop(key, None)
        return {
            "revoked": len(bindings),
            "closed": closed,
            "errors": errors,
        }


class AppShellEpochClosedError(RuntimeError):
    """The captured parent epoch is not accepting new child work."""


class AppShellEpochDrainTimeoutError(RuntimeError):
    """A revoked old-epoch request did not leave before the switch deadline."""


@dataclass(frozen=True)
class _RequestAdmission:
    operation: AppShellOperationV1

    @property
    def binding(self) -> AppShellEpochBindingV1:
        return self.operation.binding


class AppShellModeGate:
    """Serialize per-session epoch admission, revocation, drain, and mode CAS."""

    def __init__(
        self,
        store: AppShellSessionStore,
        *,
        drain_timeout_seconds: float = 2.0,
    ) -> None:
        self._store = store
        self._drain_timeout_seconds = drain_timeout_seconds
        self._condition = asyncio.Condition()
        self._switches: dict[str, AppShellEpochBindingV1] = {}

    async def admit(
        self,
        principal: AppShellPrincipalV1,
        *,
        operation_kind: str = "http",
    ) -> _RequestAdmission:
        binding = principal.epoch_binding()
        async with self._condition:
            try:
                operation = self._store.begin_operation(
                    binding,
                    operation_kind=operation_kind,
                )
            except PermissionError as exc:
                raise AppShellEpochClosedError("AppShell request epoch is closed or stale") from exc
            if binding.session in self._switches:
                self._store.release_operation(operation)
                raise AppShellEpochClosedError("AppShell request epoch is closed or stale")
            return _RequestAdmission(operation=operation)

    async def release(self, admission: _RequestAdmission) -> None:
        async with self._condition:
            self._store.release_operation(admission.operation)
            self._condition.notify_all()

    async def begin_switch(
        self,
        token: str,
        principal: AppShellPrincipalV1,
    ) -> AppShellEpochBindingV1:
        binding = principal.epoch_binding()
        async with self._condition:
            if binding.session in self._switches:
                raise AppShellSessionConflictError("AppShell session switch is already active")
            self._store.close_epoch(token, binding)
            self._switches[binding.session] = binding
            return binding

    async def wait_for_drain(self, binding: AppShellEpochBindingV1) -> None:
        deadline = asyncio.get_running_loop().time() + self._drain_timeout_seconds
        while self._store.active_operation_count(binding):
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise AppShellEpochDrainTimeoutError(
                    "Old AppShell epoch operations did not drain before the deadline"
                )
            async with self._condition:
                try:
                    await asyncio.wait_for(
                        self._condition.wait(),
                        timeout=min(remaining, 0.02),
                    )
                except TimeoutError:
                    pass

    async def commit_switch(
        self,
        token: str,
        binding: AppShellEpochBindingV1,
        *,
        to_mode: str,
        workspace: str | None,
    ) -> AppShellPrincipalV1:
        async with self._condition:
            if self._switches.get(binding.session) != binding:
                raise AppShellSessionConflictError("AppShell switch lease is no longer active")
            updated = self._store.update_mode(
                token,
                expected_owner=binding.owner,
                expected_session=binding.session,
                expected_from_mode=binding.active_mode,
                expected_workspace=binding.workspace,
                expected_epoch=binding.epoch,
                to_mode=cast("Any", to_mode),
                workspace=workspace,
            )
            self._switches.pop(binding.session, None)
            self._condition.notify_all()
            return updated

    async def abort_switch(self, binding: AppShellEpochBindingV1) -> None:
        async with self._condition:
            if self._switches.get(binding.session) != binding:
                return
            self._store.reopen_epoch(binding)
            self._switches.pop(binding.session, None)
            self._condition.notify_all()


class AppShellRoutingMiddleware:
    """Route root HTTP/WS surfaces using only ``principal.active_mode``."""

    _PARENT_PREFIX = "/api/appshell"
    _PARENT_EXACT = frozenset(
        {
            "/api/workspace/switch",
            # Child login/logout is intentionally unreachable in AppShell mode;
            # only /api/appshell/session owns the browser credential.
            "/api/auth/session",
            "/api/auth/logout",
        }
    )

    def __init__(
        self,
        app: Any,
        *,
        owner_app: Any,
        personal_app: Any,
        work_app: Any,
    ) -> None:
        self.app = app
        self.owner_app = owner_app
        self.personal_app = personal_app
        self.work_app = work_app

    def _principal(self, scope: dict[str, Any]) -> AppShellPrincipalV1 | None:
        token = HTTPConnection(scope).cookies.get(APPSHELL_SESSION_COOKIE)
        store = cast("AppShellSessionStore", self.owner_app.state.appshell_session_store)
        validator = cast(
            "Callable[[AppShellPrincipalV1], bool]",
            self.owner_app.state.appshell_principal_is_active,
        )
        principal = store.resolve(token)
        if principal is not None and not validator(principal):
            store.revoke(token)
            return None
        return principal

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        principal = self._principal(scope)
        routed_scope = dict(scope)
        state = dict(scope.get("state") or {})
        state[APPSHELL_SCOPE_MANAGED] = True
        state[APPSHELL_SCOPE_PRINCIPAL] = principal
        routed_scope["state"] = state

        path = str(scope.get("path") or "")
        if path.startswith(self._PARENT_PREFIX) or path in self._PARENT_EXACT:
            await self.app(routed_scope, receive, send)
            return

        target = (
            self.work_app if principal and principal.active_mode == "work" else self.personal_app
        )
        if target is self.work_app and not getattr(
            self.owner_app.state, "work_runtime_ready", False
        ):
            ensure = getattr(self.owner_app.state, "ensure_work_runtime", None)
            ready = False
            if callable(ensure):
                try:
                    await ensure()
                    ready = bool(getattr(self.owner_app.state, "work_runtime_ready", False))
                except Exception:
                    logger.exception("Work runtime bootstrap failed")
                    ready = False
            if not ready:
                if scope.get("type") == "http":
                    response = JSONResponse(
                        {
                            "detail": {
                                "code": "work_runtime_starting",
                                "message": "正在启动 Work",
                            }
                        },
                        status_code=503,
                    )
                    await response(routed_scope, receive, send)
                else:
                    await send(
                        {
                            "type": "websocket.close",
                            "code": 1013,
                            "reason": "正在启动 Work",
                        }
                    )
                return
        if principal is None:
            await target(routed_scope, receive, send)
            return

        gate: AppShellModeGate = self.owner_app.state.appshell_mode_gate
        try:
            admission = await gate.admit(
                principal,
                operation_kind=str(scope.get("type") or "request"),
            )
        except AppShellOperationLimitError:
            if scope.get("type") == "http":
                response = JSONResponse(
                    {"detail": {"code": "appshell_operation_limit"}},
                    status_code=429,
                )
                await response(routed_scope, receive, send)
            else:
                await send(
                    {
                        "type": "websocket.close",
                        "code": 1013,
                        "reason": "mode operation capacity",
                    }
                )
            return
        except AppShellEpochClosedError:
            if scope.get("type") == "http":
                response = JSONResponse(
                    {"detail": {"code": "appshell_epoch_closed"}},
                    status_code=409,
                )
                await response(routed_scope, receive, send)
            else:
                await send(
                    {
                        "type": "websocket.close",
                        "code": 1012,
                        "reason": "mode epoch closed",
                    }
                )
            return

        binding_token = set_current_appshell_epoch_binding(principal.epoch_binding())
        if scope.get("type") == "http":
            try:
                await target(routed_scope, receive, send)
            finally:
                await gate.release(admission)
                reset_current_appshell_epoch_binding(binding_token)
            return

        registry: AppShellWebSocketRegistry = self.owner_app.state.appshell_ws_registry
        binding = await registry.register(principal, send)

        async def routed_receive() -> Any:
            inbound = asyncio.create_task(receive())
            revoked = asyncio.create_task(binding.revoked.wait())
            done, pending = await asyncio.wait(
                {inbound, revoked},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            if revoked in done and binding.revoked.is_set():
                if not inbound.done():
                    inbound.cancel()
                return {"type": "websocket.disconnect", "code": 1012}
            return inbound.result()

        async def routed_send(message: dict[str, Any]) -> None:
            message_type = message.get("type")
            if message_type == "websocket.accept":
                binding.accepted = True
            if message_type == "websocket.close":
                if binding.close_sent:
                    return
                binding.close_sent = True
            if binding.revoked.is_set() and message_type == "websocket.send":
                return
            await send(message)

        try:
            await target(routed_scope, routed_receive, routed_send)
        finally:
            await registry.unregister(principal, binding)
            await gate.release(admission)
            reset_current_appshell_epoch_binding(binding_token)
