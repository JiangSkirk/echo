"""Apple Containerization carrier for file/build cells (P2-1).

Not Stage C. desktop/secret/memory/net stay on the host. Probe failure
falls back to L1 (Darwin sandbox-exec). Tests may inject a fake backend.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping, Sequence
from contextvars import ContextVar, Token
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from js.orin.echo_os import echo_minimal_os_carrier_available

CarrierName = Literal["container_vm", "l1"]

VM_CELL_WHITELIST: Final[frozenset[str]] = frozenset({"file", "build"})
HOST_ONLY_CELL_KINDS: Final[frozenset[str]] = frozenset(
    {"desktop", "memory", "services", "secret", "net"}
)
FORBIDDEN_GUEST_BASENAMES: Final[frozenset[str]] = frozenset(
    {
        "keybox.key",
        "echo_tool_lease.key",
        "secrets.jsonl",
    }
)
HOST_BROKER_ENV: Final[str] = "ORIN_KEYBOX_ON_HOST"
HOST_MAC_FILE_ENV: Final[str] = "ORIN_CELL_MAC_FILE"
CONTAINER_CLI_NAMES: Final[tuple[str, ...]] = ("container",)


class ContainerVmError(ValueError):
    """Cell kind or mount is not allowed in a guest VM."""


@dataclass(frozen=True, slots=True)
class GuestMount:
    source: Path
    destination: str
    read_only: bool = False


@dataclass(frozen=True, slots=True)
class GuestSpec:
    kind: str
    carrier: CarrierName
    mounts: tuple[GuestMount, ...]
    socket_path: Path
    keybox_on_host: bool


class ContainerBackend:
    """Spawn a guest. Real CLI or a test fake."""

    def available(self) -> bool:
        return False

    def launch(self, spec: GuestSpec, *, argv: Sequence[str], env: Mapping[str, str]) -> None:
        raise ContainerVmError("container backend is not available")


class FakeContainerBackend(ContainerBackend):
    """In-process backend for whitelist and mount tests. Never execs a VM."""

    def __init__(self) -> None:
        self.launches: list[GuestSpec] = []

    def available(self) -> bool:
        return True

    def launch(self, spec: GuestSpec, *, argv: Sequence[str], env: Mapping[str, str]) -> None:
        del argv, env
        reject_forbidden_mounts(spec.mounts)
        if spec.kind not in VM_CELL_WHITELIST:
            raise ContainerVmError(f"{spec.kind} is not allowed in container_vm")
        self.launches.append(spec)


class CliContainerBackend(ContainerBackend):
    def available(self) -> bool:
        return container_cli_available()

    def launch(self, spec: GuestSpec, *, argv: Sequence[str], env: Mapping[str, str]) -> None:
        del argv, env
        if not self.available():
            raise ContainerVmError("container CLI is not available")
        reject_forbidden_mounts(spec.mounts)
        if spec.kind not in VM_CELL_WHITELIST:
            raise ContainerVmError(f"{spec.kind} is not allowed in container_vm")
        raise ContainerVmError("container CLI launch is not wired; falling back to L1")


_backend: ContextVar[ContainerBackend | None] = ContextVar(
    "orin_container_vm_backend",
    default=None,
)


def container_cli_available() -> bool:
    return any(shutil.which(name) is not None for name in CONTAINER_CLI_NAMES)


def current_container_backend() -> ContainerBackend:
    injected = _backend.get()
    if injected is not None:
        return injected
    return CliContainerBackend()


def set_container_backend(backend: ContainerBackend | None) -> Token[ContainerBackend | None]:
    return _backend.set(backend)


def reset_container_backend(token: Token[ContainerBackend | None]) -> None:
    _backend.reset(token)


def production_sandbox_carrier_available() -> bool:
    """§2.4: container_vm preferred; L1 Darwin sandbox-exec is the fallback."""

    return current_container_backend().available() or echo_minimal_os_carrier_available()


def select_carrier(kind: str) -> CarrierName:
    if kind not in VM_CELL_WHITELIST:
        return "l1"
    if current_container_backend().available():
        return "container_vm"
    return "l1"


def reject_forbidden_mounts(mounts: Sequence[GuestMount]) -> None:
    for mount in mounts:
        path = Path(mount.source)
        if path.name in FORBIDDEN_GUEST_BASENAMES:
            raise ContainerVmError(f"guest must not mount {path.name}")
        destination = mount.destination.replace("\\", "/").rstrip("/")
        if any(destination.endswith(name) for name in FORBIDDEN_GUEST_BASENAMES):
            raise ContainerVmError(f"guest must not mount {destination}")


def plan_guest_spec(
    kind: str,
    *,
    state_dir: Path,
    workspace: Path,
    runtime_root: Path | None,
    socket_path: Path,
) -> GuestSpec:
    if kind in HOST_ONLY_CELL_KINDS or kind not in VM_CELL_WHITELIST:
        raise ContainerVmError(f"{kind} must stay on the host")
    carrier = select_carrier(kind)
    mounts: list[GuestMount] = [
        GuestMount(source=workspace, destination="/guest/workspace"),
        GuestMount(source=socket_path, destination="/guest/cells.sock"),
    ]
    if runtime_root is not None:
        mounts.append(GuestMount(source=runtime_root, destination="/guest/runtime"))
    reject_forbidden_mounts(mounts)
    _assert_state_dir_secrets_not_mounted(state_dir, mounts)
    return GuestSpec(
        kind=kind,
        carrier=carrier,
        mounts=tuple(mounts),
        socket_path=socket_path,
        keybox_on_host=kind == "file",
    )


def _assert_state_dir_secrets_not_mounted(state_dir: Path, mounts: Sequence[GuestMount]) -> None:
    secrets = (
        state_dir / "orin" / "keybox.key",
        state_dir / "echo_tool_lease.key",
        state_dir / "orin" / "secrets.jsonl",
        state_dir / "orin",
    )
    mounted = {mount.source.resolve() for mount in mounts}
    for secret in secrets:
        try:
            resolved = secret.resolve()
        except OSError:
            continue
        if resolved in mounted:
            raise ContainerVmError(f"guest must not mount {secret}")


def write_host_broker_mac(runtime_root: Path, mac_key: bytes) -> Path:
    """One-shot MAC copy under the cell runtime. Not production keybox.key."""

    path = runtime_root / "mac.once"
    path.write_bytes(mac_key)
    os.chmod(path, 0o600)
    return path


def read_host_broker_mac() -> bytes | None:
    """File cell in a VM reads the host-issued MAC; KeyBox stays on the host."""

    if os.environ.get(HOST_BROKER_ENV) != "1":
        return None
    raw = os.environ.get(HOST_MAC_FILE_ENV, "")
    if not raw:
        raise RuntimeError("ORIN_CELL_MAC_FILE is required when KeyBox stays on the host")
    path = Path(raw)
    key = path.read_bytes()
    try:
        path.unlink()
    except OSError:
        pass
    if len(key) != 32:
        raise RuntimeError("host broker MAC must be 32 bytes")
    return key


def apply_file_host_keybox_env(
    env: dict[str, str],
    *,
    runtime_root: Path,
    mac_key: bytes,
) -> dict[str, str]:
    mac_file = write_host_broker_mac(runtime_root, mac_key)
    updated = dict(env)
    updated[HOST_BROKER_ENV] = "1"
    updated[HOST_MAC_FILE_ENV] = str(mac_file)
    return updated


def launch_planned_cell(
    spec: GuestSpec,
    *,
    argv: Sequence[str],
    env: Mapping[str, str],
) -> None:
    """Attempt a VM launch. Callers must fall back to L1 on ContainerVmError."""

    if spec.carrier != "container_vm":
        raise ContainerVmError("carrier is L1")
    current_container_backend().launch(spec, argv=argv, env=env)
