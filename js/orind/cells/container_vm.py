"""orind-facing Containerization spawn helper (P2-1 file/build only)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from js.orin.container_vm import (
    FORBIDDEN_GUEST_BASENAMES,
    HOST_ONLY_CELL_KINDS,
    VM_CELL_WHITELIST,
    ContainerVmError,
    FakeContainerBackend,
    GuestSpec,
    apply_file_host_keybox_env,
    launch_planned_cell,
    plan_guest_spec,
    select_carrier,
)

__all__ = [
    "FORBIDDEN_GUEST_BASENAMES",
    "HOST_ONLY_CELL_KINDS",
    "VM_CELL_WHITELIST",
    "ContainerVmError",
    "FakeContainerBackend",
    "GuestSpec",
    "apply_file_host_keybox_env",
    "launch_planned_cell",
    "plan_guest_spec",
    "prepare_file_build_env",
    "select_carrier",
]


def prepare_file_build_env(
    kind: str,
    *,
    env: Mapping[str, str],
    state_dir: Path,
    workspace: Path,
    runtime_root: Path | None,
    socket_path: Path,
    mac_key: bytes | None,
    argv: Sequence[str],
) -> dict[str, str]:
    """Plan a VM guest. On probe/policy failure return env unchanged (L1)."""

    updated = dict(env)
    try:
        spec = plan_guest_spec(
            kind,
            state_dir=state_dir,
            workspace=workspace,
            runtime_root=runtime_root,
            socket_path=socket_path,
        )
    except ContainerVmError:
        return updated
    if spec.carrier != "container_vm":
        return updated
    try:
        launch_planned_cell(spec, argv=argv, env=updated)
    except ContainerVmError:
        return updated
    if spec.keybox_on_host and runtime_root is not None and mac_key is not None:
        return apply_file_host_keybox_env(
            updated,
            runtime_root=runtime_root,
            mac_key=mac_key,
        )
    return updated
