"""P2-1 container_vm: file/build only, secrets stay on the host."""

from __future__ import annotations

from pathlib import Path

import pytest

from js.orin.container_vm import (
    FORBIDDEN_GUEST_BASENAMES,
    HOST_BROKER_ENV,
    HOST_MAC_FILE_ENV,
    HOST_ONLY_CELL_KINDS,
    VM_CELL_WHITELIST,
    ContainerBackend,
    ContainerVmError,
    FakeContainerBackend,
    GuestMount,
    apply_file_host_keybox_env,
    plan_guest_spec,
    production_sandbox_carrier_available,
    read_host_broker_mac,
    reject_forbidden_mounts,
    reset_container_backend,
    select_carrier,
    set_container_backend,
)
from js.orin.stage_c import StageCEvidence, stage_c_closeout_declaration
from js.orind.cells.container_vm import prepare_file_build_env


def test_whitelist_is_file_and_build_only() -> None:
    assert frozenset({"file", "build"}) == VM_CELL_WHITELIST
    assert {"desktop", "memory", "services", "secret", "net"} <= HOST_ONLY_CELL_KINDS


@pytest.mark.parametrize("kind", sorted(HOST_ONLY_CELL_KINDS))
def test_host_only_kinds_cannot_plan_a_guest(tmp_path: Path, kind: str) -> None:
    with pytest.raises(ContainerVmError, match="must stay on the host"):
        plan_guest_spec(
            kind,
            state_dir=tmp_path / "state",
            workspace=tmp_path / "ws",
            runtime_root=tmp_path / "rt",
            socket_path=tmp_path / "cells.sock",
        )


@pytest.mark.parametrize("kind", ["file", "build"])
def test_file_and_build_guest_omits_key_material(tmp_path: Path, kind: str) -> None:
    spec = plan_guest_spec(
        kind,
        state_dir=tmp_path / "state",
        workspace=tmp_path / "ws",
        runtime_root=tmp_path / "rt",
        socket_path=tmp_path / "cells.sock",
    )
    names = {mount.source.name for mount in spec.mounts}
    assert not (FORBIDDEN_GUEST_BASENAMES & names)
    assert spec.keybox_on_host is (kind == "file")
    sources = [str(mount.source) for mount in spec.mounts]
    assert all("keybox.key" not in item for item in sources)
    assert all("echo_tool_lease.key" not in item for item in sources)
    assert all("secrets.jsonl" not in item for item in sources)


def test_forbidden_mounts_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ContainerVmError, match="must not mount keybox.key"):
        reject_forbidden_mounts(
            [GuestMount(source=tmp_path / "orin" / "keybox.key", destination="/guest/keybox.key")]
        )
    with pytest.raises(ContainerVmError, match="echo_tool_lease.key"):
        reject_forbidden_mounts(
            [
                GuestMount(
                    source=tmp_path / "echo_tool_lease.key",
                    destination="/guest/echo_tool_lease.key",
                )
            ]
        )
    with pytest.raises(ContainerVmError, match="secrets.jsonl"):
        reject_forbidden_mounts(
            [
                GuestMount(
                    source=tmp_path / "orin" / "secrets.jsonl",
                    destination="/guest/orin/secrets.jsonl",
                )
            ]
        )


def test_probe_failure_selects_l1() -> None:
    class _Down(ContainerBackend):
        def available(self) -> bool:
            return False

    token = set_container_backend(_Down())
    try:
        assert select_carrier("file") == "l1"
        assert select_carrier("desktop") == "l1"
    finally:
        reset_container_backend(token)
    token = set_container_backend(FakeContainerBackend())
    try:
        assert select_carrier("file") == "container_vm"
        assert select_carrier("desktop") == "l1"
    finally:
        reset_container_backend(token)


def test_fake_backend_smokes_file_and_build(tmp_path: Path) -> None:
    fake = FakeContainerBackend()
    token = set_container_backend(fake)
    try:
        runtime = tmp_path / "rt"
        runtime.mkdir()
        env = prepare_file_build_env(
            "file",
            env={"ORIN_CELLS_SOCKET": str(tmp_path / "cells.sock")},
            state_dir=tmp_path / "state",
            workspace=tmp_path / "ws",
            runtime_root=runtime,
            socket_path=tmp_path / "cells.sock",
            mac_key=b"k" * 32,
            argv=["python", "-m", "js.orind.cells.file"],
        )
        assert env[HOST_BROKER_ENV] == "1"
        assert HOST_MAC_FILE_ENV in env
        assert fake.launches[0].kind == "file"
        build_env = prepare_file_build_env(
            "build",
            env={},
            state_dir=tmp_path / "state",
            workspace=tmp_path / "ws",
            runtime_root=runtime,
            socket_path=tmp_path / "cells.sock",
            mac_key=None,
            argv=["python", "-m", "js.orind.cells.build"],
        )
        assert HOST_BROKER_ENV not in build_env
        assert len(fake.launches) == 2
    finally:
        reset_container_backend(token)


def test_desktop_prepare_stays_l1_even_with_fake_backend(tmp_path: Path) -> None:
    fake = FakeContainerBackend()
    token = set_container_backend(fake)
    try:
        env = prepare_file_build_env(
            "desktop",
            env={"KEEP": "1"},
            state_dir=tmp_path / "state",
            workspace=tmp_path / "ws",
            runtime_root=tmp_path / "rt",
            socket_path=tmp_path / "cells.sock",
            mac_key=b"k" * 32,
            argv=["python", "-m", "js.orind.cells.desktop"],
        )
        assert env == {"KEEP": "1"}
        assert fake.launches == []
    finally:
        reset_container_backend(token)


def test_host_broker_mac_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "rt"
    runtime.mkdir()
    env = apply_file_host_keybox_env({}, runtime_root=runtime, mac_key=b"m" * 32)
    monkeypatch.setenv(HOST_BROKER_ENV, env[HOST_BROKER_ENV])
    monkeypatch.setenv(HOST_MAC_FILE_ENV, env[HOST_MAC_FILE_ENV])
    assert read_host_broker_mac() == b"m" * 32
    assert not Path(env[HOST_MAC_FILE_ENV]).exists()
    monkeypatch.delenv(HOST_BROKER_ENV, raising=False)
    monkeypatch.delenv(HOST_MAC_FILE_ENV, raising=False)
    assert read_host_broker_mac() is None


def test_carrier_bit_does_not_claim_stage_c() -> None:
    _ = production_sandbox_carrier_available()
    declaration = stage_c_closeout_declaration()
    assert declaration.verdict == "not_implemented"
    assert "Stage C is not implemented" in declaration.statement
    evidence = StageCEvidence.observed()
    assert evidence.official_tcc_packaging is False
    assert evidence.k156_8_real_model_e2e is False
    assert evidence.k156_9_independent_red_team is False


def test_spec_documents_container_vm_and_forbids_stage_c_claim() -> None:
    spec = Path("docs/security/orin/ORIN_STAGE_C_SPEC.md").read_text(encoding="utf-8")
    assert "container_vm" in spec
    assert "production_sandbox_carrier" in spec
    assert "不得宣称" in spec
    assert "阶段 C 已实施" in spec
    closeout = Path("docs/security/orin/ORIN_STAGE_C_CLOSEOUT.md").read_text(encoding="utf-8")
    assert "Stage C is not implemented" in closeout
    assert "container_vm" in closeout
