from __future__ import annotations

import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class EchoReleaseProbeReport:
    passed: tuple[str, ...]
    failed: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.failed


def run_echo_release_probes() -> EchoReleaseProbeReport:
    passed: list[str] = []
    failed: list[str] = []

    probes = (
        ("echo_kernel_core", _kernel_core_probe),
        ("echo_recovery_probe", _recovery_probe),
        ("echo_local_sandbox_adapter", _local_sandbox_adapter_probe),
    )
    for name, probe in probes:
        if probe():
            passed.append(name)
        else:
            failed.append(f"{name}_failed")

    return EchoReleaseProbeReport(passed=tuple(passed), failed=tuple(failed))


def _kernel_core_probe() -> bool:
    try:
        from js.echo.core import pulse
        from js.echo.testing import new_fake_amber, new_fake_tide, new_fake_wheel
        from js.echo.types import InboundEvent, InboundKind, RequestEnvelope

        amber = new_fake_amber()
        wheel = new_fake_wheel()
        tide = new_fake_tide()
        new_amber, actions = pulse(
            1,
            [
                InboundEvent(
                    kind=InboundKind.REQUEST,
                    arrived_at=1,
                    request=RequestEnvelope(
                        request_id="release-gate",
                        channel="release",
                        payload_hash="sha256:release",
                    ),
                )
            ],
            amber,
            wheel,
            tide,
        )
        return new_amber is amber and len(actions) == 1
    except Exception:
        return False


def _recovery_probe() -> bool:
    try:
        from js.echo.ledger.journal import FileEchoLedger, verify_file

        with tempfile.TemporaryDirectory(prefix="echo-recovery-probe-") as directory:
            path = Path(directory) / "probe.jsonl"
            key = b"echo-release-gate-probe-key"
            ledger = FileEchoLedger(path, mac_key=key)
            ledger.append(
                record_type="release_probe",
                tenant_id="release-probe",
                run_id="probe",
                payload={"result": "pending"},
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write('{"seq":')
            recovered = FileEchoLedger(path, mac_key=key)
            return (
                verify_file(path, mac_key=key).ok
                and recovered.record_count == 1
                and recovered.records[0].record_type == "release_probe"
                and path.with_suffix(path.suffix + ".corrupt").exists()
            )
    except Exception:
        return False


def _local_sandbox_adapter_probe() -> bool:
    try:
        import asyncio

        from js.echo.os_sandbox import SandboxExecutor

        with tempfile.TemporaryDirectory(prefix="echo-sandbox-probe-") as directory:
            root = Path(directory)
            executor = SandboxExecutor(workspace=root, timeout=2.0, max_memory_mb=64)

            async def _probe() -> bool:
                allowed = await executor.execute(["/bin/echo", "echo-sandbox"], cwd=".")
                denied = await executor.execute(
                    ["/bin/cat", "/etc/hosts"],
                    cwd=".",
                    network_allowed=False,
                    fs_restricted=True,
                )
                return (
                    allowed.returncode == 0
                    and "echo-sandbox" in allowed.stdout
                    and denied.returncode != 0
                    and denied.killed
                )

            result: list[bool] = []
            failures: list[BaseException] = []

            def _runner() -> None:
                try:
                    result.append(asyncio.run(_probe()))
                except BaseException as exc:  # noqa: BLE001 - probe must fail closed
                    failures.append(exc)

            thread = threading.Thread(target=_runner, name="echo-sandbox-probe", daemon=True)
            thread.start()
            thread.join(timeout=6.0)
            return not thread.is_alive() and not failures and result == [True]
    except Exception:
        return False
