"""Build Cell (WP7): shell/code execution outside the Echo process.

Runs model-generated commands inside :class:`js.echo.os_sandbox.SandboxExecutor`
— the SAME sandbox engine the in-process path used, never a rewrite — under
the stage-B defaults: no network, no real credentials, task-scoped working
directory, bounded output and wall time. Output is untrusted tool data.

The cell process holds no lease keys, no owner identity, and no database:
it executes what orind dispatches after its Gate/policy checks and nothing
else. Killing it stops exactly the build effect class; every other tool
keeps working (fail closed per class, not white screen).
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from js.echo.os_sandbox import SandboxExecutor
from js.orind.cells.base import CellBase

_MAX_OUTPUT_CHARS = 64 * 1024


def build_cell_private_staging(state_dir: Path) -> Path:
    """Cell-private build staging. Not ``workspace/.js-code``."""

    env = os.environ.get("ORIN_BUILD_WORKSPACE")
    if env:
        return Path(env)
    return Path(state_dir) / "orin" / "cell-private" / "build"


def _strip_credential_env() -> dict[str, str]:
    """Defense-in-depth: drop obvious credential carriers before exec."""

    blocked_prefixes = ("API_", "OPENAI", "ANTHROPIC", "AWS", "GOOGLE", "AZURE_")
    blocked_keys = {
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "SLACK_BOT_TOKEN",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    }
    return {
        key: value
        for key, value in os.environ.items()
        if not any(key.startswith(prefix) for prefix in blocked_prefixes)
        and key.upper() not in {k.upper() for k in blocked_keys}
    }


class BuildCell(CellBase):
    """``cell.build`` executor: sandboxed shell/code with no network."""

    def __init__(
        self,
        *,
        socket_path: Path,
        state_dir: Path,
        workspace: Path | None = None,
        timeout_s: float = 60.0,
        max_output_bytes: int = 256 * 1024,
    ) -> None:
        self._workspace = (
            workspace if workspace is not None else build_cell_private_staging(state_dir)
        )
        self._workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._timeout_s = timeout_s
        self._max_output_bytes = max_output_bytes
        self._executor = SandboxExecutor(
            workspace=self._workspace,
            timeout=timeout_s,
            max_output_bytes=max_output_bytes,
            strict_isolation=True,
        )
        super().__init__(
            cap="cell.build",
            socket_path=socket_path,
            state_dir=state_dir,
            handler=self.execute,
        )

    async def execute(self, permit: dict[str, Any]) -> dict[str, Any]:
        kind = str(permit.get("kind") or "")
        started = time.monotonic()
        if kind not in ("shell", "code"):
            return {"status": "FAILED", "error": f"unsupported build kind {kind!r}"}
        command: str | list[str]
        if kind == "code":
            code_text = str(permit.get("code") or "")
            if not code_text.strip():
                return {"status": "FAILED", "error": "empty code payload"}
            # Same wrapper shape the in-process CodeTool uses: direct argv.
            command = ["python3", "-c", code_text]
        else:
            raw_command: str | list[str] | None = permit.get("command")
            if raw_command is None:
                return {"status": "FAILED", "error": "build payload missing command"}
            command = raw_command
        cwd = str(permit.get("cwd") or ".")
        timeout_ms = int(permit.get("timeout_ms") or self._timeout_s * 1000)
        result = await self._executor.execute(
            command,
            cwd=cwd,
            env=_strip_credential_env(),
            timeout=min(timeout_ms / 1000.0, self._timeout_s),
            network_allowed=False,
            fs_restricted=True,
        )
        output_parts = [result.stdout]
        if result.stderr:
            output_parts.append(f"[stderr]\n{result.stderr}")
        if result.killed:
            output_parts.append("[Process was terminated (timeout or resource limit)]")
        text = "\n".join(part for part in output_parts if part)[:_MAX_OUTPUT_CHARS]
        public = {
            "output": text,
            "status": "COMMITTED" if result.returncode == 0 and not result.killed else "FAILED",
            "returncode": result.returncode,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "killed": result.killed,
        }
        permit_id = str(permit.get("permit_id") or permit.get("id") or "build")
        effect_hash = str(permit.get("canonical_effect_hash") or permit.get("hash") or "")
        return self.attach_signed_receipt(
            public,
            permit_id=permit_id,
            executor_id="cell.build",
            effect_hash=effect_hash or "sha256:" + "0" * 64,
            receipt_id="receipt:build:" + permit_id,
        )


def main() -> None:  # pragma: no cover - subprocess entry
    socket_path = os.environ.get("ORIN_CELLS_SOCKET")
    state_dir = os.environ.get("ORIN_STATE_DIR")
    if not socket_path or not state_dir:
        raise SystemExit("ORIN_CELLS_SOCKET and ORIN_STATE_DIR are required")
    cell = BuildCell(socket_path=Path(socket_path), state_dir=Path(state_dir))
    cell.start()
    strict_identity = os.environ.get("ORIN_CELL_IDENTITY_ENFORCE") == "1"
    try:
        while True:
            time.sleep(1 if strict_identity else 3600)
            if strict_identity and not cell.healthy():
                raise SystemExit("Build Cell identity session became unhealthy")
    except KeyboardInterrupt:
        pass
    finally:
        cell.stop()


if __name__ == "__main__":  # pragma: no cover
    main()


__all__ = ["BuildCell", "build_cell_private_staging"]
