# Wasmtime skill sandbox prototype (P3-2)

Status: **prototype report only**. Not on the production path.
`js.skills.executor` continues to run Python and sandboxed shell only.

## What exists today

- Code skills: Python in-process or `SandboxExecutor` (Darwin `sandbox-exec` / Linux `bwrap`).
- Shell skills: the same OS sandbox as Echo tools.
- There is no Wasm compilation step and no `wasmtime` / `wasmtime-py` dependency.

## Why this is not default

1. Skill specs are prompt/Python/workflow/meta. A Wasm target would be a new skill type.
2. Hyperlight Wasm is documented as experimental; Wasmtime on macOS Host is extra binary + WASI policy work.
3. Default-on Wasm would expand the attack surface before a WASI capability model is reviewed.

## Prototype shape (if revisited)

- Opt-in skill type `wasm` with a signed `.wasm` artifact.
- Host embeds Wasmtime with a deny-default WASI preview: no ambient FS, no sockets, fuel/epoch interrupt.
- Echo still issues a single-use lease; the guest cannot talk to orind.
- Fail closed if the runtime is missing — never fall back to unsandboxed native code.

## Verdict

Keep Python/shell. Do not import this module from `js.skills.executor`.
`js.skills.wasmtime_sandbox.PRODUCTION_ENABLED` is `False`.
