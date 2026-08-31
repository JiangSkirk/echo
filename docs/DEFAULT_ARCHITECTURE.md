# Default architecture

JS Agent and JS Agent Work use Echo as their only normal runtime architecture.
`JS_ECHO_ENGINE` may be unset or set to `on`; historical values such as `off`
and `shadow` are rejected during configuration validation.

The normal turn path is:

1. A product adapter builds a complete `RuntimeContext` containing product,
   channel, owner, session, run, role, profile, capabilities, workspace, and
   state directory.
2. `run_echo_turn()` submits an immutable `TurnRequest` to `EchoRuntime`.
3. `EchoRuntime` validates attachments, applies deterministic admission, binds
   tenant context, and starts `EchoTurnLoop`.
4. `EchoTurnLoop` emits model and tool effects. `EffectInterpreter` is the only
   production adapter allowed to execute those effects.
5. Model calls pass the Echo model gate before the provider and are finalized
   afterward. Tool calls require a signed, single-use capability lease.
6. `EchoSafetyService` and `FileEchoLedger` record authorization, outbox,
   receipt, recovery, and manual-review state.

`/api/status` reports the Echo runtime and Echo ledger health. A healthy normal
state is `architecture_state=primary_healthy`; the service does not expose a
selectable legacy runtime.

Operational rollback uses a previously built application artifact together
with a verified ledger snapshot. The old runtime is not kept inside the normal
package as an environment-variable fallback.

