# ADR 0005: Echo 2.x pulse kernel unification (shadow first)

## Status

Proposed. Design-first. This ADR does not change the production authority path.

## Context

Production turns already go through `EchoRuntime` → `EchoTurnLoop` →
`EffectInterpreter` → `LeaseAuthority` / `EchoSafetyService`. The
`pulse()` kernel (`js/echo/core.py`) still stops at T5 admission: it
observes backpressure and writes Amber audit nodes, but it does not emit
`Exec` / `CommitFrame` for real model or tool side effects.

`spi.Sandbox` is an in-memory T7 fixture. Real isolation is
`js/echo/os_sandbox.py`. Two tracks make audits easy to misread.

## Decision

1. Production authority stays `EchoRuntime` + `EchoSafetyService` +
   `LeaseAuthority` until a later major version flips the switch.
2. Phase 1 (this wave and the next): **shadow mode**. `pulse()` continues
   to observe every admitted turn. A shadow driver may record the
   would-be `Exec`/`CommitFrame` and assert equality with the live
   lease/outbox path. Shadow mismatch is a metric, not a bypass.
3. Phase 2 (future major): wire `Exec` from lease consume to a pulse
   outbound driver and collapse `spi.Sandbox` onto `os_sandbox`. That
   cutover requires its own RFC, compatibility fixtures, and a rubric
   bump. It is out of scope for 2026.09.1.

## Consequences

- Auditors must not treat Amber overwrite counters or pulse snapshots as
  durable receipts.
- Shadow mode can land without changing `echo_engine=on` semantics.
- TECH_DEBT keeps the dual-track item until Phase 2 ships.
