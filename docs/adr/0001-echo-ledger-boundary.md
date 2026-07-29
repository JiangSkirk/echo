# ADR 0001: Echo Ledger Boundary

## Status

Accepted.

## Context

JS Agent needs one durable authority for model authorization, tool leases,
outbox state, receipts, recovery, and release health. Parallel ledgers or
runtime switches create ambiguous ownership and unsafe recovery behavior.

## Decision

`js/echo/ledger/` is the only persistent safety ledger implementation. All
normal requests enter `EchoRuntime`; model and tool side effects pass through
`EffectInterpreter`, and every tool invocation consumes an Echo capability
lease before its handler starts.

The public status surface is `echo` plus `echo_ledger`. There is no alternate
runtime mode. Rollback uses a previously built artifact and a verified ledger
snapshot rather than a second implementation in the package.

Journal record-shape, MAC/hash, permit, outbox, receipt, compaction, and replay
changes require an RFC and compatibility fixtures. External legal and security
approval remains a release gate, not a claim made by this ADR.

## Consequences

- One runtime and one ledger own execution and recovery.
- Provider and registry adapters cannot be public entrypoints.
- Unknown irreversible effects enter manual review instead of automatic retry.
- Product variants such as Work share Echo code but use separate settings,
  workspace, state, owner, and session scopes.
