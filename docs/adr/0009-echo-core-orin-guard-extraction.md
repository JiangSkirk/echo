# ADR 0009: echo-core / orin-guard extraction

## Status

Accepted.

Product tree: [titan-agent](https://github.com/JiangSkirk/titan-agent)
(`packages/echo-core`, `packages/orin-proto`, `packages/orin-guard`).

## Context

JS Agent's Echo runtime and Orin gatekeeper were bound inside the `js`
package. Downstream consumers could not take the kernel without the Host.
Echo imported Orin taint/sinks; Orin imported Echo leases/sandbox — a
bidirectional cycle that blocked packaging.

## Decision

1. Three workspace packages: `echo-core` (Echo 3.0), `orin-guard` (Orin 2.0),
   `orin-proto` (orin/v2 frames, no secrets).
2. Neutral taint/sink/lease vocabulary lives in `echo-core`. Policy stays in
   `orin-guard`. Echo proposes; a Host-wired `GuardianSPI` stamps. echo-core
   never imports orin-guard.
3. `js.echo` and `js.orin` in titan-agent are Host shims.
4. Import firewall forbids `import js` inside the three packages.

## Consequences

- js-agent is a downstream consumer.
- `pip install echo-core` from PyPI is a later step. Today: path-install from
  titan-agent.
- Stage C still must not be claimed until the process-split conjunction is
  observed.
