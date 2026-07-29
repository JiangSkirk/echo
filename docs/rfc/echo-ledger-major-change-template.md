# Echo Ledger Major-Change RFC Template

## Summary

Describe the protocol or behavior change in one paragraph.

## Affected Contracts

- RuntimeContext:
- PulseFrame:
- PolicyDecisionRecord:
- CapabilityLease:
- EffectOutbox / EffectReceipt:
- ModelPrivacyEnvelope:
- Context and memory provenance:

## Compatibility And Migration

List format migration, replay behavior, golden fixtures, artifact rollback,
and state snapshot restoration steps. Do not add a second runtime path.

## Security Review

Document policy effects, tenant isolation, prompt injection, secret handling,
sandbox constraints, irreversible effects, and audit requirements.

## Reliability And Performance

Document crash windows, idempotency, manual-review behavior, RPO/RTO, token
impact, first-token latency, append/replay/compaction SLOs, and soak evidence.

## Release Gate

List exact tests, benchmarks, SBOM/license evidence, and external reviews
required before merge or stable publication.
