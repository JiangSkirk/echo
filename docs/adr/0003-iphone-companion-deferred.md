# ADR 0003: iPhone Companion v1 — deferred until AppShell Phase B exit

## Status

Deferred. Design freeze remains
[architecture-research/sections/28_iphone_companion_v1.md](../architecture-research/sections/28_iphone_companion_v1.md).

## Decision

Do not implement MobileGateway, pairing listener, or SwiftUI client until:

1. Phase A maintenance (M1–M5) has a fresh digest-bound evidence root.
2. Phase B AppShell Personal|Work switch is browser-verified with zero crosstalk.
3. User authorizes Apple signing / device pairing work explicitly.

## Non-goals (unchanged)

No official relay, APNs, public ports, friend discovery, or L3/L4 from phone.
