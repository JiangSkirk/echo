# ADR 0002: AppShell Personal/Work Dual Identity

## Status

Accepted for v1 design freeze (implementation starts as a thin switch protocol).

## Context

Users want one desktop product surface similar to a GPT + Codex style merge:
Personal remains an all-purpose assistant; Work remains a professional office
agent. Sharing a shell must not merge memory, workspace, leases, ledgers,
skills, or caches.

Today the repository still runs two CLIs/ports (`js`, `js-work`) that reuse the
same web assets. Capability policy is enforced in Python feature flags and HTTP
403s; navigation historically advertised Work-unavailable tabs.

## Decision

### Shared whitelist (global layer only)

Allowed to share across Personal and Work:

- root identity / device list / contact base identity
- UI language, timezone, and chrome preferences
- credential *references* (not raw API key material)
- user-selected relay configuration references

### Never shared by default

Business text, embeddings, sessions, runs, leases, budgets, ledgers,
workspaces, skills databases, and UI/runtime caches remain product-partitioned.

Cross-domain reads require an explicit, TTL-bound, revocable, audited
`SharedMemoryView`. Direct database sharing is forbidden.

### Switch state machine

Every Personal ↔ Work switch MUST execute, in order:

1. `cancel_streams` — cancel active runs/streams for the departing product
2. `invalidate_leases` — revoke or abandon outstanding leases/session tokens
3. `clear_ui_cache` — drop client transient caches for the departing product
4. `rebind_context` — load the target product capability manifest and reconnect

Failure at any step fail-closes the switch; the UI stays on the previous
product identity.

### v1 non-goals

- Merging Personal and Work into one process or one `state_dir`
- Cross-domain direct DB reads
- Friend/Agent collaboration, iPhone remote writes, L3/L4 automation
- Official relay or public discovery

Personal keeps the full capability surface. Work keeps the professional
allowlist (office/safe/execute profiles, skills/evolution/plugins/daemon off).

## Consequences

- Capability manifests (`/api/capabilities`) are the UI/API authority for tabs.
- AppShell switch protocol is product-aware and Echo-bound.
- Digest-surface changes that touch runtime require a fresh release evidence root.
- External FTO, clean-room, security audit, and red-team remain external_pending.
