# ADR 0004: Layered memory + Friends L1/L2

## Status

- **Layered memory (Entity/Claim/Episode/Revision dual-write):** Accepted — Phase A+B in progress.
- **Friends / A2A L1/L2:** Deferred.
- **iPhone Companion:** Deferred (see ADR 0003).

## Decision

### Layered memory (now)

AppShell Personal/Work isolation is internal-ready, so layered memory may proceed
as a **side-car** beside legacy `working` / `episodic` / `semantic` tables:

- New tables: `mem_entities`, `mem_claims`, `mem_relations`, `mem_episodes`,
  `mem_tombstones` (see `js/memory/layered/`).
- Legacy semantic rows remain **authoritative**.
- `MemoryConfig.layered_memory_dual_write` (default on): best-effort dual-write;
  failures must not roll back legacy success.
- `MemoryConfig.layered_memory_retrieve` (default off): claim merge into
  `get_context_string` is opt-in so prompt injection stays unchanged.
- Claim conflicts forbid last-write-wins; implicit conflicts → `disputed`;
  explicit user/manual corrections → `superseded` + new `active`.
- Soft-retire via tombstone on the new path; no SharedMemoryView yet.

Out of scope for this phase: Procedure layer, reversible-compression UX,
migration cutover / DROP of legacy tables, cross-product SharedMemoryView.

### Friends / A2A (still deferred)

Friends / A2A starts at L1/L2 only, with a protocol distinct from iPhone Host
pairing QR. Public discovery and L3/L4 require external security review.

## References

- [architecture-research/sections/15-19_memory_model.md](../architecture-research/sections/15-19_memory_model.md)
- [architecture-research/sections/23-27_roadmap_next.md](../architecture-research/sections/23-27_roadmap_next.md)
- [docs/adr/0002-appshell-personal-work.md](0002-appshell-personal-work.md)
- [docs/adr/0003-iphone-companion-deferred.md](0003-iphone-companion-deferred.md)
