# ADR 0010: Echo two-tier phylogeny

## Status

Accepted.

Product tree: [titan-agent](https://github.com/JiangSkirk/titan-agent)
(`echo_core.phylogeny`).

## Context

Unattended self-writing skills and automatic self-learning amplify injection.
Widening (new tools, skills, policy, code) must not auto-commit.

## Decision

Evolution polarity is `tighten` / `note` / `widen`:

- `tighten` and `note` (USER_TURN-only taint) may auto-commit. They never
  grant new power.
- `widen` never auto-commits. It requires owner bind + eval gate + guardian
  stamp.
- Eval gate and rollback have **no off switch**.
- Constitution prefixes (`echo_core/capability`, `echo_core/ledger`,
  `orin_guard/`, `prompts/stable/`) are not evolvable.
- `pulse()` remains observe-only. Phylogeny runs after a turn reaches
  terminal state, never inside Exec.

## Consequences

- Two-tier autonomy without unattended widening.
- Orin policy lattice remains the veto on policy-shaped payloads.
