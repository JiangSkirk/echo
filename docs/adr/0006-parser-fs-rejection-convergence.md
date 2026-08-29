# ADR 0006: parser vs `_fs_restricted_rejection` convergence

## Status

Proposed. Design-first. No implementation in this wave.

## Context

`js/security/parser.py` decides whether a shell command is allowed by AST
shape. `js/echo/os_sandbox.py` `_fs_restricted_rejection` (and related
argv scanners) decide whether a filesystem-restricted command may write
`.git` metadata or escape the workspace.

The two engines can disagree on boundary cases (quoted tokens, `git`
long options, interpreter `-c` snippets that mention `.git`). TECH_DEBT
#4 records this as architecture debt.

## Decision

1. Do **not** merge the engines in this wave.
2. Collect a shared corpus of boundary argv cases under
   `tests/security/` (parser allow/deny + sandbox deny) before any
   rewrite.
3. Target design: one **decision record** type
   `{engine, verdict, reason, argv, fs_restricted}` so a command that
   either engine rejects is rejected. The AST engine remains responsible
   for command shape; the FS engine remains responsible for path and
   `.git` plants.
4. Explicit duty split is acceptable if a single engine would hide
   sandbox-only constraints behind parser false-negatives.

## Consequences

- Until the corpus exists, both engines stay fail-closed independently.
- A later implementation PR must bump the quality rubric and must not
  weaken either current deny list.
