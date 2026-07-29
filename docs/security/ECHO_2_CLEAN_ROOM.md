# Echo Clean-Room Boundary

Status: INTERNAL_ENGINEERING_COMPLETE_EXTERNAL_REVIEW_REQUIRED

Echo's runtime, state model, execution contract, safety ledger, tool lease,
tests, prompts, and documentation are maintained in this repository. Public
research is used only for abstract engineering principles. Project-specific
source, prompts, class hierarchies, API shapes, sample traces, and benchmark
fixtures must not be copied.

## Review Scope

- `js/echo/`: runtime, effects, context, sandbox, ledger, and recovery.
- `js/agent/`: thin product behavior implemented through Echo effects.
- `js/models/` and `js/tools/`: provider and registry adapters that must fail
  closed without Echo authorization.
- `js/web/` and `js_work/`: product adapters and owner/session boundaries.
- `tests/echo/`, `tests/work/`, and Echo smoke/benchmark scripts.
- `ORIGIN_LEDGER.md`, `THIRD_PARTY_NOTICES.md`, SBOM, and license scan.

## Avoidance Rules

Echo does not expose another project's identifying agent-runtime API. In
particular, contributors must not introduce graph-builder APIs, agent/runner
pair APIs, action-observation event-stream clones, copied prompt templates, or
lookalike workflow decorators from surveyed projects. MCP is used only through
the explicit controlled connector boundary.

`verify_echo_ip_boundary()` checks obvious naming and provenance drift. It is
an internal engineering gate, not a legal opinion.

## Stable Boundary

SBOM and local license scanning can be generated internally. GitHub stable
release still requires real independent FTO, clean-room, security-audit, and
red-team sign-off in their pending review files.

