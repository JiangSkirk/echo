# Echo Final Replacement Report

## Verdict

- Echo is the default normal-use architecture.
- The old off/shadow architecture modes have been removed from the normal JS Agent configuration surface.
- Local engineering gates support running the JS Agent on Echo-only default.
- GitHub stable release remains blocked until external approvals are signed.
- Benchmark SHA-256: `9a7cca2896afd791b776a2c1d1e9181deeb00f951150fd0495e5a382bf3fc2f1`

## Safety

- 25-item local security matrix: `25/25`, ok=`True`.
- Echo blocks secret-bearing attachment/model payloads before provider execution.
- Model calls, stream calls, and tools are bound to Echo gates.
- Journal/outbox recovery is replayable and observable through health counters.
- Removed rollback values such as `JS_ECHO_ENGINE=off` and `JS_ECHO_ENGINE=shadow` fail closed.

## Compatibility

- `/api/chat`, regular `/ws`, streaming `/ws`, `JSAgent.run()`, and `JSAgent.chat_stream()` use the Echo-gated path by default.
- Thinking is surfaced only when the provider emits thinking content; otherwise the UI does not show a thinking panel.
- Tool execution uses persistent signed leases and keeps the existing tool-call behavior available through Echo.

## Performance

- Measurements use a deterministic local fake provider with no network LLM calls; latency does not include network or provider latency variance; cl100k tokenizer counts are not DeepSeek or provider billing data.
- api_full_agent: p95 median `32.279` ms across `5` independent groups (`50` measured requests per group).
- api_wrapper_only: p95 median `0.672` ms across `5` independent groups (`50` measured requests per group).
- ws_message_wrapper: p95 median `1.347` ms across `5` independent groups (`50` measured requests per group).
- ws_stream_wrapper: p95 median `1.605` ms across `5` independent groups (`50` measured requests per group).
- api_full_agent prompt token p95: Echo `1661.0`, limit `9000.0`, within_limit `True`, source `tokenizer`.
- Concurrency: `150/150` successful, 5xx `0`, crosstalk `0`, peak RSS `159.328` MB.
- Recovery: 10k replay `0.0945` s; compaction `31.289` ms.
- Corrected detached-baseline comparison: API p95 old `43.992` ms vs Echo `32.279` ms (`-26.625%`); prompt p95 old `8857.0` vs Echo `1661.0` tokenizer tokens (`81.246%` reduction).
- Five-run API p95 median: `32.279` ms; limit `45.0` ms; faster than detached old baseline `True`.

## JS Agent Work

- Work runs as the separate `js-work` product with owner-scoped workspace, state, session, and Echo filesystem roots.
- The Office profile includes deterministic packing-details, accessory-order, PDF/Word, and spreadsheet tools.
- `excel_precise_edit` applies bounded cell/style/layout operations under a single-use signed Echo lease.
- Precise editing never overwrites the source or an existing output, rejects dangerous formulas and unsupported OOXML features, and writes a hash-bound validation report.

## Replacement Boundary

- Normal use runs on Echo-only architecture.
- Removed rollout values such as `off` and `shadow` fail closed.
- The old shadow gateway and rollback helpers have been removed from the running code.

## Stable Release Blockers

- legal_fto_review_pending
- clean_room_reviewer_pending
- external_security_audit_missing
- redteam_report_missing

## Audit Source

See `docs/echo/ECHO_10_ROUND_AUDIT.md` for the latest local audit.
