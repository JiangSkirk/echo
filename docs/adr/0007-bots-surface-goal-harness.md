# ADR 0007: Bots surface + goal harness

## Status

Accepted for implementation. This ADR does **not** declare Orin Stage C
complete, does **not** claim Echo RCE is closed, and does **not** authorize
`--orin-enforce`.

## Context

JS Agent already has a Personal host, a Work child process (`product_id=js-work`),
and a one-shot Fleet cluster. None of those is a persistent named bot with
private memory, a visible group room, or a goal contract that outlives a
single Echo turn.

Users want a GrokBot / Manus-shaped surface: named bots that understand their
own job, isolated private context, WeChat-style group bubbles, and
clarify-then-execute work that stops on acceptance or budget — not when the
model stops calling tools.

## Decision

1. **Surface, not a third process.** Bots is a first-class top-bar segment
   (`Personal | Work | Bots`) on the Personal host. `product_id` stays
   `js-agent`. `body.dataset.surface = 'bots'`. Work continues to hide the
   surface. AppShell mode is unchanged.

2. **Echo remains the only turn runtime.** Every model call, tool, room
   create, inter-bot ping, and clarification path enters through
   `run_echo_turn` / `execute_tool_effect`. Direct provider or registry
   handler calls are forbidden. Fleet / `fleet_collaborate` stays the
   one-shot cluster and remains `disabled-in-enforce`. Bots does not reuse
   Fleet as the production path.

3. **Persistence lives in `js/bots/`.** Owner isolation is
   `(owner_key_hash, product_id)` on every read and write. Draft bots
   cannot join rooms. Private memory is `bot:{id}:private`. Room transcript
   is `room:{id}`. Inter-bot sync is the shared transcript plus an authorized
   brief — never another bot's private memory.

4. **Identity is a user-editable SOUL.** Name → `BotIdentityCompiler` →
   awakening Echo turn (`disable_tools` is allowed only for this one-shot)
   writes a draft SOUL. The user edits and saves; only then is the bot
   `active`. Later turns inject the frozen SOUL into the stable system
   prefix. Editing SOUL starts a new prefix; it does not rewrite history.

5. **Manus-style harness is Bots-only.** Clarify (2–5 questions) →
   `GoalContract` → Execute in-room → Verify against success criteria.
   Clarify **keeps the same tools schema** as execute; side effects are
   lease-denied (`ask_user` only). “Never stop until the goal” is an outer
   `GoalRun` loop with `BudgetClock`, lease, cancel, and verify — not an
   infinite loop. Leaving the page pauses; v1 does not continue in the
   background.

6. **Prefix cache is a product requirement.** Token-level hit rate is
   `cache_read / (uncached_input + cache_read + cache_write)` per
   `(bot, prefix_id)`, `usage_source=provider_actual`, after warmup,
   excluding the first write and the first turn after TTL expiry. Target
   ≥96%. Do not use `cached_tokens / prompt_tokens`.

7. **Usage ledger is authoritative only when the provider reports usage.**
   Exclusive buckets: `uncached_input`, `cache_read`, `cache_write`,
   `output`, `reasoning`. Never `max(provider, local estimate)` into the
   ledger. Internal vs billed bucket error ≤2% on `provider_actual` calls.

8. **Orin is tightened, not “done”.** Reserved taint bits 13–15 become
   `BOT_PEER`, `BOT_SOUL`, `ROOM_SHARED`. They only tighten or deny; they
   never authorize. Echo cannot issue Intent or mint `BotHandle` /
   `RoomHandle`. Closed effect classes `bot.room.create`,
   `bot.message.send`, `bot.soul.write` require sealed handles. Destinations
   are never free-text names. v1 maps room / SOUL / private memory onto
   existing `cell.memory` (`personal` / `work` only). No `cell.bots`.
   `UNKNOWN_COMMIT` reconciles; it does not blind-replay. Production stays
   Echo-ambient; `orin.enforce` remains default false.

## Consequences

- A new `bots.db` product-state file is WAL-checkpointed with the rest of
  `PRODUCT_STATE_DB_NAMES`.
- Adaptive per-query tool-schema trimming is forbidden on the Bots surface
  for the life of a `GoalRun` (and should be frozen for the bot's prefix).
- Volatile memory, date, and run_id leave the system message on Bots and
  sit in a trailing untrusted user block.
- Quality labels may stamp `js/bots/` against the existing rubric. This ADR
  is not a Stage C closeout and must not be cited as one.
