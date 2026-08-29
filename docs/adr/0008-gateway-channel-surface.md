# ADR 0008: Gateway is a channel surface, not a runtime

## Status

Accepted for implementation. This ADR does **not** authorize a second turn
loop, does **not** flip `orin.enforce`, and does **not** claim Stage C is
complete.

## Context

JS Agent currently has one optional messaging integration
(`js/integrations/telegram_bot.py`) that already enters Echo through
`run_echo_turn`. OpenClaw and Hermes expose multi-channel gateways. Adding
channels without a host-owned surface would invite a second agent loop or
model-chosen routing.

Gateway traffic is untrusted inbound content. Isolation posture (ADR-adjacent
WP3) may warn or refuse those surfaces; it does not become a second runtime.

## Decision

1. **Surface, not a runtime.** `js/gateway/` adapters only receive, pair,
   construct an Echo turn, and send the reply. Model calls, tools, attachments,
   and side effects stay inside `run_echo_turn` / `execute_tool_effect`.
2. **Host configuration selects the route.** The model never chooses the
   destination bot, owner, or room. A binding table maps
   `(channel, peer_id) → (owner, bot_id, dm_scope)`.
   `dm_scope=main` shares one session per channel; `dm_scope=per-peer`
   isolates each sender.
3. **Fail-closed pairing.** Unpaired senders are discarded. Pairing uses a
   one-time code plus an allowlist. Discard events are rate-limited in logs.
4. **Default off.** `gateway.enabled=false`. Host cold start must not import
   `js.gateway` or start adapters. Enabling a channel still requires the WP3
   untrusted-surface gate (`warn` or `enforce`).
5. **Bots remain the conversation home.** Session mapping is
   channel peer → owner → bot/room. `product_id` stays `js-agent`. Gateway
   does not reuse Fleet.
6. **Inbound is always tainted.** Every gateway turn carries untrusted
   inbox/web taint. Taint only tightens or denies; it never authorizes.

## Consequences

- Telegram moves under `js/gateway/channels/` and keeps a facade at the old
  path. Webhook and Discord are additional adapters, not new runtimes.
- Outbound proactive push is a side effect and must consume a lease.
- `gateway.enabled=false` rolls the product back to “no messaging surface.”
