# Unified execution contract

This contract removes the former ambiguity over who runs a model or tool and
which durable record is authoritative.

## One turn

1. An adapter calls `run_echo_turn()` with a `TurnRequest` and complete
   `RuntimeContext`.
2. `EchoRuntime` validates identity and attachments, performs deterministic
   admission, binds owner/run context, and creates `EchoTurnLoop`.
3. The loop builds the final messages and tool schema after context trimming.
4. A model step becomes `ModelEffect`. `EffectInterpreter` invokes the gated
   model adapter. Authorization binds the actual model, final messages, tool
   schema, attachments, owner, session, and run before the provider call; the
   result is finalized afterward.
5. A tool step becomes `ToolEffect`. The interpreter requests a signed,
   single-use lease and executes the registry handler only after lease
   consumption is durably recorded.
6. The result returns to the loop as an observation. The loop either emits the
   next effect or builds a terminal state.
7. Finalization records exactly one terminal outcome. Streaming text and
   thinking are provisional; `done` is sent only after successful finalization.

`FileEchoLedger` is the only durable runtime ledger. There is no second
session/inter-session journal and no conversion between competing state
models. Incomplete or uncertain irreversible effects enter manual review;
they are not described as rolled back and are not retried blindly.

## Concrete execution routes

- `EffectInterpreter` owns effect dispatch. Its gated model adapter is
  `JSAgent.authorized_model_chat`; its gated tool adapter is
  `ToolExecutor.execute_tool`.
- `EffectBridge` maps each authorized effect to the one Echo outbox before the
  operation starts and maps the receipt back into the turn state afterward.
- Idempotent effects may use an idempotent retry. Effects whose result can be
  probed use `probe_before_merge`. Irreversible or uncertain effects use
  `manual_confirmation_required`; Echo does not claim that they were rolled
  back.

## Required invariants

- Provider and registry handlers cannot be called naked in Echo mode.
- Product, owner, session, and run lineage can only be preserved or narrowed.
- Tool capabilities and resource budgets can only be narrowed by child work.
- Cancellation and disconnect must produce a non-success terminal outcome.
- Replay must reconstruct leases, outbox, receipts, and manual-review state.
- New entry points must reuse this contract rather than create another loop.
