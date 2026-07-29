# Echo architecture

Echo owns one complete agent turn from admission through durable completion.
The design keeps deterministic decisions separate from side effects while
making the execution contract explicit.

## Runtime components

- `EchoRuntime` is the only authoritative turn boundary. It validates identity
  and attachments, applies admission control, binds context, and serializes a
  session through the lane executor when configured.
- `EchoPulseRuntime` performs small deterministic admission transitions. It
  does not call models, tools, files, or the network.
- `EchoTurnLoop` owns conversation state, context trimming, model/tool rounds,
  cancellation checkpoints, and final state construction.
- `EffectInterpreter` is the sole production side-effect adapter. It converts
  model and tool effects into gated calls under a bound `RuntimeContext`.
- `EchoSafetyService`, `ScopeGate`, and `FileEchoLedger` authorize the final
  provider payload and persist a MAC/hash-chained lifecycle, outbox, receipt,
  recovery, and manual-review state.
- `CapabilityLease` binds a tool call to product, owner, session, run, tool,
  arguments, file/network grants, budget, nonce, and signature. Consumption is
  recorded before the handler starts.
- Context trimming and compression reduce the provider payload. Token evidence
  must identify whether it came from a provider, tokenizer, or estimate.
- The OS sandbox applies bounded time, output, process, filesystem, and network
  rules. Missing required isolation fails closed.

## Extension rules

New channels build `TurnRequest` objects instead of implementing another
agent loop. New model providers implement the router provider contract but
cannot bypass model callbacks. New tools register metadata and handlers but
execute only through a leased `ToolEffect`. New durable state is represented
as ledger records with replay and recovery tests.

## Release boundary

Local tests, security matrices, benchmarks, SBOM generation, and license scans
are engineering evidence, not external approval. GitHub stable release remains
blocked until real external FTO, clean-room, security-audit, and red-team
reviewers sign their respective gates.

