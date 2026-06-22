# JS Agent v0.1.2-alpha — Harness Hardening

This alpha release hardens the harness for public macOS-first testing: more stable multi-agent orchestration, improved model connection flow, expanded memory coverage, and cleaner Web UI.

## Highlights

- More stable multi-agent orchestration with fleet strategies, lane queues, task persistence, and fleet tools.
- Better model connection flow for local and OpenAI-compatible providers, including LM Studio/Ollama discovery improvements.
- Expanded dream memory, semantic snapshot, and evolution quality scoring coverage.
- Cleaner Web UI structure with tab-specific JavaScript modules.
- WebBridge tooling and broader tool/runtime validation.
- Safer public release hygiene through stronger ignore rules and reduced false-positive secret scan triggers.

## Install

```bash
git clone https://github.com/JiangSkirk/titan-agent.git
cd titan-agent
./scripts/macos_start.sh
```

## Status

This is still an alpha build of the JS Agent Harness. It is intended for macOS public testing, real user feedback, and continued iteration.
