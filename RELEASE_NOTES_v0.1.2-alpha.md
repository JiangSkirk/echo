# JS Agent v0.1.2-alpha

This alpha release focuses on making JS Agent more usable as a public macOS-first testing build.

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

This is still an alpha build. It is intended for macOS public testing, real user feedback, and continued iteration.
