---
name: gate
description: Run the project quality gate — ruff, mypy, pytest — in order and report pass/fail. Use before committing or when asked to verify the 三件套.
---

# Quality Gate (三件套)

Run the project's mandatory gate and report results concisely:

```bash
uv run ruff check . && uv run mypy js && uv run pytest tests/ -q
```

Rules:
- Run the three in order; `&&` short-circuits so the first failure stops the chain.
- On failure: report which stage failed and the relevant tail of its output. Do
  NOT auto-fix unless the user asks.
- On success: report "三件套全绿" with the pytest pass count.
- This is the repo's hard gate — never call work "done" until it is green.
