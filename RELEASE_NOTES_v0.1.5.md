# Release Notes — v0.1.5 (stable)

发布日期：2026-06-24
分支：v0.1.4-alpha-hardening（基于该分支收口为 v0.1.5 stable）
范围：**本地发布准备 only — 不 push、不 tag、不发布构建产物。**

---

## 概览

v0.1.5 把 v0.1.4 hardening 周期里完成的工作 + v0.1.5-alpha 周期里 Skill Promotion Gate 的核心与控制面统一收口为一个 stable 版本。
**不引入新功能**。本次发布的全部内容来自先前已通过审计与门禁的 PR。

## 本版本包含

- **v0.1.4 hardening**
  - Owner isolation 全持久化层加固：`SessionLifecycleStore` / `ReviewStore` / `StateStore` 改用 `(session_id, owner_key_hash)` 复合主键；`None` owner 统一归一化到 `__legacy_local__` 哨兵；旧表首次打开就地迁移。
  - `TurnExecutor` 把 owner_key_hash 改成实例字段，并发跑不同用户不再会在心跳上 race。
  - `[office]` / `[pdf]` 安装 extras：重依赖（pandas/openpyxl/pypdf/pdfplumber/reportlab）从核心安装中拆出，可选安装，未装时相关工具优雅降级。
  - Tool output budget（默认 20k 字符）：单条工具结果超限时统一截断 + `metadata.truncated`，`file_read` 走"先分页后预算"路径，不会再因为大文件被错误判超限。
  - Task Review Capsule（无 LLM 的确定性 MVP）：每次 run 结束写一条 owner-scoped 的轻量总结记录，含首/末消息、工具调用摘要、token/turn 统计、退出状态，secrets 已脱敏。
  - Session lifecycle + abnormal-exit recovery（仅状态标记，不自动重跑）：心跳超时会被标为 `aborted` / `exit_reason="abnormal_exit_recovery"`。
  - Tool batch telemetry：每个 tool batch 发 `TOOL_BATCH` 审计事件 + `tool_batches_total{all_failed,tool_count}` Prometheus 计数器。

- **Skill Promotion Gate core**
  - Auto curator / evolver 不再直接改 trust 或覆写技能入口文件，改成只写 `skill_promotions.db` 的 `proposed` 事件。
  - 操作员显式 approve 后才走 5 步门禁：`protected → validate → security → tests → smoke`；smoke 由 30 s `asyncio.wait_for` 兜底。
  - 失败的门禁不动任何 trust、不改任何文件、不污染 `skill_usage`。
  - 每个门禁决策落审计行 `AuditEventType.SKILL_PROMOTION_GATE`，并打 `skill_promotion_events_total{decision,failed_step}` Prometheus 指标；smoke 超时额外携带 `details.timeout=True` + `details.smoke_error`。
  - Quarantine 等不受信级别的 skill 不再以 model tool 形式暴露给模型。

- **CLI / Web promotion controls**
  - CLI：`js skill promote list | show <event_id> | approve <event_id> | reject <event_id> | revert <event_id>`。
    - `approve` 走 `SkillManager.apply_proposal`（含 5 步门禁）。
    - `reject` 只翻事件状态，不动 trust、不动文件。
    - `revert` 走 `SkillManager.revert_promotion`，回滚 trust + 入口文件。
  - Web：`GET /api/skills/promotions`、`GET /api/skills/promotions/{event_id}` 普通鉴权 + owner scope；`POST /api/skills/promotions/{event_id}/{approve|reject|revert}` 强制 `require_admin`。响应永远不外露 `owner_key_hash`，路由在 `/api/skills/{skill_id}` 通配之前注册。

- **Docs / operations**
  - `README.md` / `README_en.md` 顶部状态切换为 v0.1.5 stable。
  - `README.md` / `README_en.md` / `docs/deployment.md` 中 Skill Promotion Gate / Skill Promotion Operations 章节标题去掉 `-alpha` 后缀，标注为 v0.1.5。
  - `CHANGELOG.md` 关闭 `[Unreleased]` 段，落为 `[0.1.5] - 2026-06-24`；保留全部历史 `0.1.1-alpha / 0.1.2-alpha / 0.1.3-alpha` 段落与底部链接，新增 `[0.1.5]` 链接。
  - 历史发行说明（`RELEASE_NOTES_v0.1.1-alpha.md` / `v0.1.2-alpha.md` / `v0.1.3-alpha.md`）保持原样不动。

## 范围与边界（重要）

- **No push**：本次收口不向远端推送。
- **No tag**：不创建 git tag，本地准备阶段。
- **No global alpha replace**：只清理"当前发布面"上的 alpha 字样；历史 alpha 章节、历史 RELEASE_NOTES、CHANGELOG 历史链接全部保留原样。
- **No new features**：本版本不引入任何新功能；所有内容均来自已合入的 PR。
- **No `.claude/settings.json` change**。
- **No manual `uv.lock` edit**：仅通过 `.venv/bin/uv lock` 更新。
- **Follow-ups（不混入本次收口）**：PR-2 / PR-2.1 的非阻塞观察项（CLI 输出样式、`--owner` 过滤、`details` 白名单等）留作后续小 PR 处理，本版本不动。

## 验证结果

执行命令（按顺序，全部使用本地 `.venv`）：

```bash
.venv/bin/ruff check js/ tests/ scripts/
.venv/bin/python -m mypy js/ --no-error-summary
.venv/bin/python -m pytest tests/ -q --tb=short
.venv/bin/python -m benchmarks.runner --mock
.venv/bin/python scripts/release_smoke.py --all
.venv/bin/python -m js --help
git diff --check
.venv/bin/uv lock --check
```

实际结果（本地 2026-06-24 运行）：

- `ruff check js/ tests/ scripts/` → All checks passed
- `mypy js/ --no-error-summary` → 零错误（无输出 = clean）
- `pytest tests/ -q --tb=short` → 1405 passed, 3 skipped, 11 deselected（首跑出现已知偶发 flake `test_model_context_window::test_provider_manager_falls_back_to_name_inference`，复跑稳定通过；与本次版本号收口无关）
- `python -m benchmarks.runner --mock` → Overall score 1.000 / Baseline 1.000（11/11 PASS）
- `python scripts/release_smoke.py --all` → 发布烟测通过（package / web / model / skills / dream / evolution / fleet 全部 OK）
- `python -m js --help` → CLI 加载正常，列出全部命令
- `git diff --check` → 无白空错误
- `uv lock --check` → Resolved 117 packages（lock 与 pyproject.toml 一致）

## 升级提示

- 不存在新功能上手成本；已运行 v0.1.4 / v0.1.5-alpha 的用户只需替换版本号即可继续运行，DB 表自动就地迁移。
- 如使用 Office / PDF 工具，请确认已安装对应 extra：`pip install -e ".[office]"` 或 `pip install -e ".[pdf]"`。
