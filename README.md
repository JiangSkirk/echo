# JS Agent — 本地个人 Agent Harness

> **⚠️ 当前版本: v0.1.3-alpha — API 可能变更，欢迎反馈！**
>
> [English README](README_en.md)

JS Agent 不是聊天机器人，而是一套**本地个人 Agent Harness**——围绕你选择的模型，提供记忆持久化、上下文胶囊、工具执行、安全护栏、测试反馈、模型切换和任务复盘的一整套本地驾驭系统。

模型只是引擎。Harness 才是让引擎能安全、持续、可复用地完成实际工作的完整车架。

## 核心驾驭能力

### 🧠 记忆与上下文胶囊
- **三层记忆**: 工作记忆（即时）→ 情景记忆（会话历史）→ 语义记忆（长期知识），全部本地 SQLite 存储
- **Session Capsule Lite（实验性）**: 长会话超过阈值后生成 per-session 短摘要，后续调用注入「胶囊 + 最近 6 轮」而非完整历史，用于减少 prompt token；它是短期上下文记忆，不是完整长期记忆系统
- **梦境整合**: 夜间自动合并碎片化记忆，去重、提炼、生成关联索引
- **完全本地**: 记忆数据存储在 `~/.js/` 下，owner 隔离，不上传云端

### 🔧 工具执行与编排
- **文件操作**: 带路径沙箱的安全文件读写，Workspace 外写入需确认
- **Shell 执行**: 分层沙箱环境，支持白名单/黑名单策略
- **代码执行**: 资源受限的 Python 脚本运行，超时/内存限制
- **浏览器**: 网页抓取与内容提取
- **Office**: Excel/PDF 生成与解析
- **并行执行**: 独立工具可并发调用，减少等待

### 🛡️ 安全护栏（Defense in Depth）
- **策略模式防御**: 工具调用防御不是硬编码 if-else，是可注入、可排序的策略对象
- **Fail-Open 语义**: 安全子系统自身崩溃/故障时不阻断主系统（防止安全成为单点故障）
- **行为审计**: 完整记录每个工具调用，哈希链式日志可检测篡改/截断
- **路径保护**: 防止误删系统文件，Workspace 外写操作需确认
- **秘密管理**: 自动检测和屏蔽 API keys、tokens，持久化加密存储

### 🔄 模型切换与韧性
- **本地模型自动发现**: LM Studio（端口 1234）、Ollama（端口 11434）自动检测
- **多 Provider 支持**: OpenAI / DeepSeek / DashScope / SiliconFlow 等 OpenAI-compatible 接口
- **故障转移**: 主模型不可用时自动降级到备用 Provider
- **断路器模式**: 服务故障时快速拒绝，自动恢复探测
- **上下文窗口感知**: 自动推断模型上下文长度，超限前触发压缩

### ✅ 审批与任务复盘
- **分层审批**: 手动 / 自动通过 / 自动拒绝 / 定时任务拒绝
- **异步队列**: WebSocket 会话的非阻塞审批
- **检查点恢复**: 每轮对话自动 checkpoint，中断后可从断点继续
- **任务状态持久化**: SQLite 存储会话状态，支持「继续对话」

### 🧩 Skill 系统（可扩展工作流）
- **三种类型**: Code（可执行脚本）、Prompt（LLM 指令文档）、Workflow（轻量自动化链）
- **安全扫描**: 安装时自动检测 eval/exec、子进程、网络、文件删除等风险模式
- **四级信任**: builtin → trusted → community → quarantine
- **Hermes 兼容**: 支持 Hermes 格式 skill 的直接安装与运行

### 🌐 本地 Web 界面
- **FastAPI + WebSocket**: 实时流式对话，无需 Next.js 重型依赖
- **模型管理面板**: 查看本地模型状态、健康检查、一键切换
- **记忆浏览器**: 查看、搜索、管理持久化记忆
- **审计日志**: 完整工具调用历史，支持追溯
- **Skill 面板**: 安装、卸载、信任调整、在线查看内容

## 快速开始

环境要求：macOS + Python 3.12 / 3.13 / 3.14。

```bash
# 推荐：首次运行会自动创建 .venv、安装依赖、初始化配置并打开 Web UI
./scripts/macos_start.sh
```

手动安装：

```bash
# 核心安装（不含 Office/PDF 重依赖）
pip install -e .

# 可选 extras：Excel 读写
pip install -e ".[office]"   # openpyxl + pandas

# 可选 extras：PDF 读取与生成
pip install -e ".[pdf]"      # pypdf + pdfplumber + reportlab

# 一键配置（自动检测 LM Studio / Ollama）
js setup

# CLI 交互
js

# Web UI
js web --port 8000

# 搜索
js search "最新的 AI 发展"
```

## 接入自己的模型

JS Agent 支持 OpenAI-compatible 接口。普通用户可以在 Web UI 的 Models 页面添加 Provider：

- LM Studio: `http://127.0.0.1:1234/v1`
- Ollama: `http://127.0.0.1:11434/v1`
- OpenAI / DeepSeek / DashScope / SiliconFlow 等云服务：填写对应 `base_url` 和 API Key

添加后点击 Discover 拉取模型列表，保存后即可在顶部模型下拉框切换。

## 二次开发

```bash
pip install -e ".[dev]"
ruff check js tests
mypy js
pytest tests -q -p no:cacheprovider
```

## 架构对比

| 能力 | OpenClaw | Hermes | **JS Agent** |
|------|----------|--------|-----------|
| 运行时 | Node.js (3700 chunks) | Python + Node UI | **Python 3.12+ 统一** |
| 安全 | 外部插件 (ClawAegis) | Tirith + 审批 | **内置 + 策略模式 + Fail-Open** |
| 上下文压缩 | ❌ | ✅ 最强 | ✅ **Hermes 式压缩器 + 上下文胶囊** |
| Checkpoint | ❌ | ✅ Git Shadow | ✅ **Git Shadow Repo** |
| 配置缓存 | ❌ | ✅ Stat-based | ⚠️ 已移除 (YAGNI) |
| 断路器 | ❌ | ❌ | ✅ **自动恢复探测** |
| 模型发现 | ❌ 手动配置 | ❌ 手动配置 | ✅ **自动探测** |
| 搜索 | ❌ 需插件 | Tavily 需配置 | ✅ **DuckDuckGo 开箱即用** |
| WebUI | Next.js 重型 | Next.js + Python RPC | ✅ **FastAPI + 原生 JS 轻量** |
| MCP | ❌ | 较新 | ✅ **Stdio/SSE 原生** |
| Skills | 静态文件 | ❌ | ✅ **代码/Prompt/工作流 + 安全扫描 + 可安装** |
| 多Agent | 简单子Agent | 委托线程池 | ✅ **角色系统 + 并行编排** |
| 自主学习 | ❌ | ❌ | ✅ **交互学习 + A/B 测试** |
| 安装体验 | JSON 手动配置 | YAML 388行 | ✅ **`js setup` 一键** |

## Skill 系统

JS Agent 拥有统一、安全、可扩展的 Skill 系统，支持三种类型：

### 三种 Skill 类型

| 类型 | 说明 | 示例 |
|------|------|------|
| **Code** | 可执行的 Python/Shell 脚本 | 自定义数据处理脚本 |
| **Prompt** | LLM 指令文档，注入上下文 | 代码审查指南、Git 工作流 |
| **Workflow** | 轻量级自动化链 | 多步骤数据处理 |

### 安全与信任

- **四级信任体系**: `builtin` → `trusted` → `community` → `quarantine`
- **自动安全扫描**: 安装时检测 eval/exec、子进程、网络、文件删除等风险模式
- **完整性校验**: SHA-256 内容哈希，篡改即发现
- **隔离运行**: Code 类型在子进程中执行，带环境变量沙箱

### 渐进式披露 (Progressive Disclosure)

- `list_skills()` 返回轻量元数据（省 token）
- `view_skill(id)` 按需加载完整内容、引用和模板

### 内置 Skills

开箱即用的内置 Skill：
- `api-design` — API 设计审查
- `arxiv-research` — arXiv 论文搜索指南
- `code-review` — 结构化代码审查
- `docker-helper` — Docker 使用建议
- `excel-helper` — Excel 读取、写入、合并指南
- `file-search` — 高级文件搜索
- `pdf-helper` — PDF 报告生成指南
- `python-debug` — Python 调试指南
- `regex-cookbook` — 正则表达式助手
- `shell-safety` — Shell 命令安全审查
- `sql-optimizer` — SQL 优化建议
- `web-fetch` — curl/wget 最佳实践

### CLI 管理

```bash
# 列出所有 skills（带分类/信任等级/兼容性筛选）
js skill list
js skill list --category research
js skill list --type prompt

# 查看详情
js skill info code-review

# 安装（本地路径或 git URL）
js skill install /path/to/skill
js skill install https://github.com/user/skill-repo

# 卸载
js skill uninstall my-skill

# 调整信任等级
js skill trust my-skill trusted
```

### Web UI

Web 界面的 Skills 面板支持：
- 分类/类型/关键词筛选
- 信任等级可视化（颜色标识）
- 兼容性状态（✓/✗）和前置条件检查
- 点击展开查看完整内容
- 在线安装/卸载/信任调整

## 测试

```bash
pytest tests/ -v
```

完整测试覆盖核心模块：
- 安全：Red-team (24) + Fuzz guard (40) + Sandbox (8)
- 记忆：Quality (12) + 持久化 (5)
- 路由：Provider failover (8) + Circuit breaker
- 流水线：Auto-Fetch (20) + Benchmark (11)
- 取消/恢复：Checkpoint/Resume (10) + Smoke (26)
- 发布门禁：`ruff`、`mypy`、完整测试、benchmark mock、release smoke 均需通过。

```bash
# 代码质量检查
ruff check js tests
mypy js
pytest tests/ -q -p no:cacheprovider
python scripts/release_smoke.py --all
```

## 构建与发布

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 构建 wheel + sdist
python -m build

# 产物位于 dist/
#   js_agent-0.1.3-py3-none-any.whl
#   js_agent-0.1.3.tar.gz
```

## 已知限制

- **WebSocket 流式**: 最终 assistant 回复支持原生 token 级流式，工具调用环节保持原子解析。
- **LM Studio Embeddings**: 需手动在 LM Studio 中开启 Embedding 服务端点，否则自动降级为关键词匹配。
- **Session Capsule Lite（实验性）**: 当前只提供查看、刷新、清空；失败会回退完整历史；不提供复杂编辑、跨会话长期规划或完整长期记忆保证。
- **Auto-Fetch Pipeline (实验性)**: Gmail / Slack / Drive / Calendar / GitHub / Notion 连接器目前为 **mock / 实验性**实现，仅用于演示数据流架构。生产环境请使用文件系统连接器 (`file`) 或等待后续稳定版本。
- **单工具输出预算**: 单次工具调用默认上限 20k 字符（`ToolLimits.tool_output_budget_chars`）。两条路径：`file_read` 在 `offset`/`limit` 分页之后若仍超额，返回空 `output` + `metadata.too_large=True` + 分页建议（`js/tools/files.py`）；其它工具走 registry 截断，`output` 截到预算长度并附 `[output truncated: N chars; ...]` 提示，同时打上 `metadata.truncated=True` / `metadata.original_len=N`（`js/tools/registry.py`）。两条路径都不会把完整大输出塞进 prompt。
- **Task Review Capsule（MVP）**: 每次 run 结束会落地一条确定性的、owner 隔离的复盘记录（首条 user 消息、末条 assistant 消息、工具调用清单、token/turn 计数、退出状态），存于 `review_capsules.db`。**这是去 LLM 的确定性摘要，不是 LLM 反思或反馈学习。**
- **Abnormal-Exit Recovery（仅状态标记，非自动续跑）**: 启动时如发现 `SessionLifecycleStore` 中存在心跳超时的 `running` session，会被标记为 `aborted`（`exit_reason="abnormal_exit_recovery"`）。**这只是状态标记，agent 不会自动重跑、重做工具或从 checkpoint 续上**；用户仍需手动开启新 run。Checkpoint 续跑 API 没有变化。
- **可选 extras**: Office/PDF 工具依赖通过 `pip install -e ".[office]"` / `".[pdf]"` 单独安装；未安装时相关工具会以清晰错误退场，不影响核心 agent。

## 生产部署

> 注意：绑定 `0.0.0.0` 会让服务暴露到 localhost 之外。生产、局域网或公网部署必须启用 API key；不要用 no-auth 配置对外监听。

```bash
# Web UI
js web --host 0.0.0.0 --port 8000

# 或 Docker
docker run -p 8000:8000 -e OPENAI_API_KEY=xxx js-agent

# 或 Gunicorn + Uvicorn
gunicorn "js.web:create_app()" -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

## License

MIT License — 详见 [LICENSE](LICENSE) 文件。
