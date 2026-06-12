# JS Agent

> **⚠️ 当前版本: v0.1.2-alpha — API 可能变更，欢迎反馈！**
>
> [English README](README_en.md)

一个融合 OpenClaw 和 Hermes 架构精华的 AI Agent 框架，在架构现代性上领先，在生态成熟度上持续追赶。

## 核心特性

### 🔒 安全优先 (Security-First)
- **分层沙箱**: 所有命令在隔离环境中执行，支持白名单/黑名单
- **策略模式防御** (from OpenClaw): 工具调用防御不是硬编码 if-else，是可注入、可排序的策略对象
- **Fail-Open 语义** (from OpenClaw): 安全子系统自身崩溃时不阻断主系统（防止安全成为单点故障）
- **秘密管理**: 自动检测和屏蔽 API keys、tokens，持久化加密存储（Fernet 密钥存储在 `~/.js/state/.secret_key`，权限 0o600；建议生产环境手动设置 `JS_MASTER_KEY` 环境变量以覆盖自动生成的密钥）
- **行为审计**: 完整记录每个工具调用，哈希链式日志可检测意外篡改/截断（注意：无密钥哈希链可被具有数据库写权限的攻击者重新计算伪造，迁移到 HMAC-SHA256 见 TECH_DEBT.md）
- **路径保护**: 防止误删系统文件，Workspace 外写操作需确认

### 🛡️ 极致稳定 (Stability)
- **进程隔离**: 子 agent 崩溃不影响主进程
- **断路器模式** (from OpenClaw): 服务故障时快速拒绝，自动恢复探测
- **自动恢复**: 模型调用失败自动重试，支持多 provider 降级
- **Stale-Code 自动重启** (from Hermes): 更新检测 + 自重启
- **Gateway 优雅排空** (from OpenClaw): SIGTERM 等待活跃任务完成
- **状态持久化**: SQLite 存储，断点续传
- **资源监控**: 内存/CPU 超限自动保护

### 🧠 上下文压缩器 (from Hermes)
- **保护头部**: 系统提示词和初始上下文不被压缩
- **保护尾部**: 最近 N 轮对话完整保留
- **压缩中间**: 旧对话生成摘要，带 Handoff Framing 防止误读
- **工具输出裁剪**: 过长的工具结果先截断再压缩
- **多模态感知**: 图片内容按固定 token 估算

### ✅ 增强审批系统 (from Hermes)
- **分层模式**: 手动 / 自动通过 / 自动拒绝 / 定时任务拒绝
- **异步队列**: WebSocket 会话的非阻塞审批
- **会话回调**: 支持 UI 弹窗确认

### 🔍 本地模型自动发现
- **LM Studio**: 自动检测端口 1234
- **Ollama**: 自动检测端口 11434
- **模型列表获取**: 自动拉取可用模型并推断上下文窗口

### 🔍 网络搜索
- **DuckDuckGo**: 免费，无需 API Key，开箱即用
- **Tavily**: 高质量 AI 搜索（可选）
- **Serper**: Google 搜索（可选）
- **自动降级**: 一个引擎失败自动切换下一个

### 🚀 App 级安装体验
- **一键配置**: `js setup` 自动检测一切
- **非交互模式**: `js setup -y` 适合 CI/CD

### 🌐 WebUI
- **FastAPI + WebSocket**: 实时流式对话
- **模型管理**: 查看本地模型状态和健康检查
- **网络搜索**: 独立搜索面板
- **文件浏览器 / 审计 / Skills / 多Agent / 进化仪表板**

### 🤖 多 Agent 协作 + 🧬 自主学习 + 🧩 Skill 进化
- **角色系统**: Coder、Reviewer、Researcher、Tester
- **A/B 测试**: Prompt 和 Skill 自动优胜劣汰
- **交互学习**: 从成功/失败中提取模式

## 快速开始

环境要求：macOS + Python 3.12 / 3.13 / 3.14。

```bash
# 推荐：首次运行会自动创建 .venv、安装依赖、初始化配置并打开 Web UI
./scripts/macos_start.sh
```

手动安装：

```bash
pip install -e .

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

| 能力 | OpenClaw | Hermes | **JS** |
|------|----------|--------|-----------|
| 运行时 | Node.js (3700 chunks) | Python + Node UI | **Python 3.12+ 统一** |
| 安全 | 外部插件 (ClawAegis) | Tirith + 审批 | **内置 + 策略模式 + Fail-Open** |
| 上下文压缩 | ❌ | ✅ 最强 | ✅ **Hermes 式压缩器** |
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
- Ruff 零错误，mypy 零错误。

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
#   js_agent-0.1.1-py3-none-any.whl
#   js_agent-0.1.1.tar.gz
```

## 已知限制

- **WebSocket 流式**: 最终 assistant 回复支持原生 token 级流式，工具调用环节保持原子解析。
- **LM Studio Embeddings**: 需手动在 LM Studio 中开启 Embedding 服务端点，否则自动降级为关键词匹配。
- **Auto-Fetch Pipeline (实验性)**: Gmail / Slack / Drive / Calendar / GitHub / Notion 连接器目前为 **mock / 实验性**实现，仅用于演示数据流架构。生产环境请使用文件系统连接器 (`file`) 或等待后续稳定版本。

## 生产部署

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
