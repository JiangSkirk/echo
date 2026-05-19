# JS Agent

一个比 OpenClaw/Hermes 更**稳定、好用、安全、方便**的 AI Agent 框架，融合了二者的架构精华并超越了它们。

## 核心特性

### 🔒 安全优先 (Security-First)
- **分层沙箱**: 所有命令在隔离环境中执行，支持白名单/黑名单
- **策略模式防御** (from OpenClaw): 工具调用防御不是硬编码 if-else，是可注入、可排序的策略对象
- **Fail-Open 语义** (from OpenClaw): 安全策略崩溃不阻断主系统
- **秘密管理**: 自动检测和屏蔽 API keys、tokens，持久化加密存储
- **行为审计**: 完整记录每个工具调用，哈希链式防篡改日志
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

### 📸 Checkpoint 快照系统 (from Hermes)
- **透明 Git Shadow Repo**: 零状态泄漏到用户项目
- **GIT 环境隔离**: 完全独立于用户全局 git 配置
- **每轮去重**: 同一目录每轮最多一个快照
- **安全回滚**: 一键恢复到任意历史状态

### ⚡ 配置缓存 (from Hermes)
- **Stat-Based 热重载**: 文件未变更时跳过 YAML 解析
- **版本迁移**: 支持配置结构升级

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

```bash
# 安装
pip install -e ".[dev]"

# 一键配置（自动检测 LM Studio / Ollama）
js setup

# CLI 交互
js chat

# Web UI
js web --port 8080

# 搜索
js search "最新的 AI 发展"
```

## 架构对比

| 能力 | OpenClaw | Hermes | **JS** |
|------|----------|--------|-----------|
| 运行时 | Node.js (3700 chunks) | Python + Node UI | **Python 3.12 统一** |
| 安全 | 外部插件 (ClawAegis) | Tirith + 审批 | **内置 + 策略模式 + Fail-Open** |
| 上下文压缩 | ❌ | ✅ 最强 | ✅ **Hermes 式压缩器** |
| Checkpoint | ❌ | ✅ Git Shadow | ✅ **Git Shadow Repo** |
| 配置缓存 | ❌ | ✅ Stat-based | ✅ **Stat-based** |
| 断路器 | ❌ | ❌ | ✅ **自动恢复探测** |
| 模型发现 | ❌ 手动配置 | ❌ 手动配置 | ✅ **自动探测** |
| 搜索 | ❌ 需插件 | Tavily 需配置 | ✅ **DuckDuckGo 开箱即用** |
| WebUI | Next.js 重型 | Next.js + Python RPC | ✅ **FastAPI + 原生 JS 轻量** |
| MCP | ❌ | 较新 | ✅ **Stdio/SSE 原生** |
| Skills | 静态文件 | ❌ | ✅ **代码/Prompt/工作流 + 安全扫描 + 可安装** |
| 多Agent | 简单子Agent | 委托线程池 | ✅ **角色系统 + 并行编排** |
| 自主学习 | ❌ | ❌ | ✅ **交互学习 + A/B 测试** |
| 安装体验 | JSON 手动配置 | YAML 388行 | ✅ **`js setup` 一键** |

## 测试

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

开箱即用 5 个 Prompt 类型 Skill：
- `arxiv-research` — arXiv 论文搜索指南
- `code-review` — 结构化代码审查
- `file-search` — 高级 grep/find 技巧
- `git-helper` — Git 工作流指南
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

**103 个测试**覆盖所有模块，Ruff 零错误，mypy strict 零错误。

## 生产部署

```bash
# Web UI
js web --host 0.0.0.0 --port 8080

# 或 Gunicorn + Uvicorn
gunicorn "js.web:create_app()" -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8080
```
