# 技术债务记录

> 本文件记录当前代码库中已知的技术债务和待审查项。
> 创建时间：2026-06-04（P0 子任务1 提交后）

---

## 🔴 必须回审（P1 之后）

### 机器生成的安全扫描模块

以下文件由自动化安全扫描生成，**尚未经过人工审计**，可能存在误报、漏报或实现缺陷：

| 文件 | 用途 | 风险 |
|------|------|------|
| `js/security/net_guard.py` | SSRF 防护（DNS Rebinding、元数据端点拦截） | 可能过度拦截合法请求；重定向跟随逻辑未充分测试 |
| `js/security/parser.py` | Shell 命令 AST 解析 | 解析覆盖率不完整；复杂管道/子 shell 可能绕过 |
| `js/security/rules.py` | 安全规则评估引擎 | 规则集可能不完整；误报率未知 |
| `js/security/signer.py` | Ed25519 技能/插件签名 | 密钥生命周期管理缺失；无轮换机制 |

**回审要点**：
1. 逐行代码审查，确认无逻辑错误
2. 补充单元测试（当前测试覆盖可能不足）
3. 评估生产环境适用性
4. 确认与现有 `js/security/guard.py`、`js/security/audit.py` 的集成无冲突

### 安全扫描报告（已排除在仓库外）

以下文件已加入 `.gitignore`，不进入版本控制：
- `js_agent_scan_report.md`
- `js_agent_scan_report_revised.md`
- `js_agent_security_scan_report.md`
- `js_agent_security_scan_crypto.md`
- `js_agent_comprehensive_security_report.md`

---

## 🟡 已知限制（不影响 P0，P1 评估）

### 桌面控制工具（macOS 限定）
- `js/tools/desktop/` 当前仅支持 macOS（pyobjc-framework-Quartz）
- Windows 支持需后续评估（可能用 pywinauto 或 COM）
- 当前为"截图+诊断"只读模式，点击/键盘控制需二次确认

### Scenarios / Tasks 系统
- `js/scenarios/` 和 `js/tasks/` 是预建框架，尚未与主流程深度集成
- YAML 场景定义未经过工厂场景验证

### 模型 Provider 配置
- 当前默认配置 DeepSeek 云端 API
- 本地模型（Ollama/LM Studio）需手动配置或自动发现
- `allow_private_model_providers` 默认 false，局域网 GPU 盒子需显式开启

---

## 🟢 已解决（供参考）

| 问题 | 解决方式 | Commit |
|------|---------|--------|
| agent.py 单文件过大 | 拆分为 `js/agent/` mixin 包 | `ebb7625` |
| server.py 单文件过大 | 路由拆分到 `js/web/routers/` | `b41946d` |
| 首启动 401 死锁 | Bootstrap admin key 自动创建 | `a8b4d75` |
| 无 FTS5 搜索 | `js/memory/store.py` + `enhanced_store.py` 集成 | `dce6fff` |
| 魔法数字硬编码 | `max_messages_hard_limit`、`tool_name_loop_threshold` 配置化 | `0839d03` |

---

## 审查责任人

- **安全模块回审**：待分配（建议由安全专家或 Claude 审计）
- **桌面控制跨平台**：P2 阶段评估 Windows 方案
- **Scenario/Tasks 集成**：P1 知识问答助手阶段验证

---

*最后更新：2026-06-04*
