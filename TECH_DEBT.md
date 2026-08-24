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

## ⚫ 架构级遗留项（本轮安全审计明确不修，需专项设计）

以下问题来自两轮安全审计，属于架构级取舍，无法以局部补丁修复；本轮记录但不改动：

1. **Journal/lease ledger 截断回滚无外部锚点** —— Echo ledger 的截断（truncation）回滚仅依赖本地 MAC/hash 链，攻击者控制 state_dir 时可整体回滚到旧 tip 而不留证据。需要 tip seal 设计（外部锚点/单调计数器/签名检查点）才能闭合。
2. **LeaseAuthority 账本 O(n²) 无 compaction** —— 每次校验都重放全量 JSONL 账本，租约量增长后校验成本平方级上升。需要 compaction/快照机制（与 tip seal 一并设计）。
3. **os_sandbox 内存监控只看直接子进程 RSS** —— 孙进程脱离监控，进程组级内存合计未实现。需要按进程组/cgroup 聚合记账。
4. **parser 与 `_fs_restricted_rejection` 双引擎语义不统一** —— shell 命令 AST 解析（js/security/parser.py）与文件系统受限拒绝路径各自实现一套判断，边界案例语义可能分叉。需要收敛到单一判定引擎或显式约定职责边界。
5. **skills 签名自签即 TRUSTED** —— 当前 Ed25519 签名验证只确认"持有私钥"，自签名技能也被视为 TRUSTED。需要可信 key registry（可信公钥目录 + 轮换/吊销）才有实际约束力。
6. **shell allowlist 层未逐 flag 覆盖 git 的写文件选项** —— 如 `git log --output=<path>` 在 allowlist 层放行，真实拦截依赖 OS 沙箱（sandbox-exec deny-default / bwrap 空命名空间），已实证无法写工作区外。若未来允许无 OS 沙箱运行（strict_isolation 放开），需补齐。
7. **code.py 黑名单是纵深防御而非边界** —— asyncio/multiprocessing/http 等模块仍可导入（如 `loop.run_until_complete` 可触达 asyncio 子进程 API），真实边界是 OS 沙箱（无网络、fs deny-default、strict_isolation fail-closed）。pickle/_pickle/marshal/shelve 已封堵（反序列化即代码执行，纯 Python 层可确认 RCE）。
8. **bwrap 下 `.git` 只读重挂载只在包装时 `.git` 已存在时生效** —— macOS profile 的路径 deny 无此限制；Linux 上沙箱内新建 `.git` 树理论上仍可写（需要工作区原本不是 git 仓库且用户之后在其中跑 git，场景牵强）。彻底闭合需 bwrap 对路径不存在的挂载点做占位 deny。
9. **红队残余低危项（R3）** —— 稳态下 `/docs`、`/redoc`、`/openapi.json` 无认证暴露 API 结构（信息泄露）；user 角色密钥可翻转 setup 的 onboarding 状态标志（不触及密钥签发，reset 有 admin 卡控）。

---

## 🔵 Orin 安全架构文档（机器生成，需人工评审）

| 文件 | 性质 | 状态 |
|------|------|------|
| `docs/security/orin/ORIN_DESIGN.md` v1.3 | sidecar 增强路线（迁移期设计 + 机制库存） | 已冻结归档（基线 `5a97781`） |
| `docs/security/orin/ORIN_EFFECT_KERNEL_V1.md` | 效果内核路线（终态基线） | 已冻结；勘误：`registry.py` 引用行号 655/78 互换（论断成立） |
| `docs/security/orin/ORIN_MERGE_REVIEW.md` | 合并评审：33 项机制判定 + 17 条决策（已拍板） | 引用已核验；实施以阶段 A 规格为准 |
| `docs/security/orin/ORIN_STAGE_A_SPEC.md` | 阶段 A 实施规格 | 机器生成，未经人工评审不得施工 |
| `docs/security/orin/ORIN_STAGE_C_SPEC.md` | 阶段 C「强制模式」实施规格 | 已人工评审，仅授权 C0；阶段 C 未实施 |
| WP0 基线数字 | `benchmarks/orin/WP0_BASELINE.md` | 已实测；蜜罐不用 pyahocorasick，巡逻基数用标准库近似 |
| WP1 orind 骨架 + 工牌在线化 | `js/orin/` + `js/orind/` + 测试 `tests/orin/` | 已落地：UDS 协议六类消息、KeyBox 收养不轮换、同一本 JSONL 账本、回退不丢牌、攻击面全拒。心跳在适配器内（1s 兜底）而非 turn_runtime——懒连接 + 失败语义等价，为 Stage A 有意简化 |
| WP2 污点 + 策略表 | `js/orin/taint.py` + `js/orind/policy.py` + 11 处打标 | 已落地；conservative 默认审批；compat=旧行为+记录；mock 11 任务 1.000；红队仅阻断断言 |
| WP3 蜜罐/阶梯/巡逻/审批消毒 | `js/orind/{canary,responder,patrol}/` | 已落地：标准库多模式匹配；双证冻结测试 <1s；巡逻基数为 stdlib HyperLogLog 近似；三开关独立；深层工作区伪装默认关；关闭适配器卸钩以免 `OrinUnavailable⊂LeaseDenied` 误伤写路径。闸门：ruff 绿 / mypy 绿 / pytest 6356 passed + 2 pre-existing auth 失败 |
| 阶段 A 实施边界 | 阶段 A 声明边界以 `ORIN_STAGE_A_SPEC.md` §1 为准 | 未做：IntentEnvelope/Handle/StateWitness/EffectDraft/Effect Cell、工具 handler 迁出主进程、两阶段出门证、APFS undo、双签冷静期、策略包 Ed25519 灰度、Windows/Rust/fleet |

### 阶段 B 实施与验收账本（WP8→WP10 收口）

| WP | 已落地 | 本轮门禁 | 未实测 / 阻断边界 |
|----|---------|-----------|---------------------|
| B0 | Stage B 开关默认关闭；`orind --dev` 已接通 `--stage-b` 及 Build/Secret/Net/File/Membrane 六个启动开关，非法组合 fail-fast；Stage A 旧命令不变 | CLI 8 passed；全 Orin 399 passed | 未在真实 launchd 生产配置中启停烟测；Stage C 未做 |
| WP4 | `EffectDraft` / `StateWitness` / 严格 CommitPermit / CellPackage 与 Gate Kernel 合取；硬拒绝短路，软缺项合并，ExportPass 不顶替见证 | 纳入 Orin 399 passed | 精确批准已接；完整 diff UI / 真断电仍未做 |
| WP5 | 签名 IntentEnvelope、Personal/Work 模板及 task/hash/destination/witness 全等 ExportPass；Personal 单次、Work 常设 | 纳入 Orin 399 passed | 真双控缺第二个独立 signer，R3/K4 只能权威硬阻断 |
| WP6 | 封印 HandleBroker / Effect Manifest / K4 grid；能力位严格 bool，未知字段和伪布尔拒绝 | WP6 35 passed；Ruff/Mypy 绿 | 同 EUID 本地状态整体回滚/篡改仍无外部锚点 |
| WP7 | Build Cell 保留旧 `commit(permit=WP7 payload)` 帧、shell/code 后端和故障隔离；不进 Commit Membrane | WP7–WP9 回归 84 passed；最终全库无新增红 | 未对所有操作系统/沙箱后端做真机组合烟测 |
| WP8 | 唯一外发链 `draft → preflight → export-pass → consume(draft_id)`；package 与 permit 并列仅走认证 `cells.sock`；Connector/Network/Secret 集中于 `services.py`；`net.fetch` 不查/不核销出门证 | WP10 Cell 38 passed；全 Orin 399 passed | 真邮件/provider exactly-once 未测；L2 Keychain 只有 mock/可选 Darwin `-T` 烟测，真 Secret 仍是 JSONL 0600 dev fallback；不声称 Enclave/跨进程 ACL |
| WP9 | File Cell 只从 socket 收 package；staging、规范 diff、CAS/原子 rename、owner-root、symlink/hardlink/设备/NFC/casefold/挂载逃逸防护已落地 | WP7–WP9 回归 84 passed；全 Orin 399 passed | 精确批准已接；完整 diff UI / 真断电仍未做 |
| WP10 | File/Connector 共用唯一 SQLite WAL/FULL Commit Membrane；Personal 证核销+预算+PREPARED 同事务；Work 常设证重验；UNKNOWN 只读对账；四维 100 rps/burst 200 + 全局 1024 背压；关闭膜显式 `best_effort` | WP10 92 passed（core 39 / cells 38 / integration 15）；逐状态 crash/restart 矩阵通过；全 Orin 399 passed | 真 provider 回执/不可逆 exactly-once 和真断电未测；R0/R1/R3 持久化分级只有分类/阻断，非完整分层实现；完整签名 EffectReceipt 链未接入 |

最终全库验收：`ruff check .` 通过；`mypy js` 覆盖 328 个源文件、零错误；`pytest tests/ -q` 为 6623 passed / 2 skipped / 113 deselected，仅保留两条已确认 auth 基线红；11/11 mock benchmark 通过，overall 1.000，delta +0.000，mock 工具参数已实际执行。


---

*最后更新：2026-08-24*
