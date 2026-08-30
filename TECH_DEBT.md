# 技术债务记录

> 本文件记录当前代码库中已知的技术债务和待审查项。
> 创建时间：2026-06-04（P0 子任务1 提交后）
>
> 库存审查落盘：[`quality/rubric.yaml`](quality/rubric.yaml) + [`quality/labels.yaml`](quality/labels.yaml)。
> 「本轮是否到顶」只跑 `uv run python scripts/check_quality_labels.py --peak`，不要临时发明新标准。
> 对外信任模型：[`SECURITY.md`](SECURITY.md) / [`SECURITY_en.md`](SECURITY_en.md)。内部 Orin 规格不替代该文件。

---

## 🔴 必须回审（P1 之后）

### 安全模块：已对照测试 vs 仍待外部审计

本轮**不重写**解析引擎，也不收敛 `parser.py` 与 `_fs_restricted_rejection`（架构债，见 ADR 0006）。
生产权威路径是 **EchoRuntime + EchoSafetyService + LeaseAuthority**；
`pulse()` / `spi.Sandbox` 是内核演进面，不是当前副作用主机。
本地 tip seal 防「只改 journal 不改 seal」；外部 tip 锚点 v1（Keychain / 目录外 backend）防
「state_dir 全控回滚」，不是 TPM，也不抗 root/Keychain 失陷。

#### 已对照现有/新增测试（不是外部人工审计）

| 文件 | 对照测试 | 说明 |
|------|----------|------|
| `js/security/rules.py` | `tests/test_security_rules.py`（直接）+ `tests/test_security_shell_allowlist.py` / `tests/test_security.py` | 规则引擎有直接单测；规则完备性仍未知 |
| `js/security/parser.py` | `tests/test_security.py`、`tests/test_security_hardening_round3.py` | 已有 AST/绕过对照；与 `_fs_restricted_rejection` 双引擎仍未收敛 |
| `js/security/net_guard.py` | `tests/test_net_guard.py` | SSRF/元数据拦截已对照；重定向跟随与误报未外部审计 |
| `js/security/signer.py` | `tests/test_security_b04_crypto.py` | 密钥文件硬化/截断 fail-closed 已对照；轮换与可信公钥目录仍缺 |

#### 仍待外部审计（本轮不声称已做）

| 项 | 为什么还不能盖「外部已审」 |
|----|---------------------------|
| 独立红队 / K§15.6 #9 | 仓库外人员与范围，本树不能自证。入口包已落盘 `docs/security/AUDIT_PACK.md`；报告归档 `docs/security/external/` |
| 正式 TCC / Developer ID / 公证 | `official_tcc_packaging` 保持 false |
| 技能可信公钥目录 | 已落地 registry + 吊销；TRUSTED 需目录内公钥。外部人工审计仍缺 |
| 解析引擎与 `_fs_restricted_rejection` 合一 | 架构债，ADR 0006 设计先行，本轮不施工 |
| 外部 tip 锚点（TPM / 远程公证） | v1 已有 Keychain/目录外 backend；不是 TPM，远程公证仍缺 |

**回审要点（外部）**：
1. 逐行代码审查，确认无逻辑错误
2. 评估生产环境适用性与误报
3. 确认与现有 `js/security/guard.py`、`js/security/audit.py` 的集成无冲突

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

### 预留模块（不是死代码，也不是默认运行时）
- `js/scenarios/`：实装为 bots goal 模板（启动即建 bot/房间/goal）；不进入默认 Echo turn
- `js/gateway/`：骨架已落地（ADR 0008），`gateway.enabled` 默认 false，Host 冷启动不 import
- `js/pipeline/`、`js/mobile/`：默认不在 AppShell / Host 启动 import 图里；`mobile_enabled` 默认 false。mobile 376 行合同层的正式声明见 [`docs/mobile/MOBILE_CLOSEOUT.md`](docs/mobile/MOBILE_CLOSEOUT.md)（`not_implemented`）
- `js/friends/`：v1 已实装（owner SQLite + X25519/ChaCha20-Poly1305 + Host-to-Host HMAC）。`friends_enabled` 默认 false，未启用不进 Host import 图
- `features.pipeline_enabled` 默认 true **只是能力旗标**，不等于冷启动加载 `js.pipeline`
- `js/evolution/`：cycle 只生成提案；批准后才应用并跑 mock benchmark，回归自动回滚；冷启动仍不跑。磁盘满时 applied 文件写失败保持 `proposed`，不半应用。
- 测试密度 M1（1.2:1）已入 CI 棘轮；纯 `.py` 口径 ≥ 0.94。M2（2.0）/ M3（3.2，Hermes 级）仍是方向性。覆盖率 M1 棘轮为 `js/security` ≥86%、`js/echo` ≥85%、全库 branch ≥65%；计划值 90/85/75 按里程碑上调，不在本轮假装已到。`mutmut` 杀伤率抽查只本地跑（[`docs/quality/mutation-2026-08-29.md`](docs/quality/mutation-2026-08-29.md)），不进 CI。独立红队仍待外部。
- Host 任务页（`/api/tasks` + `tabs/tasks.js`）是 bots goals 只读视图；mutate 503。不是已删除的 `TaskManager` / `TaskStore`
- 已删孤儿：`js/persistence/task_store.py`、`agent_store.py`。历史审计里对 `task_store.py` 的 High **作废**（文件不在树里）
- Fleet ≠ Bots。Fleet 是一次性集群（`js/orchestration/fleet/`）。Bots 是命名机器人 + 房间 + Goal（`js/bots/`），回合仍走 Echo。Orin 的 `bot.room.create` / `bot.message.send` / `bot.soul.write` 是收紧规格；v1 生产仍写 `bots.db`，不是第二套运行时。

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

1. **Journal/lease 外部 tip 锚点不是 TPM** —— 本地 tip seal + compaction 已落地；v1 `AnchorBackend`（macOS Keychain 或 journal 目录外 backend）抗「state_dir 全控回滚」。攻击者同时控制 Keychain/anchor 目录仍可无痕 rewind。远程公证 / TPM 仍缺。
2. **LeaseAuthority compaction 已实现，调度靠 governor** —— `compact()` / snapshot / tip seal bump 已在树内。生产由 ResourceGovernor 按行数/字节/`_ledger_full_reloads` 阈值触发。指纹 miss 仍可能全量重放；无调度时 O(n) 会恶化。
3. **os_sandbox 进程树 + 进程组 RSS，cgroup 可选** —— `_process_tree_rss` 含 descendants；监控按进程组合计，Linux cgroup v2 `memory.current` 可用时取较大值。`setsid()` 脱离进程组的进程仍盲区；macOS `RLIMIT_AS` 不生效，依赖轮询。
4. **parser 与 `_fs_restricted_rejection` 双引擎语义不统一** —— shell 命令 AST 解析（js/security/parser.py）与文件系统受限拒绝路径各自实现一套判断，边界案例语义可能分叉。ADR 0006 设计先行，本轮不施工。
5. **skills TRUSTED 需可信公钥目录** —— 自签不再授予 TRUSTED；BUILTIN 仍走内置白名单，TRUSTED 需 registry 内未吊销公钥。目录文件本身的分发/轮换运营流程仍待外部审计。
6. **shell allowlist 已拒 git 写文件 flag** —— `--output` / `--output-directory` 等在 allowlist 层拒绝。无 OS 沙箱（`strict_isolation` 放开）时仍须把 allowlist 当边界，不能只靠 sandbox-exec / bwrap。
7. **code.py 黑名单是纵深防御而非边界** —— asyncio/multiprocessing/http 等模块仍可导入（如 `loop.run_until_complete` 可触达 asyncio 子进程 API），**真实边界是 OS 沙箱**（无网络、fs deny-default、strict_isolation fail-closed）。pickle/_pickle/marshal/shelve 已封堵（反序列化即代码执行，纯 Python 层可确认 RCE）。
8. **bwrap 对缺失的工作区 `.git` 做占位 deny** —— wrap 时若 `.git` 不存在，用 `--dir` + `--ro-bind` 占位只读。macOS profile 的路径 deny 无此限制。占位不能防 `setsid` 后在其他路径新建 git 元数据；事后 `_reject_planted_git` 仍是纵深。
9. **红队残余低危项（R3）** —— `/docs`、`/redoc`、`/openapi.json` **已关**。`/api/setup/reopen`（完成后翻转 onboarding）改 admin 卡控；first-run `/skip` 仍允许已认证非 guest。reset 保持 admin + 无 admin 密钥门槛。

---

## 🔵 Orin 安全架构文档（机器生成，需人工评审）

| 文件 | 性质 | 状态 |
|------|------|------|
| `docs/security/orin/ORIN_DESIGN.md` v1.3 | sidecar 增强路线（迁移期设计 + 机制库存） | 已冻结归档（基线 `5a97781`） |
| `docs/security/orin/ORIN_EFFECT_KERNEL_V1.md` | 效果内核路线（终态基线） | 已冻结；勘误：`registry.py` 引用行号 655/78 互换（论断成立） |
| `docs/security/orin/ORIN_MERGE_REVIEW.md` | 合并评审：33 项机制判定 + 17 条决策（已拍板） | 引用已核验；实施以阶段 A 规格为准 |
| `docs/security/orin/ORIN_STAGE_A_SPEC.md` | 阶段 A 实施规格 | 机器生成，未经人工评审不得施工 |
| `docs/security/orin/ORIN_STAGE_C_SPEC.md` | 阶段 C「强制模式」实施规格 | C0 已冻结；C1–C3 harness 仍在；C7 发布裁决见 `ORIN_STAGE_C_CLOSEOUT.md`（verdict=`not_implemented`）。`orin.enforce=true` 因 #8/#9/正式 TCC 等合取缺位继续 fail-fast；默认生产仍单进程 ambient，**阶段 C 未实施，不得宣称 Echo RCE 已收口** |
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

本轮门禁快照（2026-08-27）：「到顶」以 `scripts/check_quality_labels.py --peak` 为准（rubric `2026.09.1`）。不把 `orin.enforce` 默认 true、正式 TCC、独立红队或 pulse 切权威算作本轮没到顶。


---

*最后更新：2026-08-28*
