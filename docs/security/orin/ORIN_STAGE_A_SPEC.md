# Orin 阶段 A「保安上岗」实施规格

> 状态：实施规格，机器生成（Kimi），未经人工评审不得施工；已登记 TECH_DEBT.md
> 日期：2026-08-22（Asia/Shanghai）
> 基线：commit `5a97781`（pre-Orin 工作树快照，工作树已干净）
> 上游文档：`ORIN_MERGE_REVIEW.md`（合并评审 + 17 条已拍板决策，下称 **M**）；
> 终态基线 `ORIN_EFFECT_KERNEL_V1.md`（下称 **K**）；机制库存 `ORIN_DESIGN.md` v1.3（下称 **D**，已冻结）
> 阶段 A 范围 = D 路线图 P0–P2，按 M§3.1 的声明边界执行

---

## 1. 声明边界（施工期间和验收后都必须遵守）

| 阶段 A 完成后**可以**宣称 | 阶段 A **不得**宣称 |
|---|---|
| 防模型层提示注入能力增强（污点 + 策略表 + 审批） | 防 Echo 进程 RCE（工具 handler 仍在主进程） |
| 工牌吊销即时生效（核销在线化） | 语义泄露"结构性归零"（出门证属阶段 B） |
| 蜜罐双证据泄密探测 < 1s 冻结 | 子进程内容级外发归零（白名单限速属阶段 B） |
| 每个安全判定有签名收据、可回放 | 任何性能数字（全部为目标值，实测后更新） |

声明边界写入代码：凡阶段 A 新增的用户可见文案、CLI 输出、注释中的安全承诺，违反上表即评审不通过。

---

## 2. 前置条件（开工前逐项打勾）

- [x] 工作树基线冻结：`5a97781`，文档基线冲突已停止（K9 决策）
- [x] 17 条决策已拍板（M§4）
- [ ] 分支：从 `feature/echo-runtime` 切出 `feature/orin-stage-a`
- [ ] 基线测量完成（WP0），数字回填 §8.2
- [ ] 新增依赖评审：`pyahocorasick`（C 扩展，蜜罐比对用）；若评审不通过，降级为标准库 `re` 多模式 + 接受性能降级并记录

---

## 3. 冻结协议：orin/v1（阶段 A 子集）

> 本节的权威来源。与 D 附录 D.1 的差异以本节为准；K§8 的 IntentEnvelope/Handle/Permit 属阶段 B，不在本节。

### 3.1 传输层（沿用 D§5.4，全部条款冻结）

- Unix domain socket（macOS/Linux）：`<state_dir>/orin/orind.sock`，0600；Windows 命名管道留接口不实现（决策 D1）。
- 长度前缀帧：4 字节大端 u32 + JSON payload，单帧上限 64KB；超界连接即断。
- 握手：orind 生成 32 字节会话密钥，经一次性 fd 传递 / 0600 文件下发；主进程重启即轮换。
- 报文：HMAC-SHA256（会话密钥）+ 单调递增 u64 计数器 + 会话 nonce；计数器回退/重复 = 断开并审计。
- 对端身份：macOS `audit_token`（`getpeereid` 兜底）；校验失败 = 拒绝。
- 自我保护：每客户端令牌桶（默认 100 req/s，burst 200）+ 有界队列（1024）+ 背压错误码。
- 版本协商：首帧 `hello {v: 1, caps: [...]}`；不支持版本 = 拒绝。
- 严格解析（K§8.1）：未知字段拒绝、JSON 深度 ≤ 16、字符串字段长度上限、数值范围检查。

### 3.2 消息类型（阶段 A 仅需 6 类）

```jsonc
// 1) hello / hello_ack —— 版本与能力协商
{"v":1,"type":"hello","caps":["lease.v2","taint","canary"]}

// 2) issue / issue_ack —— 工牌签发（密钥在 orind）
{"v":1,"type":"issue","seq":1,"nonce":"…",
 "lease":{...CapabilityLease 字段...,"taint_floor":"0xffff…","taint_sink":0,"sandbox_profile":0,"clearance":1}}

// 3) consume / consume_ack —— 每次工具调用在线核销（关键路径）
{"v":1,"type":"consume","seq":2,"nonce":"…","lease_id":"…","mac":"authority-hmac-sha256-v2:…",
 "context_taint":1544,"arg_taint":512,"clearance":1,"tool":"shell","args_digest":"sha256:…"}
{"v":1,"type":"consume_ack","seq":2,"verdict":"allow|approval_required|deny|freeze",
 "receipt_id":"…","policy_version":17}

// 4) revoke —— 吊销（即时生效，orind 内存态）
// 5) heartbeat / heartbeat_ack —— 1s 兜底心跳
// 6) freeze —— orind → 主进程单向冻结指令（Responder 下发）
```

### 3.3 工牌 v2 兼容编码（关键兼容点，施工红线）

`js/echo/types.py:89` 的 `CapabilityLease` 是冻结 dataclass，`capability.py:175 _canonical_lease_payload` 的 MAC 覆盖现有字段集。**新增四字段（taint_floor / taint_sink / sandbox_profile / clearance，缺省值同 D 附录 D.2）不得改变旧字段集的 MAC 编码**：

- 旧工牌：MAC 前缀 `authority-hmac-sha256:`，payload = 旧字段集，**链验证永远不变**（兼容红线）；
- 新工牌（任一新字段非缺省）：MAC 前缀 `authority-hmac-sha256-v2:`，payload = 旧字段集 + 四字段追加编码；前缀分派验证（沿用 `signer.py` 已有的前缀分派先例）；
- 旧 orind 收到 v2 前缀 = 拒绝（版本协商保护）；新 orind 验旧前缀 = 按旧语义放行 + 记录（灰期）。

---

## 4. 工作包拆解

依赖顺序：WP0 → WP1 → WP2 → WP3。每个 WP 独立可回退，验收不过不进入下一个。

### WP0：基线测量（先于一切代码改动）

交付物：`benchmarks/orin/baseline.py` + 数字报告。

| 测量项 | 方法 | 用途 |
|---|---|---|
| 工具调用端到端延迟 p50/p99 | mock provider（`benchmarks/runner.py`）跑 11 个 YAML 任务，前后对比 | §8.2 开销验收的分母 |
| LeaseAuthority issue/consume 微基准 | 直接调用 `capability.py` API，10k 次 | 在线化后的对比基线 |
| 常驻内存 / 启动时间 | 冷启动 ×10 | 回归报警阈值 |
| 现有测试套件耗时 | `pytest tests/` 全量计时 | 阶段 A 验收的回归基线 |

### WP1：orind 骨架与工牌在线化（D P0）

新建（D§10.2 包结构，orind 置 `js/` 内以继承 `runtime_tcb` 写保护）：

```
js/orin/
├── __init__.py
├── protocol.py      # §3.1 传输层 + §3.2 消息 schema + 严格解析
├── client.py        # LeaseClient：issue/consume/revoke/heartbeat/freeze 监听
├── receipts.py      # 判定收据签名（复用 security/signer.py Ed25519）
└── testing.py       # 假 orind（进程内同协议实现，单测用）
js/orind/
├── __main__.py      # launchd 托管入口；--dev 模式前台运行
├── daemon.py        # 单线程 asyncio 事件循环，无锁数据结构
├── gatekeeper.py    # 签发/核销/吊销 + 策略判定（WP2 接入策略表）
├── keybox.py        # 三级钥匙箱：dev=0600 文件；production=macOS Keychain 受控取出
└── store.py         # SQLite WAL：revocations / receipts / responder_state / canaries
```

修改：

| 文件 | 锚点 | 改动 |
|---|---|---|
| `js/agent/tool_executor.py` | `:4916 _get_echo_tool_lease_authority` | 改为返回 `LeaseClient` 支撑的 authority 适配器，**保持 `LeaseAuthority` 公共接口不变**；`orin.enabled=false` 时走原路径 |
| `js/echo/capability.py` | `:175 _canonical_lease_payload`、`:300` 签名前缀 | 增加 v2 payload 编码与前缀分派（§3.3）；旧路径一行不改 |
| `js/config.py` | Settings（pydantic 模式已核实） | 新增 `orin_*` 配置组：`orin_enabled`、`orin_fail_mode(closed/readonly)`、`orin_socket_path`、`orin_keybox_tier(dev/production)`、`orin_shadow_mode` |
| `js/echo/turn_runtime.py` | 启动路径 | orind 健康检查 + 心跳协程；`fail_mode=closed` 时 orind 失联 ⇒ 新工牌停发 |

验收门槛（D P0 沿用）：
1. 现有测试全绿（`pytest tests/`，与 WP0 基线比对）；
2. `kill orind` ⇒ 新工牌停发（fail-closed）；`fail_mode=readonly` 时仅只读工牌可发；
3. 旧 HMAC 账本链验证不受影响（用基线快照的 state_dir 实测）；
4. IPC 攻击面测试：洪水、慢客户端、计数器重放、伪造对端、未知字段、64KB+ 帧——全部拒绝且不崩溃。

回退开关：`orin_enabled=false` 完全回到现状路径。

### WP2：污点体系与策略表（D P1）

新建：`js/orin/taint.py`（u64 位掩码 + 传播/衰减规则 + arg_taint 8-gram Jaccard）、`js/orind/policy.py`（双档策略表 + 缺省行 + "拒 > 出门证 > 审批 > 放行"优先级——**决策 D 优先级定义直接沿用，不得改动**）。

11 处打标点（锚点已全部核验）：

| # | 文件 | 锚点 | 标签 |
|---|---|---|---|
| 1 | `js/echo/turn_runtime.py` | `:389 build_context` | USER_TURN / USER_HISTORY |
| 2 | `js/echo/turn_loop.py` | `:534 state.messages.append` 与 `:569 check_tool_result` 钩子同位 | TOOL_RESULT / WEB_CONTENT |
| 3 | `js/echo/attachment_gate.py` | 附件入口 | ATTACHMENT |
| 4 | `js/memory/store.py` + `enhanced_store.py` | 读路径 | MEMORY_READ（敏感条目加 SECRET） |
| 5 | `js/memory/store.py` | 写路径 | 账本 MEMORY_WRITE |
| 6 | `js/skills/manager.py` | 加载处 | SKILL_CONTENT |
| 7 | `js/compression/compressor.py` | 摘要回注 | 原文污点 \| MODEL_OUTPUT \| COMPRESSED，SECRET 强制继承 |
| 8 | `js/cron/engine.py:454 _schedule_job`、`js/daemon/core.py` | 进 Echo 处 | AUTO_TASK |
| 9 | `js/appshell/inbox.py`、`work_context.py` | 投影处 | INBOX_CONTENT |
| 10 | `js/echo/handoff_vault.py` | 读取处 | 按来源标签 |
| 11 | `js/tools/files.py` | 读路径 + 凭证路径模式表（`.env`、`*.key`、`secrets/`） | SECRET |

工牌四字段随 WP1 的 v2 编码落地；`consume` 请求携带 `context_taint` / `arg_taint` / `clearance`。

**污点定位红线（M§1.1-3/4）**：污点判定只产生 `approval_required` / `deny` 与巡逻特征；任何代码路径不得因"污点干净"而跳过其他检查。

验收门槛：
1. 每个下沉点单测（11 处打标 × 策略表全行覆盖）；
2. InjecAgent 风格用例拦截率报告（数字入文档，不许愿）；
3. 正常任务回归 ≥ 95%（WP0 的 11 任务基线）；
4. 兼容档（`orin_policy_profile=compat`）行为 = 旧行为 + 记录。

回退开关：`orin_policy_profile=compat` 即旧行为；污点打标代码可整体关闭。

### WP3：蜜罐、阶梯、审批消毒、巡逻前三件（D P2）

新建：`js/orind/canary.py`、`js/orind/responder.py`、`js/orind/patrol/{rate,egress,entropy}.py`。

| 机制 | 施工要点（含 M 的修正） |
|---|---|
| CanaryVault | 凭证型 3–5 枚 + 语义型 1–2 枚/会话；放置 = `handoff_vault` + 记忆库先行，**工作区深层路径默认关**（决策 D4）；比对挂在 `net_guard.resolve_and_validate` 下沉点（`:134` 已核实）+ shell 参数 + 写外区内容；对已审批外发同样比对 |
| 双证据 | 外发命中 ∧ 会话读取事件 ⇒ L3 FREEZE；单命中 ⇒ L1 + orind 自审日志；冻结/拒绝措辞统一固定文案 |
| Responder 阶梯 | L0–L5 六级（D§6.5）；冻结 = orind 在线吊销全部工牌即时生效；**阶梯状态机即未来合并阶梯的 orind 半边，K§16.3 的"响应动作需管理员主人证"以 TODO 注释标记，阶段 B 实现** |
| 审批消毒 | `js/security/approvals.py`（`ApprovalRequest:79` 已核实）：动作描述截断 + 转义 + 污点/密级徽标 + 按动作类型模板生成的"最坏结果一句话"（不用 LLM） |
| Patrol | 速率（EWMA 滑窗）、外发（HyperLogLog host 多样性）、熵（流式直方图）；消费 `js/echo/ledger/` outbox；**只产出收紧建议，永不放行**；新会话前 20 次调用 warmup 只观察 |

验收门槛：
1. 蜜罐双证据命中 < 1s 冻结（测试注入实测）；
2. 误报率 < 1%（回归任务集 + 申诉样本）；
3. 统一措辞检查（拒绝文案不含触发机制信息）；
4. Patrol 三检测器各自误报/检出用例通过。

回退开关：金丝雀全局停用、阶梯锁定 L0、巡逻只记录，三者独立。

---

## 5. 性能目标（目标值，WP0 后回填实测）

| 指标 | 阶段 A 目标 | 测量 |
|---|---|---|
| 每次工具调用新增延迟 | p99 < 500µs | WP0 前后 A/B，mock provider |
| orind 判定吞吐 | ≥ 10k/s | 直连 UDS 压测 |
| orind 常驻内存 | < 50MB | 稳态 + 100 会话模拟 |
| 蜜罐比对 | < 50µs / 10KB | 微基准 |

不达标时的优化顺序（K§10.4 纪律）：消息复制 → 策略查表 → 日志持久化；**不得**通过关闭核销在线化、放宽 fail-closed 换数字。

## 6. 兼容红线 checklist（每个 WP 合并前逐项过）

- [ ] 旧 HMAC 账本链验证通过（用基线 state_dir 实测）
- [ ] `orin_enabled=false` 时行为与基线完全一致
- [ ] 所有改动 = 加字段/加钩子/加默认值；无旧 API 行为变更
- [ ] mypy strict 零错误、ruff 通过、pytest 全绿（三件套）
- [ ] 新配置项全部有缺省值且有文档注释

## 7. 阶段 A 明确不做（防范围蔓延）

- 不做 IntentEnvelope / Handle Broker / StateWitness / EffectDraft（阶段 B，K§7–8）
- 不做 Effect Cell 迁移；工具 handler 仍在主进程（阶段 B/C）
- 不做提交状态机 / UNKNOWN_COMMIT 对账（阶段 B）
- 不做出门证两阶段执行（阶段 B）；WP2 只把 SECRET 位和 clearance 数据通路建好
- 不引入 Rust（决策 D2）；不出门面 Windows 实现（决策 D1）
- 不做签名策略包（D P4 内容，阶段 A 策略表内置于代码 + 配置）
- 不删除/不改写任何现有安全模块（guard/parser/rules/audit 原样保留为顾问层）

## 8. 风险登记

1. **pyahocorasick 新依赖**：C 扩展，需构建链；不通过评审则降级 `re` 并记录性能让步。
2. **Keychain 受控取出的工程细节**（`security` CLI vs Security.framework 绑定）未验证，WP1 内先 spike，最坏回退 dev 档 + 文档标注。
3. **11 处打标点的上下文携带机制**（污点如何随 ChatMessage 流转）是 WP2 最大设计自由度，施工前需 30 分钟设计评审，产出打点数据结构后动工。
4. **红队 PoC 回归**：基线快照含 `docs/security/redteam/` 五个 PoC，WP2/WP3 验收应把它们纳入回归集。
5. **orind 崩溃恢复重放**期间的在途 lease 语义（`_load_ledger` 现有 JSONL 重放 + revocations 表）需属性测试覆盖崩溃中点。

## 9. 下一步

阶段 A 三个 WP 全部验收后，按 M§3.1 进入阶段 B 规划（Build Cell 先行 → Secret/Network/Connector Cell → File Cell + 提交膜），届时本规格的安全声明边界表更新为阶段 B 版本。
