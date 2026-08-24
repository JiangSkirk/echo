# Orin 阶段 B「权限搬家」实施规格

> 状态：实施规格，机器生成（OpenCode），依据用户 2026-08-23 阶段 B 任务书编写；收尾时登记 TECH_DEBT.md
> 日期：2026-08-23（Asia/Shanghai）
> 基线：commit `dd0b862`（阶段 A 基线，pytest 6356 passed + 2 条预存在失败），分支 `feature/orin-stage-b`
> 上游文档：终态北极星 `ORIN_EFFECT_KERNEL_V1.md`（**K**，本阶段落地 K§7.2–7.10、§8、§9.1–9.4、§16.3）；
> 机制库存 `ORIN_DESIGN.md` v1.3（**D**，冻结）；决策 `ORIN_MERGE_REVIEW.md`（**M**，17 条已拍板，阶段划分以 M§3.1 为准）；
> 施工权威前置 `ORIN_STAGE_A_SPEC.md`（**A**，已完成；协议六类消息/工牌 v2/同一本 JSONL/回退开关必须兼容）
> 冲突裁决顺序：兼容红线听 A，终态语义听 K，阶段范围听 M§3.1，文件清单/WP/验收听本规格。

---

## 1. 声明边界（施工期间和验收后都必须遵守）

阶段 B 把「凭证、外发、代码执行、工作区写」四张面从 Echo 进程搬到 Orin 调度的 Effect Cell；
Echo 只提 `EffectDraft`，许可证 / CommitPermit **不回传 Echo**。

| 阶段 B 完成后**可以**宣称 | 阶段 B **不得**宣称 |
|---|---|
| 凭证、外发、代码执行、工作区写四个面对 Echo 进程失陷收口（限已迁入 Cell 的效果类） | 全进程失陷收口（Desktop/Memory Cell 整迁、Echo 最小 OS 权限属阶段 C） |
| 外部提交无重复副作用（故障注入下重复次数 = 0，实测入报告） | 防 root / 内核失陷 |
| 许可证不回传 Echo；模型文本不能制造权限对象（权限型参数必须句柄） | 图像注入完全免疫；视觉闭环（桌面仍为截图只读 + 点击必审批） |
| SECRET 上下文不能自动外发（export_gate + 两阶段出门证） | enforce 拒旧 HMAC 协议、移除 ambient authority（阶段 C，K§15.6 十条不上线） |
| 每个 Cell 动作有签名收据、可对账 | 任何未实测的性能数字（µs/qps 一律不许愿；量不了标 untested） |

声明边界写入代码：凡阶段 B 新增的用户可见文案、CLI 输出、注释中的安全承诺，违反上表即评审不通过。
产品名纪律：APFS clone 一律称「工作区回滚」，禁止「可撤销世界」。

---

## 2. 冻结协议扩展：orin/v1（阶段 B 子集）

### 2.1 不变项（一行不改，施工红线）

- 传输层沿用 A§3.1：UDS `<state_dir>/orin/orind.sock`（0600）、4 字节大端 u32 + JSON ≤64KB、
  HMAC-SHA256 会话密钥 + 单调 u64 seq + 会话 nonce、深度 ≤16、未知字段拒绝、令牌桶 100 rps/burst 200/队列 1024。
- 阶段 A 六类消息（hello/issue/consume/revoke/heartbeat/freeze 及各 ack）的字段白名单、语义、错误码**零改动**。
- 工牌 v2 编码与 `_canonical_lease_payload` 旧字节冻结；租约真相仍是同一本 `<state_dir>/echo_tool_lease.jsonl`；
  SQLite WAL **不加 revocations 表**（新增 intents/handles/effects/receipts 等新表允许）。

### 2.2 能力协商（caps）

`hello.caps` 是阶段 A 已有的可选白名单字段，阶段 B 扩展其取值域：

| cap | 解锁能力 |
|---|---|
| `intent.v1` | 收发 `intent`/`intent_ack`（主人证登记与查询） |
| `handle.v1` | 收发 `handle`/`handle_ack`（句柄签发/解析/候选集） |
| `draft.v1` | 收发 `draft`/`draft_ack`（EffectDraft 评估入口） |
| `commit.v1` | 收发 `commit`/`commit_ack`、`receipt`/`receipt_ack`、`reconcile`/`reconcile_ack` |
| `cell.build` / `cell.file` / `cell.net` / `cell.secret` / `cell.connector` | 对应 Cell 的身份接入（回连连接宣告） |

纪律：

- 旧客户端不带新 caps ⇒ 六类消息照常可用（灰期共存）；
- 对端发来未协商 cap 对应的新消息类型 ⇒ 立即断开并审计（同未知字段拒绝级别）；
- envelope 层不新增顶层信封字段。

### 2.3 新消息类型（最小集 7 类，字段白名单整表冻结）

方向约定：`C→O` = 客户端（Echo/AppShell/Cell）→ orind；`O→C` = orind → 连接对端。
认证消息沿用 seq+nonce+mac 信封；ack 统一 `ok/code/reason` + 各自载荷。

| 消息 | 方向 | 载荷字段白名单摘要（实现以 `_SCHEMA` 元组为准） |
|---|---|---|
| `intent`/`intent_ack` | C→O | `op`(register\|active\|admin_unfreeze)、`intent`(dict, K§8.2 子 schema) |
| `handle`/`handle_ack` | C→O | `op`(issue\|resolve\|seed_list)、`kind`(七种句柄)、`spec`(dict)、`handle`(dict 回程) |
| `draft`/`draft_ack` | C→O | `draft`(dict, K§7.5 子 schema)、`context_taint`/`arg_taint`/`clearance`(int 可选)；ack 加 `verdict`(§2.4 八类)、`missing`(list)、`witness`(dict 可选) |
| `preflight`/`preflight_ack` | O→Cell | `draft_id`、`executor_id`；ack 加 `witness`(K§7.6 StateWitness 子 schema) |
| `commit`/`commit_ack` | O→Cell | `permit`(K§8.4 CommitPermit 子 schema)。**只在 orind→Cell 认证连接下发，绝不经过 Echo** |
| `receipt`/`receipt_ack` | Cell→O | `receipt`(K§8.5 EffectReceipt 子 schema)；orind 落 WAL 并链式哈希 |
| `reconcile`/`reconcile_ack` | C↔O | `effect_id`、`probe`(dict 可选)；ack 加 `state`(committed\|absent\|unknown) |

IntentEnvelope 子 schema 按 K§8.2 整表实现（严格拒绝未知键）：`protocol/intent_id/subject{owner_key_hash,product_id,profile}/task_id/raw_request_hash/allowed_effect_classes/allowed_resource_handles/allowed_sink_handles/budgets{max_invocations,max_bytes_read,max_bytes_out,max_cost_minor_units}/approval_policy/issued_by/issued_at/expires_at/signature`。
Handle 家族按 K§7.3 表：DirectoryHandle/ArtifactHandle/RecipientHandle/EndpointHandle/AccountHandle/SecretHandle/DesktopTargetHandle（最后一种**只留类型不签发**）。

### 2.4 判定与错误码扩展

- `draft_ack.verdict` 八类（K§7.7）：`allow_read / allow_stage / require_approval / require_dual_control / deny_policy / deny_missing_witness / deny_stale_state / defer_reconciliation`。
- Gate Kernel 判定 = K§7.7 合取，缺一即 deny；返回给模型只有稳定低信息量类别，完整原因进受保护审计。
- `ERROR_CODES` 追加：`unknown_intent`、`unknown_handle`、`stale_state`、`backpressure`（现有 19 个错误码零改动）。

---

## 3. 文件清单与包结构

全部置于 `js/` 内以继承 `runtime_tcb` 写保护：

```
js/orin/                      # Echo 侧客户端面（schema + 薄客户端）
├── intent.py                 # IntentEnvelope 严格 schema、验签、会话内只收紧检查
├── handles.py                # OriginHandle 家族 schema + HandleClient 面
└── draft.py                  # EffectDraft / StateWitness / CommitPermit / EffectReceipt + GateVerdict 枚举
js/orind/
├── intent_store.py           # 主人证登记（WAL intents 表）、验证密钥、R2/R3 前置检查
├── broker.py                 # Handle Broker：签发/解析/播种候选集（通讯录/历史收件人/cron 模板）
├── manifest.py               # Effect Manifest 注册表（本地签名；MCP 未知工具默认开放世界行）
├── kernel.py                 # Gate Kernel：K§7.7 合取 → §2.4 八类判定
├── membrane.py               # （仅 WP10）提交状态机 + UNKNOWN_COMMIT 对账 + R0–R3 持久化分级 + 背压令牌桶
└── cells/
    ├── __init__.py
    ├── base.py               # CellBase：回连 orind UDS、一次性会话钥握手（复用 A 握手）、心跳、dispatch
    ├── build.py              # Build Cell：os_sandbox.SandboxExecutor 后端，常驻池
    ├── file.py               # File Cell：staging + 逃逸防御 + 原子 rename/CAS；WP10 接入膜
    ├── net.py                # Network Cell：签名 Endpoint Manifest 强制
    ├── connector.py          # Connector Cell：服务专属凭证、无 token passthrough、出门证原样发送
    └── secret.py             # Secret Cell：SecretHandle 签发、audience 绑定、Keychain 优先
```

修改文件：

| 文件 | 改动 |
|---|---|
| `js/config.py` | OrinConfig 扩展：`stage_b=False` 总闸 + `cell_build/cell_secret/cell_net/cell_file/commit_membrane=False` 五独立开关 |
| `js/orind/daemon.py` | Cell 回连 socket（`<state_dir>/orin/cells.sock`，短路径搬家沿用）+ 新消息 dispatch + cap 门禁 |
| `js/orind/responder.py` | 清 `:73 TODO`：L3+ 解冻/策略回滚 = R3，需管理员主人证（intent.op=admin_unfreeze） |
| `js/agent/tool_executor.py` | `stage_b && cell_build` 时 shell/code 分流 Build Cell；其余工具照旧阶段 A 工牌路径 |
| `js/tools/shell.py` / `code.py` | 增加 cell 后端分支；开关关时进程内路径一行不改 |
| `js/appshell/routers.py` | 用户确认任务边界时经 AppShell 签名身份签发 IntentEnvelope（Echo 不可写通道） |
| `js/security/net_guard.py` | Connector/Network Cell 挂载点（复用 resolve_and_validate，不另写 SSRF） |

---

## 4. 工作包拆解

依赖顺序：B0 → 4 → 5 → 6 → 7 → 8 → 9 → 10，**禁止跳步**；每 WP 先测试后实现，
局部绿后过三件套（只允许 net_guard/auth_security 两条预存在红），验收不过不进下一个。
**膜只在 WP10 实现一份**（File Cell 与 Connector 外发都从这一份走）；WP9 不预埋第二套。

### WP-B0：本规格 + 自检

- [x] 规格成文（本文件）
- [ ] 自检与 A/K/M 无矛盾（协议扩展不破坏 A§3；范围 = M§3.1 B 行；语义对齐 K§7–9）
- [ ] 基线复用 `benchmarks/orin/WP0_BASELINE.*`，新数字一律实测后写

### WP4：三证+草案类型与协议（先数据结构，后接线）

交付物：`js/orin/{intent,handles,draft}.py`、`js/orind/kernel.py` 骨架、protocol.py caps+7 类消息、WAL 新表。

验收门槛：
1. schema 往返测试 + 未知字段拒绝测试（逐消息类型）；
2. 无 AppShell 签名私钥的进程无法产出合法 IntentEnvelope（Echo 无法伪造主人证）；
3. 过期 StateWitness 拒绝（deny_stale_state / expired）；
4. CommitPermit 不出现在任何 Echo 可见结构（draft_ack/工具结果不含 permit 字段——回归测试钉死）；
5. 无 cap 对端发新类型 = 断开；
6. `stage_b=false` 时主路径仍只走阶段 A 工牌（对照测试）。

回退开关：`stage_b=false`（总闸）。

### WP5：AppShell 签发主人证 + 管理员解冻

交付物：AppShell intent 签发端点、默认模板（Personal=读+暂存+出门证申请权；Work=读+暂存+常设授权；工厂模板可配置占位）、会话内只收紧、responder.py 管理员证解冻。

验收门槛：
1. 无主人证不能获得 R2/R3 效果授权；
2. 伪造主人证（错误签名/过期/扩权字段）全部拒；
3. 冻结后只有管理员主人证能解冻；Echo 自动解冻路径不存在（代码审计 + 测试）；
4. 会话内扩权尝试被拒且产生审计事件（I-08）。

回退开关：随 `stage_b`。

### WP6：Handle Broker + 播种 + Effect Manifest

验收门槛：
1. 权限型参数必须句柄：`email.send(recipient="attacker@…")` 类自由文本拒；只接受 `recipient_handle`；
2. 播种候选集（用户通讯录、历史任务收件人、cron 模板）非空时开放任务不卡死；Echo 只能选候选；
3. 新对象 = 一次性审批后入册（handle_ack 记录审批来源）；
4. MCP/第三方工具不信 readOnlyHint/destructiveHint/描述文本；未知工具默认开放世界、可写、可能破坏、非幂等 ⇒ 升审批；
5. 工具描述哈希钉扎保留并升级为本地签名 Manifest。

回退开关：随 `stage_b`。

### WP7：Build Cell（第一个 Cell）

施工要点：复用 `os_sandbox.SandboxExecutor`（不重写引擎）；默认无网络、无真实凭证、只挂任务 overlay；
CPU/内存/进程数/输出/时间上限；输出 = 不可信 TOOL_RESULT 污点（沿用阶段 A fold 点）；持久改动走 File Cell（WP9）；
Build Cell 常驻池，冷启动不进交互快路径。

验收门槛：
1. `stage_b && cell_build` 打开时 `tools/shell.py`/`code.py` 在主进程不再直接起无约束子进程；
2. kill Build Cell ⇒ 该类动作停、其他工具不受影响（隔离测试）;
3. 无网络/无凭证有测试（Cell 内 curl/ping 失败、凭证环境变量不存在）；
4. 输出污点标记 TOOL_RESULT 回归通过。

回退开关：`cell_build=false` 回阶段 A 进程内 shell/code（仍受工牌/沙箱/审批）。

### WP8：Secret Cell + Network/Connector Cell + 两阶段出门证

施工要点：SecretHandle 取不回明文；audience/操作/次数/期限绑定；生产钥优先 Keychain ACL（不宣称 Enclave 做 HMAC）；
Network 只打签名 Endpoint Manifest 端点；DNS/重定向/代理/最终目标同一授权边界校验（挂 net_guard.resolve_and_validate）；
Connector 持服务专属凭证禁止 token passthrough；外发走幂等键、预算、visibility；Connector 按需拉起。
出门证：PUBLIC 不能读 SECRET；CONFIDENTIAL 默认无外发；批准对象 = payload_hash + destination_handles + state_witness；
Connector Cell 无 LLM 原样发送，不交新模型改写；出门证不是扫描豁免（预算/收件人/租户/audience 仍过主人证与策略）；
**已审批外发仍要比对蜜罐**（hooks.inspect_canary_text 挂 Connector 发送前）。

验收门槛：
1. SECRET 上下文自动外发 = `export_gate`；
2. 无出门证发不出去；重定向改目标被拒；
3. token 不出现在 Echo 工具结果里（回归测试钉死）。

回退开关：`cell_secret=false` / `cell_net=false` 独立回退。

### WP9：File Cell 本体（不做膜）

施工要点：只接触句柄授权目录；默认写 staging/overlay；防符号链接、硬链接、大小写/规范化、挂载逃逸；
提交 = 规范化 diff + 文件数 + 字节 + 覆盖对象 → 用户或预授权模板批准精确 diff → 再核源哈希和路径句柄 →
临时文件 + 原子 rename/CAS。APFS clone 只做「工作区回滚」加速，不是安全语义。File Cell 无网络权限，常驻池。
**提交状态机 / UNKNOWN_COMMIT 不在本 WP 实现**（WP10 一份）。

验收门槛：
1. 相对路径写进 owner root（现有 work 测试必须继续绿）；
2. staging 未批准不出现在真实工作区；
3. 符号链接逃逸拒；硬链接/大小写规范化逃逸拒。

回退开关：`cell_file=false`。

### WP10：提交状态机 + UNKNOWN_COMMIT + R0–R3 + 背压（唯一一份膜）

交付物：`js/orind/membrane.py`——K§9.1 状态机（PROPOSED→DENIED/PREFLIGHTED→APPROVAL_PENDING→PREPARED→COMMITTING→COMMITTED/UNKNOWN_COMMIT→reconcile→RECEIPTED，禁盲重试）；
崩溃语义按 K§9.2 表逐行实现并测试（外部调用中崩溃 ⇒ UNKNOWN_COMMIT，重启先 reconcile）；
通道持久化分级：R0 普通 receipt / R1 暂存元数据 / R2 durable prepare / R3 强持久化+双签或冷静期；
背压（K§9.4）：每 owner/session/task/effect class 令牌桶、队列硬上限、超大 payload 只读句柄、审批等待不占执行 worker；
连接器能力登记表（K4）：幂等/草稿/etag/对账查询四格，缺格 ⇒ 自动升审批并写明残余风险（先给现有 connector 建表，多半「不支持」）；
File Cell 工作区提交与 Connector 外发统一接入本膜。

验收门槛：
1. 故障注入下重复副作用次数 = 0（实测数字写入报告）；
2. 正常任务回归 ≥95%（`python -m benchmarks.runner --mock` 11/11）；
3. 日均审批/误报量不了就标 untested，禁止写成已达标。

回退开关：`commit_membrane=false` 时不进 UNKNOWN_COMMIT 路径，外发/写回退阶段 A 工牌+审批并在日志标明无强保证。

---

## 5. 兼容红线 checklist（每个 WP 合并前逐项过）

- [ ] 旧 HMAC 账本链验证通过（用 dd0b862 的 state_dir 实测）
- [ ] `orin_enabled=false` 且 `stage_b=false` ⇒ 行为与 dd0b862 完全一致
- [ ] 六类旧消息语义零改动；旧客户端（无新 caps）issue/consume 正常
- [ ] 所有改动 = 加字段/加钩子/加默认值；无旧 API 行为变更
- [ ] 租约真相仍在 JSONL；WAL 未加 revocations 表
- [ ] ChatMessage.taint 未进入模型 API 序列化（阶段 A 回归保留）
- [ ] guard/parser/rules/audit 未动；os_sandbox 仅被调用未被改写
- [ ] 许可证/CommitPermit 未出现在 Echo 可见结构
- [ ] mypy strict 零错误、ruff 通过、pytest 全绿（仅 2 条预存在红）
- [ ] 新配置项全部有缺省值且有文档注释；六个新开关相互独立

## 6. 阶段 B 明确不做（防范围蔓延）

- 阶段 C 全部内容：Echo 最小 OS 权限、enforce 拒旧 HMAC 协议、移除 ambient authority、K§15.6 十条当上线门槛
- Desktop Cell 整迁、图像注入新机制、fleet 委托
- Memory Cell 独立进程化（保持阶段 A 打标即可）
- 删除/改写阶段 A 六类消息或旧 HMAC 语义
- 删除/重写 guard.py/parser.py/rules.py/audit.py/os_sandbox.py
- 引入 Rust、Windows 命名管道实现、新 C 扩展
- 许可证回传 Echo、Echo 自签主人证、`if taint_clean: skip`
- 提交密钥、攻击 PoC、把目标值写成「已达标」
- 「修」两条预存在 auth 测试语义

## 7. 性能与基线纪律

基线复用 `benchmarks/orin/WP0_BASELINE.*`（任务 p50 94ms/p99 215ms 等），不编新数字。
阶段 B 唯一量化验收：重复副作用 = 0（故障注入实测）、mock 11 任务 ≥95%。
冷启动/延迟目标参考 K§10.4 但不作承诺；未测指标一律标 untested。

## 8. 风险登记

1. **Cell 子进程生命周期**：僵尸进程/孤儿 socket 清理；orind 重启时 Cell 池重建顺序。
2. **Keychain 受控取出**（继承 A 风险条目）：WP8 内 spike，最坏回退 dev 档 + 文档标注。
3. **os_sandbox 在 Cell 进程内的行为差异**：嵌套 env/git 探测需在子进程中复测。
4. **Connector 现状 mock/experimental**：能力登记表四格多半「不支持」⇒ 默认升审批是常态而非异常。
5. **AppShell 前端改动范围**：主人证签发 UI 与出门证展示的最小实现边界，避免蔓延到整个前端重构。
6. **膜的唯一性**：WP9 期间 File Cell 直接原子 rename（受 Gate Kernel 审批门控）；WP10 合入时一次性切换到膜，防止双实现并存。
