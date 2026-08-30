# OpenCode 任务：实施 Orin 阶段 A「保安上岗」

你是 titan-agent / JS Agent 仓库的实施代理。只做 **阶段 A**。不要发明新架构，不要提前做阶段 B/C。

仓库：`{repo_root}`
建议分支：从当前 `feature/echo-runtime` 切出 `feature/orin-stage-a`（若已存在则在其上继续，不要另起第三套设计）。

---

## 0. 四份文档怎么用（已人工终核）

| 文件 | 角色 | 你怎么用 |
|---|---|---|
| `docs/security/orin/ORIN_EFFECT_KERNEL_V1.md`（K） | **终态北极星** | 读懂“Echo 只提案、Orin 盖章、许可证不回传 Echo”。阶段 A **禁止**实现 K 的三证/Cell/提交膜。 |
| `docs/security/orin/ORIN_DESIGN.md` v1.3（D） | **机制库存，已冻结** | 只取 P0–P2 机制。D 摘要里“未授权外发=0 / 污点即主授权 / 进程内工牌兜底即终态”**作废**，以合并评审为准。 |
| `docs/security/orin/ORIN_MERGE_REVIEW.md`（M） | **已拍板决策** | 17 条决策全部按建议执行，不得重开辩论。 |
| `docs/security/orin/ORIN_STAGE_A_SPEC.md`（A） | **施工权威** | 文件清单、协议、WP 顺序、验收门槛、回退开关以 A 为准。与 D 附录 D.1 冲突时听 A §3。 |

一句话：阶段 A 把现有 HMAC 工牌的签发/核销/吊销搬进独立 `orind`，加上污点信号、蜜罐报警、巡逻收紧、六级阶梯。Echo 仍然干活；Orin 开始当保安。**还不能宣称防 Echo 进程 RCE。**

---

## 1. 产品原则（写进代码注释和用户文案）

Echo = 员工：规划、调用技能/工具提案、把结果讲给人。
Orin = 保安：发证、核销、吊销、记收据。快路径 **无 LLM、无分类器放行**。

铁律：

1. 判定路径永不调用模型。
2. fail-closed：orind 失联 ⇒ 默认停发新工牌（`orin_fail_mode=closed`）。不是白屏：纯对话可继续，新副作用停。
3. 污点 / 蜜罐 / 巡逻 **只产生** `approval_required` / `deny` / 收紧后续权限，**不得**因为“污点干净 / 没撞蜜罐”而跳过工牌、路径沙箱、Origin 等既有检查。
4. 兼容红线：加字段、加钩子、加默认值。旧 HMAC 账本链 MAC 预像一行不改。`orin_enabled=false` 必须与改前行为一致。
5. 阶段 A 用户可见文案 **禁止**出现：防 RCE、语义泄露结构性归零、子进程外发归零、任何未实测的 µs/qps 数字。

已拍板（不得改）：

- 语言：Python。不引入 Rust。
- 平台：macOS/Linux Unix socket；Windows 命名管道只留接口。
- orind 失联：`closed` 默认，`readonly` 可配。
- 出门证 UX：阶段 A 只铺 SECRET/clearance 数据通路，不做两阶段出门证。
- 蜜罐：`handoff_vault` + 记忆库；工作区深层伪装路径默认关。
- 多 Agent / fleet：不做，协议可预留字段。
- 现有 `js/security/{guard,parser,rules,audit}.py` 原样保留为顾问层。

---

## 2. 开工顺序（必须按 WP，验收不过不准进下一个）

### WP0 基线（先于业务改动）

按 A §4 WP0：`benchmarks/orin/baseline.py`，记录工具调用 p50/p99、LeaseAuthority issue/consume 微基准、常驻内存、`pytest tests/` 耗时。数字写进报告，不要编。

### WP1 `orind` 骨架 + 工牌在线化

包结构严格按 A §4 WP1（`js/orin/` 客户端，`js/orind/` 守护进程，放在 `js/` 下以吃到 `runtime_tcb` 写保护）。

协议冻结：A §3。

- 传输：UDS `<state_dir>/orin/orind.sock`，0600；4 字节大端长度 + JSON，单帧 ≤ 64KB。
- 会话密钥由 **orind 生成**，一次性 fd 或 0600 文件；主进程重启轮换。
- HMAC-SHA256 + 单调 `seq` + nonce；回退/重复断开并审计。
- 严格解析：未知字段拒绝、JSON 深度 ≤ 16。
- 阶段 A 消息仅 6 类：`hello` / `issue` / `consume` / `revoke` / `heartbeat` / `freeze`。
- 每客户端令牌桶 100 rps / burst 200，队列 1024。

工牌 v2（最危险的兼容点）：

- `js/echo/types.py` 的 `CapabilityLease` 现为冻结 15 字段形状。新增 `taint_floor` / `taint_sink` / `sandbox_profile` / `clearance` 必须带 D 附录 D.2 缺省值。
- **`_canonical_lease_payload` 对旧字段集的字节不得改变。** 旧 MAC 前缀仍为 `authority-hmac-sha256:`。仅当任一新字段非缺省时用 `authority-hmac-sha256-v2:` 并追加四字段。新 orind 验旧前缀 = 旧语义放行 + 记录。
- 用基线 `state_dir` / 旧 lease 样本实测旧链仍能 verify。

主进程接入（这些调用点都要吃到适配器，不要只改一处）：

- `js/agent/tool_executor.py` `_get_echo_tool_lease_authority`（约 4916）
- `js/appshell/routers.py` 同类 getter
- `js/echo/effect_interpreter.py` 经 agent getter

适配器必须保持现有 `LeaseAuthority` 公共方法语义（issue / consume / revoke / verify）。`orin_enabled=false` 走原内存/JSONL authority。

配置：在 `js/config.py` 的 pydantic Settings 增加 `orin_*`：`orin_enabled`（默认 false，直到 WP1 测绿再考虑默认 true，**合并前默认 false 更安全**）、`orin_fail_mode`、`orin_socket_path`、`orin_keybox_tier`、`orin_shadow_mode`、`orin_policy_profile`。每个字段有缺省和注释。

KeyBox：dev = 0600 文件；production = macOS Keychain 受控取出。Keychain 先做 spike，失败则 dev 档 + 文档标注，不要假装 Enclave HMAC（Enclave 不做 HMAC）。

测试：`js/orin/testing.py` 进程内假 orind，单测不依赖 launchd。

WP1 验收：A §4 WP1 四条 + IPC 洪水/重放/未知字段/超长帧全部拒绝且守护进程不崩。`kill orind` ⇒ 停发。三件套：`uv run ruff check . && uv run mypy js && uv run pytest tests/ -q`。

### WP2 污点 + 策略表

- `js/orin/taint.py`：u64 位定义按 D §6.1；拼接=OR；窗口衰减；SECRET 不衰减。
- `js/orind/policy.py`：双档 conservative/compat；缺省行；优先级 **deny > export_gate > approval > allow**（出门证数据通路预留，阶段 A 不执行两阶段出门）。
- 11 处打标按 A §4 WP2 表。**行号会漂，以符号为准重新定位**，不要死盯旧行号。
- 施工前先设计「污点如何挂在 ChatMessage / turn 状态上」的数据结构（A §8 风险 3），写进 `js/orin/` 模块注释，再打点。
- consume 请求带 `context_taint` / `arg_taint` / `clearance`。
- 红线：不存在 `if taint_clean: skip_other_gates`。

WP2 验收：11 处打标单测、策略表全行、compat 档 = 旧行为+记录。防御性回归可纳入 `docs/security/redteam/` 已有验证脚本的**阻断断言**，不要新写可利用 PoC。

### WP3 蜜罐 / 阶梯 / 审批消毒 / 巡逻前三件

按 A §4 WP3。Canary 比对挂在 `js/security/net_guard.py` `resolve_and_validate`、shell 参数、写外区内容。已审批外发也要比对。拒绝文案固定，不泄露触发机制。

`pyahocorasick`：先评估依赖；批不过就用标准库多模式，并在 TECH_DEBT 记性能让步。

Responder L0–L5 按 D §6.5。K「解除冻结需管理员主人证」用 TODO 标阶段 B，不要在 A 伪实现。

Patrol 只建议收紧，warmup 前 20 次只观察。

---

## 3. 明确不要做

- IntentEnvelope / Handle / StateWitness / EffectDraft / Effect Cell / UNKNOWN_COMMIT
- 把工具 handler 迁出主进程
- 出门证两阶段执行、APFS undo、双签冷静期、策略包 Ed25519 灰度（那是后续阶段）
- 删除或重写 `guard.py` / `parser.py` / `rules.py` / `audit.py` / `os_sandbox.py`
- 改旧 HMAC journal 语义
- 默认打开 Windows 实现、Rust crate、fleet 委托
- 提交密钥、写攻击步骤、把目标值写成“已达标”

---

## 4. 工程约束（本仓库）

- `from __future__ import annotations`，Python 3.12+，行宽 100。
- 新代码必须过 mypy strict。
- 正常副作用仍走 Echo 入口；Orin 是盖章，不是第二条聊天运行时。
- 不要 `git push`。不要改 git config。用户没要你提交就别 commit；若用户要提交，信息写“为什么”（Orin 阶段 A 把门禁从 Echo 进程里搬出去）。
- 改完更新 `TECH_DEBT.md` 一句：阶段 A 实施以本规格为准，声明边界见表。

---

## 5. 完成后的回报格式

1. 做了哪些 WP，哪些开关默认值。
2. 旧 lease / 旧账本如何验证仍绿。
3. `orin_enabled=false` 对照结果。
4. 三件套数字。
5. 没做的阶段 B 清单（确认没漏做进去）。
6. 已知风险（Keychain spike、ahocorasick、打标挂载方式）。

先读 A 全文和 M §1–§3，再动第一行业务代码。WP0 数字没落地之前不要改 `capability.py`。
