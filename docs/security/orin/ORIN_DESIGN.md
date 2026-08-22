# Orin：JS Agent 的确定性安全防护架构

**设计报告 v1.3（终版）**

> 状态：设计方案（未实施）
> 作者：Kimi（机器生成，需人工评审；登记进 TECH_DEBT.md）
> 日期：2026-08-22
> 版本历史：v0.1 初稿 → v0.2 经 20 轮自审修订 → v0.3 极限突破机制 → v1.0 核验后终版 → v1.1 轮回式全面复查修订 → v1.2 轮回复查第 2 轮修订 → v1.3 轮回复查第 3 轮修订（修订记录见附录 A）
> 关联：`js/echo/`（员工运行时）、`js/security/`（现有防护）、`docs/security/`、`docs/echo/`

---

## 摘要

JS Agent 的 Echo 运行时已经具备能力工牌（capability lease）、审计账本、AST 命令规则等企业级安全地基，但与现代所有 Agent 系统共享三个结构性弱点：防护逻辑与被防护者同进程同权限、依赖可绕过的内容检测、对"语义级泄露"等已知极限只能承认无法解决。本报告提出 Orin——一个与 Echo 职责分离的独立防护子系统（"保安"）。Orin 遵循三条铁律：决策路径永不含 LLM（设计免疫注入）、只做确定性判定（证件/污点/行为，不做语义判断）、快路径全确定性而慢路径全异步。技术上，Orin 将现有对称 HMAC 工牌体系的签发/核销/验证/吊销整体迁入独立守护进程 orind（密钥硬件锚定，吊销即时生效），在工牌上扩展 64 位污点向量与密级维度实现"污点即权限"，并引入四项调研范围内未见同款组合的机制：双证据蜜罐仓、每 turn 动态合成的沙箱画像、六级响应阶梯、以及把语义泄露转化为访问控制问题的"密级分区 + 出门证"。全部关键路径检查为微秒级确定性操作，每次工具调用新增开销预算 < 500µs（p99），约占一次模型往返的 0.1%。报告同时给出 P0–P5 技术路线、模块级实现方案、产品能力与部署运维方案、以及基于 AgentDojo/ASB 的验证计划，并诚实列明残余极限。

**关键词**：Agent 安全；能力安全；信息流控制；污点追踪；蜜罐；沙箱；fail-closed；低延迟

---

## 目录

1. 引言
2. 相关工作与调研结论
3. 威胁模型
4. 设计原则
5. 系统总体架构
6. 核心机制详设
7. 极限突破机制
8. 性能工程
9. 安全性分析
10. 技术路线与实现方案
11. 产品能力与产品实现方式
12. 验证与评估方案
13. 开放问题与决策请求
14. 结论
- 附录 A 修订记录 / 附录 B 术语表 / 附录 C 参考文献 / 附录 D 关键 Schema 草案

---

## 1. 引言

### 1.1 背景与动机

JS Agent 是面向工厂车间场景的本地个人 Agent Harness：目标用户是非技术工人，macOS 开发先行、后续部署 Windows。Echo 是其唯一运行时边界——HTTP、WebSocket、CLI、TUI、Telegram、cron、模型调用与工具执行全部经 Echo 进入，辅以 fail-closed 授权与持久化账本。

随着 Agent 从"聊天"走向"替人操作真实系统"（读写文件、执行命令、访问网络、收发消息），它实际上成为**一个拿着用户全部权限、却会阅读不可信内容的远程执行体**。2026 年对七款主流开源 Agent 的安全审计（grith.ai，单一来源，结论引用）显示：应用层 deny 规则普遍是"虚假安全感"，七家中仅一家具备 OS 级沙箱，无一家在系统调用层逐次评估。OWASP 已为此发布 Agentic Top 10（ASI01–ASI10）。

### 1.2 问题陈述

Echo 是"员工"——负责把事做成。但员工会被骗（提示注入）、会被偷（凭证外泄）、会犯错（不可逆损伤）、会被连坐（防护逻辑与员工同进程，员工被控则防护同亡）。本项目要回答的问题是：

> **如何为 Echo 设计一个"保安"子系统 Orin，使得即使模型被注入完全欺骗、主进程被部分控制，攻击者也无法造成未授权的数据外泄与不可逆破坏——同时满足安全、稳定、快速、低延迟、低开销的工程要求，且不破坏现有系统的向后兼容性？**

### 1.3 设计目标

| 目标 | 量化指标 |
|---|---|
| 安全 | 未授权外发 = 0（结构性保证，非检测率）；保安自身不可注入 |
| 稳定 | orind 崩溃有定义良好的失效语义；旧账本/旧工牌/旧数据全部兼容 |
| 快速 | 关键路径每次工具调用新增 < 500µs（p99） |
| 低延迟 | orind 判定吞吐 ≥ 10k/秒（Python 版） |
| 低开销 | orind 内存常驻 < 50MB；不增加任何 LLM 调用 |
| 可审计 | 每个安全判定有签名收据，可回放、可申诉 |
| 可用 | 正常任务回归通过率 ≥ 95%；日均审批打断 ≤ 5 次 |

### 1.4 贡献摘要

1. **双进程职责分离的工程化**：保安进程无 LLM、无网络、无外部输入，密钥硬件锚定——从结构上消除"guard 被一起注入"。
2. **污点即权限（Taint-as-Capability）**：将学术界的每变量 IFC（CaMeL）降维到工具调用粒度的工牌约束，开销低三个数量级，并配窗口衰减机制解决长会话污点饱和。
3. **双证据蜜罐仓**：凭证型 + 语义型金丝雀，近零误报的确定性泄密探测。
4. **密级分区 + 出门证**：把"语义级泄露"这一全行业标注为开放问题的极限，转化为可解的访问控制问题——未审批路径上结构性归零。
5. 配套机制：沙箱画像合成、六级响应阶梯、可撤销世界、审批经济学。

---

## 2. 相关工作与调研结论

调研范围：GitHub 四个 topic（llm-firewall / ai-firewall / agent-safety / ai-guardrails，合计约 210 个仓库，清单级浏览）、arXiv 2024–2026 Agent 安全论文约 20 篇（正文/摘要级精读）、OWASP Agentic Top 10、上述七 Agent 审计报告。完整引用见附录 C。

### 2.1 五大流派

| 流派 | 代表 | 做法 | 固有弱点 |
|---|---|---|---|
| 内容扫描器 | Meta LlamaFirewall（PromptGuard 2）、LLM Guard、各 LLM 代理防火墙 | 分类器/正则扫输入输出 | 概率性检测可绕过；扫描在关键路径加延迟；分类器自身可被对抗攻击 |
| 代理网关 | Pipelock、Lakera 等 | HTTP/MCP 流量边界拦截 | 在体外，看不到进程内文件/shell/内存操作 |
| 双模型/特权分离 | CaMeL（Google DeepMind, 2503.18813）、Dual-LLM、Progent | 特权 LLM 出计划，隔离 LLM 碰脏数据 | AgentDojo 上最强（GPT-4o 成功攻击 233→0，完成率 77% vs 84%），但第三方实测 token 开销约 2.7–2.8 倍，且需改写编程模型 |
| 策略 DSL | AgentSpec、Progent、CEL 引擎 | 手写策略运行时评估 | 策略质量取决于人；与数据流脱节 |
| OS 沙箱 | Codex（Landlock+seccomp）、Anthropic sandbox-runtime、nono | 内核级隔离 | 挡不住"界内使坏"：注入后 Agent 用合法权限替攻击者干活 |

### 2.2 学术前沿（值得借鉴）

信息流控制（Wu et al. 2409.19091；Prompt Flow Integrity 2503.15547）、运行时权威控制（AIRGuard、ClawGuard）、因果归因（AgentSentry、CausalArmor，有效但烧 LLM）、被拒绝行为的溯源图（ARM 2604.04035，并提醒拒绝措辞差异会泄露监控信号）、Meta Agents Rule of Two（单会话不得同时具备"处理不可信输入 + 访问私密数据 + 对外通信"三能力——7.1 密级分区是其工程化严格版）、OWASP ASI 控制族（意图门、JIT 凭证、记忆回滚、签名清单、熔断、kill-switch）。

### 2.3 盲区分析（Orin 的机会）

1. 检测派与结构派各走极端，无人做"确定性结构约束 + 异步行为分析"双平面；
2. guard 与 Agent 同进程同权限，几乎全行业"同住一屋"；
3. 蜜罐凭证这一传统安全的成熟手段在 Agent 领域几乎无人使用；
4. 沙箱策略静态，不与逐次授权联动；
5. 处置只有 allow/block 两档，无响应阶梯；
6. 语义泄露被普遍标注为开放问题，无人给出结构性收口。

---

## 3. 威胁模型

### 3.1 攻击者能力假设

**假设存在的攻击者：**
- A1 远程内容注入者：控制 Agent 会读到的网页/邮件/文档/工具返回（间接注入），目标 = 劫持行为、外泄数据；
- A2 恶意/被投毒的工具供应链：MCP 服务器、插件、技能描述被 rug-pull 改动；
- A3 本机同用户态的其他进程：能发起 IPC、读写其自身权限内的文件；**不能读写主进程或 orind 的内存**——macOS 对跨进程内存访问（task port）有独立授权限制，同用户态并不意味着可读写他进程内存；本设计依赖该 OS 保护成立，若不成立见 9.4 残余风险；
- A4 被部分控制的主进程：模型被完全欺骗、turn_loop 的决策被操纵，但 **Python 代码本身仍按编写执行**（攻击者只能操纵输入与决策，不能篡改执行中的代码与污点标签计算）。

**不假设的攻击者（超出边界，诚实声明）：** 宿主机 0day + root/内核级攻击者；物理攻击（Secure Enclave 级别以下）；主人本人执意作恶（治理边界，7.3 提供双签工具）；模型在授权范围内说错话（质量问题，7.2 提供损伤可回滚）。

### 3.2 OWASP ASI Top 10 映射

| OWASP | 威胁 | Orin 对策 |
|---|---|---|
| ASI01 | 目标劫持（注入） | 污点准入 + 下沉授权（6.1–6.2）+ 密级分区（7.1） |
| ASI02 | 工具误用 / confused deputy | 单次性工牌 + 参数级 scope 校验（6.2） |
| ASI03 | 身份与权限滥用 | 独立进程签发、在线核销、撤销级联、硬件钥匙箱（5.1, 6.5, 7.5） |
| ASI04 | 供应链投毒 | 工具描述哈希钉扎 + 变更告警（6.9） |
| ASI05 | 意外代码执行 | 沙箱画像合成（6.7）+ 现有 AST 规则 + 可撤销世界（7.2） |
| ASI06 | 记忆/上下文投毒 | 记忆污点标签 + 使用面限权 + 异步复核隔离（6.10） |
| ASI07 | Agent 间通信 | 单 Agent 为主，协议预留 delegation chain（§13-3） |
| ASI08 | 级联失败 | 巡逻检测 → 响应阶梯降速冻结（6.4–6.5） |
| ASI09 | 人机信任滥用 | 审批经济学（7.6）+ 审批展示消毒（6.6） |
| ASI10 | 流氓 Agent | kill-switch + 心跳 fail-closed（5.6, 6.5） |
| 补 1 | 本机进程攻击 orind | IPC 对端校验 + 限流 + orind 自沙箱（5.4, 7.4） |
| 补 2 | 主人误用/内部人 | 双签与冷静期（7.3） |

### 3.3 安全目标（可检验）

- **G1 工牌不可伪造**：没有 orind 内密钥的实体无法构造通过核销的工牌；
- **G2 撤销即时**：已吊销工牌在下一次核销即失效，无本地缓存时间窗；
- **G3 SECRET 不相交**：持有 SECRET 密级的上下文，除出门证外无任何外发通道；
- **G4 泄密可探测**：金丝雀读取事件 + 外发命中双证据 ⇒ 1 秒内冻结；
- **G5 fail-closed**：orind 失联 ⇒ 新工牌停发（默认），无静默裸奔窗口；
- **G6 损伤可回滚**：任意 turn 的工作区状态可恢复；
- **G7 全链路可审计**：每个判定有签名收据，证据卷可导出。

---

## 4. 设计原则

**三铁律：**

1. **保安不做语义判断，只查证与行为。** 判定路径无 LLM、无分类器作为放行依据。边界澄清：确定性模式匹配（固定字符串、哈希、语法解析、位运算）属"查证"而非"语义判断"；关键词/分类器式内容扫描降级为可选顾问意见，永不作为放行依据。
2. **保安自身不可被注入。** 因为第一条，注入对 Orin 无意义——这是"设计免疫"而非"检测免疫"。
3. **快路径全确定性，慢路径全异步。** 在线检查只允许 O(微秒) 级操作；烧模型/重放/统计一律走异步巡逻，以"收紧后续授权"生效，绝不阻塞当前调用。

**两条工程红线（继承自项目既有原则）：**

4. **Fail closed**：门禁、核销、心跳、入口登记，任何环节缺失或异常 = 拒绝，不是放行。
5. **向后兼容优先**：旧账本链验证不受影响、旧数据不丢、旧语义不改——所有改动为加字段、加钩子、加默认值。

---

## 5. 系统总体架构

### 5.1 双进程架构

```
┌────────────────────────── 主进程（员工宿舍） ──────────────────────────┐
│                                                                      │
│   Web/CLI/TUI/Telegram ──► EchoRuntime ──► turn_loop ──► 工具执行    │
│                                │                                     │
│                    （只有 IPC 客户端，没有任何密钥）                     │
│                                                                      │
└────────────────────────────────┼─────────────────────────────────────┘
                                 │  Unix socket（macOS/Linux）/ 命名管道（Windows）
                                 ▼
┌────────────────────────── 门卫室（orind 独立进程） ───────────────────┐
│                                                                      │
│   OrinDaemon（单线程事件循环 + 无锁数据结构）                            │
│   ├── GateKeeper     门禁：签发/核销/吊销工牌，入口污点标记             │
│   ├── CanaryVault    蜜罐仓：金丝雀生成、放置登记、命中比对              │
│   ├── Patrol         巡逻：异步消费 ledger outbox 流                  │
│   ├── Responder      处置：六级响应阶梯状态机                          │
│   ├── PolicyStore    策略：签名策略包、版本化、灰度                     │
│   ├── Snapshotter    快照：APFS clonefile 写时复制（7.2）              │
│   └── KeyBox         钥匙箱：工牌密钥（硬件锚定，7.5）                  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**关键决策：工牌全在线化。** 代码事实：现有 `js/echo/capability.py` 使用对称 HMAC-SHA256（`authority-hmac-sha256` 前缀），密钥在主进程。对称密钥无"公钥"可分，因此签发、核销（consume）、验证、吊销**全部经 IPC 到 orind 在线完成**，密钥永不离开 orind。由此自动获得两个性质：主进程被控无法伪造/撤销造假（G1）；吊销即时生效、无本地缓存时间窗（G2）。若未来基准证明 IPC 是瓶颈，备选升级为 Ed25519 非对称签名（主进程持公钥离线验证 + orind 短 TTL < 100ms 推送吊销列表）——`security/signer.py` 已具备 Ed25519 能力（已核验），且两算法按签名前缀分派并存，旧 HMAC 账本链永远可验证。

### 5.2 组件职责

| 组件 | 职责 | 关键路径？ |
|---|---|---|
| GateKeeper | 工牌签发/核销/吊销；污点准入；策略判定；蜜罐比对调度 | 是 |
| CanaryVault | 金丝雀生成/轮换/放置登记；命中双证据判定 | 比对在关键路径，生成不在 |
| Patrol | 六类流式行为检测器，产出授权收紧建议 | 否 |
| Responder | 六级阶梯状态机；冻结/终止/隔离；签名收据 | 否（除冻结指令下发） |
| PolicyStore | 策略包验签、版本管理、灰度影子、回滚保护 | 否（策略快照常驻内存） |
| Snapshotter | 工作区写时复制快照；快照 ID 写入 effect 收据 | 否（异步触发） |
| KeyBox | 密钥持有与代签名；三级硬件锚定 | 是（签名在签发路径） |

### 5.3 三制数据流

```
入口（用户输入/工具结果/附件/记忆/技能/压缩摘要/自动任务/inbox）
   │  ① 门禁：打污点标签、密级标记、钉扎哈希、准入检查
   ▼
turn_loop 正常运行
   │  ② 每次工具调用：在线校验（工牌核销 + 污点 + 密级 + 蜜罐 + 画像版本）
   ▼
effect 执行 ──► ledger journal ──► outbox ──► 快照索引
                                     │  ③ 巡逻：异步流式行为分析
                                     ▼
                              ④ 处置：observe → narrow → slow → freeze → kill → quarantine
```

**入口 fail-closed 原则**：任何未在 Orin 入口注册表登记的入口，其数据默认污点全标（最低信任）。漏标 = 更严，而不是更松。

### 5.4 IPC 协议设计

- **传输**：Unix domain socket（macOS/Linux）/ 命名管道（Windows）；长度前缀帧，单帧上限 64KB。
- **握手密钥**：由 **orind 生成**（不经主进程 secrets.py，避免主进程被控后泄露），启动时经一次性 fd 传递 / 0600 权限文件下发；主进程重启即轮换。
- **报文安全**：HMAC 认证 + 单调递增计数器（防重放）+ 会话 nonce。
- **对端身份**：macOS audit token / Linux SO_PEERCRED / Windows 客户端 SID 校验。
- **自我保护**：每客户端令牌桶限流 + 有界队列 + 背压（呼应现有 `EchoBackpressureError`），防被控主进程对门卫发洪水。
- **版本协商**：协议版本号握手，新旧版本按能力集降级协商——升级不破坏旧客户端。

### 5.5 状态与持久化

orind 状态（撤销列表、金丝雀表、Responder 状态、快照索引、策略版本）落 SQLite（WAL 模式），崩溃重启后恢复——沿用现有 `LeaseAuthority._load_ledger` 恢复机制。关键状态写前 fsync，收据先落盘后生效。

### 5.6 失效语义

- 心跳：主进程每 1s 向 orind 要心跳（核销在线化后心跳为兜底）。**orind 失联 ⇒ 新工牌停发**（G5，fail-closed 默认）。
- **降级只读模式（可选，默认关）**：orind 失联时仅允许只读类工牌（读文件/检索记忆），禁一切写/外发/shell——供工厂车间权衡"停产 vs 裸奔"。
- 崩溃由 launchd/systemd 自动拉起（秒级窗口），重启期间按上述配置行为执行。

---

## 6. 核心机制详设

### 6.1 污点标签体系

每个进入上下文的数据块获得 64-bit 污点向量（位掩码，比较 = 一次 AND，纳秒级）：

```
bit 0  USER_TURN       用户本轮输入（最高信任）
bit 1  USER_HISTORY    用户历史消息
bit 2  TOOL_RESULT     工具返回（不可信外部内容）
bit 3  WEB_CONTENT     网页/网络抓取内容
bit 4  ATTACHMENT      用户上传附件
bit 5  MEMORY_READ     长期记忆检索结果
bit 6  SKILL_CONTENT   第三方技能/插件文本
bit 7  MODEL_OUTPUT    模型自身输出（可被上游污染，非纯白）
bit 8  CANARY_ADJACENT 与蜜罐同域出现过
bit 9  COMPRESSED      经压缩/摘要
bit 10 AUTO_TASK       cron/daemon 自动任务输入
bit 11 INBOX_CONTENT   AppShell inbox / work-context 投影
bit 12 SECRET          密级数据（凭证文件/金丝雀邻域/敏感记忆）——7.1 的输入
bit 13–15 保留（multi-agent delegation）
bit 16+  会话级自定义
```

**完整打标点清单（已逐文件核验存在性）：**

| # | 入口 | 代码位置 | 标签 |
|---|---|---|---|
| 1 | 用户输入 | `echo/turn_runtime.py: build_context` | USER_TURN / USER_HISTORY |
| 2 | 工具结果回收 | `echo/effect_interpreter.py` + `turn_loop.py` 的 `state.messages.append` 处（与现有 `check_tool_result` 钩子同位） | TOOL_RESULT / WEB_CONTENT |
| 3 | 附件 | `echo/attachment_gate.py` | ATTACHMENT |
| 4 | 记忆检索 | `memory/store.py` / `enhanced_store.py` 读路径 | MEMORY_READ（敏感条目加 SECRET） |
| 5 | 记忆写入 | `memory/store.py` 写路径 | 账本 MEMORY_WRITE 记录 |
| 6 | 技能/插件文本 | `skills/manager.py` 加载处 | SKILL_CONTENT |
| 7 | 压缩摘要回注 | `compression/compressor.py` | 原文污点 \| MODEL_OUTPUT \| COMPRESSED（SECRET 强制继承） |
| 8 | 自动任务输入 | `cron/engine.py`（`_schedule_job`）、`daemon/core.py` 进 Echo 处 | AUTO_TASK |
| 9 | inbox/work-context 投影 | `appshell/inbox.py`、`appshell/work_context.py` | INBOX_CONTENT |
| 10 | 交接内容 | `echo/handoff_vault.py` 读取处 | 按来源标签 |
| 11 | 凭证类文件读取 | `tools/files.py` 读路径 + 路径模式表（`.env`、`*.key`、`secrets/` 等） | SECRET |

**传播与衰减规则：**
- 拼接 = 位或；工具调用携带两层快照：`context_taint`（活动上下文累计）与 `arg_taint`（参数与近期脏数据的子串/n-gram 重叠度启发式，区分"上下文里有脏数据"与"参数直接来自脏数据"）。
- **窗口衰减**：污点绑定活动上下文而非会话——内容被压缩或滑出窗口即从 `context_taint` 移除，长会话不再污点饱和。
- **SECRET 例外**：SECRET 位不衰减、不洗白，压缩强制继承；**会话历史延续同理**——若历史消息中包含机密数据（含曾读过机密的工具结果消息），后续 turn 的活动上下文仍带 SECRET。唯一合法跨越 = 出门证（7.1）；日常外发负担由常设授权（7.6）吸收。
- **洗白途径**：用户本轮显式审批（颁发 USER_TURN 级一次性工牌）；非 SECRET 内容滑出窗口。

### 6.2 工牌扩展（污点即权限）

```
CapabilityLease {
  ... 现有字段（tool, fs_roots, network_hosts, budget, nonce, exp, mac）...
  taint_floor:     u64  // 允许消费的上下文污点上限
  taint_sink:      u64  // 动作性质（WRITES_OUTSIDE / NETWORK_EGRESS / SPAWN ...）
  sandbox_profile: u64  // 沙箱画像版本号（6.7）
  clearance:       u8   // 密级 0=PUBLIC / 1=INTERNAL / 2=SECRET（7.1）
}
```

**兼容**：旧 lease 无新字段，反序列化取缺省值并按旧语义放行 + 记录，灰期新老并存，现有链验证不受影响。

**缺省策略表（双档；原则：默认走审批，拒绝只留结构性高危）：**

| 动作 | 保守档（新部署默认） | 兼容档（老用户升级默认） |
|---|---|---|
| 读工作区内文件 | 任意（凭证类路径加 SECRET 位） | 任意 |
| 写工作区内文件 | `arg_taint` 含 WEB/TOOL_RESULT → 审批；否则放行 | 同左，审批可"本会话不再询问" |
| Shell 执行 | context 含 WEB_CONTENT 且 arg 与脏数据重叠 → 拒；含 USER_TURN → 放行 | 同左 |
| 网络外发 | arg 含 MEMORY_READ 或未审批脏数据 → 审批；**上下文含 SECRET → 必须走出门证，普通审批不可替代** | 同左 |
| 写长期记忆 | 任意（写入自由），异步复核（6.10） | 同左 |
| 修改策略/工牌权限 | 仅 USER_TURN 直达，拒绝一切间接驱动，无审批通道 | 同左 |
| **其他未命中任何行的动作（缺省行）** | **审批**（fail-closed 姿态） | **放行 + 记录**（灰期兼容姿态） |

**规则冲突优先级：拒 > 出门证 > 审批 > 放行**——同一动作同时命中同 sink 多行时，处置强度最高者胜：结构性拒绝行（如 shell 的"arg 重叠 → 拒"）优先于一切；外发动作同时命中"含 SECRET → 出门证"与"含脏数据 → 审批"时走出门证（普通审批不可替代）；审批行优先于放行行；缺省行只在无任何行命中时生效。

单次检查 = 两次位运算 + 一次查表 + 一次相似度启发式，微秒级。与 CaMeL 的区别：不追踪每变量数据流图，而是工具调用粒度约束——精度粗一档的残余风险由 7.1 密级分区结构性收口。

### 6.3 蜜罐仓 CanaryVault

1. **两类金丝雀**（每会话生成，orind 持有真值表）：
   - 凭证型 3–5 枚：`sk-orin-canary-<40位随机>` 式假 key/token/密码；
   - 语义型 1–2 枚：全网唯一假事实实体（假发票号 `INV-2026-8842137-ORIN`、假人名、假编号）——模型转述改写句子但通常照抄实体值，覆盖"改写后泄露"路径。语义型实体选型原则是"业务中永不应外发的类型"；用户主动提及该实体让人代发属已知误报残余，由申诉闭环（本条第 7 款）吸收——"近零误报"以此为边界。
2. **放置**：`handoff_vault`、记忆库（语义型混入合理条目）、工作区深层伪装路径（如 `.config/.cache/` 下，不进常规 `ls`/glob 结果；不放会被正常打包任务误触的位置）。
3. **读取即事件（tripwire）**：file 工具读金丝雀文件 → 上报 orind（不阻塞），记 CANARY_ADJACENT，该上下文密级升 SECRET。
4. **比对面与覆盖边界**：对**应用层外发**（`net_guard.resolve_and_validate` 下沉点的请求体）、**shell 命令参数**、**写外区文件内容**做 Aho-Corasick 多模式匹配（pyahocorasick C 扩展，10KB < 50µs，1MB 分块流式）；对已审批外发同样比对（出门证不是免检通道）。
   **明确不直接覆盖**：子进程内部的内容级外发（如 shell 中 `curl -d @file`——外发内容不经过主进程）。该面由两层兜底：沙箱画像的网络白名单（6.7：子进程只能连 lease 授权的 host，白名单外即内核拒绝）+ 外发巡逻（6.4 熵/字节量异常）。
5. **双证据命中**：外发命中 ∧ 会话存在对应读取事件 ⇒ 硬报警直达 L3 FREEZE；单命中无读取事件（理论不可能，除非 orind 状态丢失）⇒ 软报警 L1 + orind 日志自审。
6. **防探测**：返回模型的拒绝/冻结措辞统一固定文案，不泄露触发机制。
7. **申诉通道**：冻结后人工裁决界面一键解封并标记误报，误报样本进审计日志改进放置策略。

### 6.4 巡逻 Patrol

消费 `ledger/` outbox 事件流，全部检测器流式、O(1)/事件、无 LLM：

| 检测器 | 信号 | 成本 |
|---|---|---|
| 速率异常 | 每会话调用速率/失败率滑窗（>3σ） | 每事件两次浮点 |
| 外发异常 | host 多样性/字节量突变（相对会话基线） | HyperLogLog + 滑窗 |
| 熵异常 | 外发 payload 香农熵突增 | 流式直方图 |
| 循环恶化 | 现有 check_loop 的跨会话版 | 复用 LRU 计数器 |
| 记忆复核 | 新记忆条目的指令型模式 | 批量正则，秒级 |
| 工牌消耗模式 | 同族高频短工牌 = 边界试探 | 计数器 |

**基线 warmup**：新会话前 20 次调用只观察（或按租户先验基线起步），避免冷启动误报。**定位**：不产生 block，只产出收紧建议给 Responder——误报代价 = 审批变多，不是误杀。

### 6.5 处置 Responder —— 六级响应阶梯

```
L0 OBSERVE    仅记录（默认态）
L1 NARROW     后续工牌 scope 收紧一档（网络白名单收缩、禁写外区）
L2 SLOW       高风险下沉点（外发/写外区/shell）全部审批 + 会话速率封顶；低风险自动放行
L3 FREEZE     会话冻结：orind 在线吊销全部工牌（即时生效），上下文封存，等人工裁决
L4 KILL       进程终止 + 账本封存为证据卷（evidence_export 已有）
L5 QUARANTINE 全部会话冻结 + 策略回滚到上一"已知好"版本（回滚保护见 6.8）
```

- 升级触发：蜜罐双证据（直达 L3）、多检测器共振、同一动作被拒后第 2 次重试（计数防试探）。
- 降级：人工裁决后显式降级，降两级间至少隔一个无告警完整 turn。
- 统一措辞、逐步签名收据（触发者/规则/前后状态），可回放可申诉（G7）。

### 6.6 审批展示消毒（ASI09）

审批卡内容本身可能是脏数据（诱导性描述）。规定：动作描述截断 + 转义 + 来源污点/密级徽标（"此动作由网页内容触发""此上下文读过机密数据"醒目展示），让"同意"建立在知情上。

### 6.7 沙箱画像合成

代码事实：`echo/os_sandbox.py` 是**子进程命令沙箱**——Seatbelt/Landlock 只约束 spawn 的子进程，管不到主进程内 Python 工具。因此：

1. **子进程执行面**：turn 开始按策略上限**预声明**画像（over-approximation，消除 TOCTOU 窗口），经 `os_sandbox.py` 下发；turn 内工牌只能收缩不能扩张，需扩张 → 重申请画像（新版本号）+ 审批。
2. **版本绑定**：lease 带 `sandbox_profile`，核销校验"工牌 ⊆ 当前画像"。
3. **进程内工具面**：file 类工具由应用层工牌 + `tools/files.py` 路径解析 + `runtime_tcb.py` 兜底，残余风险由污点/密级/蜜罐对冲；长期 worker 化见 7.4。
4. TCB 目录永远不在任何画像写权限内。

### 6.8 策略包 PolicyStore

- 策略即数据（JSON/YAML），签名发布——`security/signer.py` 已核验为 Ed25519 实现；**验签公钥预置 orind 资源目录**（TCB 保护），不依赖主进程。
- 版本化 + 灰度：新策略 observe-only 影子模式 24h（影子明细本地留存、脱敏、可清理），人工确认转 enforce。
- 回滚保护：版本单调递增；只可回滚到"已知好"标记版本；回滚 = 元操作，需 USER_TURN 直达审批。

### 6.9 供应链防护（ASI04）

每个 MCP/插件工具注册时对其 `name + description + input_schema` 算 SHA-256 存底；每次调用前重算比对（缓存，O(1)）。**描述被 rug-pull 改动 → 工具立即冻结并告警**——把 Invariant 发现的 tool poisoning 对策做成运行时逐次校验而非安装时一次扫描。

### 6.10 记忆投毒专项（ASI06）

- 写入带污点进账本；检索命中打 MEMORY_READ（敏感条目加 SECRET），外发下沉点触发审批/出门证。**敏感判定来源有三**：凭证路径模式表命中（6.1 打标点 11）、曾被 quarantined 的条目、用户显式标记——确定性来源，不靠模型判断。
- 巡逻器异步复核新条目，指令型/触发词型 → `quarantined` 标志位隔离（**不删数据**）。
- 迁移：`ALTER TABLE ... ADD COLUMN quarantined INTEGER DEFAULT 0`；旧条目视为未审计照常限权。
- 取舍依据：MINJA（NeurIPS 2025，据转述仅查询交互即 >95% 注入成功率）说明写入拦不住也不该拦——管住使用面即可。

### 6.11 压缩链路

`compression/compressor.py` 摘要由模型生成，是污点 laundering 潜在通道：摘要污点 = 原文污点 | MODEL_OUTPUT | COMPRESSED，**SECRET 位强制继承**；摘要进"写文件/外发"判定时走 `arg_taint` 重叠度检查。压缩器必须携带污点元数据，不得丢弃。

---

## 7. 极限突破机制

前章机制解决"已知可解"的问题；本章针对六项被普遍承认的极限，给出四项结构性突破与两项工程上限。原则不变：无 LLM、全确定性。

### 7.1 语义级泄露 → 密级分区 + 出门证

**认知转换**：语义泄露的本质是"同一上下文既碰了秘密又能对外说话"。文本级追踪问错了问题——不问"这段话里有没有秘密"，而问"**产生这段话的上下文有没有接触过秘密**"。污点从"贴在文本上"升级为"贴在上下文的权限状态上"。这是 Meta Agents Rule of Two 的严格工程化。

**形式化不变式：**
- I1（不相交）：∀ 上下文 c：c.clearance = SECRET ⇒ c 的外发工牌集合 = ∅（出门证除外）；
- I2（单调）：SECRET 位只升不降，压缩/摘要/交接/会话历史延续均强制继承；
- I3（唯一穿越点）：SECRET → 非 SECRET 的唯一转换是出门证审批事件，且该事件写签名收据。

**机制：**
1. 密级三级：PUBLIC / INTERNAL / SECRET（打标点 §6.1 第 4、11 行注入 SECRET 位；金丝雀 tripwire 亦升 SECRET）；
2. 不相交铁律：net_guard 下沉点硬检查 `clearance < SECRET ∨ 出门证`——模型不能泄露它没读过的东西，**语义问题转化为访问控制问题**；
3. **出门证（Export Gate）**：任务确需"读私密再外发"时强制两阶段——机密阶段（读、整理，无外发权）→ 穿越点（向用户展示全文 + 来源密级 + 目的地，显式批准）→ 外发阶段。**外发阶段的实现要点**：批准后生成一个**独立的最小外发上下文**（只含获批内容与目的地，在单独的外发 turn 中执行），原会话上下文密级保持 SECRET 不变、不受批准影响——因此不与 I2 矛盾；
4. 语义金丝雀对已审批外发同样比对（6.3）；
5. 外发预算：目的地白名单（联系人级）+ 字节量/熵预算——语义泄露需要带宽，带宽封顶。

**结论**：未审批路径语义泄露**结构性归零**（G3）；已审批路径归位于人审穿越点，可审计、可申诉、有金丝雀兜底。

### 7.2 模型说错话 → 可撤销世界（Undo Layer）

不消灭错误（不可能），让错误代价可恢复：

1. **快照范围与时机**：每个 turn 开始、以及每次**工作区内**写/删/批量操作前，对工作区做 APFS 写时复制快照（macOS clonefile，亚秒、近零空间；Linux btrfs/overlayfs；Windows VSS 随部署补）。**注意：快照只能恢复工作区**；写外区属于不可逆清单，不走快照走审批/双签（本条第 4 款）；
2. **账本联动**：快照 ID 写入 effect 收据——任何操作可定位"做之前的世界"；
3. **一键回滚**：`agent undo <turn>` 恢复到任一 turn 前状态（G6）；记忆库同机制；
4. **不可逆清单**：外发/支付/删外区/写外区这类"出了门就收不回"的动作，天然进入审批/双签通道——可回滚的放快道，不可回滚的走慢道。

### 7.3 用户亲自下毒指令 → 双签与冷静期

不判断主人意图善恶，但对灾难级动作提供治理工具：**双签**（可配置清单：删外区/写外区/群发/支付/改策略/策略回滚，需第二可信主体确认——工厂 = 班长扫码，个人 = 第二设备/硬件密钥）；**冷静期**（灾难级动作延迟 N 分钟执行，期间可撤回，配合快照）。默认全关，工厂部署建议开。

### 7.4 宿主 0day → TCB 收缩

打不赢 OS 厂商的仗，但能收缩暴露面：**orind 自沙箱**（独立用户运行 + 自身套 Seatbelt/Landlock 画像：只读策略目录、只写状态库、无网络——保安也戴手铐）；**Echo 执行面 worker 化**（P5 目标：工具执行迁入常驻沙箱 worker，主进程只做编排，0day 爆炸半径从整台机器缩到一个 worker 的画像范围）。

### 7.5 同用户态攻击 → 硬件钥匙箱（KeyBox）

**技术事实先行**：macOS Keychain 是"受控取出"（访问控制绑定 orind 代码签名，取出时密钥短暂进内存，驻留窗口毫秒级）；Linux/Windows 的 TPM2 支持**原生 HMAC 命令**（密钥不出芯片）；macOS Secure Enclave **不支持 HMAC 代算**（仅 ECDSA P-256 与 AES-GCM），故高安档改用 Enclave 内 ECDSA 签名替代 HMAC——工牌算法按签名前缀分派的机制（5.1）已为此预留。

三级锚定：
- **开发档**：0600 权限文件（仅开发用）；
- **生产档**（P0 默认）：macOS Keychain 受控取出 / Linux·Windows TPM 代算 HMAC；
- **高安档**（P5 可选）：Secure Enclave 内 ECDSA 签名——密钥永不出安全芯片，攻击者完整转储 orind 内存也只能拿到"可请求签名的句柄"，吊销句柄即失效。

效果：同用户态攻击从"拿到钥匙"降级为"拿到一张随时作废的门禁卡"。

### 7.6 审批疲劳 → 审批经济学

审批是稀缺资源，按预算分配：
1. **降总量**：密级分区 + 双档策略把绝大多数动作移出审批通道，只有"出门"和"灾难级"打断；
2. **常设授权**：批准过的模式可转签名常设授权（scope 上限 + 过期时间，如"给 Bob 发邮件每周 ≤ 2 次"），orind 复核使用，超界自动失效回到审批（schema 见附录 D.4）；
3. **批量摘要审**：低风险项聚合成每日一次风险排序摘要卡（复用 `appshell/inbox.py`），只有高风险实时打断；
4. **质量护栏**：审批卡展示污点/密级徽标 + 全文 + 目的地（6.6），高风险强制展示"若点同意，最坏结果是什么"一句话（按动作类型模板生成，不用 LLM）。

---

## 8. 性能工程

### 8.1 关键路径时序（每次工具调用）

```
turn_loop 组装 tool call
  ├─ 污点快照贴附（位运算）                ~ns
  ├─ IPC: 核销请求（UDS 往返 + orind 判定）  < 300µs
  │    orind 内部：密钥核销 + 污点位运算 + 钉扎哈希 + arg_taint 相似度（≤8KB）
  ├─ 蜜罐比对（仅外发/shell 参数/写外区）     < 50µs / 10KB
  └─ 画像版本校验（随核销一并完成）           ~0
合计新增 < 500µs（p99）
```

### 8.2 预算表

| 路径 | 预算 | 手段 |
|---|---|---|
| 工牌签发（IPC + 签名） | < 100µs | UDS、批签（核销在线化后批签不削弱撤销即时性） |
| 在线核销校验 | < 300µs | 位掩码、缓存哈希、预编译结构体 |
| 蜜罐比对 | < 50µs / 10KB | pyahocorasick C 扩展，1MB 分块流式 |
| 沙箱画像 | < 5ms / turn | 模板渲染，每 turn 一次 |
| 快照 | < 50ms / 次（每 turn 一次 + 工作区内危险操作前） | APFS 写时复制，异步触发不阻塞 |
| 巡逻 | 每事件 < 1µs 均摊 | 无锁队列，批量消费 |
| **合计（每次工具调用新增）** | **< 500µs p99** | 对比：本地工具调用 ≥ 1ms，模型往返 ≥ 500ms，占比 < 0.1% |

### 8.3 吞吐与容量

orind Python 版目标 ≥ 10k 判定/秒（签名 ~1µs/次、UDS 往返 20–50µs，10 倍余量；Rust/Go 版再提，见 §13-2）；内存常驻 < 50MB；单 orind 支撑并发会话 ≥ 100（每会话峰值判定 << 100/s）。

### 8.4 编码规范禁止项

关键路径禁 LLM 调用、禁回溯型正则、禁磁盘 I/O（策略常驻内存、收据异步批量落盘）、禁锁竞争（单线程事件循环 + 不可变策略快照）。

---

## 9. 安全性分析

### 9.1 安全性质与论证

| 性质 | 论证 |
|---|---|
| P1（G1 不可伪造） | 签名密钥不出 orind（7.5 硬件锚定）；核销在线，伪造工牌无法通过校验 |
| P2（G2 撤销即时） | 核销在线化 ⇒ 吊销状态在 orind 内存即生效，无本地缓存窗 |
| P3（G3 SECRET 不相交） | I1–I3 由三处确定性检查保证：net_guard 下沉点、工牌核销、压缩/历史继承；无 LLM 参与 ⇒ 无概率失效 |
| P4（G4 泄密可探测） | 金丝雀真值表只在 orind；双证据判定逻辑确定；L3 冻结指令经 IPC 下发 < 1s |
| P5（G5 fail-closed） | 签发/核销/心跳/入口登记任一缺失 = 拒绝；orind 失联默认停产 |
| P6（G7 可审计） | 每判定签名收据进账本（现有 MAC/hash journal），证据卷可导出 |

### 9.2 攻击链逐步断点分析（间接注入 → 外泄）

```
① 脏内容进入（网页/邮件/工具返回）
   └─ 断点1：入口打标 TOOL_RESULT/WEB_CONTENT（6.1），未登记入口默认全标
② 注入指令驱动模型发起危险工具调用
   └─ 断点2：策略表（6.2，含缺省行审批）——脏数据驱动的 shell/写文件/外发 → 审批或拒
   └─ 断点3：工具描述钉扎（6.9）——供应链 rug-pull 即冻结
③ 模型被完全欺骗，试图读机密再外发
   └─ 断点4：读凭证/金丝雀 → SECRET 位（6.1）→ 外发权丧失（7.1，I1）
   └─ 断点5：出门证强制人审穿越点 + 独立最小外发上下文（7.1.3）
④ 攻击者绕过应用层直接 spawn 子进程外泄（curl -d @file）
   └─ 断点6：沙箱画像网络白名单（6.7）——子进程只能连授权 host，其余内核拒绝
⑤ 攻击者低频慢速外泄规避检测
   └─ 断点7：蜜罐双证据（6.3）+ 外发巡逻熵/多样性检测（6.4）
⑥ 攻击者探测监控机制
   └─ 断点8：统一措辞（6.5）+ 拒绝重试计数升级（6.5）
⑦ 攻击者控制主进程伪造/吊销工牌
   └─ 断点9：密钥硬件锚定（7.5）+ IPC 对端校验（5.4）+ 核销在线（5.1）
```

### 9.3 与相关工作对照

| 维度 | 扫描器派 | 代理防火墙派 | CaMeL/Progent | 纯沙箱派 | **Orin** |
|---|---|---|---|---|---|
| 判定依据 | 内容像不像攻击 | 流量像不像攻击 | 数据流策略 | 越没越界 | 证件 + 污点 + 密级 + 行为 |
| 判定路径含 LLM | 是 | 部分 | 是 | 否 | **否（设计免疫）** |
| 关键路径开销 | ms–秒级 | 网络级 | ~2.7x token（第三方实测） | ~0 | **< 500µs** |
| 防"界内使坏" | 弱 | 弱 | 强 | 无 | 较强（污点下沉 + 审批） |
| 未审批语义泄露 | 概率检测 | DLP | 策略拦截 | 无 | **密级分区结构性归零** |
| 泄密探测 | 模式匹配（有误报） | DLP | 策略 | 无 | **蜜罐双证据 + 语义金丝雀** |
| 错误损伤 | 不可恢复 | 不可恢复 | 不可恢复 | 不可恢复 | **可撤销世界（工作区）** |
| 沙箱与授权联动 | 无 | 无 | 无 | 静态 | **每 turn 动态合成** |
| 保安进程独立性 | 否 | 体外 | 否 | — | **同机独立进程 + 硬件密钥** |
| 响应粒度 | block/allow | block/allow | block/allow | — | **六级阶梯 + 取证回放** |

### 9.4 残余风险（诚实声明，不再掩饰）

1. **出门证那一眼依赖人**：用户看走眼，泄露照样发生。7.6 用展示消毒与"最坏结果一句话"缓解，但不能归零——**人作为最后一环的固有属性；任何宣称全自动消灭语义泄露的方案都是在撒谎**；
2. **硬件信任根之下无安全**：Secure Enclave/TPM 被物理攻破（成本数万美元起）则钥匙箱失守——对本场景不现实，但写清楚；
3. **双签之外的主人恶意**：只能留证不能阻止——治理边界；
4. **模型权限内说错话**：7.2 让工作区损伤可回滚，"说错"本身仍是质量问题；
5. **粗粒度污点的精度损失**：arg_taint 启发式有理论误报/漏报空间，由审批通道吸收；
6. **OS 进程内存保护失效**：若同用户态跨进程内存读写保护（A3 假设）被突破，污点标签完整性失去依托——该面依赖 OS 厂商，Orin 不宣称覆盖；
7. **子进程内容级外发**：不由蜜罐比对直接覆盖，依赖画像白名单 + 巡逻兜底（6.3.4），白名单内的隐秘慢速外泄只能限速不能归零。

---

## 10. 技术路线与实现方案

### 10.1 阶段路线图

| 阶段 | 内容 | 依赖 | 验收 | 回滚策略 |
|---|---|---|---|---|
| P0 | `js/orin/` + `js/orind/` 骨架：IPC 协议（对端校验/限流/防重放/版本协商）、LeaseClient 迁出、心跳 fail-closed、orind 状态持久化、KeyBox 生产档（Keychain/TPM） | 现有 capability.py、secrets.py | 现有测试全绿；orind 停掉新工牌停发；旧账本链验证不受影响 | LeaseAuthority 保留主进程回退路径，配置开关切回 |
| P1 | 污点向量 + 11 处打标点 + 工牌四字段 + 双档策略表（含缺省行） | P0 | 每个下沉点单测；InjecAgent 风格用例拦截率报告；正常任务回归 ≥ 95% | 策略表兼容档 = 旧行为 |
| P2 | CanaryVault（凭证+语义型）+ 六级阶梯 + 审批消毒 + 巡逻前三件（速率/外发/熵） | P1 | 蜜罐双证据命中 < 1s 冻结；误报率 < 1%；统一措辞检查 | 金丝雀可全局停用，阶梯可锁定 L0 |
| P3 | 沙箱画像合成（macOS 先行，Linux 随 Windows 部署前补）+ 版本绑定 | P0 | 画像逃逸测试；TOCTOU 窗口测试；性能基准达标 | 画像合成失败回退现有 os_sandbox 静态策略 |
| P4 | 策略包签名/灰度/回滚保护 + 记忆投毒专项 | P2 | 灰度演练；回滚攻击演练；MINJA 风格用例 | 策略锁定出厂版 |
| P5 | 极限突破包：密级分区 + 出门证 + Undo Layer + KeyBox 高安档 + 审批经济学 + 高危工具 worker 化 | P1–P3 | 密级不相交属性测试（§12-2）；快照回滚演练；日均审批 ≤ 5 次统计 | 各机制独立开关，逐项灰度 |
| 持续 | AgentDojo / ASB 基准跑分并公开 | — | 报告进 docs/ | — |

### 10.2 包结构

```
js/orin/
├── __init__.py
├── protocol.py        # IPC 帧格式、消息类型、版本协商（附录 D.1）
├── client.py          # LeaseClient：主进程侧 IPC 客户端（签发/核销/吊销/心跳）
├── taint.py           # 污点向量定义、传播、衰减、arg_taint 相似度
├── clearance.py       # 密级与出门证状态机
├── receipts.py        # 判定收据签名与序列化
└── testing.py         # 假 orind（单测用，进程内实现同协议）

js/orind/              # 守护进程包——置于 js 包内，自动进入 runtime_tcb 写保护
├── __main__.py        # 入口：launchd/systemd 托管
├── daemon.py          # 单线程事件循环
├── gatekeeper.py      # 签发/核销/吊销 + 策略判定
├── canary.py          # 金丝雀生成/比对/双证据
├── patrol/            # 六个流式检测器
├── responder.py       # 六级阶梯状态机
├── policy.py          # 策略包验签/灰度/回滚
├── snapshot.py        # APFS clonefile 封装
├── keybox.py          # 三级钥匙箱（文件/Keychain-TPM/Enclave-ECDSA）
└── store.py           # SQLite(WAL) 状态持久化
```

（设计说明：orind 代码置于 `js/` 包内而非仓库顶层——`runtime_tcb.py` 保护的是 js 包安装树，放包内自动继承 TCB 写保护，与 6.8/7.4 的自保护条款一致。）

### 10.3 关键算法与数据结构

- 污点：u64 位掩码 + 每数据块元数据表（LRU 100k）；arg_taint 用 8KB 窗口内 8-gram Jaccard 相似度（阈值可配）；
- 蜜罐：Aho-Corasick 自动机（pyahocorasick），金丝雀表 SQLite 持久化，每会话轮换；
- 巡逻：EWMA 滑窗（速率）、HyperLogLog（host 多样性）、流式字节直方图（熵）；
- 快照：clonefile 写时复制 + 快照索引（turn_id → snapshot_id → 账本偏移）。

### 10.4 数据库迁移（表名/列名为示意，实施时以实际 schema 为准）

```sql
-- 记忆表（向后兼容，不丢数据）
ALTER TABLE memories ADD COLUMN quarantined INTEGER DEFAULT 0;
ALTER TABLE memories ADD COLUMN taint INTEGER DEFAULT 32;  -- MEMORY_READ
-- orind 状态库（新建，独立文件）
CREATE TABLE IF NOT EXISTS canaries (session_id TEXT, token_hash TEXT, kind INTEGER, placed_at TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS revocations (lease_id TEXT PRIMARY KEY, revoked_at INTEGER, reason TEXT);
CREATE TABLE IF NOT EXISTS responder_state (session_id TEXT PRIMARY KEY, level INTEGER, since INTEGER, evidence TEXT);
CREATE TABLE IF NOT EXISTS snapshots (id TEXT PRIMARY KEY, turn_id TEXT, path TEXT, ledger_offset INTEGER, created_at INTEGER);
```

### 10.5 与现有代码整合映射

| 现有资产 | Orin 中的去向 |
|---|---|
| `echo/capability.py` | 签发/核销/验证/吊销迁入 orind；主进程留 LeaseClient；签名前缀分派，旧 HMAC 链永远可验证 |
| `security/guard.py` | 保留为顾问层（BLOCK 仍生效，WARN 喂巡逻器） |
| `security/parser.py` + `rules.py` | 原样保留，shell 工牌签发输入 |
| `security/runtime_tcb.py` | 并入画像合成器（永远 deny）+ orind 自画像（js/orind/ 随包自动受保护） |
| `security/audit.py` / `echo/ledger/` | 巡逻数据源；取证出口；快照索引写入点 |
| `security/approvals.py` | L2 审批通道 + 展示消毒 + 出门证 + 常设授权 |
| `security/net_guard.py` | 外发下沉点（`resolve_and_validate` 处挂密级检查 + 蜜罐比对） |
| `security/signer.py`（Ed25519，已核验） | 策略包签名；Ed25519 工牌备选方案基础 |
| `security/secrets.py` | 真实凭证存储域（SECRET 位数据源）；与 orind KeyBox 相互独立 |
| `echo/os_sandbox.py` | 画像执行后端（子进程面） |
| `echo/attachment_gate.py` | 打标点（ATTACHMENT） |
| `memory/store.py` / `enhanced_store.py` | quarantined/taint 列（10.4 迁移） |
| `compression/compressor.py` | 摘要污点携带（6.11） |
| `skills/manager.py` | 打标点（SKILL_CONTENT） |
| `cron/engine.py` / `daemon/core.py` / `appshell/` | 打标点（AUTO_TASK / INBOX_CONTENT）——**注：cron 入口实际在 `engine.py._schedule_job`，AGENTS.md 中 `scheduler.py` 为过时信息** |
| `benchmarks/` | 新增 orin 性能套件 |

### 10.6 兼容红线

所有改动 = 加字段/加钩子/加默认值；不改 HMAC 链格式语义、不删旧数据、不改旧 API 行为；每个新机制有独立配置开关 + 灰度路径 + 回退方案（10.1 回滚策略列）。

---

## 11. 产品能力与产品实现方式

### 11.1 产品能力总览（用户视角）

**看不见的防护（默认开启，零打扰）：**
- 工牌门禁：每次工具调用的证件核验（< 500µs，无感）；
- 污点追踪与密级分区：脏数据、机密数据的流动约束；
- 蜜罐哨兵：每会话自动埋设、自动比对；
- 供应链钉扎：工具描述改动即时冻结；
- 异步巡逻：速率/外发/熵/循环行为分析；
- 自动快照：每个 turn 的可回滚点。

**看得见的控制（按需出现）：**
- 审批卡（含污点/密级徽标、"最坏结果一句话"）；
- 出门证卡（读私密再外发时的穿越点审批）；
- `agent undo <turn>` 一键回滚；
- 每日安全摘要卡（inbox 聚合，风险排序）；
- 冻结通知 + 一键解封/申诉。

**可拿出的证据：**
- 签名判定收据、证据卷导出（对接现有 evidence_export）；
- 安全姿态报告（拦截统计、误报率、审批量趋势）。

### 11.2 用户交互设计

| 交互 | 触发 | 形态 |
|---|---|---|
| 审批卡 | 策略表命中审批档（含缺省行） | 动作描述（截断+转义）+ 来源徽标 + 目的地 + 最坏结果一句话；选项：同意一次 / 转常设授权 / 拒绝 |
| 出门证卡 | SECRET 上下文请求外发 | 全文展示 + 密级警示 + 语义金丝雀预检结果；选项：批准外发 / 编辑后外发 / 拒绝 |
| undo | 用户主动 | `agent undo <turn>` 或 inbox 历史卡片上的"回滚到此"按钮 |
| 摘要卡 | 每日一次 | 低风险事件聚合 + 趋势；高风险已在发生时实时打断 |
| 冻结通知 | L3+ | 统一措辞通知 + 人工裁决界面（解封/升级/导出证据） |

### 11.3 配置体系（面向管理员）

```yaml
orin:
  enabled: true
  fail_mode: closed          # closed（默认，停产）| readonly（降级只读）
  policy_profile: conservative   # conservative | compat
  canary:
    enabled: true
    per_session: 5               # 凭证型数量
    semantic_entities: 2         # 语义型数量
  approval:
    standing_authorization: true # 常设授权
    daily_digest: true           # 批量摘要审
    show_worst_case: true
  dual_control:                  # 双签（默认全关，工厂建议开）
    enabled: false
    actions: [delete_outside, write_outside, mass_send, payment, policy_change, policy_rollback]
    cooldown_minutes: 10
  snapshot:
    enabled: true
    retain_turns: 50
  responder:
    honeytrip_level: L3          # 蜜罐命中直达级别
  keybox:
    tier: production             # dev | production | enclave
```

### 11.4 部署形态

| 形态 | 内容 |
|---|---|
| 个人 macOS（首发） | orind 由 launchd 托管（KeepAlive），UDS 通信，Keychain 钥匙箱，Seatbelt 画像，APFS 快照；setup_wizard 增加一页"保安配置"（默认全开，高级项折叠） |
| 工厂车间 | 上述 + 双签（班长扫码）+ readonly 降级可配 + 每日摘要推送到管理端 + 证据卷定期导出 |
| Windows（后续） | 命名管道 + SID 校验 + TPM 钥匙箱 + Job Object/受限令牌替代沙箱画像 + VSS 快照——工程量集中在 P3 |

### 11.5 运维与监控

- **指标**（对接现有 `utils/metrics.py` Prometheus）：判定延迟 p50/p99、orind 吞吐、审批量/通过率、冻结次数、蜜罐命中数、快照大小、策略版本；
- **告警**：orind 失联、蜜罐命中、L3+ 事件、策略灰度偏差超阈；
- **审计**：账本 + 证据卷导出，支持回放任一 turn 的安全判定链；
- **故障手册**：orind 崩溃（自动拉起 + 期间行为）、IPC 握手失败（密钥文件重生成流程）、快照空间不足（保留策略调整）、误报申诉处理 SOP。

### 11.6 与 AppShell 角色的配合

复用现有 Personal/Work 单壳架构：审批卡/摘要卡/冻结通知进 `appshell/inbox.py`；出门证审批绑定 session/run（`work_context.py` 投影）；工厂场景按 principal 角色（owner/班长/工人）区分审批权限与双签路由。

---

## 12. 验证与评估方案

1. **攻击面回归**：InjecAgent、AgentDojo、ASB 三基准逐版本跑分；目标：间接注入导致的未授权外发 = 0（结构性保证 + 蜜罐兜底）；
2. **密级不相交属性测试**：构造 1000 组"SECRET 上下文尝试外发"用例（含压缩、摘要、跨 turn、模型转述变体），断言出门证之外外发 = 0（G3）；
3. **正常任务回归**：厂内真实任务集通过率 ≥ 95%（防"安全加到没法用"）；
4. **性能基准**：`benchmarks/` 新增 orin 套件——每次调用新增延迟 p50/p99、orind 吞吐（10k/s）、内存（< 50MB）、快照开销；
5. **故障演练（八类）**：kill orind、kill 主进程、篡改策略包、rug-pull 工具描述、蜜罐主动触发、orind 洪水请求、吊销时间窗探测、内存转储取密钥（验证硬件钥匙箱）；
6. **三件套**：`ruff` / `mypy` / `pytest` 全绿才准合并（沿用 gate 流程）；
7. **误报审计**：蜜罐与审批误报率持续统计，目标 < 1%，样本进改进闭环。

---

## 13. 开放问题与决策请求

1. **Windows 部署形态**：Job Object + 受限令牌 + WDAC 工程量大；P3 之前只做 macOS，可接受吗？
2. **orind 语言**：Python（一致性好，10k/s 够用）vs Rust/Go（余量大，双工具链）；建议 P0–P2 Python 验证逻辑，P3 按基准数据决定；
3. **多 Agent / fleet**（ASI07）：已有 fleet/orchestration 模块，协议预留 delegation chain，是否现在做跨 Agent 签发？
4. **蜜罐放置位置**：`handoff_vault` + 记忆库 + 工作区深层路径三处，具体命名需配合业务习惯；
5. **高危工具 worker 化**（file/code 迁沙箱 worker）：已列 P5，确认优先级；
6. **降级只读模式**：orind 失联默认停产，是否开放 readonly 配置给工厂？
7. **出门证 UX**：每次"读私密再外发"都打断审批，还是接受"常设授权 + 语义金丝雀兜底"减轻（7.6.2）？

---

## 14. 结论

Orin 把 Agent 安全从"检测内容像不像攻击"的概率游戏，换成"查证、控权、巡逻、处置"的确定性工程：保安与员工分进程居住、密钥硬件锚定、权限以工牌逐次核验、污点和密级把数据流动变成可判定的访问控制问题、蜜罐提供近零误报的泄密事实探测、快照让工作区可撤销、响应阶梯让处置有梯度。它没有发明新的安全原语——它把 capability、IFC、蜜罐、参考监视器、内核沙箱、写时复制、硬件密钥这些经过数十年检验的原语，针对 LLM Agent 的威胁模型做了一致、低耗、可回退的组合，并对包括"语义泄露"在内的既往公认极限给出了结构性收口或诚实的工程上限。全部设计满足：关键路径 < 500µs、无 LLM 依赖、fail-closed、向后兼容红线不破。

---

## 附录 A：修订记录

### A.1 v0.1 → v0.2（20 轮自审，20 项修复）

| # | 缺陷 | 修复 |
|---|---|---|
| 1 | 污点单调累积致长会话饱和 | 窗口衰减（6.1） |
| 2 | 参数继承上下文污点一刀切误杀 | 双层污点 + 重叠度启发式 |
| 3 | 缺省策略表过激进 | 双档 + 审批优先 |
| 4 | "公钥验证"与对称 HMAC 事实矛盾 | 全在线 IPC 签发/核销/验证 |
| 5 | 本地缓存验证有撤销时间窗 | 核销在线化 |
| 6 | IPC 密钥由主进程注入 | orind 生成 + 轮换 |
| 7 | IPC 无防重放/对端校验/限流 | 单调计数器 + audit token/PEERCRED/SID + 令牌桶 |
| 8 | "不看内容"与蜜罐比对矛盾 | 铁律一措辞澄清 |
| 9 | 漏四个入口 | 完整打标清单 + 未登记默认全脏 |
| 10 | 压缩链路 laundering | 摘要污点继承 |
| 11 | 蜜罐位置误报 | 深层伪装 + tripwire + 双证据 |
| 12 | 拒绝反馈泄露监控信号 | 统一固定措辞 |
| 13 | 沙箱"永远一致"夸大 | 子进程面 + 进程内工牌兜底 |
| 14 | 画像 TOCTOU 窗口 | 预声明 + 版本绑定 |
| 15 | L2 审批轰炸 | 高风险才审批 + 展示消毒 |
| 16 | 检测器无基线 | warmup 条款 |
| 17 | orind 崩溃即停产 | 降级只读选项 + 1s 心跳 + 持久化 |
| 18 | 性能数字失真 | 10k/s、500µs p99、依赖注明 |
| 19 | 策略缺验签与回滚保护 | 公钥预置 + 版本单调 + 回滚审批 |
| 20 | 引用与绝对化措辞 | 全面软化标注出处 |

### A.2 v0.2 → v0.3（极限突破，7 项）

| # | 极限 | 突破机制 |
|---|---|---|
| 21 | 语义级泄露 | 密级分区 + 出门证 + 语义金丝雀 + 外发预算（7.1） |
| 22 | 错误损伤不可逆 | 可撤销世界（7.2） |
| 23 | 主人恶意/误用 | 双签 + 冷静期（7.3） |
| 24 | 宿主 0day 爆炸半径 | orind 自沙箱 + worker 化（7.4） |
| 25 | 同用户态取密钥 | 硬件钥匙箱三级（7.5） |
| 26 | 审批疲劳 | 审批经济学（7.6） |
| 27 | 配套 | SECRET 位、clearance 字段、P5、属性测试 |

### A.3 v0.3 → v1.0（核验修订，5 项）

| # | 问题 | 修订 |
|---|---|---|
| 28 | 章节编号错乱（§14 排在 §11 之前） | 全文重排为顺序编号 |
| 29 | 打标点表引用 `cron/scheduler.py`，实际不存在（实为 `cron/engine.py._schedule_job`；AGENTS.md 过时） | 已修正并加注（10.5） |
| 30 | `security/signer.py` 能力未核验 | 已核验为 Ed25519 实现，支撑策略签名与工牌备选算法（5.1、6.8） |
| 31 | 其余引用文件未逐一核验 | 已核验存在：`tools/files.py`、`appshell/inbox.py`/`work_context.py`、`daemon/core.py`、`compression/compressor.py`、`skills/manager.py`、`memory/store.py`/`enhanced_store.py`、`benchmarks/runner.py` |
| 32 | 终版补全 | 攻击者能力假设（3.1）、安全目标 G1–G7（3.3）、IPC 协议（5.4）、安全性质论证（9.1）、攻击链断点分析（9.2）、包结构（10.2）、迁移 SQL（10.4）、产品能力与部署运维（§11）、Schema 草案（附录 D）、术语表（附录 B）、参考文献（附录 C） |

### A.4 v1.0 → v1.1（轮回式全面复查第 1 轮，8 项）

| # | 缺陷 | 修复位置 |
|---|---|---|
| 33 | 蜜罐比对对子进程内容级外发（如 shell 中 `curl -d @file`）的覆盖边界未声明——该外发不经过主进程 | 6.3.4 明确不覆盖 + 两层兜底（画像网络白名单 + 外发巡逻）；9.2 断点6、9.4 残余风险 7 同步 |
| 34 | A3 攻击者"读写主进程内存"假设过强，与污点标签完整性矛盾 | 3.1 澄清：依赖 macOS task-port 跨进程内存保护；失效则列入 9.4 残余风险 6 |
| 35 | 快照机制对"写外区"无恢复能力，7.2/8.2 措辞矛盾 | 7.2 明确快照只覆盖工作区；写外区归入不可逆清单走审批/双签；8.2 快照行同步 |
| 36 | orind/ 置仓库顶层不在 runtime_tcb 保护内，与 6.8/7.4 自保护矛盾 | 10.2 改为 `js/orind/`（随 js 包自动继承 TCB 写保护）并加设计说明 |
| 37 | "Secure Enclave 代算 HMAC"技术不准确（Enclave 不支持 HMAC；TPM2 支持原生 HMAC；Keychain 是受控取出） | 7.5 重写三级钥匙箱的技术事实与档位定义 |
| 38 | 出门证"外发阶段上下文不携带 SECRET"与 I2 单调性表面矛盾 | 7.1.3 明确：批准后生成独立最小外发上下文，原会话密级不变 |
| 39 | 策略表缺缺省行（未命中动作的处理未定义） | 6.2.2 增加缺省行：保守档审批 / 兼容档放行+记录 |
| 40 | 术语表缺"活动上下文/turn/会话"定义；10.4 SQL 未声明示意性质 | 附录 B 补三条术语；10.4 加"以实际 schema 为准"声明 |

### A.5 v1.1 → v1.2（轮回式全面复查第 2 轮，3 项）

| # | 缺陷 | 修复位置 |
|---|---|---|
| 41 | 策略表内"拒/审批/放行"规则冲突时优先级未定义（如 shell 行"含 USER_TURN→放行"与"arg 重叠→拒"同时命中谁赢） | 6.2.2 表格后新增：拒 > 审批 > 放行，结构性拒绝行优先于一切放行条件 |
| 42 | 6.10"敏感条目加 SECRET"的敏感判定标准未定义，存在"靠模型判断"的误读空间（违背铁律一） | 6.10 明确三来源：凭证路径模式表命中、曾被 quarantined、用户显式标记——全确定性 |
| 43 | 语义型金丝雀存在合法引用误报残余（用户主动报出假实体让人代发）未声明 | 6.3.1 补充：实体选型原则"业务中永不应外发"，合法提及由申诉闭环吸收，"近零误报"以此为边界 |

### A.6 v1.2 → v1.3（轮回式全面复查第 3 轮，1 项）

| # | 缺陷 | 修复位置 |
|---|---|---|
| 44 | v1.2 新增的冲突优先级"拒 > 审批 > 放行"未覆盖出门证：D.3 中 NETWORK_EGRESS 有"脏数据→审批"与"SECRET→出门证"两条规则，同一外发同时命中时无定义，而出门证明确"普通审批不可替代" | 6.2.2 优先级改为"拒 > 出门证 > 审批 > 放行"并给出同 sink 冲突示例；D.3 rules 加同步注释 |

## 附录 B：术语表

| 术语 | 定义 |
|---|---|
| Echo | JS Agent 的唯一运行时边界（"员工"） |
| Orin / orind | 本报告提出的防护子系统（"保安"）及其守护进程（`js/orind/`） |
| 工牌 / Lease | capability lease：绑定工具、范围、预算、时效的单次性授权凭证 |
| 污点 / Taint | 标识数据来源的 64 位向量，用于约束数据可流向的动作 |
| 密级 / Clearance | 上下文的保密级别（PUBLIC/INTERNAL/SECRET），SECRET 只升不降 |
| 出门证 / Export Gate | SECRET 上下文内容外发前的唯一合法穿越点（人审），批准后生成独立最小外发上下文执行 |
| 金丝雀 / Canary | 植入的假凭证/假事实实体，用于确定性泄密探测 |
| 画像 / Sandbox Profile | 按 turn 授权动态合成的 Seatbelt/Landlock 沙箱策略 |
| 响应阶梯 | L0–L5 六级渐进处置状态机 |
| TCB | Trusted Computing Base，可信计算基（必须可信的最小代码/数据集合） |
| IFC | Information Flow Control，信息流控制 |
| Fail-closed | 失效即拒绝（门禁失效 = 不放行） |
| turn | 一轮"用户请求 → Agent 处理 → 响应"的完整周期 |
| 会话 / session | 由若干 turn 组成的持续交互单元，承载会话历史 |
| 活动上下文 | 当前实际送入模型的消息窗口；污点与密级绑定的对象 |

## 附录 C：参考文献

**学术论文（arXiv 编号）**
1. Debenedetti et al., *Defeating Prompt Injections by Design*（CaMeL）, 2503.18813, 2025
2. Shi et al., *Progent: Programmable Privilege Control for LLM Agents*, 2503.11703 / 2504.11703, 2025
3. Wang et al., *AgentArmor: Enforcing Program Analysis on Agent Runtime Trace*, 2508.01249, 2025
4. Wang, Poskitt, Sun, *AgentSpec: Customizable Runtime Enforcement*, ICSE 2026
5. Wu et al., *IsolateGPT: An Execution Isolation Architecture*, 2403.04960 / NDSS 2025
6. Wu, Cecchetti, Xiao, *System-level Defense: An IFC Perspective*, 2409.19091, 2024
7. *Prompt Flow Integrity*, 2503.15547, 2025
8. Zhu et al., *MELON: Indirect Prompt Injection Defense via Masked Re-execution*, 2502.05174 / ICML 2025
9. Chen et al., *StruQ: Structured Queries*, USENIX Security 2025；*SecAlign*, CCS 2025
10. Nikolaidis et al., *LlamaFirewall*, 2505.03574, 2025
11. Zhao et al., *ClawGuard*, 2604.11790, 2026；*AIRGuard*, 2605.28914, 2024
12. Zhong et al., *RTBAS*, 2502.08966, 2025
13. *ARM: Provenance-aware Runtime Mediation*, 2604.04035, 2026
14. Ji et al., *MAC Framework for Agent Systems*, 2601.11893, 2026
15. Xiang et al., *Architecting Secure AI Agents*, 2603.30016, 2026
16. Zhan et al., *InjecAgent*, ACL 2024 Findings；Zhang et al., *Agent Security Bench*, 2410.02644 / ICLR 2025；Debenedetti et al., *AgentDojo*, NeurIPS 2024

**行业与标准**
17. OWASP GenAI Security Project, *Top 10 for Agentic Applications 2026*（ASI01–ASI10）
18. Meta, *Agents Rule of Two*, 2025
19. Willison, S., *The Dual LLM Pattern*, 2023
20. Invariant Labs / Snyk, mcp-scan 与 tool poisoning 演示, 2025
21. grith.ai, *We Audited the Security of 7 Open-Source AI Agents*, 2026-02（单一来源，结论引用）
22. GitHub topics: llm-firewall / ai-firewall / agent-safety / ai-guardrails（约 210 仓库清单级调研）
23. Anthropic sandbox-runtime；OpenAI Codex 沙箱（Landlock+seccomp）；nono；yolobox；Pipelock；Lakera Guard
24. MINJA（NeurIPS 2025，经 iternal.ai 转述）；EchoLeak（CVE-2025-32711）

## 附录 D：关键 Schema 草案

### D.1 IPC 消息（协议 v1）

```json
// 请求：工牌核销（每次工具调用）
{"v": 1, "type": "consume", "seq": 10234, "session_nonce": "…",
 "lease_id": "…", "mac": "authority-hmac-sha256:…",
 "context_taint": 1544, "arg_taint": 512, "clearance": 1,
 "tool": "shell", "args_digest": "sha256:…"}
// 响应
{"v": 1, "type": "consume_ack", "seq": 10234,
 "verdict": "allow | approval_required | deny | freeze",
 "receipt_id": "…", "policy_version": 17}
```

### D.2 工牌扩展字段（capability.py 兼容）

```python
# 新字段全部带缺省值；旧 payload 反序列化时缺省 → 旧语义放行 + 记录
taint_floor: int = 0xFFFFFFFFFFFFFFFF   # 缺省不限制（旧语义）
taint_sink: int = 0
sandbox_profile: int = 0                # 0 = 未绑定画像
clearance: int = 1                      # 缺省 INTERNAL
```

### D.3 策略包

```yaml
policy_version: 18            # 单调递增
profile: conservative
signature: "ed25519:…"        # security/signer.py 签发
rules:                        # 同 sink 多行命中优先级：deny > export_gate > approval > allow
  - sink: NETWORK_EGRESS
    forbid_taint: [MEMORY_READ]
    require: [approval]
  - sink: NETWORK_EGRESS
    forbid_clearance: [SECRET]
    require: [export_gate]    # 普通审批不可替代
  - sink: SHELL
    forbid_taint: [WEB_CONTENT]
    when_arg_overlap: true
    require: [deny]
  - default: true             # 缺省行：未命中任何规则
    require: [approval]       # 保守档；兼容档为 [allow, log]
```

### D.4 常设授权

```json
{"standing_auth_id": "…", "pattern": {"tool": "send_mail", "to": "bob@…"},
 "caps": {"per_week": 2}, "expires_at": 1767225600,
 "granted_by": "user_turn:…", "signature": "…"}
```

---

*报告完。下一步：等待主人对 §13 七项开放问题的拍板，即可进入 P0 实施。*
