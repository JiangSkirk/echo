# Orin 阶段 C「强制模式」实施规格

> 状态：已人工评审；C0 已冻结；C1–C3 仅显式 harness 检查点已测；§6.1 合取检查器、enforce fail-fast、C6/C7 证据索引与 [C7 完成声明](ORIN_STAGE_C_CLOSEOUT.md) 已成文。默认生产在 enforce 关闭时仍是 652d035 单进程 ambient；`orin.enforce=true` 因 #8/#9/正式 TCC/AppShell 分离/provider token 等合取缺位继续 fail-fast；**阶段 C 未实施**
> 日期：2026-08-28（Asia/Shanghai）
> 施工基线：commit `652d035e0fda0e945da97e55b73a8f4116716410`，分支 `feature/orin-stage-b`
> 终态北极星：`ORIN_EFFECT_KERNEL_V1.md`（**K**）；阶段 C 对应 K P5，上线验收只听 K§15.6
> 阶段裁决：`ORIN_MERGE_REVIEW.md`（**M**）§3.1；机制库存：`ORIN_DESIGN.md` v1.3（**D**，只取自沙箱与 fail-closed）
> 兼容基线：`ORIN_STAGE_A_SPEC.md`（**A**）与 `ORIN_STAGE_B_SPEC.md`（**B**）
> 冲突裁决：兼容听 A，终态听 K，范围与安全声明听 M§3.1，工作包与阶段内验收听本规格

---

## 1. 声明边界与证据纪律

阶段 C 的目标只有一句话：

> Echo 生产进程失去环境权力。生产副作用只许由 Orin 调度的 Cell 执行；强制模式下，旧 HMAC 工牌、缺失状态见证或失联 Orin 都不能产生生产副作用。

截至本规格基线，这句话是**拟议目标**，不是已观察事实。在全部工作包和 K§15.6 十条硬门槛关闭前，不得宣称阶段 C 已实施，也不得宣称 Echo RCE 已收口。

### 1.1 证据标签

本文只使用以下四种证据标签：

| 标签 | 含义 |
|---|---|
| **已观察** | 能由基线代码、阶段 B 验收账本或本轮只读检查直接支持 |
| **已推断** | 由已观察事实和明确不变量推出，仍需实现或实测验证 |
| **拟议** | 阶段 C 计划采用的实现、开关、文件或测试，不代表已落地 |
| **目标值** | K§10.4 或产品接受标准中的目标，未附实测报告时绝不写成通过 |

验收状态另用 `已具备（B 已测）`、`本阶段必须测`、`blocked`、`untested`、`external-pending`。`计划完成` 不是验收状态。

### 1.2 可以宣称 / 不得宣称

| 只有全部硬门槛关闭后**可以**宣称 | 本阶段始终**不得**宣称 |
|---|---|
| 在已验收的 macOS 生产构建、固定版本和测试边界内，Echo 进程失陷后的生产副作用已结构性收口 | 当前阶段 C 已实施，或当前 Echo RCE 已收口 |
| Desktop、Memory 与阶段 B 已迁效果类都只经 Orin/Cell，Echo 无 ambient 网络、真实凭证、真实写目录、桌面控制或记忆持久化权 | 防 root、内核、宿主 0day、物理攻击或被攻破的 OS 安全原语 |
| `orin.enforce=true` 时，旧副作用工牌、缺见证提交、Orin/Cell 失联和协议降级不能恢复生产副作用 | 图像型提示注入完全免疫、模型判断永远正确、用户批准永不出错 |
| 每条已登记生产效果都有 Orin/Cell 收据，未登记环境出口默认阻断 | Linux/Windows 已具备同等隔离；Windows 命名管道不在本阶段实现 |
| 某个 Cell 故障只收紧该效果类，纯对话与已有上下文分析可继续 | P6 高安全档、Secure Enclave/TPM、per-task VM 或 Fleet 委托已完成 |
| K§10.4 指标只按实际报告或书面调整后的门槛陈述 | `100% 安全`、未测 exactly-once、未测性能数字或“工作区回滚”等于任意世界状态可撤销 |

产品名冻结：APFS 相关能力只称**工作区回滚**，不得扩张为工作区以外的全局回滚承诺。

### 1.3 当前已观察边界

- **已观察**：阶段 B 已落地 EffectDraft、Handle、Intent、Gate Kernel、ExportPass、五类 Cell、唯一 Commit Membrane、AppShell 文件绑定及 Personal 精确批准。
- **已观察**：`stage_b`、`cell_*` 与 `commit_membrane` 默认关闭；当前没有阶段 C 强制开关。
- **已观察**：Desktop 与 Memory 尚未整迁入 Cell；现有 AppShell runtime 与 Echo 仍共享 Python 服务进程。
- **已观察**：模型供应商连接、部分 Office/WebBridge/MCP/技能路径仍可能在主进程持有网络、凭证、写目录或子进程能力。
- **已观察**：现有 `js/echo/os_sandbox.py` 约束命令子进程，不是生产 Echo 进程的最小 OS 权限证明。
- **已推断**：只打开一个布尔开关或只删除 Python handler 不能构成进程失陷收口；OS 权限负面测试和完整出口清单缺一不可。

---

## 2. 安全边界、信任对象与不变量

### 2.1 本阶段威胁模型

本阶段必须覆盖：

- Echo 进程已被任意控制，攻击者可绕过 Python registry、直接调用已导入代码或发起系统调用；
- 模型、网页、邮件、文档、工具结果、记忆内容和技能描述均可恶意；
- 攻击者可重放旧工牌、旧批准、旧见证和旧协议帧，尝试降级 caps 或关闭 Cell；
- Orin、Echo 或任一 Cell 可在提交状态机任意边界崩溃、超时或断连；
- 同一普通用户态进程可尝试连接公开 socket 或冒充 Cell，但不能假设其拥有 root、内核或代码签名信任根。

超出保证范围：

- root、内核、物理攻击、OS 沙箱或代码签名根本身被攻破；
- 主人明确批准了精确展示的有害动作；
- 模型在合法权限内给出错误业务判断；
- 尚未验收的 Linux/Windows 平台隔离；
- P6 高安全档。

### 2.2 信任边界

| 对象 | 阶段 C 定位 |
|---|---|
| Echo / 模型 / 工具文本 | 不可信提案者；不能持有环境权力、许可证或主人签名私钥 |
| AppShell 主人确认面 | 可信输入通道；生产态必须与受限 Echo 进程隔离，不能继续把主人签名权留在 Echo 失陷域 |
| orind / Gate Kernel / Commit Membrane | 确定性仲裁 TCB；无 LLM，不承载完整模型上下文，不拥有通用网络 |
| Effect Cell | 每类最小环境权力的执行 TCB；只接受 Orin 身份，不接受 Echo 直连 |
| macOS 生产启动与沙箱载体 | 声明成立所依赖的 OS TCB；必须实机、打包、签名形态验证 |
| Intent / Handle / StateWitness / Permit / Receipt | 权威对象；模型只能看到允许投影，不能制造、覆盖或取回许可材料 |
| 未登记 handler / 插件 / MCP / skill | 默认无生产环境出口；先登记 Effect Manifest 与执行 Cell 才能启用 |

### 2.3 阶段 C 冻结不变量

1. **C-I01，默认关闭**：所有阶段 C 新开关默认 `false`；升级不会静默改变 `652d035` 行为。
2. **C-I02，Echo 无 ambient authority**：`orin.enforce=true` 的生产 Echo 身份不能直接读取真实凭证、任意联网、写真实目录、控制桌面、写记忆库或访问 Cell 私有接口。
3. **C-I03，Cell 只认 Orin**：Cell 同时验证 socket 所有权、对端 OS 身份、orind 启动绑定、cap、会话 MAC、seq 与 nonce；同 UID 或知道 socket 路径不等于 Orin 身份。
4. **C-I04，生产提交有见证**：R2/R3 生产提交必须绑定当前 StateWitness；缺失、过期、被替换或不全等时拒绝。R0 `net.fetch` 继续是无请求正文、签名 EndpointHandle 的读取路径，不查询或核销 ExportPass。
5. **C-I05，阶段 B 3+1 不变**：`{draft_id}` 走草案链；`cell.build` 保留 WP7 原帧；混装/Connector 原始 payload 硬拒；`cell.net` 保留 R0 旁路。
6. **C-I06，Build 无生产出口**：WP7 Build 原帧可以执行隔离计算，但 Build Cell 无网络、真实凭证或真实目录写权；任何持久化结果重新经 `file.commit`。因此缺生产 StateWitness 的 Build 结果不得直接成为生产副作用。
7. **C-I07，出门证条件步不变**：ExportPass 只用于 `net.send` / `email.send_exact`；`net.fetch` 与 `file.commit` 不查询、不核销、也不复用 ExportPass。
8. **C-I08，唯一提交膜不变**：不新增第二套膜或状态机；`UNKNOWN_COMMIT` 只有对账证明从未发出才回 `PREPARED`，`COMMITTED` 永不回退。
9. **C-I09，签名收据全覆盖**：每条已登记效果路径都产生 K§8.5 完整签名 EffectReceipt，严格绑定 permit ID、executor ID、状态、适用时的远端 operation ID、committed effect hash、result digest、起止时间、前序收据哈希与签名；执行 Cell 用自身独立软件签名身份签发，orind 验签后才追加同一条收据链。WP7 Build 客户端调用/结果帧保持不变，许可证仍不回 Echo。
10. **C-I10，fail-closed**：Orin/Cell/见证/身份任一缺失时，纯对话与已有上下文分析可继续；新读取、执行、写入、外发、桌面动作和记忆持久化按对应类只读、只草稿或拒绝，绝不恢复 ambient fallback。
11. **C-I11，判定路径无 LLM**：效果分类、开关依赖、身份校验、见证、回放、收据和降级判定全部由严格 schema、封印 manifest、OS 身份与状态机决定。
12. **C-I12，零权威回传**：Permit、CellPackage、Secret token、owner-root、stage 路径和私有签名材料不进入 Echo 可见工具结果、ack 或全文审计。
13. **C-I13，Desktop/Memory 是前置**：两类未完成产品迁移时，`orin.enforce=true` 不能进入发布配置，也不能作进程失陷收口声明。
14. **C-I14，回退需冷启动**：`orin.enforce=false` 经冷重启精确回到 `652d035` 行为；运行中不得动态解除 OS 沙箱。

### 2.4 P2-1：file/build 的 `container_vm` 载体（2026-08-30）

**已观察（本修订）**：合取位 `production_sandbox_carrier` 的语义不再等于「Darwin `sandbox-exec` 是否存在」。P2-1 起该位表示 **file 与 build** 具备生产隔离载体：优先 Apple Containerization（独立 Linux VM，`js/orin/container_vm.py`），探测失败则自动 **L1**（Darwin `sandbox-exec` / Linux `bwrap`，即既有 `echo_minimal_os` 探针）。

**白名单（冻结）**：只有 `file` 与 `build` 可以进 VM。desktop、secret、production keybox、memory、net（含与 secret 同进程的 `services` cell）留宿主。guest **禁止**挂载 `orin/keybox.key`、`echo_tool_lease.key`、`orin/secrets.jsonl`。file 进 VM 前 KeyBox 留在宿主 broker；lease 校验走宿主 `cells.sock`。不得按模块名猜测是否构造 KeyBox。

**拟议落地**：无 macOS 26 / 无 `container` CLI 时用假后端测白名单与挂载拒绝；真实 CLI 缺失不得裸跑进 guest。

**不得宣称**：该位置真、本修订或 `container_vm` 代码存在，都不构成阶段 C 已实施，也不关闭 `official_tcc_packaging` / `k156_8_real_model_e2e` / `k156_9_independent_red_team`。

---

## 3. A/B 兼容红线与冲突裁决

### 3.1 非 enforce 行为零改动

`orin.enforce=false` 时：

- A 的六类旧消息 `hello / issue / consume / revoke / heartbeat / freeze` 及其 ack、字段白名单、错误码、帧上限、HMAC 会话认证、seq、nonce 全部保持；
- 工牌 v2 的 `_canonical_lease_payload` 字节、`authority-hmac-sha256` 前缀、旧 JSONL 账本和历史链验证全部保持；
- B 的消息、caps、草案链、五类 Cell、File 产品绑定、ExactCommitApproval、ExportPass 和膜状态机保持；
- Stage A/B 原有回退开关语义保持，结果必须与 commit `652d035` 一致；
- 所有 C 子开关在 `orin.enforce=false` 时均为惰性配置，只允许测试工具直接覆盖模块；不得改变产品路由、权限或用户可见结果；
- 两条预存在 auth 基线红保持原语义，本阶段不顺手修复。

### 3.2 enforce 不是协议删除

`orin.enforce=true` 时仍严格解析、验签并审计旧帧，但旧 HMAC 工牌不能授权生产副作用：

| 旧消息用途 | enforce 行为 |
|---|---|
| `hello` / `heartbeat` | 继续用于会话、健康与能力协商 |
| `revoke` / `freeze` | 继续用于收紧、吊销和冻结 |
| 旧 `issue` / `consume` 试图触发生产副作用 | 稳定拒绝并审计；不进入 raw handler |
| 历史工牌或账本链验证 | 继续可验证，但验证成功不等于在 enforce 下有执行权 |
| B 的 `draft → preflight → consume(draft_id)` | 保持唯一 R2/R3 产品提交入口 |

禁止通过删除 A schema、改变 v2 canonical bytes、停止历史验签或让旧客户端解析崩溃来实现“拒旧协议”。

### 3.3 本规格不回改阶段 B

- 不改变 consume 3+1；
- 不改变 WP7 Build 调用帧、结果帧及沙箱后端契约；
- 不把预检塞进 CommitPermit，package 仍与严格 permit 并列且只走认证 `cells.sock`；
- 不新增顶层消息类型；Desktop/Memory 与签名效果收据只扩展既有 `hello.caps`（拟议 `cell.desktop`、`cell.memory`、`receipt.signed.v1`）、封印 Effect Manifest 和既有 `intent/handle/draft/preflight/commit/receipt/reconcile`；
- 非 enforce 对端未协商 `receipt.signed.v1` 时继续使用 B 的旧 EffectReceipt 形态；enforce 启动必须要求该 cap 和完整 K§8.5 签名字段，不能把旧收据误算为上线证据；
- 不拆 `js/orind/cells/services.py`；
- 不改变 Personal/Work ExportPass、ExactCommitApproval 或 file.commit 语义；
- 不改变唯一 Commit Membrane 的状态图。

### 3.4 冲突裁决

1. 兼容性冲突听 A；
2. 终态安全语义听 K；
3. 阶段 C 声明范围听 M§3.1；
4. D 只提供自沙箱与 fail-closed 机制库存；D 的旧终态口号、性能断言、KeyBox 高安档和全局回滚措辞作废；
5. 文件范围、工作包顺序和阶段内验收听本规格；
6. 任一不确定性按更窄权限与更窄声明处理。

---

## 4. Desktop / Memory 单一路线裁决

本规格选择：**Desktop Cell 与 Memory Cell 作为阶段 C 的前置工作包完成整迁**。

不选择“本阶段不迁、只作窄声明”路线。原因是 M§3.1 允许的阶段 C 声明是 macOS 上的进程失陷结构性收口；同时保留 Desktop/Memory ambient authority 与该声明矛盾。

### 4.1 Desktop Cell

- `desktop_screenshot` / observe 由 Desktop Cell 获取真实像素并形成状态见证；
- `DesktopTargetHandle` 只由 Desktop Cell 在可信 observe 后封印签发（K§7.3），沿用既有 `handle/draft/preflight/receipt` 载荷，并对齐 File Cell ArtifactHandle 的“Cell 封印 + orind 验签”；禁止重开 `handle.op=issue`、新增顶层消息、Echo 自造或 AppShell 通用 issue；
- click/fill/key/drag 等动作绑定封印的 `DesktopTargetHandle`、当前窗口/控件状态、精确动作和审批下限；
- 动作后必须重新观察并写收据，形成真实 `observe → act → observe`；
- Echo 只得到必要图像或安全结果投影，不得到 Accessibility 权限、底层控制 token 或 Cell 私有接口；
- 现有静态 screenshot/click 单测不能替代真实模型 E2E；
- 完成 Desktop Cell 不等于图像型提示注入免疫。

### 4.2 Memory Cell

- 长期记忆数据库、`state_dir/memory` 持久文件、自动 prefetch、`sync_turn` 和所有 mutation 都由 Memory Cell 持有；
- Echo 可通过既有协议请求 R0 读取或提出 R1/R2 写草案，但不能直接打开记忆数据库或文件；
- 权限绑定使用可信 owner/profile/session/task、签名 Intent、封印 Effect Manifest 与 StateWitness，不新增 MemoryHandle 或顶层消息类型；若引用具体文件/生成物，只能消费 File Cell 已签发的 ArtifactHandle，Memory Cell 不得把它扩义为记忆权限或自行签发；
- 旧数据原样兼容；`quarantined`、taint、来源、完整性和保密标签由确定性规则保留，不删数据、不让 LLM决定放行；
- Cell 失联时已在活动上下文中的内容可继续分析；新读取与持久化关闭，不回退主进程数据库访问。

### 4.3 发布阻断

以下任一成立，Stage C 发布状态即 `blocked`：

- Desktop Cell 未覆盖真实观察和所有桌面动作；
- Memory Cell 未覆盖自动读写、后台同步与 Personal/Work owner 隔离；
- macOS Accessibility / Screen Recording 权限仍授予 Echo 身份；
- AppShell 与 Echo 仍共享主人签名私钥或同一不受限进程身份；
- Desktop 真实闭环没有通过 K§15.6 第 8 条。

---

## 5. 强制模式的效果路由与降级语义

### 5.1 权威出口清单

C0 必须机器生成并人工签署 authority inventory。每个注册 handler 只能属于四类之一：`cell`、`readonly`、`draft-only`、`disabled-in-enforce`；未知类默认禁用。

| 环境能力 | enforce 下唯一允许路径 |
|---|---|
| 模型供应商网络与凭证 | 固定目的地、固定账号的 Network/Connector/Secret Cell 组合；Echo 不持 token 或通用 connect。若其隐私/授权分类未人工冻结，发布 blocked |
| 浏览器读取 | 既有 `cell.net` R0；签名 EndpointHandle、无请求正文、无 ExportPass |
| 邮件/外部写 | 既有草案链与 Connector Cell；只对冻结的外发类使用 ExportPass |
| 文件/Office 生成/WebBridge 持久写 | File Cell 的 DirectoryHandle、staging、preflight 与唯一膜 |
| shell/code | WP7 Build 原帧；输入在 Cell 私有 staging，Build 无生产出口；持久输出再经 File Cell |
| 真实凭证 | Secret Cell；每 Cell 显式环境白名单，禁止继承完整 `os.environ` |
| 桌面观察与动作 | Desktop Cell |
| 长期记忆读写 | Memory Cell |
| MCP、skills、插件安装/更新 | 先有本地封印 Effect Manifest，再映射 Build/File/Network/Connector；未分类即禁用 |
| cron/daemon/Fleet 既有调度入口 | 沿用可信 task/Intent，最终效果仍走对应 Cell；跨 Agent/Fleet 委托不做，无法映射的既有入口在 enforce 下禁用 |
| 新工具 | 默认 `disabled-in-enforce`，不得靠 MCP 描述或模型文本自报 read-only |

模型供应商通道不是通用网络旁路，也不得被悄悄并入 ExportPass。C0 必须明确它是受审查的产品基础通道还是某个既有外发效果；无法作出确定性分类时，`orin.enforce` 不得发布。

### 5.2 AppShell 可信确认面

- 生产态主人签名私钥和批准动作必须在受限 Echo 进程之外；
- AppShell 继续使用 B 已有的签名 Intent、DirectoryHandle 与 ExactCommitApproval schema，不新造 Orin 消息；
- Echo 可以请求显示确认界面，但不能触发“已确认”事件、读取私钥或调用内部签发分支；
- 现有同进程 AppShell/Echo 结构只允许在非 enforce 模式继续；C1 必须冻结最小进程边界或可信宿主边界；
- 若可信确认面分离需要未获准的 Rust 改造，则本阶段标 `blocked`，不得用同进程共享密钥替代。

### 5.3 Cell 身份与环境

- 复用 `cells.sock`、既有 hello/caps、PID allowlist 和会话 MAC，不增加顶层消息类型；
- 加强 socket owner/mode/no-symlink、orind 对端 PID/审计身份或继承 FD 绑定；具体 macOS 载体在 C0 人工冻结并实机验证；
- 每个 Cell 仅继承启动所需的显式环境变量；provider key、通用代理、用户 shell 环境和无关 token 默认不继承；
- Build/File/Desktop/Memory/Services 的 cap 互不替代；一个 Cell 不能声明另一 Cell cap；
- 伪造 `cell.*` hello、重放会话 key、同 UID 直连、错误 PID/cap/seq/nonce 均拒绝。

### 5.4 故障与回退

`orin.enforce=true` 时：

- orind 失联：纯对话继续，新环境读取与生产副作用关闭；
- 单 Cell 失联：该类退到只读、只草稿或拒绝；其他 Cell 可按各自健康状态工作；
- Commit Membrane 不可用：R2/R3 不提交，不能切到 `best_effort`；
- Desktop Cell 不可用：不执行桌面动作；若无法可信观察，也不生成新状态见证；
- Memory Cell 不可用：不直接打开记忆库；
- Model Connector 不可用：可以显示安全降级，不能给 Echo 通用网络或 provider token；
- 恢复后先对账 `UNKNOWN_COMMIT` 和未完成操作，再接收新不可逆动作；
- 所有拒绝返回稳定低信息量原因，内部保留最小审计证据。

回到兼容行为的唯一总回退是：停止生产实例，以 `orin.enforce=false` 冷重启。该操作意味着主动离开阶段 C 安全声明，不得包装成强制模式内的自动降级。

### 5.5 单一签名 EffectReceipt 链

- enforce 模式为每个 executor 实例建立独立的软件收据签名身份；私钥经受保护的启动通道交付，只存在于对应 Cell，不进入 Echo、其他 Cell、环境变量或共享执行目录；
- orind 把公钥固定绑定到 `executor_id + 启动 PID/OS 身份 + cap`，不同 Cell 不共享收据私钥；
- orind 通过现有认证会话为执行分配唯一 permit/operation 与当前 `previous_receipt_hash`；具体承载字段受 `receipt.signed.v1` cap 约束，不改变 WP7 客户端调用/结果帧；
- Cell 对完整 K§8.5 payload 签名后经既有 `receipt` 消息回报；orind 在 R2/R3 转为 `RECEIPTED`、或 R0/R1 标记审计完成前，验证签名、executor、permit、effect hash、结果摘要、时间和 previous hash 全等，再原子追加唯一 WAL 收据链；
- unsigned commit_ack 不能由 orind 二次签名后冒充 Cell-signed EffectReceipt；orind 自身的 DecisionReceipt 只证明仲裁/账本事实，不能替代执行 Cell 收据；
- `js/orin/receipts.py` 仍只承载 orind DecisionReceipt；K§8.5 签名 EffectReceipt 只在 `js/orin/draft.py` 按 `receipt.signed.v1` 扩展，禁止把 DecisionReceipt 冒充 Cell 收据；
- 密钥轮换后旧公钥只用于历史收据验证，旧私钥不再签发；跨 Cell 签名、断链、重复链位和错误 executor 全拒；
- 这是软件身份与单链完整性，不是 P6 硬件密钥、设备证明或第二套膜。

---

## 6. 拟议开关与文件清单

本节全部为**拟议**，不是当前 diff；所有新开关默认 `false`。

### 6.1 开关

| 配置 / CLI | 默认 | 用途 |
|---|---:|---|
| `orin.enforce` / `--orin-enforce` | `false` | 阶段 C 总闸；禁止旧副作用工牌与 ambient fallback |
| `orin.echo_minimal_os` | `false` | 用受审查的 macOS 生产载体启动最小权限 Echo |
| `orin.cell_identity_enforce` | `false` | Cell 只接受 Orin OS 身份、启动绑定与协议身份 |
| `orin.cell_desktop` | `false` | Desktop Cell 产品路径 |
| `orin.cell_memory` | `false` | Memory Cell 产品路径 |

`orin.enforce=true` 的启动前置合取：

```
orin.enabled
∧ orin.stage_b
∧ orin.cell_build
∧ orin.cell_secret
∧ orin.cell_net
∧ orin.cell_file
∧ orin.commit_membrane
∧ orin.cell_desktop
∧ orin.cell_memory
∧ orin.cell_identity_enforce
∧ orin.echo_minimal_os
```

任一为假、必要 Cell 未协商 `receipt.signed.v1`、authority inventory 有未知出口、AppShell 信任面未分离或生产沙箱载体未验收时，启动必须 fail-fast；禁止自动补开或静默降级。`orin.enforce=false` 不自动改动任何 A/B 开关。

所有 C 子开关只在 `orin.enforce=true` 时参与产品路由；总闸关闭时，即使配置文件残留 `cell_desktop=true` 等值，也必须保持惰性并精确执行 `652d035` 路径。灰度与预演通过显式测试 harness/影子证据完成，不得借子开关改变非 enforce 生产行为。

### 6.2 拟议修改文件

核心配置、协议与调度：

- `js/config.py`
- `js/orind/__main__.py`
- `js/orind/daemon.py`
- `js/orin/client.py`
- `js/orin/draft.py`
- `js/orin/protocol.py`
- `js/orin/receipts.py`
- `js/orind/broker.py`
- `js/orind/manifest.py`
- `js/orind/kernel.py`
- `js/orind/membrane.py`（只接收现有状态机，不新增第二份）
- `js/orind/store.py`
- `js/orind/cells/__init__.py`
- `js/orind/cells/base.py`
- `js/orind/cells/services.py`（保持单文件，不拆分）

拟议新增 Cell：

- `js/orind/cells/desktop.py`
- `js/orind/cells/memory.py`

AppShell / 生产进程边界：

- `js/appshell/launcher.py`
- `js/appshell/server.py`
- `js/appshell/routers.py`
- `js/appshell/principal.py`
- `desktop/sidecar/host.py`
- `js/ui/cli.py`
- `scripts/macos_start.sh`
- 拟议新增 `js/security/orin_enforce_macos.py` 与只读 macOS profile 资产；具体载体须在 C0 人工冻结，不得把未验证的 `sandbox-exec` 行为写成生产证明

Desktop 接线：

- `js/agent/tool_executor.py`
- `js/tools/desktop_tools.py`
- `js/tools/desktop/{guard,controller,controller_native,permissions,wizard}.py`
- `js/web/routers/desktop.py`

Memory 接线：

- `js/memory/{provider,store,enhanced_store,scheduler}.py`
- 涉及真实持久化的 `js/memory/layered/` 与 `js/memory/layers/`
- `js/web/routers/memory.py`

ambient handler 收口：

- `js/agent/__init__.py`
- `js/models/{providers,provider_manager}.py`
- `js/web/server.py`
- `js/tools/{browser,files,shell,code,office,webbridge}.py`
- `js/mcp/controlled.py`
- `js/cron/engine.py`
- `js/daemon/core.py`
- `js/tools/fleet_tools.py`（只做 enforce 映射/禁用，不实现 Fleet 委托）

测试与证据（拟议）：

- `tests/orin/test_orin_stagec_*.py`
- AppShell 进程边界、macOS profile、Desktop/Memory、provider transport、raw-handler inventory、协议降级、崩溃/重放测试
- `benchmarks/orin/` 阶段 C 基线与实测报告；数字只有实际运行后才能回填

不修改 Rust；不新增 Windows 命名管道实现。

---

## 7. 工作包拆解

依赖顺序：C0 → C1 → C2 → C3 → C4 → C5 → C6 → C7，**禁止跳步**。每个 WP 先写负面测试，再改实现，再跑局部回归与全库门禁。本文成文不代表任何 WP 获准施工。

### WP-C0：人工评审、基线与 authority inventory

交付物：

- 本规格人工评审结论；
- 机器生成的 handler/系统调用/凭证/目录/socket/子进程出口清单；
- 每项标记 `cell / readonly / draft-only / disabled-in-enforce`；
- macOS 生产隔离载体、AppShell/Echo 进程边界和发布签名方案的书面冻结；
- B 的 consume 3+1、ExportPass、File approval、WP7 帧和膜状态机 golden 回归。

验收门槛：

1. 未登记 handler 默认拒绝测试先红；
2. provider、Browser、Office、WebBridge、MCP、skills、cron/daemon/Fleet、`workspace/.js-code` staging、Desktop、Memory 全部在 inventory；
3. 每个环境权力都有未来 Cell 或 enforce 禁用裁决；
4. macOS 隔离载体能在真实打包形态实施；不能证明则标 `blocked`；
5. 两条 auth 基线红仅登记，不修、不扩散。

回退开关：所有 C 开关保持 `false`；无运行时变化。

C0 证据索引：[`ORIN_STAGE_C_C0_INVENTORY.md`](ORIN_STAGE_C_C0_INVENTORY.md)。该索引只记录只读盘点、书面冻结与基线回归，不代表 C1 或任何运行时施工获准。

### WP-C1：可信控制面、Cell 身份与环境收紧

状态（2026-08-24）：

- **已观察 / 身份检查点**：Build/File/Services 的严格 Orin 身份、逐 Cell 环境 allowlist 与 private-path 合同已在显式 `C1TestOrind` harness 验收。生产 orind 入口仍不传 `c1_test_harness`；`--cell-identity-enforce` 可在 `--stage-b` 下显式打开身份合同（默认仍 false），不再绑死测试 harness。Desktop/Memory 进程仍只在 harness 或 `orin.enforce` 合取下 spawn。`orin.enforce=true` 仍因 §6.1 合取未全真 fail-fast。
- **已观察 / macOS 显式 harness 进程分离**：测试宿主先持有 owner-witness 私钥并按既有 B schema 签名，再以全新 OS 进程执行 `JSAgent → run_echo_turn → EchoTurnLoop`。worker 只读宿主生成的裁剪 runtime image、只写私有 scratch state，并只接收 task/handle ID、模型上下文与安全投影；宿主从 `create_subprocess_exec` 记录 Darwin `sandbox-exec` payload PID，固定攻击进程在同一 OS 策略下不能读主人私钥/宿主 state/仓库签发源码、不能发现 AppShell 签发模块或连接宿主 UDS。worker 能用临时自有 key 构造 `approved=True` DTO，但该签名不能通过宿主公钥验证，因而不能成为受信权威事件。旧 stdlib 探针仅保留为负对照。
- **边界未扩张**：C1 进程分离证据仍只通过显式 `c1_harness` 取得。默认 `launcher/server/sidecar` 仍是 `652d035` 的单进程产品路径；`echo_minimal_os` 仍为 Echo worker 的 Darwin `sandbox-exec` 探针。`production_sandbox_carrier` 自 P2-1 起按 §2.4 计算（file/build 的 `container_vm` 或 L1 回退），不把 `SandboxExecutor` 写成已公证 Echo OS 身份。真实 provider token、Keychain/Mach 与正式打包边界仍为 `untested` / `external-pending`。`appshell_echo_separated` 与 `provider_tokens_out_of_echo` 合取位保持假。该检查点不构成阶段 C 已实施或 Echo RCE 已收口的证据。

交付物：

- AppShell 主人确认/签名权移出受限 Echo 进程；
- Cells 只接受 Orin 的 OS + 启动 + 协议三层身份；
- Cell 启动环境改为逐 Cell allowlist；
- socket owner/mode/no-symlink、PID/cap、seq/nonce/MAC 与重放检查。

验收门槛：

1. 假定 Echo RCE 后无法读取主人签名私钥或调用内部 `approved=True` 分支；
2. 普通 UDS 客户端、同 UID 假 Cell、错误 PID/cap、复制 key、重放 hello/commit 全拒；
3. C1 只验收当时已存在的 Build/File/Services Cell 环境 allowlist，确保无无关 provider key、代理或用户 shell 凭证；Desktop/Memory 复用同一环境合同并分别在 C2/C3 落地，禁止为通过 C1 预建其 Cell 本体或跳步；
4. 无 grant 的 register、普通 handle/issue 和 B 的 AppShell 签发回归保持；
5. 不新增 Orin 顶层消息类型。

回退开关：`orin.enforce=false` 冷重启；`cell_identity_enforce` 在总闸关闭时惰性。强制实例不回退身份校验。

### WP-C2：Desktop Cell 产品迁移

状态（2026-08-25）：

- **已观察 / 显式 harness 检查点**：`C2TestOrind` 复用 C1 launch ticket、Cell 身份、private path 与逐 Cell 环境 allowlist，只在显式 harness 启动 `cell.desktop`。真实 macOS 只读观察已取得像素、坐标 scale 与哈希证据；脚本后端已验证严格 draft/preflight/package/permit、DesktopTargetHandle 的 Cell 会话封印 + orind 验签重封、状态漂移/重放拒绝、preflight 零动作和协议级 `observe → act → observe`。普通 `handle.op=issue` 与 Echo 读取完整 DesktopTargetHandle 继续硬拒。
- **已观察 / fail-closed 裁决**：Desktop preflight 在调用 Cell 前、Cell 返回后及 handle sealing 返回后均重新执行主人证/effect/handle/time Gate。K4 能力表不完整仍按阶段 B 规则升级双控；fresh witness 与 post-observe 不顶替幂等/对账证据。因此 Work 预授权不能让 Desktop action consume，Personal 也不能借 ExportPass 放行。
- **已观察 / 本轮原生补证**：Cell-private `MacOSAXActionSink` 只使用 AX/CoreGraphics/AppKit，按 action 派生 point/drag/pointer/focused/application/window selector；PID、bundle id、CGWindowID、AX 结构路径、role/identifier/bounds 与 topmost window 进入 Cell 私有 target/state digest，动作边界再次全等解析。自动化负测覆盖遮挡、同名窗口、PID/window/control/bounds 漂移、单次 sink 与无 legacy controller fallback；本机受控 Calculator 原生烟测观察到真实 AXButton 的像素 `observe → click → observe` 发生变化。该烟测不是模型 E2E，也不证明正式签名包的 TCC。
- **已观察 / 本轮 C2 残余**：Cell 内列表/截图/状态不再构造 `DesktopController`；`AppShellDesktopAppBindingV1` 派生 `ApplicationHandle`，observe/action 只在主人签发的 bundle 内解析，普通 `handle.op=issue` 仍硬拒；原生 window/control 缺 bundle 硬拒；`window_facts` 带 `bundle_id`；Echo 安全投影不再带 PID/AX/`window_number`；store upsert 保留 before/after/target digest，reconcile 可带回；膜重建挂 ApplicationHandle 且不把 `desktop.action` 放进膜自动 consume；Cell commit 封印 HMAC `receipt.signed.v1`，orind 验签后才记 committed，Echo 不见该字段。C2 harness 有与 File 同构的主人签发助手；默认 `/intent` 模板仍只发 DirectoryHandle。
- **blocked / 不算 C2 完成**：`desktop.action` 的 `idempotent` 必须保持 False，K4 能力表因此仍不完整，完整 consume 继续双控；全局 CGEvent 验证后竞态不能从 OS 消掉；真实模型尚未消费真实像素完成决策和动作，K§15.6 第 8 条保持 `blocked`；正式打包 TCC 仍 `external-pending`。§12「Desktop 已整迁」保持未勾。默认生产 DesktopTools 仍 ambient。
- **兼容边界**：默认 launcher/server/router/sidecar 与生产 DesktopTools 在 `orin.enforce=false` 时仍执行 `3b739e5` / `652d035` 的单进程 ambient Desktop 路径。enforce 产品路径已接线 `OrinDesktopCellBackend` 且失联不回 `DesktopController`，但合取未全真，该路径不可达。`cell_desktop` 默认 `false` 且单独置真仍惰性。本状态不证明图像注入免疫、阶段 C 已实施或 Echo RCE 已收口。

交付物：

- DesktopTargetHandle 只由 Desktop Cell 在可信 observe 后封印签发并由 orind 验签；沿用既有 `handle/draft/preflight/receipt` 载荷，对齐 File Cell ArtifactHandle，禁止重开 `handle.op=issue`、新增顶层消息、Echo 自造或 AppShell 通用 issue；
- screenshot/observe、click/fill/key/drag 全部走 Desktop Cell；
- 真实像素状态见证、机器生成审批事实、动作后重观察与收据；
- Echo 主进程不再持有 Accessibility/Screen Recording/控制后端。

验收门槛：

1. 静态与动态检查证明主进程 raw desktop controller 不能产生动作；
2. 目标窗口、控件、坐标、witness、task 或 hash 任一变化全拒；
3. preflight 零副作用，动作后真实观察，收据与目标全等；
4. 真实模型 `observe → act → observe` E2E 通过；仅 mock/静态测试不算；
5. 图像注入用例可以导致拒绝或审批，但测试结论不得写成“完全免疫”。

回退开关：`orin.enforce=false` 冷重启；`cell_desktop` 在总闸关闭时惰性。enforce 实例中的 Desktop Cell 故障只关闭桌面动作/新观察，不恢复 Echo 权限。

### WP-C3：Memory Cell 产品迁移

状态（2026-08-25）：

- **已观察 / 显式 harness**：`C3TestOrind` 才启动 `cell.memory`；`cell_memory` 默认 false 且单独置真惰性。Memory Cell 私有库绑定 owner/profile/session/task + source/taint/clearance；`arguments.session_id` 必须与 AppShell/parent session 全等，错 session/profile/task 经 client 硬拒；DB 只写 `ORIN_CELL_PRIVATE_STATE`，KeyBox 仍用 `ORIN_STATE_DIR`；write/mutate commit 复验 SECRET/taint，未知 commit 行不插入；commit 封印 `receipt.signed.v1` 并由 orind 验签。SECRET/低完整性不得被摘要洗白；重放不重复持久化；跨 owner/session/profile 读取为 ABSENT 或硬拒。
- **blocked / 不算 Memory 已整迁**：默认 launcher/server/sidecar 零接入。`orin.enforce=false` 时 `js.memory.store` / EnhancedStore / `/api/memory*` / cron dream 仍是生产 ambient 路径。enforce 绑定后 ambient 写/读硬拒且 HTTP 503，不回主进程 DB；合取未全真故该路径不可达。§12 Memory 复选框保持未勾。

交付物：

- MemoryStore、EnhancedStore、layered memory、prefetch、`sync_turn` 与 mutation 的 Cell 后端；
- owner/profile/session/task + Intent/Manifest/StateWitness 隔离；具体 ArtifactHandle 仍由 File Cell 签发，Memory Cell 不扩张其语义；
- 旧数据兼容、单写者、崩溃恢复、来源/taint/clearance/quarantine 规则；
- Echo 侧只有薄客户端和安全投影。

验收门槛：

1. Personal/Work 跨 owner、session、profile 读取或写入全拒；
2. 自动 prefetch/sync 与 UI mutation 不存在主进程直写旁路；
3. Cell/Orin 失联后目标库不变，已有上下文仍可分析；
4. 重放、重复写、崩溃恢复不产生重复持久化；
5. 旧记忆不删除、不洗白，判定路径无 LLM。

回退开关：`orin.enforce=false` 冷重启；`cell_memory` 在总闸关闭时惰性。enforce 实例中的 Memory Cell 故障关闭新记忆读取/写入，不回退直接数据库访问。

### WP-C4：macOS 最小 OS 权限与 ambient handler 收口

状态（2026-08-30）：P2-1 为 **file/build** 增加 `container_vm` 载体（§2.4）；探测失败回 L1。显式 deny-default 沙箱探针仍要求 stdout `ok` 且成功退出。默认 launcher 未把整进程 Echo 接入 Containerization。正式签名包 TCC **external-pending**，不得因此打开 enforce。不得把 `SandboxExecutor` 或 `container_vm` 写成 Echo OS 身份或阶段 C 已实施。

交付物：

- 受审查的 macOS 生产启动/沙箱载体；
- Echo 仅保留模型编排、Orin 客户端和必要非权威临时存储；
- provider、Browser、File/Office、WebBridge、shell/code、Desktop、Memory、MCP/skill 环境权力按 §5.1 迁移或禁用；
- Build staging 移入 Cell 私有区，持久输出只经 File Cell；
- orind 自沙箱：无通用网络，只读代码/策略，只写状态与 socket；
- Cell 按类最小权限，`services.py` 不拆。

验收门槛：

1. 在真实打包的 macOS 生产进程中，Echo 对真实凭证、任意网络、真实写目录和 Cell 私有接口的 OS 级负面测试全部拒绝；
2. 仅删除 registry/handler 不算通过；假定任意 Python 控制流后直接 `open/connect/exec` 仍失败；
3. 模型通道仍可完成产品任务，但 Echo 不持 provider token 或通用网络；
4. 每个 Cell 权限矩阵只有自身必要能力，完整环境不继承；
5. authority inventory 扫描无 `unknown`，动态探针无未登记真实出口。

回退开关：`orin.enforce=false` 冷重启；`echo_minimal_os` 在总闸关闭时惰性。强制实例运行中不能解除沙箱；某类故障退只读/只草稿，不把权限还给 Echo。

### WP-C5：`orin.enforce` 与降级阻断

状态（2026-08-25）：`receipt.signed.v1` 已扩 `EffectDraft` 侧 `SignedEffectReceiptV1`，C2/C3 Cell commit 封印并由 orind 验签后才记 committed，Echo 投影丢弃该字段；DecisionReceipt 不得冒充 Cell 收据；C2/C3 harness 缺/错/过期 witness 经 client 全拒；未登记 handler 默认 deny；HMAC `handle.op=issue` 仍无生产副作用。§6.1 合取检查器列出缺失位（含 #8/#9/正式 TCC/AppShell 分离/provider token 离 Echo）；任一为假则 `orin.enforce=true` 继续 fail-fast，禁止空泛 “C2-C7 未完成”。`orin.enforce=false` 默认路径仍不拉起 Desktop/Memory Cell。

交付物：

- 总闸及 §6.1 前置合取；
- enforce 下旧生产工牌、缺 witness、失联 orind、raw handler 与非法开关组合的稳定拒绝；
- 使用既有 `receipt/receipt_ack` 完成 K§8.5 签名 EffectReceipt 链与未登记 handler 默认 deny；不新增消息类型；
- 非 enforce 与 `652d035` 的 golden 等价测试。

验收门槛：

1. `orin.enforce=false` 时 A 六类消息、HMAC v2 字节、B 3+1、WP7 帧与工具行为等价；
2. `orin.enforce=true` 时旧 HMAC `issue/consume` 无法产生生产副作用；
3. R2/R3 缺见证、错见证、过期见证或不全等见证全拒；
4. orind/膜/Cell 任一失联都没有 ambient fallback；
5. `net.fetch` 继续不查 ExportPass，`file.commit` 继续不查/不核销 ExportPass；
6. Build 原帧不变且只能产生隔离结果，持久化必须重新走 File Cell；
7. Permit/package/token 不进入 Echo 可见结构。
8. 每个 R0–R3 效果都有 permit ID、executor ID、状态、适用时的远端 operation ID、effect hash、result digest、时间、前序哈希和签名全等绑定的 EffectReceipt；断链、伪签、跨 Cell 收据全拒。
9. 未协商 `receipt.signed.v1` 的非 enforce 对端只接受和产生 B 的原字段集合，额外 `signature` 字段按未协商字段拒绝；协商 cap 后才启用新的严格 schema。

回退开关：冷重启为 `orin.enforce=false`，精确恢复 `652d035` 行为并退出阶段 C 声明。

### WP-C6：崩溃、重放、RCE 假设与降级验证

状态（2026-08-25）：Desktop/Memory harness 已观察 UNKNOWN_COMMIT 不盲重放；C3 client `draft→preflight→consume` 路径覆盖 Memory UNKNOWN_COMMIT 与 Cell 失联否认。无真实 provider 幂等证据的不可逆 Connector 保持 blocked。禁止把本文件写成攻击 PoC。

交付物：

- 状态机每一边界的 kill/timeout/断连矩阵；
- 旧协议、cap/版本/算法降级、permit/witness/approval 重放与 Cell 冒充测试；
- 假定 Echo 已获任意控制流的无害环境探针；
- 对发布支持的真实不可逆 Connector 使用测试账号做幂等与对账验证；
- 收据、预算、重启和 `UNKNOWN_COMMIT` 证据报告。

验收门槛：

1. durable prepare 前后、发送前后、响应丢失、receipt 前后均无静默放行；
2. 不可逆重复副作用为 0；无法提供 provider 幂等/查询证据的效果类标 `blocked`；
3. `UNKNOWN_COMMIT` 不盲重试，只有证明从未发出才回 `PREPARED`；
4. 已 `COMMITTED` 的操作永不回退；
5. 降级、重放、socket 直连和 raw syscall 探针不能绕过完整仲裁；
6. 测试是受控负面验证，不产出、保存或发布可武器化攻击 PoC。

回退开关：保持 `orin.enforce=false`；任一失败不得扩大权限或跳到性能 WP。

### WP-C7：性能、产品接受、独立复核与发布裁决

状态（2026-08-28）：K§10.4 延迟/RSS/启动/背压 **untested**，非正式 K§10.4。仓库现有测量夹具只产出带 “harness 观察 / untested / 非正式 K§10.4” 标签的观察，禁止把数字写成达标。C2/C3 harness 可记录一条 IPC/commit 延迟作为 **harness 观察**。enforce 关闭时继续走 `3b739e5`/`652d035` 单进程路径，不在日常启动拉起 Desktop/Memory Cell；Cell 在 harness/enforce 下常驻由 watchdog 保活。enforce 效用与日均审批 **untested**。#8 真实模型 E2E 与 #9 独立红队无证据，正式 TCC/公证仍 external-pending，不得上线、不得宣称 Echo RCE 已收口。发布决议已写成 [`ORIN_STAGE_C_CLOSEOUT.md`](ORIN_STAGE_C_CLOSEOUT.md)，裁决为 **阶段 C 未实施**。

交付物：

- K§10.4 的硬件/OS/payload/并发/基线完整报告，或逐项书面调整；
- enforce 下正常任务、mock benchmark 与日均审批统计；
- K§15.6 十条证据索引；
- 独立于实施者的红队复核；
- blocked/untested/external-pending 终表和发布决议。

验收门槛：

1. 性能、RSS、CPU、启动、背压与故障收紧全部有实测或获批书面调整；
2. 产品接受标准：正常任务效用不低于批准基线，mock ≥95%，日均审批 ≤5；未测就是 `untested`；
3. K§15.6 第 8 条真实桌面闭环通过；
4. K§15.6 第 9 条独立红队完成且未发现完整仲裁新旁路；
5. 两条 auth 基线红保持同一原因，任何新增红都失败；
6. 十条任一仍为 `blocked`、`untested` 或 `external-pending`，不得作上线或结构性收口声明。

回退开关：不发布 `orin.enforce=true`；已部署试点冷重启为 `orin.enforce=false`，并明确退出阶段 C 声明。

---

## 8. K§15.6 十条对照

本表记录**本规格成文时**的状态，不是未来目标状态。

| # | K§15.6 硬门槛 | 当前状态 | 已有证据与缺口 | 阶段 C 关闭条件 |
|---:|---|---|---|---|
| 1 | Echo OS 身份无真实凭证、任意网络、真实写目录、Cell 私有接口 | **本阶段必须测** | B 迁了部分效果；Echo 最小 OS 权限未落地 | WP-C4 真实打包 macOS OS 级负面测试 |
| 2 | 所有副作用有 Orin/Cell 收据，无未登记环境出口 | **本阶段必须测** | Desktop/Memory、provider、Office/WebBridge 等尚有主进程路径；K§8.5 完整签名 EffectReceipt 链仍有债务 | C0 inventory 清零 + C2/C3/C4 迁移 + C5 签名收据链 + 动静态出口验证 |
| 3 | 旧协议、缺见证、失联 Orin 无生产副作用 | **本阶段必须测** | 非 enforce 下兼容路径仍合法；强制开关不存在 | WP-C5 enforce 矩阵 + WP-C6 故障/降级验证 |
| 4 | 机密外发只接受精确出门证 | **本阶段必须测** | **已具备（B 已测）子证据**：task/hash/destination/witness 全等、Personal 单次与 Work 常设；ambient/provider 网络出口尚未收口 | C5/C6 回归并证明无 OS 网络旁路；不改变 ExportPass 效果类 |
| 5 | 崩溃与超时中不可逆重复次数为 0 | **本阶段必须测** | B 已测本地膜逐状态 crash/restart；真 provider、响应丢失和真实不可逆效果仍不足 | WP-C6 对每个发布 Connector 给出 provider 级幂等/对账证据 |
| 6 | 性能、内存、CPU、启动、背压达 K§10.4 或书面调整 | **untested** | K§10.4 全部是目标值；不得沿用 D 的微秒/qps 口号 | WP-C7 实测报告或逐项书面调整 |
| 7 | 正常效用与审批量达产品标准 | **untested** | B mock 11/11、overall 1.000 是已有局部证据；enforce 效用与日均审批未测 | mock ≥95%、批准的真实任务基线、日均审批 ≤5 |
| 8 | 真实 `observe → act → observe` 桌面闭环 | **blocked** | C2 显式 harness 已观察 ApplicationHandle、原生 window bundle 硬拒、Echo 去 PID/AX/`window_number`、digest upsert 与 HMAC Cell 收据验签；确定性烟测仍无真实模型决策，`desktop.action` 因非幂等继续双控，默认 Desktop 仍 ambient | 真实模型 E2E 与生产 Desktop 整迁；未通过即禁止上线声明 |
| 9 | 独立红队未发现完整仲裁绕过 | **blocked** | 独立复核资源与结果均为 external-pending | WP-C7 独立复核完成；外部资源未到位也不得上线 |
| 10 | 未完成项明确标 blocked/untested/external-pending | **本阶段必须测** | B 债务已有标签，但 C 尚无实施证据账本 | 每 WP 更新证据索引，最终人工审计；“计划完成”不算 |

第 6 条不承诺任何数字。第 7 条的 `日均审批 ≤5` 与 `mock ≥95%` 是产品接受标准，不是当前实测结论。第 8、9 条在本表为发布阻断项，因此本规格不能支持任何上线声明。

软件关不掉的外部门：正式 TCC / Developer ID / 公证、K§15.6 #8 真实模型 `observe → act → observe`、#9 独立红队、每个不可逆 Connector 的 provider 幂等 / operation ID 证据。未完成前不得打开 `orin.enforce`，不得勾选 §12「Desktop/Memory 已整迁」，不得宣称阶段 C 已实施或 Echo RCE 已收口。全局 CGEvent 验证后 TOCTOU 无法从 OS 消掉；`desktop.action` 必须保持 `idempotent=False`。

---

## 9. 测试、证据与验收纪律

### 9.1 每个 WP 的固定门禁

1. 先写拒绝/逃逸/回退红测；
2. 最小实现，不顺手重构 A/B；
3. 严格 schema、未知字段、伪布尔、Unicode/NFC、长度/深度/重复键测试；
4. 局部 ruff、mypy、pytest；
5. A 六消息/HMAC v2、B consume 3+1、WP7、WP8、WP9、WP10 回归；
6. 全库 ruff、mypy、pytest 与 mock benchmark；
7. 只接受两条已确认 auth 基线红，且原因、数量和测试身份不变；
8. `git diff --check` 与秘密扫描；
9. 证据报告记录版本、硬件、OS、配置、payload、并发、时间和失败项；
10. 未跑项目标 `untested`，外部依赖标 `external-pending`，无法继续标 `blocked`。

### 9.2 强制负面测试

- Echo RCE 假设：直接 `open/connect/exec`、读取 provider/key 文件、写 workspace、访问 memory DB、连接 cells.sock；
- raw handler：Browser/File/Shell/Code/Office/WebBridge/Desktop/Memory/MCP/skills 绕过；
- 协议：旧 HMAC、缺 witness、错 task/hash/executor/handle、版本/cap/算法降级、乱序与重放；
- 身份：同 UID 假 Cell、错误 PID、cap 扩张、socket 替换、symlink、会话 key 复制；
- 故障：orind/Cell/Echo kill、队列满、磁盘满、时钟跳变、网络分区与响应丢失；
- 回退：Cell 故障、膜关闭、orind 失联时不恢复 ambient authority；
- 泄漏：Echo 可见结果与日志无 permit/package/token/root/stage 路径/主人私钥；
- Desktop：真实像素进安全输入、精确目标见证、动作后重观察；
- Memory：跨 owner/profile/session、自动同步、旧数据、崩溃重放和 quarantine。

### 9.3 不以攻击 PoC 代替验证

RCE 验证使用“已获得任意控制流”的无害测试入口与哨兵资源，验证权限边界本身。禁止为此开发或提交漏洞利用链、凭证窃取器、持久化载荷或面向真实目标的攻击 PoC。

---

## 10. 阶段 C 明确不做

- K P6 全部：Secure Enclave/TPM 高安全签名、per-task VM、独立双签与冷静期、Fleet/多 Agent 跨设备委托、企业设备证明；
- Rust 实现或 Rust 重构；
- Windows 命名管道、AppContainer/LPAC 实现；Linux 强隔离实现；
- 修复两条预存在 auth 基线红；
- 重做阶段 A/B，改变 consume 3+1、WP7 Build 帧、ExportPass 条件步、File approval 或 Commit Membrane 状态机；
- 拆分 `services.py` 或新增 Orin 顶层消息类型；
- 完整可视化 diff UI；
- 把 K§10.4、审批量、性能或资源目标写成已达标；
- 真正攻击 PoC、恶意利用链或秘密采集工具；
- 提交 `.env`、credentials、Keychain 真凭证、token、私钥或任何许可证材料；
- 宣称工作区回滚覆盖外部系统、桌面、记忆或任意世界状态；
- 宣称图像注入完全免疫、root/内核失陷可防或阶段 C 已经落地。

---

## 11. 风险登记

| 风险 | 当前状态 | 阶段 C 控制 | 不能关闭时的裁决 |
|---|---|---|---|
| AppShell 与 Echo 同进程，主人签名权在同一失陷域 | **blocked** | C1 分离可信确认面与受限 Echo | 不启用 enforce，不作收口声明 |
| 模型 provider 需要网络和真实凭证 | **blocked** | C0 分类，C4 迁固定 Connector/Secret 路径或采用经审查的无 ambient 方案 | 聊天不可用或声明不成立；不得给 Echo 通用网络 |
| Desktop Accessibility/Screen Recording 权限归属新 Cell 未实机验证 | **external-pending** | C2 真机与打包 E2E | K§15.6 #8 保持 blocked |
| Memory 自动同步、layered store 或 UI mutation 漏迁 | **blocked** | C0 inventory + C3 单写者/全路径测试 | Memory 整类关闭 |
| Office/WebBridge/MCP/skills 等未分类 handler | **blocked** | C0 机器 inventory，未知默认禁用 | 不发布 enforce |
| Cell 继承完整 `os.environ` | **本阶段必须测** | C1 每 Cell 环境 allowlist | 对应 Cell 不启动 |
| 同 UID 假 Cell 或 socket 替换 | **本阶段必须测** | C1 OS/启动/协议三层身份 | Cell 接口关闭 |
| macOS 生产沙箱载体与打包/签名不兼容 | **external-pending** | C0 先实机冻结载体，C4 包内验证 | 阶段 C blocked；不得用未测机制替代 |
| Build 在主进程预写 `workspace/.js-code` | **本阶段必须测** | C4 移入 Cell 私有 staging，持久输出走 File Cell | code/shell 只草稿或关闭 |
| provider 不支持幂等或对账 | **external-pending** | C6 测试账号与 provider operation ID | 该不可逆效果类 blocked |
| 真断电与真实 provider exactly-once 尚未覆盖 | **untested** | C6 先满足 K 的 crash/timeout；物理断电保持诚实标签 | 不宣称超出已测故障模型 |
| 性能、启动、RSS、CPU 与审批量未测 | **untested** | C7 实测或书面调整 | 不发布 |
| 独立红队资源未安排 | **external-pending** | C7 独立复核 | K§15.6 #9 blocked |
| 同用户恶意进程探测 IPC、读同权限文件或冒充 Cell | **范围内残余风险** | C1 身份/权限测试；依赖 macOS task-port、文件 ACL 与代码签名假设成立 | 不作为单独上线阻断，但声明写明 OS 假设；绕过完整仲裁则 blocked |
| OS 0day、root/内核、物理攻击 | **范围外残余风险** | 最小权限、代码签名和日志只缩小影响，不提供保证 | 安全声明明确排除 |
| 关闭 enforce 会恢复兼容 ambient 行为 | **已推断** | 只允许冷重启并明确退出强制模式声明 | 不称为安全降级 |

---

## 12. 阶段退出清单

只有以下全部满足，才允许把阶段 C 从“规格”改为“已实施候选”：

- [x] 本规格已人工评审；C0 已冻结，C1/C2 仅获显式 construction harness 检查点授权；
- [ ] C0–C7 严格顺序完成；
- [ ] Desktop 与 Memory 已整迁；
- [ ] AppShell 可信确认面已离开 Echo 失陷域；
- [ ] macOS 生产 Echo 最小 OS 权限有真实打包证据；
- [ ] Cell 只接受 Orin 身份且环境变量按类白名单；
- [ ] authority inventory 无未知生产出口；
- [ ] enforce 拒旧 HMAC 生产副作用、缺 witness 与失联 Orin；
- [ ] A/B 兼容 golden 全绿，WP7 帧与 B 3+1 未变；
- [ ] K§15.6 十条全部有证据，不再含 blocked/untested/external-pending；
- [ ] 第 8 条真实桌面闭环和第 9 条独立红队均通过；
- [ ] 性能与产品目标已实测或书面调整；
- [ ] 两条 auth 基线红未被本阶段“修复”或改变；
- [ ] 无秘密、permit、package、token 或 owner-root 泄漏；
- [ ] 发布说明只限 macOS、固定版本和实际测试边界。

在此清单关闭前，本文只是一份实施规格。C7 完成声明见 [`ORIN_STAGE_C_CLOSEOUT.md`](ORIN_STAGE_C_CLOSEOUT.md)；写成“未实施”不等于把上表勾成已实施候选。
