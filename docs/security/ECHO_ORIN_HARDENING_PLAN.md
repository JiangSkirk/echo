# Echo × Orin 架构强化方案

> 版本：v1.1 · 2026-08-30
> 范围：js-agent（`{repo_root}`）
> 基线：v1.0 针对 commit `7652629`（2026-08-30 02:04）实测；v1.1 评审对照 HEAD `c4aa97b`（其后仅文档修订）
> 目标：让 Echo（通用 agent 核心）与 Orin（安全防护架构）做到 **安全、稳定、快捷、低延迟、省 token、低设备要求**
> 方法：完整盘点现状 → 学术/工程调研（Google Scholar + arXiv + 一手工程资料）→ 交叉检查 → 可执行方案

### v1.1 修订记录（2026-08-30）

对照仓库代码评审 v1.0 后的修订，不是推倒重写。逐条：

- **A1** 动态风险门控：P0 中途 dirty 位单调收窄（禁写/禁 egress）；中途升级 plan-commit 挪到 P2-2。
- **A2** 默认生效面：`gateway.enabled=true` ⇒ 该表面 plan-commit 默认开且不落入 `policy_profile=compat`。
- **A3** Containerization 只作 file/build 载体；desktop/secret/keybox/memory/net 留宿主；不宣称解锁 Stage C。
- **B1** 值槽位是新建；EXECUTE 确定性步进；T2 只承诺控制流部分零额外 token；P0 工期 4–5 周。
- **B2** 稳定前缀：不可信表面冻结集不得扩大；memory 移出 system prompt。
- **B3** 前向安全与 Merkle 锚定绑定交付；`tip_anchor.py` 不是 Merkle。
- **B4** 收窄检查守护真实策略入口，不预设 evolution 接线；挡住 supervisor 静默 compat。
- **B5** AgentDojo 基线期仅报告，稳定后阻断；每夜子集/每周全量。
- **B6** 存在非本地后端时，plan-commit（含 PLAN）与中途 dirty 之后的模型调用禁止 `is_local_model`；仅本地后端时 deny-write。
- **C** 530 个测试文件；顶层 `echo/` 无代码；两套门不得混用。

---

## 0. 摘要（结论先行）

**核心判断：Echo 和 Orin 的架构方向与 2025–2026 年学术界的最新结论高度同构，不需要推倒重来；需要的是把学术界已验证的 6 项技术"嵌进现有骨架"，而不是替换骨架。**

具体结论：

1. **Echo 的 capability lease + effect 管道，本质上就是 Google DeepMind CaMeL 的"能力安全模型"的独立实现**——CaMeL 在 AgentDojo 上以 77% 任务完成率（无防护 84%）取得"可证明安全"，代价是 2.8 倍 token。Echo 已有等价骨架但**没有 CaMeL 的"控制流先于不可信数据定型"这一关键性质**，这是本次方案最重要的一课。
2. **Orin 的 taint（u64 位掩码 + "taint 永不授权"铁律）方向正确**，但学术界已经走得更远：Microsoft FIDES 把信息流标签放进规划器做确定性执行，在 AgentDojo 上挡住全部测试注入且任务完成率反而提升约 16%。Orin 应升级到"规划器级 IFC"。
3. **"绝对安全"在学术界已被证伪为不可能目标**——Google 防 Gemini 注入的复盘（arXiv:2505.14534）确认：一切分类器/启发式在自适应攻击下都会失效。Orin 的正确目标不是"绝对安全"，而是 **"结构性安全边界 + 可验证审计 + 受控降级"**。这与 Orin 现有 SECURITY.md 信任模型一致，方案不会承诺做不到的事。
4. **省 token / 低延迟 / 低设备三个目标与安全性存在真实冲突**（CaMeL 花 2.8 倍 token 买安全），本方案的解法是 **动态风险门控（risk-gated）**：入口可信且 `context_taint` 无 dirty 位时走轻路径；入口不可信走 plan-commit 重路径；**入口可信但回合中途出现 dirty 位时，P0 对剩余迭代单调收窄（禁写/禁 egress），不在当回合中途升级 plan-commit**。只看入口会漏掉最常见的注入路径（CLI/桌面回合中途用 web 工具读入恶意内容）。现有 `js/orin/taint.py` 已按来源给工具结果打位（`WEB_CONTENT`/`INBOX_CONTENT`/`BOT_PEER` 等），P0 消费该信号做收窄；中途升级 plan-commit 放到 P2 与 taint→label 合并。
5. **最紧迫的工程发现**：macOS 的 `sandbox-exec`（Echo 当前默认沙箱载体）已被 Apple 标记废弃且被认为"弱"（见 §2.3），而 Apple 官方 Containerization 框架（每容器独立轻量 **Linux** VM、亚秒启动、Apache-2.0、v1.0.0 已于 2026-06-09 发布）是 **file/build cell** 的载体候选，**不是** desktop/secret/memory/net 或 Stage C 外部门的总开关。desktop（AX/AppKit/`screencapture`）与 secret / production keybox（Keychain）必须留宿主。memory 与 net+connector 今日在进程内构造 `KeyBox`/`SecretStore`，P2-1 **不得**把它们放进 VM。guest **禁止**挂载生产 KeyBox / lease 密钥 / secret 路径。`production_sandbox_carrier` 合取位**当前语义**是 Darwin `sandbox-exec` 可用性（`js/orin/stage_c.py`），升级为 Containerization 验收须先改 `ORIN_STAGE_C_SPEC.md`；即便该位置真，`official_tcc_packaging` / `k156_8_real_model_e2e` / `k156_9_independent_red_team` 仍是外部门，本方案不宣称解锁 Stage C。

**推荐行动**：按 §5 的 P0→P3 四阶段执行。P0（零新外部依赖，但是槽位策略与测试密度配套，不是"纯重组"）即可拿到"入口不可信 → plan-commit"与"中途 dirty 位 → 单调收窄"两大收益；P1 引入 AgentDojo 作为 Orin 的 CI 安全门；P2 把中途收窄升级为剩余迭代 plan-commit，并解决沙箱载体迁移；P3 做性能与 token 优化。**任何阶段失败都可回退到上一阶段，不破坏现有行为。**

---

## 1. 现状基线（代码实测，非文档转述）

### 1.1 Echo —— 通用 agent 核心（`js/echo/`，约 4.3 万行 Python）

| 组件 | 文件 | 现状 |
|---|---|---|
| 回合权威边界 | `turn_runtime.py`（33 KB） | 所有副作用只能以 `ModelEffect`/`ToolEffect` 形式经 `EffectInterpreter` 执行；workspace 路径派生不透明句柄（域分隔 SHA-256） |
| 效应解释器 | `effect_interpreter.py`（26 KB） | 可信适配器：授权 effect → 执行 → receipt |
| 能力租约 | `capability.py`（70 KB） | HMAC-SHA-256 租约：签发/验证/单次消费/BFS 级联撤销；密钥不出 authority 边界；纯策略 oracle 零 I/O |
| 防篡改账本 | `ledger/`（28 个模块） | 哈希链日志 + MAC journal + tip anchor/seal + e2e 签名 + 证据导出 + 恢复 |
| OS 沙箱 | `os_sandbox.py`（56 KB） | macOS `sandbox-exec` / Linux `bwrap`+`unshare`；环境变量白名单 8 项；`.git` 写保护；`strict_isolation=True` 时沙箱不可用则拒绝执行（fail-closed，不降级裸跑） |
| 上下文节省 | `context_savings.py` 等 | 内容寻址存储（CAS）去重 + Session Capsule 压缩；token 计数启发式可注入真实 tokenizer |
| 回合循环 | `turn_loop/` | model gate、流式工具、遥测 |

### 1.2 Orin —— 安全防护架构（`js/orin/` 约 8 千行 + `js/orind/` 约 1.9 万行）

| 组件 | 现状 |
|---|---|
| 污点追踪 `taint.py` | u64 位掩码标记消息来源；`context_taint` 为活跃窗口 OR 累积；SECRET 位通过压缩粘性传播；工具调用时附 8-gram Jaccard 参数重叠度。**铁律（代码层）：taint 永不授权，干净的 taint 不能跳过任何检查，只能产生 approval/deny**。**产品默认路径另有降级**：AppShell Stage A 启用 Orin 时强制 `policy_profile=compat`（`js/orin/supervisor.py`），非 allow 判定变为 allow+log；`SECURITY.md` 写明默认 Host 路径不把 taint 当审批门。P0 的默认生效面（下节不变量 5 例外）必须让 gateway 表面脱离此降级，否则新机制交付后默认安装防护提升为零 |
| 门内核 `orind/kernel.py` | 确定性三见证合取：owner 意图 + 来源句柄契约 + 新鲜状态见证 + 本地策略 + 审批满足 + 配额余量 + 无冻结/撤销。**决策路径上没有任何模型/分类器调用**，任何缺失/过期输入即拒绝 |
| 提交膜 `orind/membrane.py` | 不可逆 Stage-B 效应的持久化提交膜；只存授权元数据（标识符/摘要/句柄/计数器），效应内容永不入库 |
| Cell 体系 `orind/cells/` | desktop/file/memory/build/services 五类 cell + keybox 密钥隔离 + patrol（egress/entropy/rate 三道巡逻） |
| Stage C 状态 | **未实施**（`ORIN_STAGE_C_CLOSEOUT.md` 2026-08-28 裁决）：`orin.enforce` 默认 false；缺 process split、provider token 出 Echo、生产沙箱载体、官方 TCC 打包、真实模型 e2e、独立红队六项外部门 |

### 1.3 与学术前沿的差距（一句话版）

Echo/Orin 已经造出了"能力 + 污点 + 确定性门 + 防篡改账本"的骨架，但**缺三样东西：① 控制流在接触不可信数据前定型的保证（CaMeL 的核心性质）；② 安全效果的标准化度量（AgentDojo）；③ 生产级隔离载体（Stage C 卡点）**。性能侧缺"模型级联路由 + 提示压缩 + KV 复用"三板斧的系统化。

---

## 2. 调研结果：技术地图

> 调研范围：Google Scholar（经 scholar 数据源）、arXiv、NeurIPS/ICLR/USENIX S&P/IEEE S&P/NDSS/HotOS 论文与一手工程资料，2026-08-30 检索。原始检索数据存于 `research/*.csv`。

### 2.1 Agent 安全的结构性防御（最重要的一类）

**CaMeL —— "Defeating Prompt Injections by Design"**（Google DeepMind + ETH Zurich, arXiv:2503.18813, 2025-03）
- 机制：特权 LLM（P-LLM）只看可信用户请求并生成显式计划/程序；隔离 LLM（Q-LLM）处理不可信数据但只能提取值、永不能发起工具调用；自定义 Python 解释器给每个值挂 capability 标签（来源 + 允许读者），每次工具调用前做策略检查
- 结果：AgentDojo 上 77% 任务以**可证明安全**完成（无防护基线 84%）；对 Gemini 2.5 Pro / o3 配置 949 次攻击 0 次成功（带策略）
- 代价：约 2.8 倍 token 开销；工具效用随模型变弱显著下降（Claude 3.5 Sonnet -26.8pp）
- 来源：arXiv: 2025-03(https://arxiv.org/abs/2503.18813)；Zylos Research: 2026-06-18(https://zylos.ai/research/2026-06-18-prompt-injection-defense-autonomous-agents/)；Replyant: 2026-04-23(https://replyant.com/lab/camel-dual-llm-defense/)

**Progent —— 可编程权限控制**（UC Berkeley, arXiv:2504.11703, 2025-04）
- 机制：DSL 表达工具调用最小权限策略；**Z3 SMT 求解器做确定性的策略比较**；"单调约束"（Monotonic Confinement）：动作空间无审批只能缩不能扩
- 结果：AgentDojo 间接注入攻击成功率 39.9%→1.0%（相对降 97.5%）且效用零损失（79.4% 保持）；手动审批模式 ASR 0.0%；94% 策略更新是收窄（可自动批准）
- 来源：arXiv: 2025-04(https://arxiv.org/abs/2504.11703)；ndqkhanh/lyra 调研笔记: 2026-06-07(https://github.com/ndqkhanh/lyra/blob/main/docs/lyra-upgrade/plans/12-permissions.md)

**FIDES —— 规划器内确定性信息流控制**（Microsoft Research, arXiv:2505.23643, 2025-05）
- 机制：信息流标签在规划器中确定性传播与执行
- 结果：挡住全部测试的 AgentDojo 注入；配合推理模型时任务完成率**反超基线约 16%**——结构不仅不伤效用，还能增效用
- 来源：arXiv 引用列表: 2026-06-25(https://arxiv.org/html/2606.26479v1)；jadenfix/tempOS 分析: 2026-07-04(https://github.com/jadenfix/tempOS/issues/48)

**Design Patterns for Securing LLM Agents**（Invariant Labs/ETH + IBM + Google + Microsoft, arXiv:2506.08837, 2025-06）
- 六个结构性模式：action-selector（模型只能把意图翻译成预批动作）、plan-then-execute（接触不可信数据前提交计划）、LLM map-reduce（不可信数据只进隔离子代理）、dual-LLM、code-then-execute、context-minimization
- 价值：这是一套**现成的执行模式词汇表**，可直接映射为 Echo 的回合模式
- 来源：arXiv: 2025-06(https://arxiv.org/abs/2506.08837)；FuzzySlipper/agora-os 调研: 2026-04-09(https://github.com/FuzzySlipper/agora-os/blob/main/research/research.md)

**AgentDojo —— 注入攻防基准**（ETH Zurich, NeurIPS 2024 D&B, arXiv:2406.13352）
- 97 个任务 + 629 个安全用例，度量间接注入成功率与防御有效率；已成为 CaMeL/Progent/FIDES 的共同度量衡
- 来源：NeurIPS 2024 论文页(https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html)（scholar 检索 s1，被引 950）

**重要反方证据 —— Gemini 防御复盘**（Google, arXiv:2505.14534, 2025-05）：分类器与输出校验这类"检测式"防御在**自适应攻击**下会失效，只是缓解不是保证。来源：arXiv: 2025-05(https://arxiv.org/abs/2505.14534)，经 arXiv:2606.26479 引用确认

**其他已核验的相关工作**：IsolateGPT/SecGPT（NDSS 2025, arXiv:2403.04960，每应用独立实例 + 权限接口）；Conseca（HotOS 2025, arXiv:2501.17070，上下文化策略）；SAGA（arXiv:2504.21034，agent 治理架构）；AgentSpec（ICSE 2026, arXiv:2503.18666，可定制运行时执行）；StruQ（USENIX Security 2025, arXiv:2402.06363，指令/数据双通道微调）；LlamaFirewall（Meta, arXiv:2505.03574，分层检测管道）；llmbda 演算（arXiv:2602.20064，CaMeL 模式的形式化）；AgentSys（arXiv:2602.07398，分层内存 + IFC）；PCAS 策略编译器（arXiv:2602.16708，Datalog 派生策略语言，合规率 48%→93%）
来源：arXiv 各论文页与引用列表（见 §8 来源清单）；scholar 检索 s1/s6

### 2.2 防篡改审计日志（对应 Echo ledger）

- **前向安全日志（Schneier-Kelsey 传统）**：密钥随时间演进，攻击者拿到当前密钥也无法伪造历史——Echo 的 HMAC 链可升级为前向安全键控（多篇来源确认该传统：scholar 检索 s2，Custos 论文引述 Bellare-Yee 与"forward integrity"定义）
- **WinSeal**（IEEE S&P 2026）：高效溯源日志篡改保护，指出现有部署的审计日志系统存在窗口期漏洞。来源：IEEE Xplore: 2026(https://ieeexplore.ieee.org/abstract/document/11573416/)（scholar s2）
- **Custos**（USENIX Security 2020）：用可信执行环境做操作系统级防篡改审计，被引 145。来源：NSF PAR: 2020(https://par.nsf.gov/biblio/10146530)（scholar s2）
- **证书透明（Certificate Transparency, RFC 6962）式 Merkle 树**：把账本 tip 周期性锚定到外部见证，提供包含证明。Echo 已有 `tip_anchor.py`，但是**外部单调计数器 + MAC，不是 Merkle**；inclusion proof 是新组件，不得写成"扩展量小"

### 2.3 隔离载体（对应 Orin Stage C `production_sandbox_carrier` 卡点）

| 载体 | 冷启动 | 隔离强度 | 平台 | 适配判断 |
|---|---|---|---|---|
| `sandbox-exec`（现状） | 进程级 | 弱：仅文件/网络 ACL，**已被 Apple 废弃**；macOS 无 namespaces/cgroups/seccomp | macOS | 现状可用但需规划迁移 |
| **Apple Containerization** | **亚秒** | 每容器独立轻量 Linux VM（Virtualization.framework），共享内核 VM 模型被淘汰 | macOS 26 + Apple Silicon，Apache-2.0，v1.0.0（2026-06-09） | **P2-1：file/build 载体**；desktop/secret/keybox/memory/net 留宿主直至密钥材料离开该进程 |
| Wasmtime（WASM） | <0.03 ms（AOT 预编译） | 软件沙箱（类型系统 + 边界检查线性内存）；Cranelift 形式化验证进行中 | 全平台 | skill/插件代码执行的理想载体 |
| Hyperlight | 1–2 ms | 硬件 VM 隔离，无 guest OS，默认 64KB 栈/128KB 堆；Hyperlight Wasm = Wasmtime + microVM 双层 | Linux/Windows 原生；macOS 支持有限（见 §6 风险 R7） | Windows 部署阶段的候选 |
| Firecracker | ~125 ms | KVM 硬件 VM | Linux | Linux staging 可选 |
| gVisor | 容器级 | 用户态内核拦截全部 syscall | Linux | Linux staging 可选 |

来源：Microsoft 开源博客: 2024-11-07(https://opensource.microsoft.com/blog/2024/11/07/introducing-hyperlight-virtual-machine-based-security-for-functions-at-scale/)；Hyperlight 官网对比表(https://hyperlight.org/)；Microsoft 开源博客: 2025-03-26(https://opensource.microsoft.com/blog/2025/03/26/hyperlight-wasm-fast-secure-and-os-free/)；awesome-sandbox 平台档案: GitHub(https://github.com/restyler/awesome-sandbox)；oflight 专栏: 2026-06-29(https://www.oflight.co.jp/en/columns/apple-container-macos-linux-runtime-2026-06)；networkeffect journal: 2026-04-15(https://networkeffect.dev/)（"sandbox-exec 已废弃且弱"的出处）

### 2.4 省 token / 低延迟 / 低设备（对应 Echo 性能目标）

- **LLMLingua 提示压缩**（Microsoft, EMNLP 2023, arXiv:2310.05736）：用小模型困惑度做由粗到细的提示压缩，**最高 20 倍压缩、性能仅降 1.5 分**；黑盒可用。注意：25–30 倍以上压缩率性能崩塌；压缩小模型与目标模型 tokenizer 不一致会低估 token 数。来源：ACL Anthology: 2023(https://aclanthology.org/2023.emnlp-main.825.pdf)；arXiv(https://arxiv.org/abs/2310.05736)
- **KV 缓存复用 / C2KV**（ACM 2026）：压缩可组合的 KV 缓存复用，系统提示与查询的 prefill 成本免于重复计入 TTFT。来源：ACM DL: 2026(https://dl.acm.org/doi/abs/10.1145/3770855.3817715)（scholar s4）
- **模型级联路由**：Route-and-Reason（WWW 2026，强化学习路由做能效扩展，约 6 美分达到 DoT 同等性能）；cost-aware contrastive routing（NeurIPS 2025）；ParaCascade（并行级联 + 早路由）。来源：ACM DL: 2026(https://dl.acm.org/doi/abs/10.1145/3774904.3793038)；NeurIPS 2025 论文页(https://proceedings.neurips.cc/paper_files/paper/2025/hash/e46eb6403af68506331f941282d838aa-Abstract-Conference.html)（scholar s5）
- **推测解码（speculative decoding）**：小草稿模型 + 大模型验证，agentic 推理加速已有专门工作（arXiv:2607.03333，2026）；SPADE 面向边-云分布式低成本推理（arXiv:2608.13076，2026）。来源：arXiv(https://arxiv.org/abs/2607.03333；https://arxiv.org/abs/2608.13076)（scholar s7）
- **分层记忆**：AgentSys（arXiv:2602.07398）显式分层内存管理 + 不可信内容路由到非特权 LLM，只有结构化、经策略检查的摘要回流——与 js-agent 三层记忆 + 梦境整合同构，可直接借其"策略检查摘要回流"环节（scholar s6）
- 业界实践旁证：符号索引导航相比整文件读取可减少约 77% 活跃 token（2026 从业者报告，弱来源，仅作方向参考）。来源：GitHub: 2026-07-18(https://github.com/melodygaoyifan/autoproduct-design/blob/main/15-validation-and-traceability.md)

---

## 3. 技术适配矩阵（每个候选 × Echo/Orin 现状）

| # | 技术 | 落点 | 预期收益 | 成本 | 与现状冲突 | 裁决 |
|---|---|---|---|---|---|---|
| T1 | CaMeL 双 LLM + 值级 capability | Orin 高风险回合模式 | 注入攻击结构性免疫（可证明） | 高：2.8× token、双模型 | 与"省 token"直接冲突 → **风险门控，不全局启用** | 采纳（改造版） |
| T2 | Plan-then-Execute / Action-Selector 模式 | Echo `turn_loop` 新增 plan-commit 回合模式 | 控制流先于不可信数据定型；**控制流部分**零额外 token（填槽若走隔离提取则另计） | 中高：非纯重组——lease 现状是整参数摘要，槽位策略是新建；须配套 M1 ≥1.2 测试 | 无第二套 loop | **采纳（P0 核心）** |
| T3 | Progent Z3 单调约束 | Orin 策略更新路径（`policy_profile` / 策略表 / config / 手动 `policy.change`；**不**预设 evolution 接线） | 策略只能收窄不能扩，SMT 确定性证明 | 中：Z3 依赖 ~30MB，只在策略更新路径，不在回合热路径 | 无 | 采纳（P1） |
| T4 | FIDES 规划器级 IFC | Orin taint 升级：标签进规划器 | 证据显示可增效用（+16%） | 中高 | taint 铁律保持不破 | 采纳（P2） |
| T5 | AgentDojo CI 门 | Orin 验收体系 | 安全效果从"自说自话"变标准化度量 | 中高：须写 Echo 工具→AgentDojo pipeline 适配器；每夜真模型成本与抖动 | 2pp 阈值在 LLM 抖动下易 flaky | **采纳（P1 核心）** |
| T6 | 前向安全键控 + Merkle 锚定 | Echo ledger 升级 | 历史日志前向完整；外部可验证证据 | 中：现状单静态 `journal.key`/`permit.key`，`PermitSeal.key_epoch` 硬编码 `permit-epoch-1`；`tip_anchor.py` 非 Merkle | 验证路径必须改：按 epoch 选钥或从 genesis 验证棘轮 | 采纳（P1，**绑定交付**） |
| T7 | Apple Containerization 载体 | Orin Stage C `production_sandbox_carrier`（**先改 SPEC 再改位语义**） | P2-1 给 **file/build** 真 VM 隔离；memory/net 须先让该进程不再持有生产 KeyBox；**不**解锁 Stage C 外部门，也**不**承载 desktop/secret | 中：需 macOS 26；老设备回退 sandbox-exec | 设备要求上升 → 分层回退；Linux VM 跑不了 AppKit/Keychain；file/memory/services 今日会在进程内构造 KeyBox | **采纳（P2 核心，范围收窄）** |
| T8 | Wasmtime skill 沙箱 | Echo skill/插件执行 | 亚毫秒启动的全平台沙箱 | 中：skill 需编译 wasm 或运行时嵌入 | 现有 skill 是 Python → 渐进式 | 采纳（P3 探索） |
| T9 | LLMLingua 式压缩 | Echo context_savings 升级 | 工具输出/长文档最多 20× 压缩 | 中：压缩模型本地运行（phi-2 级 <8GB），启发式回退 | 与"低设备"部分冲突 → 可选模块 | 采纳（P3，可选） |
| T10 | KV 复用 + 稳定前缀契约 | Echo prompt 组装层 | prefill 成本显著下降；零质量损失 | 低中：须冻结自适应 schema、把 memory 移出 system | 与自适应工具子集互斥 → 可信会话可冻结后追加；**不可信表面整段会话不得扩大冻结集** | **采纳（P0 顺手做）** |
| T11 | 模型级联路由 | Echo models/router 升级（`_task_complexity` 预留桩可作落点） | 本地小模型优先，云端兜底；成本/延迟双降 | 中 | **存在非本地后端时**：plan-commit（含 PLAN）与中途 dirty 之后的模型调用禁止 `is_local_model`。仅本地后端时这些回合 deny-write。与 CaMeL 弱模型 -26.8pp 同构 | 采纳（P2） |
| T12 | 推测解码 | 本地推理后端（Ollama/LM Studio）集成层 | 本地模型解码 2–3× 加速 | 低（后端配置而非自研） | 依赖后端支持 | 采纳（P3 配置层） |
| T13 | Gemini 教训：检测式防御的定位 | SECURITY.md 已声明 | 防止团队对分类器产生错误信心 | 零 | 无 | 已采纳（维持） |
| T14 | seL4 形式化验证路线 | 仅作灵感（capability 命名、规格先行） | — | 极高 | 超出项目阶段 | 不采纳（记入远景） |

---

## 4. 目标架构

```
┌─────────────────────────────────────────────────────────────┐
│  AppShell / CLI / Gateway（入口；channel 经 set_entry_source 打污点）│
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Echo Core（通用 agent 核心）                                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ turn_runtime（唯一回合边界；动态风险门控）                  │  │
│  │  ├─ 轻路径：入口可信且无 dirty 位 → 现有 effect 管道        │  │
│  │  ├─ 中途收窄（P0）：迭代边界发现 context_taint 新增 dirty 位  │  │
│  │  │     → 剩余迭代禁写/禁 egress（只收紧不放松）             │  │
│  │  └─ 重路径：入口不可信 → plan-commit 模式（T2）            │  │
│  │       1. PLAN：模型只见可信指令，disable_tools，输出计划骨架     │  │
│  │       2. BIND：新建槽位级绑定（工具名 + 每槽 taint_policy + 填充源）│  │
│  │          现有 capability 整参数哈希不够；allowlist 只锁工具名     │  │
│  │       3. EXECUTE：确定性步进已绑定序列，不让模型再选工具         │  │
│  │           装配器填槽；模型 tool_calls.arguments 非权威           │  │
│  │  P2：中途 dirty 位可升级为对剩余动作 BIND（与 T4 合并）     │  │
│  ├─ capability（租约签发/消费/撤销，+ T3 SMT 收窄证明）      │  │
│  ├─ ledger（哈希链 + 前向安全键控 + Merkle 锚定，T6）         │  │
│  ├─ context（CAS 去重 + 稳定前缀 T10：system+冻结 schema；memory 不进前缀）│  │
│  └─ models（级联 T11：轻路径可本地优先；重路径与中途 dirty 后禁止降级弱模型）│  │
└──────────────────────────┬──────────────────────────────────┘
                           ▼  每个 effect 草案
┌─────────────────────────────────────────────────────────────┐
│  Orin Gate（安全平面，决策路径零模型调用）                       │
│  ├─ kernel：三见证合取（意图 + 句柄 + 新鲜见证 + 策略 + 审批    │
│  │   + 配额 + 无冻结）→ ALLOW 是全合取，缺一即拒               │  │
│  ├─ taint→label 升级（T4）：污点标签进入 plan 的槽位级策略     │  │
│  ├─ membrane：不可逆效应的持久化提交膜                          │  │
│  └─ patrol：egress / entropy / rate 三道巡逻                  │  │
└──────────────────────────┬──────────────────────────────────┘
                           ▼  持有 CommitPermit 的效应
┌─────────────────────────────────────────────────────────────┐
│  Cells（执行载体，分层回退）                                    │
│  L0 进程内（现状，仅可信本地操作）                               │
│  L1 sandbox-exec / bwrap 子进程（现状默认，strict_isolation）  │
│  L2 Apple Containerization Linux VM（T7：P2-1 仅 file/build）     │
│     desktop/secret/keybox/memory/net 留宿主，直至密钥材料离开该进程 │
│  L3 Wasmtime（T8，skill/插件代码，全平台探索）                  │
└─────────────────────────────────────────────────────────────┘
```

设计不变量（任何阶段不得违反）：

1. **回合唯一边界**：模型、工具、附件只从 `run_echo_turn` 进；plan-commit 是回合内模式，不是第二套 loop
2. **taint 铁律**：污点永不授权；升级后的 label 同样只能收紧不能放松；中途 dirty 位触发的收窄（P0）与剩余迭代 BIND（P2）同样只收紧，不得因后续干净消息放松已收窄的动作空间
3. **决策路径零模型**：Orin kernel 合取不调用任何模型/分类器（现状已满足，保持）
4. **fail-closed**：任何子系统缺失/异常 → 拒绝，不降级。orind kernel 合取与 `strict_isolation` 沙箱路径现状已满足；**不得把默认 Host 路径写成已 fail-closed**——`orin.enforce` 默认 false，AppShell 把 `policy_profile` 改成 compat。新机制在默认生效面上必须真正拦截，不得再落入 allow+log
5. **向后兼容**：轻路径（未开启不可信表面时）行为与当前版本逐字节一致；所有新机制默认关，显式开启。**例外（opt-in 表面联动默认）**：用户显式打开不可信入站表面时，该表面的防护默认开，不算破坏向后兼容。具体：`gateway.enabled=true` ⇒ 该表面 `plan_commit` 默认开，且该表面的 Orin 策略档**不落入 compat**（deny/approval_required 必须拦截，不得 allow+log）。CLI/桌面等未声明为不可信入口的路径保持现状，直到用户另开开关

**默认生效面（P0 必须交付，否则防护提升为零）**：gateway 是配置默认 `false` 的显式 opt-in。开启 gateway 而不联动 plan-commit + 脱离 compat，等于把最需要结构性防御的表面留在"只记日志"路径上。验收见 P0-4。

---

## 5. 分阶段实施路线图

### P0 —— plan-commit 模式 + 稳定前缀（**4–5 周**；零新外部依赖，含 M1 测试密度配套）

| 项 | 内容 | 验收标准 | 回退 |
|---|---|---|---|
| P0-1 | `turn_loop` 新增 `plan_commit` 回合模式：PLAN→BIND→EXECUTE 三阶段。**激活条件是动态风险门控，不是入口一次性判定**。（1）入口不可信（`run_echo_turn` 经 `orin_taint.set_entry_source(channel)` 打上 `INBOX_CONTENT\|WEB_CONTENT` 或 `AUTO_TASK`）→ 整回合走 plan-commit；（2）入口可信但迭代边界发现 `context_taint` 新增 dirty 位（至少 `WEB_CONTENT`/`INBOX_CONTENT`/`BOT_PEER`；与现有 `DIRTY_FOR_WRITE` 对齐）→ **P0 对剩余迭代单调收窄：禁写、禁 egress，只收紧不放松**；（3）中途升级到 plan-commit（对剩余动作重新 BIND）放到 P2-2，与 taint→label 合并。收窄是确定性策略，零额外 token。不沿用 `require_untrusted_surface`（那是隔离姿态门，不是逐回合信任标记）。 | 新增模式与收窄路径单测全覆盖；轻路径现有 **530** 个 `test_*.py` 零回归；构造"可信入口 + 中途 web 读入注入"用例，收窄后 0 次写/egress 成功 | 配置开关 `echo.plan_commit=false` 恢复现状；收窄路径可单独关但默认与 plan-commit 同开关 |
| P0-2 | 值槽位机制（**新建，不是复用现有 capability 检查**）。现状 lease 把**整份 arguments** 哈希进 `args_schema`（`js/agent/tool_executor.py` 的 `stable_payload_hash`），`taint_floor`/`taint_sink` 是 lease 级字段，`consume` 不做逐参数评估。P0 要新增槽位：计划里每个参数位 `{slot:taint_policy}`，EXECUTE 只能填已 BIND 的槽。**填槽来源（二选一，优先 1）**：（1）工具输出的确定性投影（结构化字段：路径、ID、URL、状态码）——零模型、零额外 token；（2）隔离提取调用（Q-LLM 角色，只许返回值、不许发起工具）——**有额外 token，T2 不承诺全局零 token**。禁止用同一个受污染上下文的模型既提取值又隐式决定参数拼装（否则拿不到 CaMeL 控制流性质）。**落点必须分三层，缺一不可**：（a）PLAN 用 `TurnRequest.disable_tools`；（b）BIND 冻结工具**名**（`lease_tool_allowlist`；bots 冻结 schema / `c4aa97b` 只覆盖这一层，不够）**并且**签发槽位级绑定（每槽 taint_policy + 允许的填充源），不是只哈希模型刚产出的整份 JSON；（c）EXECUTE 是对已绑定序列的**确定性步进**（下一步由计划计数器决定，不是模型选择）：本阶段不向模型下发可选工具 schema；由装配器按 BIND 表填槽，再对装配结果做 `args_schema`。若为填槽发起隔离提取，那是一次 `disable_tools` 的独立模型调用，不得进入工具循环。若实现仍把模型 `tool_calls` 接到 EXECUTE，视为缺陷：模型建议只能校验、不得增键、不得改已填槽、不得改下一步工具名，否则 deny。 | 构造注入用例（邮件/网页/文档，优先扩展 `tests/adversarial/corpus.jsonl`）重路径下 0 个导致计划外动作；负例：仅设 `lease_tool_allowlist` 仍消费模型 arguments、或 EXECUTE 仍让模型选下一步工具 → 必须失败；新增代码保持测试密度 ≥1.2 | 同上 |
| P0-3 | prompt 稳定前缀契约。今日破坏前缀的因素包括：memory `get_context_string`（query 依赖，注入 system prompt）、learned insight / optimizer A/B、session capsule 改写、**自适应工具 schema 子集**（`turn_loop/schema.py`，按 query 变化）、压缩替换中段、bots volatile tail。**决策：会话内冻结工具子集**（该冻结集同时作为 plan-commit PLAN 的动作词典）。可信 CLI：可按首回合 query 定集，之后只许追加不得重排/删减。**不可信表面（gateway 等）：冻结集 ⊆ 该表面静态允许清单，整段会话不得扩大**——静态清单是显式配置（建议 `gateway.tool_allowlist`，默认只读/无 exec/无任意 egress），**不得把全量 registry 当默认清单**；清单缺失则 fail-closed（该表面不下发写/egress 工具，或拒绝启动 gateway）。首回合 = 静态清单 ∩ 自适应；后续回合只可保持或再交而缩小，**禁止追加、禁止把后续用户消息或工具结果并入冻结集**。memory 注入从 system prompt 挪到 system 之后的独立消息（保持 `<memory trust="untrusted">`），不得进入可缓存前缀。推广 bots 已有 `prompt_cache_key` + Anthropic `cache_control` 钩子（`js/bots/persona.py`）到通用 Echo 路径。 | **限定**无压缩、无 capsule 的会话段，且 **5 回合用户 query 互不相同**（须覆盖若走旧自适应路径会选出不同工具子集的 query）：`system+冻结工具 schema` 前缀哈希一致；哈希输入**不得**含 memory 块（负例：memory 仍在 `_build_system_message` → fail）；负例：未冻结 schema 时这 5 个 query 的工具子集哈希应互不相同；**负例：gateway 会话无论第 1 条还是第 N 条塞工具关键词，冻结集不得超出该表面静态允许清单，也不得比本会话已冻结集更宽**。token 计量入 ledger | 开关回退；schema 冻结可单独关，关则不宣称缓存收益 |
| P0-4 | **默认生效面（gateway 联动）**：`gateway.enabled=true` 时，（1）`gateway:*` channel 的 `plan_commit` 默认开（仍可用显式 `echo.plan_commit=false` 关掉，但文档必须把这标成降级）；（2）该表面策略档不落入 `policy_profile=compat`：`file_write`+dirty→approval、`shell`+`WEB_CONTENT`→deny 等现有表项必须拦截，不得 allow+log。AppShell 全局 compat 改写不得覆盖 gateway 表面。CLI/桌面默认仍可不启用 plan-commit。 | gateway 开启的集成测试：注入用例走 plan-commit；Orin 非 allow 判定实际拒绝/要求审批，日志里不得出现"compat degraded to allow" | 显式 `echo.plan_commit=false` 或关闭 gateway；compat 降级必须打可见警告 |

### P1 —— 可度量安全（3–4 周）

| 项 | 内容 | 验收标准 | 回退 |
|---|---|---|---|
| P1-1 | 接入 AgentDojo：把 js-agent 工具集映射到 AgentDojo 任务套件（**适配器是真实工程量**，不是 drop-in）。CI：**每夜子集、每周全量**；固定模型版本 + 多 seed 降抖动。预算上限写入 CI 配置，超支停跑并报告。**门控分两期**：基线期（未写入 `benchmarks/` 或约定基线文件前）仅报告、不阻塞发布；基线稳定后 ASR 回归 >2pp 或 ASR >5% **阻断发布**（与 §7 一致）。 | CI 产出 ASR 数字与基线存档；基线期流水线黄灯；稳定后回归超阈值红灯阻断；held-out 不进调参循环（R3） | 基线期可关阻断；不可关报告 |
| P1-2 | ledger 前向安全升级，**与 Merkle 锚定绑定交付**（拆开即缺口）：HMAC 密钥按 epoch 演进，旧 epoch 密钥销毁后，该 epoch 历史条目的完整性验证义务**必须**转移到关闭该 epoch 时的 seal / Merkle 根（否则要么留着链头等于没销毁，要么历史不可验证）。现状：单静态 `journal.key`/`permit.key`（`js/echo/ledger/service.py` 无轮换）；`PermitSeal.key_epoch` 仅命名、硬编码 `"permit-epoch-1"`。`tip_anchor.py` 是外部单调计数器 + MAC，不是 Merkle；inclusion proof 是新组件。双读期 1 个版本：旧验证器可读旧链。 | 篡改任一历史条目 → 验证失败且定位到条目；密钥泄露模拟：当前 epoch 钥泄漏不得伪造已关闭 epoch；关闭 epoch 后销毁旧钥仍能用 Merkle 根+包含证明验证该 epoch | 保留旧验证器读旧链（双读期 1 个版本）；不得单独上线"销毁旧钥"而无锚定 |
| P1-3 | 策略收窄证明（T3 轻量版）。**守护现有真实入口**，不预设 evolution→policy 接线：evolution 今日是 proposal-only，`approve_and_apply` 只写 `evolution/applied/` JSON，不改 Orin 策略表；`policy.change`/`SINK_POLICY_CHANGE` 只是效应词汇。本项覆盖：（1）`policy_profile` 切换；（2）策略表 / `orin.*` config 变更；（3）手动 intent 的 `policy.change`。**包括** AppShell `prepare_product_orin` 把 `conservative` 静默改成 `compat`——这是扩张，P1-3 必须挡住或改成显式配置；该静默改写不得覆盖 P0-4 gateway 表面。暂不引入 Z3，用格（lattice）比较：动作空间是否收窄。日后若接线 evolution，须先经过本检查，本项不负责去建那条接线。 | 扩张性策略变更 100% 触发人工审批；收窄性变更可自动通过；负例：伪造 evolution 提案直接改策略表 → deny；负例：supervisor 静默 conservative→compat 仍发生在 gateway 表面 → fail | 全部转人工审批 |

### P2 —— 生产隔离载体（4–6 周；对齐 Stage C **合取位之一**，不关闭外部门）

| 项 | 内容 | 验收标准 | 回退 |
|---|---|---|---|
| P2-1 | Apple Containerization 集成：`orind/cells` 新增 `container_vm` 载体后端。**P2-1 VM 白名单只有 file 与 build**（memory **不**进本项：`js/orind/cells/memory.py` 同样在进程内构造 `KeyBox`）。net+connector **不得**进 VM：今日它们与 secret 走同一 `_spawn_services_cell()`（`js/orind/daemon.py`），即使 `ORIN_CELLS_CAPS` 只有 `cell.net` 也会构造 `KeyBox`/`SecretStore`。desktop / secret / production keybox 留宿主。凡进 VM 的 cell：**禁止把生产 KeyBox、`echo_tool_lease.key` 或 `orin/secrets.jsonl` 挂进 guest**；lease 校验走宿主 broker（`cells.sock`）。file 入口今日会构造 `KeyBox`，build 入口今日只用 session MAC——白名单仍按"无密钥材料进 guest"验收，不按模块名猜测。`production_sandbox_carrier` 现语义是 Darwin `sandbox-exec` 可用性（`js/orin/stage_c.py`）；置真前必须先改 `ORIN_STAGE_C_SPEC.md`。置真后仍不得宣称 Stage C 已实施。 | VM 内 **file 与 build** 冒烟通过；白名单拒绝 desktop/secret/net/memory；guest 挂载清单不含 keybox/secret/lease 密钥路径；desktop 冒烟仍在宿主；SPEC 修订后该合取位可置真 | 载体探测失败自动 L1；memory/net 维持宿主直到 KeyBox 离开该进程；外部门保持 pending |
| P2-2 | taint→label 规划器升级（T4）：plan 的每个槽位携带来源标签，策略判定从"工具调用时"提前到"计划绑定时"。**同时把 P0 的中途收窄升级为剩余迭代 plan-commit**：已执行步骤保持，未执行动作空间按当前 taint 重新 BIND（只收紧不放松）。 | AgentDojo 重路径 ASR 对比 P0 再降；效用分不回退超 3pp；中途升级用例在收窄之上进一步禁止计划外动作 | 标签层开关；关闭后回退为 P0 中途收窄 |
| P2-3 | 模型级联路由（T11）：难度/风险分类器（规则式，非 LLM）→ 本地小模型优先 → 云端升级；与现有 fallback/断路器合并。落点：`js/models/router.py` 的 `_task_complexity` 预留桩。**交互条款**：只要配置了非本地后端，plan-commit（含 PLAN）与中途收窄后仍要调模型的回合 **禁止** `is_local_model`。仅当本地是唯一可用后端时，该回合改为 deny-write（诚实话第 2 条），不得用弱模型跑 PLAN/EXECUTE 写/egress。 | 预定义任务集上**轻路径**云端调用占比下降 ≥40% 且任务成功率不降；负例：存在非本地后端时，入口重路径（含 PLAN）或可信入口中途 dirty 之后的模型调用被路由到 `is_local_model` → fail；仅本地后端时这些回合必须 deny-write | 路由表配置回退；禁降级条款（plan-commit 与中途 dirty 后的模型调用）不得随路由表关掉 |

### P3 —— 性能与 token 深化（持续，全部可选模块）

| 项 | 内容 | 验收标准 | 回退 |
|---|---|---|---|
| P3-1 | LLMLingua 式压缩（T9）：工具输出/长文档压缩，压缩率上限 10×（远离 25× 崩塌区）；压缩模型本地 phi-2 级；无 GPU 设备回退现有启发式 | 压缩后任务成功率降 <2pp；token 节省 ≥60%（长文档场景） | 模块级开关，默认关 |
| P3-2 | Wasmtime skill 沙箱探索（T8）：新 code 类 skill 可选编译 wasm | 原型报告 | 不进入默认路径 |
| P3-3 | 推测解码配置层（T12）：Ollama/LM Studio 后端的 draft-model 配置模板 + 文档 | 本地模型解码吞吐提升实测记录 | 纯配置，无代码风险 |

---

## 6. 全面检查：失效模式分析

> "万无一失"的工程定义 = 每个机制都有明确的失效模式、检测手段和降级路径。以下逐条过堂。

| # | 机制 | 失效模式 | 检测 | 缓解/降级 | 残余风险 |
|---|---|---|---|---|---|
| R1 | plan-commit（P0） | 模型生成的计划本身错误（非恶意） | 计划 schema 校验 + 动作白名单 | BIND 阶段拒绝不合法计划，转人工 | 计划质量依赖模型能力；弱模型效用下降（CaMeL 实测 -26.8pp）→ 轻路径不受影响 |
| R2 | plan-commit（P0） | 不可信数据填满值槽位时语义下毒（值合法但内容误导）；或填槽由受污染模型同时拼装参数 | taint 标签 + 槽位策略；填槽来源审计（确定性投影 vs 隔离提取） | CaMeL 同源局限：只能保证控制流安全，不保证值正确；SECRET 槽位禁填不可信数据；**禁止**受污染模型既提取又拼装 | **明示残余风险，写入 SECURITY.md** |
| R3 | AgentDojo CI（P1） | benchmark 过拟合（针对 629 用例调参） | 保留 held-out 用例集不进 CI 调参循环 | 每季度引入新攻击集；配合内部红队用例 | 中 |
| R4 | 前向安全键控（P1） | epoch 切换时密钥管理 bug 导致链验证失败；或销毁旧钥却未写 Merkle 根 | 双读期 + 链回放测试；关闭 epoch 的合取：根已锚定 ∧ 旧钥已销毁 | 旧链只读冻结归档；缺根则拒绝销毁旧钥 | 低 |
| R5 | 格比较策略收窄（P1） | 策略语言表达力不足，误判"收窄/扩张" | 全部误判偏向人工审批（fail-safe 方向） | 误判成本=多一次人工审批，无安全损失 | 低 |
| R6 | Apple Containerization（P2） | macOS 26 以下 / Intel Mac / 未来 Windows；误把 desktop/secret/net/memory 放进 Linux VM；guest 挂上生产 KeyBox | 启动探测 + **cell 类型白名单（P2-1 仅 file/build）** + guest 挂载不得含 keybox/secret/lease 密钥 | 自动回退 L1；凡进 VM 的 cell 一律走宿主 broker，不按模块名猜测是否构造 KeyBox | 中（spawn 模型与密钥材料） |
| R7 | Hyperlight（P3 候选） | 基座 macOS 支持缺失/不成熟；Hyperlight Wasm 自述"实验性，非生产级" | 原型评估 | 仅作 Windows 阶段候选，不进 macOS 关键路径 | 中（故列 P3） |
| R8 | 级联路由（P2） | 难度误判：难任务、plan-commit 或中途 dirty 后的模型调用路由给弱模型 → 质量下降或控制流崩溃 | 任务成功率监控（ledger 计量）；重路径与中途 dirty 后的选模审计 | 成功率降 >2pp 自动上调该任务类别；存在非本地后端时上述回合命中 `is_local_model` → fail；仅本地后端时 deny-write | 低 |
| R9 | 提示压缩（P3） | 压缩丢关键信息；tokenizer 不一致低估长度 | 压缩前后任务成功率 A/B | 上限 10×；默认关闭；仅长文档场景 | 低 |
| R10 | 全局 | 任何新层引入的 bug | 现有测试密度 ratchet（M1 ≥1.2:1）继续适用 | 全部新机制默认关 + 特性开关 + 分版本灰度 | — |
| R11 | 中途污点收窄（P0） | 可信入口回合中途读入注入内容；收窄只作用于**后续**迭代，本批工具结果打位之前已派出的写/egress 无法撤回 | 迭代边界（工具结果打位并写入 `state.messages` 之后、下一轮 `_get_response` 之前）检查 `context_taint` 增量；不得沿用"本阶段开始前"的旧 snapshot | 收窄只收紧：剩余迭代禁写/禁 egress；已发出动作记入 ledger | 中：与现状相同的"本阶段 snapshot 先于 dispatch"窗口仍在，P0 必须把检查点移到结果回流之后 |
| R12 | 默认生效面（P0-4） | gateway 开启后仍走 AppShell 全局 compat，plan-commit 与 taint 表只记日志 | 集成测试断言非 allow 判定不得变成 allow；启动日志若仍是 compat 则 fail | 拒绝启动 gateway（fail-closed 联动可选）或强制该表面 conservative | 低（显式 opt-in 表面） |

**三条全局诚实话**：

1. "绝对安全"不存在：Google 的自适应攻击复盘（arXiv:2505.14534）已证明检测式防御必然可被绕过；本方案的安全承诺限于"结构性边界 + 可验证审计 + 受控降级"，与现有 SECURITY.md 一致
2. CaMeL 类机制对弱模型效用损失大（-26.8pp 实测），工厂低配设备 + 小模型场景下 plan-commit 可能不可用 → 仅本地后端时这些回合改为只读（deny 一切写动作）。**T11 不得用级联把 plan-commit 或中途 dirty 之后的模型调用悄悄送到弱模型上。**
3. 外部红队审计（Orin 外部门 K§15.6 #9）不是本方案能自闭环的，保持 external-pending 状态如实声明

---

## 7. 验证表（前瞻性指标的可证伪跟踪）

| 指标 | 预测/目标 | 确认阈值 | 挑战阈值 | 触发行动 |
|---|---|---|---|---|
| 重路径注入防御 | plan-commit 使入口不可信表面的内部注入用例 0 成功（P0 验收） | 20/20 用例无计划外动作 | ≥1 用例突破 | 暂停该表面写入权限，回退 deny-all 读模式 |
| 中途污染收窄 | 可信入口 + 中途 web/邮件/文档注入后，剩余迭代 0 次写/egress 成功（P0 验收） | 构造用例 0 次收窄后写/egress | ≥1 用例在收窄后仍写出或 egress | 暂停该工具类写入，回退 deny-all 读模式 |
| gateway 默认生效面 | `gateway.enabled=true` 时该表面 plan-commit 开且 Orin 非 allow 判定实际拦截（P0-4） | 注入用例走重路径；compat 降级计数 = 0 | 仍走轻路径或 allow+log | 拒绝启动 gateway 或标为降级并阻断该表面写入 |
| AgentDojo ASR | P1 建立基线后，P2 末 ASR ≤5% | CI 实测 ≤5%（固定模型+多种子中位数） | 基线稳定后 >5% 或回归 >2pp | **基线稳定后**阻断版本发布，启动用例复盘；基线期仅报告 |
| 云端 token 成本 | 级联路由 + 稳定前缀后，同任务集**轻路径**云端调用量降 ≥40% | 降 ≥40% | 降 <20% | 检查路由误判率；重路径调用不计入该降幅 |
| 任务成功率 | 全部优化后成功率不低于当前基线 -2pp | 降幅 ≤2pp | 降幅 >2pp | 按 P3→P0 逆序逐个关开关定位元凶 |
| 回合延迟 | plan-commit 重路径增加的本地延迟 <200ms（不含模型调用） | p95 <200ms | p95 ≥500ms | 计划缓存 + 合并 BIND 检查 |
| 设备要求 | 默认安装（无压缩模块）内存增量 <100MB | 实测 <100MB | ≥200MB | 压缩模块拆为可选 extra |
| Stage C 合取位 | P2 末在 SPEC 修订后 `production_sandbox_carrier` 位可置真 | 合取检查器通过**该位**（不是 Stage C 整体） | 载体冒烟失败 | 维持 L1 默认，外部门（TCC / 真模型 e2e / 独立红队）保持 pending 如实声明 |

---

## 8. 定义与口径

- **产品代码口径**：产品代码在 `js/`、`js_work/`、`desktop/` 三目录（py/js/ts/rs/swift/css/html/sh），排除 tests/docs/demos/benchmarks/scripts 与数据文件。顶层 `echo/` 只有 `connector_artifacts/`，**无代码**，不得计入第四代码目录。v1.0 原文写的 199,764 行含该空壳口径，修订后不再沿用该数字。
- **测试文件数**：截至评审工作树（HEAD `c4aa97b` 及之后的文档修订提交）为 **530** 个 `tests/**/test_*.py`（另有少量非 `test_` 辅助 `.py` 与 1 个 `tests/adversarial/corpus.jsonl`）。P0 注入用例优先扩展该 corpus，不另起炉灶。
- **两套门，不要混用**：`require_untrusted_surface`（`js/security/posture.py`）是隔离**姿态**门（`untrusted_ingestion_policy=enforce` 时要求 container-full）；`orin_taint.set_entry_source(channel)` 才是逐回合入口污点。风险门控消费后者（及中途 `context_taint`），不把前者当信任标记。
- **ASR**（Attack Success Rate）：AgentDojo 口径的注入攻击成功率
- **轻/重路径 / 中途收窄**：轻路径 = 现状 effect 管道（入口可信且无 dirty 位）；重路径 = 入口不可信时的 plan-commit 模式；中途收窄 = P0 在轻路径回合中途发现 dirty 位后对剩余迭代禁写/禁 egress（P2 才升级为剩余迭代 plan-commit）。dirty 位至少包括 `WEB_CONTENT`/`INBOX_CONTENT`/`BOT_PEER`，与 `js/orin/taint.py` 的 `DIRTY_FOR_WRITE` 对齐并显式纳入 `INBOX_CONTENT`
- **T11 落点**：`js/models/router.py` 的 `_task_complexity` 是预留未用的桩，级联路由可接在 `select_model` 上，不是新造路由入口。
- **Stage C 状态**：以 `docs/security/orin/ORIN_STAGE_C_CLOSEOUT.md`（2026-08-28 裁决）为准——未实施，本方案不构成对其状态的修改
- **调研截至**：2026-08-30；arXiv 编号均经本轮检索核验，二手转述处已标注

## 9. 来源清单（去重）

- CaMeL：arXiv:2503.18813(https://arxiv.org/abs/2503.18813)；Zylos Research: 2026-06-18(https://zylos.ai/research/2026-06-18-prompt-injection-defense-autonomous-agents/)
- Progent：arXiv:2504.11703(https://arxiv.org/abs/2504.11703)
- FIDES：arXiv:2505.23643（经 https://arxiv.org/html/2606.26479v1 引用列表核验）
- Design Patterns：arXiv:2506.08837(https://arxiv.org/abs/2506.08837)
- AgentDojo：arXiv:2406.13352(https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html)
- Gemini 防御复盘：arXiv:2505.14534(https://arxiv.org/abs/2505.14534)
- IsolateGPT：arXiv:2403.04960；Conseca：arXiv:2501.17070；SAGA：arXiv:2504.21034；AgentSpec：arXiv:2503.18666；StruQ：arXiv:2402.06363；LlamaFirewall：arXiv:2505.03574；llmbda：arXiv:2602.20064；AgentSys：arXiv:2602.07398；PCAS：arXiv:2602.16708（均经本轮 scholar/WebSearch 检索核验）
- WinSeal：IEEE S&P 2026(https://ieeexplore.ieee.org/abstract/document/11573416/)；Custos：USENIX Security 2020(https://par.nsf.gov/biblio/10146530)
- Hyperlight：Microsoft 开源博客 2024-11-07(https://opensource.microsoft.com/blog/2024/11/07/introducing-hyperlight-virtual-machine-based-security-for-functions-at-scale/)；hyperlight.org 对比表(https://hyperlight.org/)；Hyperlight Wasm 2025-03-26(https://opensource.microsoft.com/blog/2025/03/26/hyperlight-wasm-fast-secure-and-os-free/)
- Apple Containerization：awesome-sandbox(https://github.com/restyler/awesome-sandbox)；oflight 专栏 2026-06-29(https://www.oflight.co.jp/en/columns/apple-container-macos-linux-runtime-2026-06)；sandbox-exec 废弃评价：networkeffect.dev 2026-04-15(https://networkeffect.dev/)
- LLMLingua：arXiv:2310.05736(https://arxiv.org/abs/2310.05736)；C2KV：ACM DL 2026(https://dl.acm.org/doi/abs/10.1145/3770855.3817715)；Route-and-Reason：WWW 2026(https://dl.acm.org/doi/abs/10.1145/3774904.3793038)；cost-aware routing：NeurIPS 2025(https://proceedings.neurips.cc/paper_files/paper/2025/hash/e46eb6403af68506331f941282d838aa-Abstract-Conference.html)；agentic 推测解码：arXiv:2607.03333(https://arxiv.org/abs/2607.03333)；SPADE：arXiv:2608.13076(https://arxiv.org/abs/2608.13076)
- 现状基线：`{repo_root}` 工作树实测（`js/echo/`、`js/orin/`、`js/orind/`、`docs/security/orin/`）

*调研原始数据：`research/s1_agent_sec.csv` ~ `s8_sel4.csv`*
