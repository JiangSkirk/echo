# Echo × Orin 架构强化方案

> 版本：v1.0 · 2026-08-30
> 范围：js-agent（`/Users/jiangxuanzhen/titan-agent`，最新提交 `7652629`，2026-08-30 02:04）
> 目标：让 Echo（通用 agent 核心）与 Orin（安全防护架构）做到 **安全、稳定、快捷、低延迟、省 token、低设备要求**
> 方法：完整盘点现状 → 学术/工程调研（Google Scholar + arXiv + 一手工程资料）→ 交叉检查 → 可执行方案

---

## 0. 摘要（结论先行）

**核心判断：Echo 和 Orin 的架构方向与 2025–2026 年学术界的最新结论高度同构，不需要推倒重来；需要的是把学术界已验证的 6 项技术"嵌进现有骨架"，而不是替换骨架。**

具体结论：

1. **Echo 的 capability lease + effect 管道，本质上就是 Google DeepMind CaMeL 的"能力安全模型"的独立实现**——CaMeL 在 AgentDojo 上以 77% 任务完成率（无防护 84%）取得"可证明安全"，代价是 2.8 倍 token。Echo 已有等价骨架但**没有 CaMeL 的"控制流先于不可信数据定型"这一关键性质**，这是本次方案最重要的一课。
2. **Orin 的 taint（u64 位掩码 + "taint 永不授权"铁律）方向正确**，但学术界已经走得更远：Microsoft FIDES 把信息流标签放进规划器做确定性执行，在 AgentDojo 上挡住全部测试注入且任务完成率反而提升约 16%。Orin 应升级到"规划器级 IFC"。
3. **"绝对安全"在学术界已被证伪为不可能目标**——Google 防 Gemini 注入的复盘（arXiv:2505.14534）确认：一切分类器/启发式在自适应攻击下都会失效。Orin 的正确目标不是"绝对安全"，而是 **"结构性安全边界 + 可验证审计 + 受控降级"**。这与 Orin 现有 SECURITY.md 信任模型一致，方案不会承诺做不到的事。
4. **省 token / 低延迟 / 低设备三个目标与安全性存在真实冲突**（CaMeL 花 2.8 倍 token 买安全），本方案的解法是 **风险门控（risk-gated）**：可信回合走轻路径，接触不可信表面的回合才走重路径。已有代码基础（gateway 的 untrusted-surface gate）证明这条路可行。
5. **最紧迫的工程发现**：macOS 的 `sandbox-exec`（Echo 当前默认沙箱载体）已被 Apple 标记废弃且被认为"弱"（见 §2.3），而 Apple 官方 Containerization 框架（每容器独立轻量 VM、亚秒启动、Apache-2.0、v1.0.0 已于 2026-06-09 发布）是 Orin Stage C `production_sandbox_carrier` 外部门的现成答案。

**推荐行动**：按 §5 的 P0→P3 四阶段执行。P0（零新依赖、纯现有代码重组）即可拿到"plan-commit 模式 + 风险门控"两大收益；P1 引入 AgentDojo 作为 Orin 的 CI 安全门；P2 解决沙箱载体迁移；P3 做性能与 token 优化。**任何阶段失败都可回退到上一阶段，不破坏现有行为。**

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
| 污点追踪 `taint.py` | u64 位掩码标记消息来源；`context_taint` 为活跃窗口 OR 累积；SECRET 位通过压缩粘性传播；工具调用时附 8-gram Jaccard 参数重叠度。**铁律：taint 永不授权，干净的 taint 不能跳过任何检查，只能产生 approval/deny** |
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
- **证书透明（Certificate Transparency, RFC 6962）式 Merkle 树**：把账本 tip 周期性锚定到外部见证，提供包含证明——Echo 已有 `tip_anchor.py`，扩展量小

### 2.3 隔离载体（对应 Orin Stage C `production_sandbox_carrier` 卡点）

| 载体 | 冷启动 | 隔离强度 | 平台 | 适配判断 |
|---|---|---|---|---|
| `sandbox-exec`（现状） | 进程级 | 弱：仅文件/网络 ACL，**已被 Apple 废弃**；macOS 无 namespaces/cgroups/seccomp | macOS | 现状可用但需规划迁移 |
| **Apple Containerization** | **亚秒** | 每容器独立轻量 Linux VM（Virtualization.framework），共享内核 VM 模型被淘汰 | macOS 26 + Apple Silicon，Apache-2.0，v1.0.0（2026-06-09） | **Orin cell 生产载体的首选答案** |
| Wasmtime（WASM） | <0.03 ms（AOT 预编译） | 软件沙箱（类型系统 + 边界检查线性内存）；Cranelift 形式化验证进行中 | 全平台 | skill/插件代码执行的理想载体 |
| Hyperlight | 1–2 ms | 硬件 VM 隔离，无 guest OS，默认 64KB 栈/128KB 堆；Hyperlight Wasm = Wasmtime + microVM 双层 | Linux/Windows 原生；macOS 支持有限（见 §4 风险 R7） | Windows 部署阶段的候选 |
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
| T2 | Plan-then-Execute / Action-Selector 模式 | Echo `turn_loop` 新增 plan-commit 回合模式 | 控制流先于不可信数据定型；零额外 token | 中：纯代码重组 | 无 | **采纳（P0 核心）** |
| T3 | Progent Z3 单调约束 | Orin 策略更新路径（尤其 evolution 自进化提案） | 策略只能收窄不能扩，SMT 确定性证明 | 中：Z3 依赖 ~30MB，只在策略更新路径，不在回合热路径 | 无 | 采纳（P1） |
| T4 | FIDES 规划器级 IFC | Orin taint 升级：标签进规划器 | 证据显示可增效用（+16%） | 中高 | taint 铁律保持不破 | 采纳（P2） |
| T5 | AgentDojo CI 门 | Orin 验收体系 | 安全效果从"自说自话"变标准化度量 | 中：benchmark 适配 | 无 | **采纳（P1 核心）** |
| T6 | 前向安全键控 + Merkle 锚定 | Echo ledger 升级 | 历史日志前向完整；外部可验证证据 | 低：已有 tip_anchor 基础 | 无 | 采纳（P1） |
| T7 | Apple Containerization 载体 | Orin Stage C `production_sandbox_carrier` | 解锁 Stage C 外部门；真 VM 隔离 | 中：需 macOS 26；老设备回退 sandbox-exec | 设备要求上升 → 分层回退 | **采纳（P2 核心）** |
| T8 | Wasmtime skill 沙箱 | Echo skill/插件执行 | 亚毫秒启动的全平台沙箱 | 中：skill 需编译 wasm 或运行时嵌入 | 现有 skill 是 Python → 渐进式 | 采纳（P3 探索） |
| T9 | LLMLingua 式压缩 | Echo context_savings 升级 | 工具输出/长文档最多 20× 压缩 | 中：压缩模型本地运行（phi-2 级 <8GB），启发式回退 | 与"低设备"部分冲突 → 可选模块 | 采纳（P3，可选） |
| T10 | KV 复用 + 稳定前缀契约 | Echo prompt 组装层 | prefill 成本显著下降；零质量损失 | 低 | 无 | **采纳（P0 顺手做）** |
| T11 | 模型级联路由 | Echo models/router 升级 | 本地小模型优先，云端兜底；成本/延迟双降 | 中 | 现有 fallback 路由器兼容 | 采纳（P2） |
| T12 | 推测解码 | 本地推理后端（Ollama/LM Studio）集成层 | 本地模型解码 2–3× 加速 | 低（后端配置而非自研） | 依赖后端支持 | 采纳（P3 配置层） |
| T13 | Gemini 教训：检测式防御的定位 | SECURITY.md 已声明 | 防止团队对分类器产生错误信心 | 零 | 无 | 已采纳（维持） |
| T14 | seL4 形式化验证路线 | 仅作灵感（capability 命名、规格先行） | — | 极高 | 超出项目阶段 | 不采纳（记入远景） |

---

## 4. 目标架构

```
┌─────────────────────────────────────────────────────────────┐
│  AppShell / CLI / Gateway（入口，含 untrusted-surface 判定）    │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Echo Core（通用 agent 核心）                                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ turn_runtime（唯一回合边界）                             │  │
│  │  ├─ 轻路径：可信回合 → 现有 effect 管道                   │  │
│  │  └─ 重路径：不可信回合 → plan-commit 模式（T2）           │  │
│  │       1. PLAN：模型只见可信指令，输出计划（动作序列骨架）    │  │
│  │       2. BIND：计划经 capability 策略检查，锁定动作空间     │  │
│  │       3. EXECUTE：不可信数据只能填充计划内的值槽位          │  │
│  │           （值槽位带 taint 标签，策略拒绝越权使用）         │  │
│  ├─ capability（租约签发/消费/撤销，+ T3 SMT 收窄证明）      │  │
│  ├─ ledger（哈希链 + 前向安全键控 + Merkle 锚定，T6）         │  │
│  ├─ context（CAS 去重 + 稳定前缀契约 T10 + 可选压缩 T9）      │  │
│  └─ models（级联路由 T11：本地小模型 → 云端，风险/难度感知）   │  │
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
│  L2 Apple Containerization 独立 VM（T7，macOS 26+ 生产姿态）   │
│  L3 Wasmtime（T8，skill/插件代码，全平台探索）                  │
└─────────────────────────────────────────────────────────────┘
```

设计不变量（任何阶段不得违反）：

1. **回合唯一边界**：模型、工具、附件只从 `run_echo_turn` 进；plan-commit 是回合内模式，不是第二套 loop
2. **taint 铁律**：污点永不授权；升级后的 label 同样只能收紧不能放松
3. **决策路径零模型**：Orin kernel 合取不调用任何模型/分类器（现状已满足，保持）
4. **fail-closed**：任何子系统缺失/异常 → 拒绝，不降级（现状已满足，保持）
5. **向后兼容**：轻路径行为与当前版本逐字节一致；所有新机制默认关，显式开启

---

## 5. 分阶段实施路线图

### P0 —— plan-commit 模式 + 稳定前缀（2–3 周，零新依赖）

| 项 | 内容 | 验收标准 | 回退 |
|---|---|---|---|
| P0-1 | `turn_loop` 新增 `plan_commit` 回合模式：PLAN→BIND→EXECUTE 三阶段；仅当入口判定为不可信表面（沿用 gateway untrusted-surface gate）时激活 | 新增模式单测全覆盖；轻路径现有 508 个测试文件零回归 | 配置开关 `echo.plan_commit=false` 恢复现状 |
| P0-2 | 值槽位机制：计划中的参数位标记 `{slot:taint_policy}`，不可信数据只能填槽；槽位策略复用现有 capability 检查 | 构造 20 个注入用例（邮件/网页/文档各含恶意指令），重路径下 0 个导致计划外动作 | 同上 |
| P0-3 | prompt 稳定前缀契约：系统提示 + 工具描述排序固定，变动只追加在尾部（配合 provider 的 prompt caching） | 相同会话连续 5 回合的 prompt 前缀哈希一致；token 计量记录入 ledger | 开关回退 |

### P1 —— 可度量安全（3–4 周）

| 项 | 内容 | 验收标准 | 回退 |
|---|---|---|---|
| P1-1 | 接入 AgentDojo：js-agent 工具集映射到 AgentDojo 任务套件，CI 每夜跑注入套件 | CI 产出 ASR（攻击成功率）数字；基线存档；ASR 回归 >2pp 即 fail | 不阻塞发布，仅报告 |
| P1-2 | ledger 前向安全升级：HMAC 密钥按 epoch 演进（旧 epoch 密钥销毁），tip 计算 Merkle 根并可导出包含证明 | 篡改任一历史条目 → 验证失败且定位到条目；密钥泄露模拟测试通过 | 保留旧验证器读旧链（双读期 1 个版本） |
| P1-3 | 策略收窄证明（T3 轻量版）：evolution 自进化提案的策略变更先经"动作空间是否收窄"判定；暂不引入 Z3，用格（lattice）比较实现 | 扩张性策略变更 100% 触发人工审批；收窄性变更自动通过 | 全部转人工审批 |

### P2 —— 生产隔离载体（4–6 周，对齐 Orin Stage C 外部门）

| 项 | 内容 | 验收标准 | 回退 |
|---|---|---|---|
| P2-1 | Apple Containerization 集成：`orind/cells` 新增 `container_vm` 载体后端；macOS 26 + Apple Silicon 检测，不满足则回退 L1 | 在 VM 内运行 file/desktop cell 冒烟测试通过；`production_sandbox_carrier` 合取位可置真 | 载体探测失败自动 L1，strict_isolation 语义不变 |
| P2-2 | taint→label 规划器升级（T4）：plan 的每个槽位携带来源标签，策略判定从"工具调用时"提前到"计划绑定时" | AgentDojo 重路径 ASR 对比 P0 再降；效用分不回退超 3pp | 标签层开关 |
| P2-3 | 模型级联路由（T11）：难度/风险分类器（规则式，非 LLM）→ 本地小模型优先 → 云端升级；与现有 fallback/断路器合并 | 预定义任务集上云端调用占比下降 ≥40% 且任务成功率不降 | 路由表配置回退 |

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
| R2 | plan-commit（P0） | 不可信数据填满值槽位时语义下毒（值合法但内容误导） | taint 标签 + 槽位策略 | CaMeL 同源局限：只能保证控制流安全，不保证值正确；SECERT 槽位禁填不可信数据 | **明示残余风险，写入 SECURITY.md** |
| R3 | AgentDojo CI（P1） | benchmark 过拟合（针对 629 用例调参） | 保留 held-out 用例集不进 CI 调参循环 | 每季度引入新攻击集；配合内部红队用例 | 中 |
| R4 | 前向安全键控（P1） | epoch 切换时密钥管理 bug 导致链验证失败 | 双读期 + 链回放测试 | 旧链只读冻结归档 | 低 |
| R5 | 格比较策略收窄（P1） | 策略语言表达力不足，误判"收窄/扩张" | 全部误判偏向人工审批（fail-safe 方向） | 误判成本=多一次人工审批，无安全损失 | 低 |
| R6 | Apple Containerization（P2） | macOS 26 以下设备 / Intel Mac / 未来 Windows | 启动时探测 | 自动回退 L1（sandbox-exec/bwrap）；Windows 候选 Hyperlight（1–2ms microVM，Linux/Windows 原生） | 低 |
| R7 | Hyperlight（P3 候选） | 基座 macOS 支持缺失/不成熟；Hyperlight Wasm 自述"实验性，非生产级" | 原型评估 | 仅作 Windows 阶段候选，不进 macOS 关键路径 | 中（故列 P3） |
| R8 | 级联路由（P2） | 难度误判：难任务路由给弱模型 → 质量下降 | 任务成功率监控（ledger 计量） | 成功率降 >2pp 自动上调该任务类别路由级别 | 低 |
| R9 | 提示压缩（P3） | 压缩丢关键信息；tokenizer 不一致低估长度 | 压缩前后任务成功率 A/B | 上限 10×；默认关闭；仅长文档场景 | 低 |
| R10 | 全局 | 任何新层引入的 bug | 现有测试密度 ratchet（M1 ≥1.2:1）继续适用 | 全部新机制默认关 + 特性开关 + 分版本灰度 | — |

**三条全局诚实话**：

1. "绝对安全"不存在：Google 的自适应攻击复盘（arXiv:2505.14534）已证明检测式防御必然可被绕过；本方案的安全承诺限于"结构性边界 + 可验证审计 + 受控降级"，与现有 SECURITY.md 一致
2. CaMeL 类机制对弱模型效用损失大（-26.8pp 实测），工厂低配设备 + 小模型场景下重路径可能不可用 → 小模型部署时重路径改为"不可信表面只读"（deny 一切写动作）
3. 外部红队审计（Orin 外部门 K§15.6 #9）不是本方案能自闭环的，保持 external-pending 状态如实声明

---

## 7. 验证表（前瞻性指标的可证伪跟踪）

| 指标 | 预测/目标 | 确认阈值 | 挑战阈值 | 触发行动 |
|---|---|---|---|---|
| 重路径注入防御 | plan-commit 使内部注入用例 0 成功（P0 验收） | 20/20 用例无计划外动作 | ≥1 用例突破 | 暂停该表面写入权限，回退 deny-all 读模式 |
| AgentDojo ASR | P1 建立基线后，P2 末 ASR ≤5% | CI 实测 ≤5% | >5% 或回归 >2pp | 阻断版本发布，启动用例复盘 |
| 云端 token 成本 | 级联路由 + 稳定前缀后，同任务集云端调用量降 ≥40% | 降 ≥40% | 降 <20% | 检查路由误判率，调整难度分类规则 |
| 任务成功率 | 全部优化后成功率不低于当前基线 -2pp | 降幅 ≤2pp | 降幅 >2pp | 按 P3→P0 逆序逐个关开关定位元凶 |
| 回合延迟 | plan-commit 重路径增加的本地延迟 <200ms（不含模型调用） | p95 <200ms | p95 ≥500ms | 计划缓存 + 合并 BIND 检查 |
| 设备要求 | 默认安装（无压缩模块）内存增量 <100MB | 实测 <100MB | ≥200MB | 压缩模块拆为可选 extra |
| Stage C 合取 | P2 末 `production_sandbox_carrier` 位可置真 | 合取检查器通过该位 | 载体冒烟失败 | 维持 L1 默认，外部门保持 pending 如实声明 |

---

## 8. 定义与口径

- **产品代码口径**：`js/`、`js_work/`、`desktop/`、`echo/` 四目录的代码文件（py/js/ts/rs/swift/css/html/sh），排除 tests/docs/demos/benchmarks/scripts 与数据文件（json/md/yaml）；截至 2026-08-30 02:04（commit `7652629`）为 199,764 行
- **ASR**（Attack Success Rate）：AgentDojo 口径的注入攻击成功率
- **轻/重路径**：本方案术语，轻路径 = 现状 effect 管道；重路径 = plan-commit 模式
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
- 现状基线：`/Users/jiangxuanzhen/titan-agent` 工作树实测（`js/echo/`、`js/orin/`、`js/orind/`、`docs/security/orin/`）

*调研原始数据：`research/s1_agent_sec.csv` ~ `s8_sel4.csv`*
