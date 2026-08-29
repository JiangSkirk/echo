# JS Agent 差距收敛计划（对标 OpenClaw / Hermes Agent）

- 日期：2026-08-29
- 状态：决策已拍板（见 §6，2026-08-29 用户确认），待最终批准后施工
- 基线：工作区当前树（rubric `2026.09.1`，ORIN Stage C verdict=`not_implemented`）
- 关联：`TECH_DEBT.md`、`quality/rubric.yaml`、`docs/security/orin/ORIN_STAGE_C_CLOSEOUT.md`、ADR 0005/0006/0007
- 对比对象：
  - **Hermes Agent**：本机 `~/.hermes/hermes-agent`（0.17.0，NousResearch），可实地核对
  - **OpenClaw**：openclaw.ai / github.com/openclaw/openclaw（未本地安装，按官方文档核对）

---

## 0. 核验结论：七项声称逐条裁定

| # | 声称 | 裁定 | 关键证据 |
|---|------|------|----------|
| 1 | 没有整进程容器隔离，接触不可信内容时无真实安全边界 | **部分成立**（默认桌面路径成立；「无边界」说法过重） | 每工具 OS 沙箱真实存在且 fail-closed（`js/echo/os_sandbox.py:168-539`：sandbox-exec / bwrap+unshare / RLIMIT_AS）；整进程 Docker 姿态存在但为可选（`Dockerfile` production 非 root + `docker-compose.yaml` 仅回环）；macOS 桌面默认是原生单进程 ambient，Stage C 进程拆分 verdict=`not_implemented`，`orin.enforce` 默认 false（`TECH_DEBT.md` ⚫3/⚫7 明言「真实边界是 OS 沙箱」「不得宣称 Echo RCE 已收口」） |
| 2 | 依赖用版本区间而非精确 pin，供应链攻击面大 | **大部分不成立，但 CI 有真实缺口** | `uv.lock` 存在且被强制：`scripts/install.sh:119-146`（缺 lock 即 fail、拒绝 curl\|sh、拒绝远程模式）、`Dockerfile:14,36,55`（uv 二进制钉 0.11.24 + `uv sync --frozen`）、`scripts/deploy.sh:57-74`（同样冻结）、`desktop/requirements-build.txt` 精确 pin。**真实缺口**：`.github/workflows/ci.yml:27` 用 `pip install -e ".[dev,monitor]"` 非冻结解析（CI 供应链暴露 + 测试环境与生产偏移）；actions 只钉 tag 未钉 SHA；无定时依赖审计（pip-audit 只在构建产物校验时跑一次） |
| 3 | 缺少对外正式的 SECURITY.md 信任模型文档 | **成立** | 仓库根目录无 SECURITY.md；`docs/security/orin/` 是内部实施规格不是对外信任模型。Hermes 有 313 行 SECURITY.md（信任模型、唯一承重边界=OS 隔离、进程内启发式不算边界、报告渠道与范围裁定） |
| 4a | 没有消息平台 gateway | **成立** | 仅有可选 Telegram 集成（`js/integrations/telegram_bot.py`，已正确走 `run_echo_turn`）。对比：OpenClaw 12+ 渠道插件 + 确定性路由 + 配对/白名单；Hermes `gateway/` 含 whatsapp_cloud / signal / weixin / qqbot / bluebubbles(iMessage) / msgraph / yuanbao / webhook |
| 4b | 没有自我进化闭环 | **成立（组件在，环未闭）** | `quality_scorer` 已挂 turn loop telemetry，`auto_learn` / `evolver` / promotion gate 存在；但 daemon 的 `_cb_skill_evolve` 是只打日志的空壳（`js/daemon/core.py:231-232`），冷启动不跑 evolution cycle，mutate 走 admin（`TECH_DEBT.md` 预留模块节）。README 对比表宣称「自主学习 ✅」偏乐观，需 true-up |
| 5 | pipeline/friends/mobile/scenarios 还是空壳预留 | **成立（有意设计且有测试锁定）** | 23 个文件存在但默认不进 Host 冷启动 import 图；`friends_enabled`/`mobile_enabled` 默认 false（`js/config.py:804-805`），`pipeline_enabled=true` 只是能力旗标（`js/config.py:648`）；`tests/test_reserved_runtime_isolation.py` + `tests/test_tasks_empty_shell.py` 锁定；`/api/tasks` 列表空 + mutate 503 |
| 6 | 63 万行测试 / 19.6 万产品代码的 Hermes 级密度未达到 | **成立（数字实测吻合）** | Hermes `tests/` = **632,824** 行（63 万 ✓）；核心运行时（agent 81,800 + gateway 70,690 + skills 10,091 + cron 6,322 + acp_adapter 5,193 + providers 408 + 根模块 ≈2 万）≈ **19.6 万** ✓ → 密度 ≈ **3.2:1**。js-agent：产品 **172,760**（js/ 162,193 + js_work/ 10,567）vs 测试 **161,709** → **0.94:1** |
| 7 | 尚未经过真实多用户环境的安全审计 | **成立** | `TECH_DEBT.md`「仍待外部审计」表（独立红队、正式 TCC/公证、可信公钥目录运营均缺）；owner 隔离只有 in-repo 测试（bots/fleet/memory owner isolation），无外部审计记录 |

**一句话总结**：7 条里 5 条成立、1 条部分成立、1 条（依赖 pin）基本不成立但暴露了 CI 冻结缺口。js-agent 的真实短板不是「没有沙箱」而是：**对外安全契约缺失、默认桌面姿态无整进程隔离、消息渠道只有 1 个、进化环未闭、测试密度约为 Hermes 的 29%、无外部审计背书**。

---

## 1. 对比矩阵与缺口清单

### 1.1 能力矩阵（✅ 有 / ⚠️ 部分 / ❌ 无）

| 能力 | OpenClaw | Hermes | JS Agent 现状 |
|------|----------|--------|---------------|
| 消息平台 gateway（多渠道、路由、配对） | ✅ 12+ 渠道插件 | ✅ 8+ 平台（含微信/QQ/iMessage） | ❌ 仅 Telegram 可选集成 |
| 对外 SECURITY.md 信任模型 | ⚠️ 文档+配置审计器 | ✅ 313 行正式政策 | ❌ 无 |
| 整进程隔离姿态 | ⚠️ 每会话 Docker 沙箱（默认关） | ✅ 文档化双姿态（Docker/OpenShell，默认关） | ⚠️ Docker 存在但姿态未文档化、桌面默认原生 |
| 每工具 OS 沙箱（fail-closed） | ❌（工具策略是软层） | ❌（默认 host 直跑） | ✅ **领先**：sandbox-exec/bwrap 默认强制 |
| 单一运行时边界 + 效果账本 | ❌ | ❌ | ✅ **领先**：Echo + lease + ledger + taint |
| 配置安全审计器（`security audit` 命令） | ✅ runSecurityAudit 数十项 | ⚠️ 文档为主 | ❌ 无（有分散的启动校验） |
| 自我进化闭环（评分→提案→门禁→应用→回归） | ❌ | ❌ | ⚠️ 组件全有，环未闭 |
| 测试密度 | ~中 | ✅ 3.2:1 | ⚠️ 0.94:1 |
| 移动端节点/Canvas | ✅ iOS/Android nodes | ⚠️ apps/desktop | ❌ mobile 预留空壳 |
| 编辑器协议（ACP） | ⚠️ | ✅ acp_adapter | ❌（非目标，暂不做） |
| 外部安全审计/CVE 响应流程 | ✅（有公开 CVE 与修复流程） | ✅ SECURITY.md 定义 | ❌ 无 |

### 1.2 借鉴要点（只抄对的，不抄错的）

- **Hermes SECURITY.md 的立场**：「对抗性 LLM 的唯一安全边界是操作系统；进程内一切筛查都是启发式」——js-agent 应采用同样诚实的表述，把 Echo/lease/guard 定位为**正确性与授权机制**，把 OS 沙箱/容器定位为**安全边界**。
- **OpenClaw 的分层**：网关认证 → 工具策略 → 沙箱隔离 → 密钥管理 → 外部内容防御（UNTRUSTED 标记+注入检测）→ 配置安全审计。js-agent 已有中间三层的等价物，缺两端（gateway 认证/配对、配置审计命令）。
- **不要抄的**：OpenClaw 的 gateway 常驻 host、工具默认 host 直跑、`tools.elevated` 逃生门语义混乱（曾出 CVE-2026-25253 RCE）。js-agent 的 fail-closed 与单边界原则严于两者，**新功能不得为了渠道便利引入第二运行时或旁路 Echo**。

---

## 2. 执行总则（每个工作包共同约束）

1. **单一运行时边界不动摇**：一切新表面（gateway 渠道、进化提案执行）都进 `run_echo_turn` / `execute_tool_effect`，禁止直连 provider 或工具 handler。
2. **fail-closed 默认关**：新增功能旗标默认 false（`gateway.enabled=false`、进化自动应用不存在=永远人工批准）。
3. **出口门禁（每个 WP 完成时全部通过，缺一不可）**：
   - `uv run ruff check .` 绿
   - `uv run mypy js` 绿（strict，零错误）
   - `uv run pytest tests/ -q` 绿（仅环境性 skip）
   - `quality/labels.yaml` 更新 + `uv run python scripts/check_quality_labels.py --peak` 通过；**新增质量 bar 必须 bump `rubric_version` + changelog**（rubric 文件头规定）
   - 提交为独立 commit（每 WP 一个分支或一组连续 commit）
   - **Bugbot 审查（分支变更）**：High/Medium 发现全部处理（修复或书面豁免）后才算收口 —— 这是用户明确要求的每部分强制检查点
4. **文档诚实**：每个 WP 同步更新 README 对比表 / AGENTS.md / TECH_DEBT.md，不夸大（如「自主学习 ✅」在 WP5 落地前应降级为 ⚠️）。
5. **前置条件 P0**：当前工作区有大量未提交改动（M 波拆分 + bots + Orin Stage C 收尾）。**先把在途工作落库**（提交或收纳），否则每 WP 的 Bugbot「分支变更」审查会被无关 diff 污染。

---

## 3. 工作包（WP0–WP8）

### WP0 — 基线冻结（0.5 天）

**目标**：拿到干净的绿色基线，后续每个 WP 的 diff 可独立审查。

步骤：
1. 落库当前在途改动：由执行 agent 按主题拆 2–4 个 commit（M 波拆分 / bots / Orin C6-C7 / 文档），已拍板。
2. 跑通门禁：三件套 + `check_quality_labels --peak` + `python -m benchmarks.runner --mock` 记录基线分。
3. 记录密度基线：产品 172,760 行 / 测试 161,709 行 = 0.94:1（写入本文件 §WP7 跟踪表）。

**验收**：全绿截图/日志留档。**Bugbot**：对落库的在途改动跑一次分支审查（这是既有代码第一次过 Bugbot，发现按严重度处理）。

---

### WP1 — 对外安全契约：SECURITY.md + 信任模型（1 天）

**目标**：补齐第 3 项缺口，成为后续隔离/审计工作的「宪法」。

改动清单：
- 新建 `SECURITY.md`（中文，对外正式版）+ `SECURITY_en.md`（英文，与 README/README_en 惯例一致），内容仿 Hermes 结构并如实反映 js-agent：
  1. 漏洞报告渠道与格式（私密渠道、不设赏金）
  2. 信任模型定义（agent 进程 / 输入表面 / 信任包络 / 姿态声明）
  3. **承重边界声明**：对抗性模型输出的边界 = OS 层隔离（每工具 sandbox-exec/bwrap fail-closed + 整进程 Docker 姿态）；Echo lease/guard/taint/allowlist 是授权与纵深，不是对抗边界
  4. 支持的部署姿态矩阵：macOS 桌面原生（strict_isolation 强制每工具沙箱）/ Docker 整进程（接触不可信表面与共享部署的推荐姿态）/ 不支持的姿态（关闭 strict_isolation 又接不可信输入）
  5. 范围裁定：哪些报告收、哪些按启发式极限关闭
  6. 如实披露：无外部审计、无正式 TCC/公证、`orin.enforce` 默认关、Stage C 未实施（链接 TECH_DEBT ⚫ 表与 ORIN closeout）
- README.md / README_en.md 增加安全章节链接；对比表「安全」行改为与 SECURITY.md 一致的表述；「自主学习 ✅」降级 ⚠️（待 WP5）。
- 新测试 `tests/test_security_policy_doc.py`（仿 `tests/test_deploy_script.py` 风格）：断言两个文件存在、关键小节齐全、与 `js/config.py` 默认值一致（`orin.enforce=false`、`strict_isolation` 默认值、`friends/mobile_enabled=false` 被如实描述）。
- `quality/rubric.yaml`：`docs.debt` 单元加 `security.policy_doc` scope（pytest_node 指向新测试），bump `rubric_version` → `2026.09.2`。

**风险**：表述过强（宣称未达成的边界）或过弱（自贬有损采用）。**回滚**：纯文档+测试，revert 即可。
**出口门禁**：§2 全套 + **Bugbot**。

---

### WP2 — 供应链收紧（1 天）

**目标**：把「除 CI 外全冻结」补成「全链路冻结 + 持续审计」，终结第 2 项争议。

改动清单：
- `.github/workflows/ci.yml`：
  - 安装步骤改为 uv 冻结安装（钉 uv 版本与 Dockerfile 的 0.11.24 一致；`uv sync --frozen --extra dev --extra monitor`），矩阵不变
  - 加 `uv lock --check`（锁文件与 pyproject 漂移即红）
  - 所有 actions 由 tag 钉到 commit SHA（checkout/setup-python 等）
- 新增 `.github/workflows/deps-audit.yml`：每周 + 手动触发，跑 `uv run pip-audit`（对 uv.lock 解析出的环境）+ 保留现有 `verify_installed_artifact.py --audit` 作为发布闸门
- `desktop/requirements-build.txt` 附 `--hash`（pip `--require-hashes` 模式），`desktop/build_driver.py` 相应加参
- SECURITY.md 增「供应链姿态」小节（锁文件、冻结安装、审计节奏、uv 二进制钉扎）
- 新测试 `tests/test_ci_workflow_frozen.py`：断言 ci.yml 无裸 `pip install -e`、含 `--frozen`、actions 全部 SHA 钉扎（正则即可，风格同 `test_docker_release_context.py`）

**风险**：CI 迁 uv 后 3.13/3.14 矩阵解析差异；SHA 钉扎后 actions 升级成本。**回滚**：workflow 文件独立，revert 即可。
**出口门禁**：§2 全套 + CI 在分支上实际跑绿一轮 + **Bugbot**。

---

### WP3 — 整进程隔离姿态（2 天）

**目标**：不实施 Stage C 的前提下，把「接触不可信内容时的真实安全边界」做成**可检测、可声明、可强制**的产品姿态，收敛第 1 项。

改动清单：
- 新模块 `js/security/posture.py`：运行时姿态探测（是否容器内 / sandbox-exec 或 bwrap 可用 / strict_isolation 生效 / RLIMIT 支持），输出结构化 `IsolationPosture`（枚举：`container-full` / `native-tool-sandbox` / `degraded`）
- Host 启动时记录姿态并暴露：`/api/status` 加 `isolation_posture` 字段；设置页显示徽章（`js/web/static/` 小改）
- 新配置 `security.untrusted_ingestion_policy`（已拍板走折中档）：`warn`（默认档，含 gateway——原生姿态可启用，但 gateway 回合**强制打不可信污点 + conservative 审批 + 状态页持续警示**，`container-full` 姿态下才解除警示）/ `enforce`（可选严格档：非容器姿态拒绝启用不可信入站表面，供共享/生产部署自行开启）
- 新增 `docker-compose.hardened.yaml`（或 compose profile）：`read_only: true` + `cap_drop: [ALL]` + `security_opt: [no-new-privileges:true]` + 显式网络策略 + tmpfs 工作目录，对齐 OpenClaw 加固清单
- 新命令 `js doctor --security`（借鉴 OpenClaw runSecurityAudit）：汇总姿态探测 + 危险配置检查（0.0.0.0 绑定、strict_isolation 关闭、guest 权限、密钥文件权限等），输出分级清单；CI 冒烟不跑（本机诊断用）
- `docs/deployment.md` 增「不可信内容部署姿态」章节
- 测试：`tests/security/test_posture.py`（探测矩阵，容器/非容器 mock）、`tests/test_docker_hardened_compose.py`（配置断言）、`tests/test_doctor_security.py`
- rubric：`security` 单元加 `security.posture` scope，bump 版本

**明确不做**：不完成 Stage C cells、不把 `orin.enforce` 默认打开、不做 macOS 桌面整进程 seatbelt 包裹（Tauri+sidecar 下不可靠，留给 Stage C 路线）。
**风险**：姿态探测误报（容器检测启发式）；enforce 档误伤本地开发（用 `warn` 默认 + gateway 单独 enforce 化解）。
**出口门禁**：§2 全套 + **Bugbot**。

---

### WP4 — 消息平台 Gateway（拆 3 个子包，共 5–7 天）

**目标**：补第 4a 项。一个渠道无关的 gateway，全部入站消息以**不可信污点**进入 Echo 回合，路由到 bots 房间，默认 fail-closed。

#### WP4a — ADR + 骨架（1 天）
- 新 ADR `docs/adr/0008-gateway-channel-surface.md`：明确 gateway 是**表面不是运行时**——渠道适配器只做「收→配对校验→构造 Echo 回合→发」，回合权威仍是 `run_echo_turn`；路由确定性（借鉴 OpenClaw：模型不选路由，宿主配置选）；会话映射 = 渠道 peer → owner → bot/房间（复用 `js/bots/` 房间与 goal harness，`product_id` 不变）
- 新包 `js/gateway/`：`__init__.py`、`adapter.py`（`ChannelAdapter` 协议：`name/start/stop/send`，入站回调携带 `ChannelPeer`）、`router.py`（绑定表：peer→bot，dmScope 等价物：main/per-peer）、`pairing.py`（一次性配对码 + 发件人白名单，未配对一律丢弃并限频记录）、`service.py`（生命周期，挂 Host lifespan，`gateway.enabled=false` 默认不启动）
- 配置：`GatewaySettings`（enabled、渠道表、pairing 策略、速率限制、`untrusted_ingestion_policy` 联动 WP3 enforce 档）
- 测试：适配器契约测试（mock 渠道）、配对 fail-closed、路由确定性、未启用时零 import 副作用（仿 reserved.isolation 写 `tests/gateway/test_gateway_cold_start.py`）
- rubric 新单元 `gateway`（paths: `js/gateway/`），bump 版本
- **Bugbot** 后再进 4b

#### WP4b — Telegram 迁移 + 通用 Webhook（2 天）
- `js/integrations/telegram_bot.py` 重构为 `js/gateway/channels/telegram.py`，旧路径留 facade（M 波惯例，`tests/test_m_wave_facades.py` 加断言）；行为保持：仍走 `run_echo_turn`、附件门禁不变
- 新 `js/gateway/channels/webhook.py`：认证入站 webhook（HMAC 签名 + 时间窗），作为「任意平台最小接入」与 cron 主动推送出口
- 入站污点：gateway 构造的回合全部打 orin taint 标记（复用 `js/orin/taint.py` 打标点位），tainted 回合的副作用走 conservative 审批（既有策略表）
- 测试：telegram 契约回归（现有测试迁移）、webhook 签名/重放拒绝、taint 传播断言、跨 owner 泄漏（两个配对发件人互相看不到房间/记忆——复用 bots owner isolation 测试模式）
- **Bugbot**

#### WP4c — Discord 渠道 + 主动推送（2–3 天）
- 渠道已拍板：**Discord**。新增可选 extra `[discord]`（依赖钉入 uv.lock、纳入 pip-audit 覆盖）；Bot 长连接（gateway websocket）复用 fleet realtime stream 的资源治理模式，断线重连有界退避
- 主动推送：daemon cron 任务可向已配对渠道发「每日简报」类消息（借鉴 OpenClaw proactive push；只允许白名单模板，不允许模型自由外发——外发本身是副作用，走 lease）
- e2e：mock transport 全链路（入站→房间→Echo mock 回合→出站）+ 限频/滥用用例
- **Bugbot**

**WP4 整体风险**：渠道库拉新依赖（进 uv.lock、pip-audit 覆盖）；长连接进程与 governor 资源治理的交互（复用 fleet realtime stream 的模式）。**回滚**：`gateway.enabled=false` 即回到现状，包可整体 revert。

---

### WP5 — 自我进化闭环 v1（2–3 天）

**目标**：补第 4b 项。把「评分→反思→提案→人工门禁→应用→回归测量→回滚」连成真实闭环；**不做无人值守自改**（fail-closed）。

改动清单：
- `js/evolution/cycle.py`：编排一次进化周期——输入 `quality_scorer` 聚合 + `learner` 模式抽取 → `metacognition` 生成报告 → `evolver`/`optimizer` 产出**提案**（skill 改写 / prompt 变体），提案落库（复用 `js/skills/promotion_store.py` 语义或平行的 `evolution_proposals` 表，owner 作用域）
- daemon 接线：`_cb_skill_evolve`（`js/daemon/core.py:231`）从空壳改为调用 cycle（仅生成提案，不应用）；冷启动仍不跑（按 TECH_DEBT 约束，cron 显式排程才跑）
- 审批面：提案进现有 `manual_reviews` 路由（`js/web/routers/manual_reviews.py`）供 admin 批准/驳回；批准后经既有 admin mutate 路径应用
- 应用后测量：自动跑 `python -m benchmarks.runner --mock` 对比 `benchmarks/baseline.json`，回归则自动回滚该提案并标记 REGRESSED
- README 对比表「自主学习」恢复 ✅（此时才属实）
- 测试：cycle 单测（mock provider）、提案生命周期（生成→批准→应用→回归回滚）、owner 隔离、未排程时零行为
- rubric：`reserved` 单元里 `js/evolution/` 移入新 `evolution` 单元 + scope，bump 版本

**风险**：提案质量低造成审批噪音（加提案数量/频率上限配置）；benchmark 分数抖动误回滚（用 mock 确定性套件，阈值取 baseline 严格等值）。
**出口门禁**：§2 全套 + **Bugbot**。

---

### WP6a — 空壳裁决与轻实装（1–2 天）

**目标**：对第 5 项逐模块给出「实装 / 保留」的明确裁决（已拍板），消灭「说不清的预留」。

| 模块 | 现状 | 处置（已拍板） | 动作 |
|------|------|----------|------|
| `js/scenarios/` | loader/registry/schemas 可用，不进默认回合 | **实装**：接入 bots goal 模板（场景=预制 goal + persona） | bots UI 暴露场景启动；测试补契约 |
| `/api/tasks` 空壳 + `tabs/tasks.js` | 列表空、mutate 503 | **实装**：改为 bots goals 只读视图（goal harness 已有真实数据） | 路由读 goals store；`test_tasks_empty_shell.py` 改写为 goals 视图契约 |
| `js/pipeline/` | orchestrator + mock connectors | **保留预留**：WP4 后作为 gateway ingestion 二期评估（gmail/slack connectors 与渠道适配器天然合并） | 只更新 TECH_DEBT 措辞与到期评估时间 |
| `js/mobile/` | gateway.py/protocol.py 骨架 | **保留预留**：对标 OpenClaw nodes 有真实路线，等 WP4 稳定后立项 | 不动代码 |
| `js/friends/` | manager/protocol 骨架 | **实装 v1**（已拍板，不删除） | 独立工作包 WP6b |

- 同步更新：`AGENTS.md` 预留模块清单、`TECH_DEBT.md` 预留节、`quality/rubric.yaml` `reserved` 单元 paths、`tests/test_reserved_runtime_isolation.py`
- **出口门禁**：§2 全套 + **Bugbot**。

---

### WP6b — Friends v1 实装（3–5 天，依赖 WP4）

**现状**：`js/friends/` 是纯数据契约 + 内存版管理器——QR 邀请/互确认（`protocol.py` FriendRequest）、"E2E 加密"文本消息（目前只是字符串字段）、防重放/密钥轮换纪律（`manager.py`）、预算封顶的远程任务信封（RemoteTaskEnvelope + CollaborationGrant，禁递归委托）。**无持久化、无真实加密、无网络传输**，`friends_enabled` 默认 false。

**实装范围**（严守骨架既定负面清单：无公开搜索、无群聊、无附件、朋友不能直接调本地工具、禁止递归委托、无中心化离线队列）：

1. **持久化**：新增 `js/friends/store.py`——owner 作用域 SQLite（仿 `js/bots/store.py` 模式），库名进 `PRODUCT_STATE_DB_NAMES` + governor WAL 白名单；`FriendManager` 改为 store 背书，保留现有校验语义
2. **真实 E2E 加密**：X25519 密钥协商 + ChaCha20-Poly1305 载荷加密（`cryptography` 已是主依赖），邀请码内嵌公钥指纹，`key_rotation_epoch` 绑定真实密钥版本；本方私钥入 `js/security/secrets.py` 加密存储
3. **传输（Host-to-Host）**：出站 = 经 net_guard 的 HTTPS POST，目的地仅允许已确认朋友登记的端点（白名单，SSRF 防护复用）；入站 = 新增认证路由 `js/web/routers/friends.py`（签名信封校验；未确认/已拉黑/epoch 不匹配/重放一律 4xx 且限频记录）；投递失败走 Echo ledger outbox 重试语义
4. **Echo 集成**：朋友消息与 L2 任务一律作为**不可信污点回合**进 `run_echo_turn`（与 WP4 gateway 同档：强制污点 + conservative 审批）；`RemoteTaskEnvelope` 映射为 bots goal run，预算从信封各维封顶，`allowed_tools` v1 恒为空（纯文本/LLM 任务）；`CollaborationResult` 经出站链路回投
5. **UI/API**：邀请二维码生成/接受、朋友列表/拉黑/吊销、消息时间线、协作授权管理页；`friends_enabled` 默认仍 false，开启时受 WP3 姿态警示联动
6. **测试**：store owner 隔离、加密往返 + 防重放 + 轮换矩阵、传输认证拒绝矩阵、taint 传播断言、预算强制、递归委托拒绝；双实例 e2e 用两个临时 HOME 的本机 Host（仿 fresh-install-check 模式）互发消息与任务
7. rubric：`js/friends/` 移出 `reserved` 单元成独立 `friends` 单元 + scope，bump 版本；`tests/test_reserved_runtime_isolation.py` 相应调整（friends 启用后允许进 import 图，未启用仍隔离）

**风险**：非回环可达性——默认仍回环绑定，跨机需用户显式开放端口或自建隧道（文档说明，不做打洞/中继）；双机联调复杂度用双临时 HOME e2e 化解。
**回滚**：`friends_enabled=false` 即回到现状；store 文件独立可删。
**出口门禁**：§2 全套 + **Bugbot**。

---

### WP7 — 验证密度攻坚（贯穿，按里程碑收口）

**目标**：从 0.94:1 走向 Hermes 级 3.2:1。**行数是滞后指标**，主抓手是覆盖质量，行数随之到位；禁止灌水式测试。

抓手（按优先级）：
1. **覆盖率地板**：`pytest --cov` 分包阈值入 CI——`js/security/` ≥ 90%、`js/echo/` ≥ 85%、全库 ≥ 75%（branch），逐里程碑上调
2. **属性测试**（新 dev 依赖 `hypothesis`）：`security/parser.py` shell AST、路径沙箱规范化（symlink/NFC/casefold 边角）、ledger 编码往返、lease 参数绑定
3. **对抗语料回归**：prompt 注入/工具越权语料库跑 guard+taint（吸收 OpenClaw EXTERNAL_UNTRUSTED_CONTENT 思路），沉淀为 `tests/adversarial/`
4. **故障注入矩阵扩面**：把 Orin WP10 的 crash/restart 矩阵模式推广到 gateway outbox、evolution 提案库、memory dreaming（磁盘满 / 时钟回拨 / 进程 kill -9）
5. **变异测试抽查**（`mutmut`，本地跑不进 CI）：`js/security/` + `js/echo/ledger/` 杀伤率 ≥ 70%，杀不死的变异体补测试
6. 新增功能（WP4/5/6）按「测试行 ≥ 2× 产品行」标准落地

里程碑跟踪（`scripts/test_density_report.py` 新增，CI 输出比值并设不回退棘轮）：

| 里程碑 | 密度目标 | 绑定 | 性质（已拍板） |
|--------|----------|------|----------------|
| M1 | ≥ 1.2:1 | WP1–WP4b 收口时 | **硬验收** |
| M2 | ≥ 2.0:1 | WP4c–WP6b 收口 + 抓手 1–4 铺开 | 方向性，持续推进 |
| M3 | ≥ 3.2:1（Hermes 级） | 独立攻坚期，含变异测试补强 | 方向性，不设死线 |

**每个里程碑收口 = §2 门禁 + Bugbot（审查该阶段新增测试的真实性，防灌水）。**

---

### WP8 — 真实多用户环境安全审计（in-repo 2–3 天 + 外部流程）

**目标**：第 7 项。仓库内先把「可审计性」做满，再走外部审计——外部审计本身不是代码任务，但证据包是。

in-repo 交付：
- `docs/security/THREAT_MODEL.md`：多 owner 表面威胁模型（bots 房间串扰、fleet owner 混淆、web 多密钥会话、gateway 多发件人、cron owner 作用域），每威胁映射到现有测试或新增测试
- `tests/multiuser/` 滥用套件：并发多 owner 压测下的跨 owner 泄漏探测（记忆/房间/账本/审批队列）、会话固定、限频绕过、guest 提权（吸收现有 `test_fleet_owner_isolation.py` / `test_bot_store_owner_isolation.py` / `test_room_no_private_memory_leak.py` 扩成矩阵）
- `docker-compose.staging.yaml`：多用户试运行拓扑（hardened 镜像 + 多 owner 密钥 + 审计日志外挂卷）
- `docs/security/AUDIT_PACK.md`：给外部审计者的入口文档（边界声明、攻击面清单、已知未修清单=TECH_DEBT ⚫ 表、复现环境）
- 外部流程（操作项，不在仓库内完成）：选定独立红队 → 按 AUDIT_PACK 执行 → 报告归档 `docs/security/external/` → 发现回灌 TECH_DEBT/issue → 修复各自走 §2 门禁 + Bugbot

**出口门禁**：in-repo 部分 §2 全套 + **Bugbot**；外部报告归档后单独复盘一轮。

---

## 4. 顺序、依赖与体量

```
WP0 ─→ WP1 ─→ WP2 ─→ WP3 ─→ WP4a → WP4b → WP4c ─→ WP6a ─→ WP6b ─→ WP8(in-repo) ─→ 外部审计
                         └────────→ WP5（依赖 WP0 即可，可与 WP4 并行）
WP7 贯穿全程：M1（1.2:1 硬验收）在 WP4b 收口时；M2/M3 方向性
```

| WP | 体量（agent 协作节奏） | 主要交付 |
|----|------|----------|
| WP0 | 0.5 天 | 绿色基线 + 在途落库（agent 按主题拆 2–4 commit） |
| WP1 | 1 天 | SECURITY.md ×2 + 测试 + rubric bump |
| WP2 | 1 天 | CI 冻结 + SHA 钉扎 + 周期审计 |
| WP3 | 2 天 | 姿态探测 + hardened compose + `js doctor --security` |
| WP4 | 5–7 天 | ADR 0008 + js/gateway/ + Telegram 迁移 + webhook + Discord + 主动推送 |
| WP5 | 2–3 天 | 进化闭环 v1（提案制） |
| WP6a | 1–2 天 | 空壳裁决：scenarios 实装 + tasks 页接 goals |
| WP6b | 3–5 天 | Friends v1：持久化 + 真实 E2E 加密 + Host-to-Host 传输 + Echo 集成 |
| WP7 | 贯穿 | 密度 0.94 → **1.2（硬）** → 2.0 → 3.2（方向） |
| WP8 | 2–3 天 + 外部 | 威胁模型 + 滥用套件 + 审计包 |

合计 in-repo 体量约 18–25 天（agent 协作节奏），每个 WP 独立可验收、可回滚。

---

## 5. 明确不做（本计划范围外）

- 不完成 Orin Stage C cells、不默认打开 `orin.enforce`（继续按 `ORIN_STAGE_C_CLOSEOUT.md` 口径）
- 不做 ACP/编辑器协议、不做 iOS/Android node 实装（mobile 保持预留）
- 不做无人值守自我修改（进化环永远有人工批准闸）
- 不宣称多租户 SaaS 能力：js-agent 仍是单租户个人 harness，「多用户」指单 host 多 owner 表面
- 不为凑密度写快照式/同义反复测试（Bugbot 检查点明确盯这一条）

---

## 6. 已拍板决策（2026-08-29 用户确认）

| 决策 | 结论 |
|------|------|
| 执行范围与顺序 | WP0–WP8 全量按计划顺序执行 |
| WP4c 第二渠道 | **Discord**（微信个人号明确不做：封号+ToS 风险） |
| gateway 与隔离的关系 | **折中档**：原生可启用，gateway 回合强制不可信污点 + conservative 审批 + 状态页持续警示；容器姿态解除警示；`enforce` 作为可选严格档 |
| friends 模块 | **实装 v1**（WP6b），不删除 |
| tasks 空壳页 | 接 bots goals 只读视图 |
| 测试密度目标 | M1（1.2:1）为硬验收；M2/M3 方向性推进 |
| WP0 在途落库 | 由执行 agent 按主题拆 2–4 个 commit |
| SECURITY.md 语言 | 中文主 + 英文副（与 README 惯例一致，默认采纳） |
| 外部审计供应商 | 未定；AUDIT_PACK 先行，不阻塞 |

---

## 7. 进度跟踪

| WP | 状态 | Bugbot | 备注 |
|----|------|--------|------|
| WP0 | 未开始 | — | |
| WP1 | 未开始 | — | |
| WP2 | 未开始 | — | |
| WP3 | 未开始 | — | |
| WP4a/b/c | 未开始 | — | 渠道=Discord |
| WP5 | 未开始 | — | |
| WP6a | 未开始 | — | |
| WP6b | 未开始 | — | Friends v1 实装 |
| WP7 M1/M2/M3 | 未开始 | — | 基线 0.94:1；M1 硬验收 |
| WP8 | 未开始 | — | |
