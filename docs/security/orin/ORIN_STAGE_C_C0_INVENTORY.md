# Orin 阶段 C WP-C0 Authority Inventory

> 状态：机器生成、人工分类的只读证据；仅完成 WP-C0 盘点与书面冻结；本轮软件侧为 enforce 增加未分类出口 deny-list 与 digest 钉死，默认生产开关仍关闭，阶段 C 未实施
> 日期：2026-08-25（Asia/Shanghai）
> 文档基线：`245c208ce95bf6bb3c05702f8dce65b8483da542`
> 运行时行为基线：`652d035e0fda0e945da97e55b73a8f4116716410`
> 授权边界：本索引冻结 WP-C0；C1–C3 仅获显式 construction harness 授权；软件合取检查器仍将 #8/#9/正式 TCC/AppShell 分离标为未观察；所有阶段 C 生产开关保持关闭，不得宣称阶段 C 已实施

本文件是 `ORIN_STAGE_C_SPEC.md` 的 C0 证据索引，不是实现报告。它不证明阶段 C 已实施，不证明 Echo RCE 已收口，也不授权修改产品路由、预建 Desktop/Memory Cell 或打开任何强制模式开关。

---

## 1. 方法、证据标签与分类语义

### 1.1 证据标签

| 标签 | 本文件中的含义 |
|---|---|
| **已观察** | 由上述基线的源代码、现有测试或本轮只读命令直接支持 |
| **已推断** | 由已观察事实推出，仍须后续实现或实机验证 |
| **拟议** | C1+ 的施工或验收约束；不代表已落地 |
| **目标值** | 产品或 K§10.4 目标；本文件没有把任何目标值写成已测 |

`blocked`、`untested` 与 `external-pending` 是验收状态，不是四类 authority。每个 inventory 项的 `enforce 分类` 只能取以下一个值：

| 分类 | 冻结含义 |
|---|---|
| `cell` | 最终允许执行时必须只经指定 Cell；当前标成 `cell` 不表示 C 已启用 |
| `readonly` | 只允许经审计的安全读取或安全投影；C4/C5 仍须证明 OS 层没有写、网、凭证或子进程旁路 |
| `draft-only` | 只能生成文本、计划或未提交草案；不能产生生产副作用 |
| `disabled-in-enforce` | `orin.enforce=true` 时必须稳定拒绝或不可达；完成指定后续 WP 后才可重新分类 |

任何未知、动态新增、热加载、改名或未登记 handler 一律 `disabled-in-enforce`。描述文本、自报 `read_only`、Python registry 可见性或普通 HMAC 工牌都不能提升分类。

### 1.2 机器枚举

本轮在干净基线上用 Python AST 枚举 `js/**/*.py` 中的 `ToolSpec(...)` 和 FastAPI `get/post/put/patch/delete/websocket` 装饰器，再用 `rg` 交叉查找网络客户端、凭证恢复、写目录、socket、子进程与 daemon 注册点。结果由下文人工按实际 authority 分类。

| 枚举集合 | 已观察结果 | canonical 列表 SHA-256 |
|---|---:|---|
| `ToolSpec` 构造点 | 66 | `0c1a7e894dc7955c7278491abc05dd021da80109dcfee33458416b5668e6c21c` |
| FastAPI 装饰路由 | 156 | `1775ae98a845a7a5f5cbfcc27fcad306ca4a3d5091007ac466220e03fd4e0898` |

哈希输入是按路径、行号、方法/名称排序后的紧凑 UTF-8 JSON；动态 MCP 和 skill 名称保留为动态占位。基线变更会使行号哈希变化，因此后续 WP 必须重生成，而不能复制本表。

只读交叉扫描覆盖：

- 注册入口：`js/agent/tool_executor.py:1309-1376`、`js/agent/__init__.py:261-265,935-946`；
- 网络/凭证：`httpx`、OpenAI client、Search、WebBridge、MCP、SecretManager；
- 文件写入：owner workspace、`.js-code`、uploads、Memory、skills、cron、Fleet、ledger、Orin 私有目录；
- 进程与 IPC：`subprocess`、`asyncio.create_subprocess_exec`、multiprocessing、`orind.sock`、`cells.sock`、WebBridge loopback HTTP；
- 产品 handler：AppShell 与 Web 的 156 条装饰路由、cron/daemon 的 10 个注册 callback。

### 1.3 C0 总结

| 事项 | C0 裁决 |
|---|---|
| authority inventory | **已观察**：66 个 ToolSpec 构造点、156 条 HTTP/WS 路由及非路由环境出口已枚举并人工分类 |
| 模型供应商通道 | 冻结为“受审查的产品基础通道”；当前实现 **blocked**，不能给 Echo 通用网络或 token |
| AppShell/Echo 边界 | 目标进程边界已书面冻结；当前同进程实现 **blocked** |
| macOS 生产隔离载体 | 现有配置与构建路径只定义本地 ad-hoc 流程；本轮未观察到可复验实际产物，生产载体 **external-pending**，发布 **blocked** |
| 发布签名 | 方案已书面冻结；真实 Developer ID/notary 环境 **external-pending** |
| Desktop/Memory | 只登记为 C2/C3 整迁前置；C0 未创建 Cell、handler、cap 或协议 |
| 阶段 B golden | 本轮只读选择集 `31 passed`；两条已知 auth 基线红只登记、未重跑、未修复 |

---

## 2. 四项书面冻结

### 2.1 模型供应商通道：受审查的产品基础通道

**冻结选择**：模型推理是固定用途的产品基础通道，不映射为 `net.send` 或 `email.send_exact`，不使用或核销 ExportPass。允许的终态只能是固定 provider endpoint、固定账号、固定 transport/model 的受审查通道，由阶段 C 设计中的既有 Network/Connector/Secret Cell 能力组合持有连接与凭证；Echo 只提交模型输入并接收安全投影，不能持有通用 socket 或 token。

证据与状态：

- **已观察**：`ModelProviderConfig` 包含动态 `base_url`、`api_key`、`api_key_env`，环境变量会解析成进程内明文 key（`js/config.py:32-40,71-75`）。
- **已观察**：JSAgent 在同一进程构造 `SecretManager`、恢复 provider key、创建 `ModelRouter`（`js/agent/__init__.py:119-153`；`js/models/provider_manager.py:35-45,131-157`）。
- **已观察**：provider 在同一进程创建 `httpx`/OpenAI client 并发起 chat、stream、health 网络请求（`js/models/providers.py:250-316,390-438,538-575,611-660,712-735`）。
- **已观察**：管理路由允许登记动态 HTTP(S) provider，discovery 虽有 DNS/private-IP 检查，运行期仍是通用 provider client（`js/web/server.py:1435-1505,1653-1721`；`js/models/provider_manager.py:364-410`）。
- **裁决**：当前实现为 `disabled-in-enforce`，发布 **blocked**。custom、未知或不能确定性归类的 provider 保持禁用；不得借产品基础通道给 Echo 通用网络、动态目的地或 token。

### 2.2 AppShell 与受限 Echo：不同 OS 进程

**冻结边界**：可信 AppShell 控制/签名宿主与受限 Echo worker 必须是不同 OS 进程。

- 可信 AppShell 宿主持有 owner-witness 私钥、可信会话、主人确认 UI 和既有 B 协议的特权调用能力；
- 受限 Echo worker 只接收 task/handle ID、模型上下文与安全投影，不读取 owner key、真实 provider token、AppShell state directory 或 Cell 私有材料；
- 两者只经认证的最小本地 IPC 交换严格 schema；这不新增 Orin 顶层消息，也不重开 `handle.op=issue`；
- Tauri 外层与 Rust launcher 本阶段不改。优先在现有 Python 打包形态内分成可信宿主与受限 worker；若真实隔离必须依赖未获授权的 Rust 修改，则保持 `blocked`，不得用同进程共享私钥冒充分离。

证据与状态：

- **已观察**：当前 AppShell 在一个 uvicorn/Python 进程内创建 Personal/Work child app 与 agent runtime（`js/appshell/launcher.py:46-102`；`js/appshell/server.py:27-75,96-113`；`js/web/server.py:716-763`）。
- **已观察**：desktop host 自述为 single-process Python sidecar（`desktop/sidecar/host.py:1-6,278-303,388-405`）。
- **已观察**：owner-witness 私钥从 state directory 加载为进程内 `Ed25519PrivateKey`，`/intent`、`ExactCommitApprovalV1`、ExportPass、unfreeze 路由在同一进程使用它（`js/orin/witness.py:1-9,67-90`；`js/appshell/routers.py:503-585,706-862`）。
- **已观察（C1 身份检查点）**：存在测试专用 `c1_harness`，会在 deny-default 策略下启动固定 stdlib OS 子进程探针；它不是真实 Echo runtime，且未接入 launcher/server/sidecar 生产路径，不能作为生产进程分离证明。
- **已观察（C1 第一块 macOS construction harness）**：新增固定 `js.echo.c1_worker` 入口；测试宿主先持有 owner-witness 私钥并签署既有 Intent / ExactCommitApproval / ExportPass / unfreeze schema，再通过认证匿名管道只投影 task/handle ID、模型上下文与安全字段。worker 是另一 OS 进程并真实执行 `JSAgent → run_echo_turn → EchoTurnLoop`；只读 runtime image 排除 AppShell 签发面和生产 orind，私有 state 不含真实 provider token。父进程记录 Darwin `sandbox-exec` payload PID，固定攻击进程在相同 deny-default 策略下验证宿主 state/私钥/仓库控制面/UDS 不可达。worker 临时 key 可构造 `approved=True` DTO，但宿主公钥验证失败，不能成为受信权威事件；旧 stdlib 探针仅为负对照。
- **裁决**：C1 第一块在显式 harness 已测，身份/env/path 其余门槛沿用已冻结检查点；默认 launcher/server/sidecar 仍是同进程产品路径，因此生产实施与打包验证保持 **blocked**。真实 provider token、Keychain/Mach 与正式打包边界保持 `untested` / `external-pending`；不得把 harness 写成生产隔离或阶段 C 收口证明。

### 2.3 macOS 生产隔离载体

**冻结载体边界**：保留现有 macOS `.app`、Tauri 外壳与 PyInstaller Python sidecar 配置所定义的打包外形；可信 AppShell 宿主必须启动一个另行受限的 Echo worker。接受的生产载体必须在最终签名包内证明 Echo 身份没有网络、真实凭证、真实写目录、Desktop 或 Memory authority，并通过 C4 的 OS 权限负向验收以及 C6 的 RCE/raw-syscall 绕过复验。

- **已观察**：仓库配置定义 `.app` bundle/`js-agent-host` sidecar 形态（`desktop/src-tauri/tauri.conf.json:29-37`）；本轮未观察到可复验的实际 `.app`、`.dmg`、`.pkg` 或 ZIP 产物。
- **已观察**：构建脚本定义 unsigned bundle、`--no-sign` 构建和 ad-hoc 签名流程；代码明确声明这不是 Developer ID、没有 notarization，拟生成的产物名含 `unsigned`（`desktop/build_driver.py:1-6,828-883,1154-1203,1275-1303,1952-1979`）。
- **已观察**：`js/echo/os_sandbox.py` 的 `sandbox-exec` 只包裹命令子进程；它允许 workspace 写，且没有包裹生产 Echo 进程（`js/echo/os_sandbox.py:70-165,336-451`；`tests/echo/test_os_sandbox.py:226-252`）。
- **裁决**：具体可上线的 macOS 沙箱/宿主机制尚无真实打包、签名和实机证据，状态为 **external-pending**；阶段 C 发布为 **blocked**。不得把未验证的 `sandbox-exec` 写成生产隔离证明。

### 2.4 发布签名

**冻结方案**：由发布者控制的独立 post-build 阶段验证源码/manifest/依赖树；所有嵌套 Mach-O、helper、sidecar 与受限 Echo worker 都按 inside-out 顺序使用 Developer ID Application、Hardened Runtime 和各角色显式最小 entitlements 签名，最后签外层 `.app`。随后 notarize、staple，并记录 artifact hash、Team ID、签名身份和验证报告。验收必须包含 `codesign --strict`、Gatekeeper、notary/staple 检查、C4 OS 权限负测及 C6 RCE/raw-syscall 复验。

- **已观察**：当前 release workflow 只覆盖 Python wheel/sdist 与 smoke，没有桌面 Developer ID/notary 链（`.github/workflows/release-smoke.yml:13-40`）。
- **裁决**：方案已冻结；真实 Apple 身份、证书、notary 服务与签名产物为 **external-pending**。证书、notary 凭证和私钥不得入库。

---

## 3. ToolRegistry handler inventory（66 个构造点）

下表覆盖 AST 枚举出的全部 66 个 `ToolSpec` 构造点。动态 skill 构造点按实例的封印 kind 分型；每个实际实例仍只有一个 enforce 分类。

| 数量 | handler | 当前 authority（已观察） | enforce 分类 | 后续关闭条件 |
|---:|---|---|---|---|
| 1 | `browser_fetch` | 有 `cell_net` 时只走 Network Cell；否则 Echo 内直接 `httpx`（`js/tools/browser.py:37-162`） | `cell` | enforce 必须要求现有 Network Cell；Cell 失联不回退 |
| 5 | `file_read`, `file_list`, `file_search`, `file_view`, `code_search` | Echo 直接读取 owner workspace（`js/tools/files.py:275-333,476-634,1282-1300`） | `readonly` | C4/C5 证明只读 root、无链接/多进程旁路和零写权限 |
| 2 | `file_write`, `file_edit` | 有 File Cell backend 时失败不回退；否则 Echo 直写（`js/tools/files.py:657-697,799-860`） | `cell` | enforce 只保留阶段 B `file.commit` 草案链 |
| 1 | `file_delete` | File Cell 模式拒绝，否则 Echo `unlink/rmdir`（`js/tools/files.py:755-797`） | `disabled-in-enforce` | 未有封印语义和 Cell 路径前不启用 |
| 2 | `shell`, `python` | 可走 WP7 Build Cell；`python` 仍先在 `.js-code` 写脚本，关闭 backend 时本地起子进程（`js/tools/shell.py:429-491`；`js/tools/code.py:335-529`） | `cell` | 保留 WP7 帧；C4 将 staging 搬入 Cell，删除 raw fallback |
| 2 | `csv_read`, `excel_read` | Echo 内直接读取 workspace（`js/tools/office.py:517-534,650-697`） | `readonly` | C4/C5 证明只读 OS root 和库调用无副作用 |
| 5 | `csv_write`, `excel_write`, `excel_merge`, `excel_create`, `pdf_generate` | Echo 内直接保存/发布到 workspace（`js/tools/office.py:667-782,1151-1192,1293-1383,1536-1682`） | `disabled-in-enforce` | 接入 File Cell 后方可重新分类为 `cell` |
| 1 | `web_search` | SearchManager 直接联网并取 Tavily key（`js/agent/tool_executor.py:5164-5210`；`js/search/engines.py:44-71,272-300`） | `disabled-in-enforce` | 固定目标的 Network/Secret Cell 路径完成后再审 |
| 9 | `web_navigate`, `web_snapshot`, `web_click`, `web_fill`, `web_screenshot`, `web_evaluate`, `web_find_tab`, `web_list_tabs`, `web_extract_text` | Echo 持有 0600 WebBridge token，经 loopback HTTP 控制真实浏览器（`js/tools/webbridge.py:24-72,158-239,262-713`） | `disabled-in-enforce` | C2/C4 明确映射 Desktop/Network/File Cell；自报 read-only 不算 |
| 16 | `desktop_get_permissions`, `desktop_get_state`, `desktop_screenshot`, `desktop_list`, `desktop_operation_log`, `desktop_emergency_stop`, `desktop_clear_stop`, `desktop_click`, `desktop_move`, `desktop_scroll`, `desktop_drag`, `desktop_type`, `desktop_key`, `desktop_app`, `desktop_window`, `desktop_set_mode` | 默认生产 Echo 仍直接持有 Screen Recording/Accessibility 并调用 Quartz、`cliclick`、`screencapture`、`osascript`（`js/tools/desktop_tools.py`；`js/tools/desktop/controller.py`） | `disabled-in-enforce` | C2 显式 harness 已观察 ApplicationHandle、原生 window bundle 硬拒、digest upsert 与 Echo 去 PID/AX/`window_number`；`idempotent` 仍为 False，真实模型 E2E 与正式 TCC blocked，默认生产分类不变 |
| 1 | `fleet_collaborate` | 同进程创建 JSAgent workers，并直写 workspace/state/history（`js/tools/fleet_tools.py:17-214`；`js/orchestration/fleet.py:1280-1957`） | `disabled-in-enforce` | 本地编排须继承非扩张 task/Intent 且所有效果进 Cell；跨设备委托属 P6 |
| 1 | `desktop_wizard_action` | 控制 Desktop 配置/权限引导，当前在 Echo/AppShell 失陷域 | `disabled-in-enforce` | C1 可信宿主 + C2 Desktop Cell 后再审 |
| 18 | `control_skill_install`, `control_clawhub_discover`, `control_clawhub_install`, `control_provider_discover`, `control_provider_mutate`, `control_fleet_configure`, `control_fleet_continue`, `control_fleet_session_delete`, `control_model_switch`, `control_setup_state`, `control_session_mutate`, `control_desktop_state`, `control_task_mutate`, `control_memory_mutate`, `control_skill_mutate`, `control_evolution_action`, `control_upload_mutate`, `control_cron_mutate` | 当前可变更 provider、skill、Fleet、session、Desktop、task、Memory、upload、cron 等产品状态 | `disabled-in-enforce` | 逐项迁入可信 AppShell、Cell 或永久关闭；不能因模型不可见而豁免 |
| 1 动态点 | `mcp_<server>_<tool>` | manifest 可描述 stdio/HTTPS，但执行目前被 tombstone 拒绝（`js/mcp/controlled.py:125-212`；`js/mcp/client.py:1-60`） | `disabled-in-enforce` | 封印 Effect Manifest 并映射既有 Cell 前保持禁用 |
| 1 动态点 | PROMPT skill handler | 可读 skill references 并调用模型，只应产出文本/提案（`js/skills/manager.py:225-305`；`js/skills/executor.py:286-350`） | `draft-only` | 模型通道先满足 §2.1；运行期 skill digest 漂移即禁用 |
| 同一动态点的其他实例 | CODE / WORKFLOW / META skill handler | 可经 SandboxExecutor 起 Python/Shell 或组合其他能力（`js/skills/executor.py:142-223,354-430`） | `disabled-in-enforce` | 每个子步有封印 manifest 并映射 Build/File/Network/Connector 后再审 |

`ToolRegistry.execute()` 当前对未知名字返回 `Unknown tool`；对已登记名字，`get_handler()` 返回拒绝直接调用的代理（`js/tools/registry.py:480-490,571-592,990-993`）。这些都是纵深防御，但 C 的威胁模型包含绕过 Python registry；它们不是“未登记 handler 默认拒绝”的 OS/产品证明。

---

## 4. HTTP / WebSocket handler inventory（156 条路由）

下表按机器枚举源文件和精确路径组覆盖全部 156 条装饰路由。计数总和为 156；同一行的每条路由只有所列一个分类。

| 数量 | 路由组 | enforce 分类 | 裁决 |
|---:|---|---|---|
| 9 | `js/appshell/routers.py` 的 GET：`/capabilities`, `/intent/active`, `/file-commit/pending`, `/inbox`, `/artifacts`, `/work-context`, `/settings`, `/devices`, `/friends` | `readonly` | 仅可信会话的安全投影；C5 验证不含 owner-root、token、permit/package |
| 8 | 同文件 POST：`/session`, `/logout`, `/bootstrap`, `/intent`, `/file-commit/approve`, `/export-pass`, `/admin/unfreeze`, `/switch` | `disabled-in-enforce` | 当前与 Echo 同进程；C1 分离后只在可信 AppShell 宿主重开 |
| 1 | `js/appshell/server.py` GET `/api/appshell/health` | `readonly` | 仅固定健康投影 |
| 1 | 同文件 POST `/api/workspace/switch` | `disabled-in-enforce` | 已退休入口，不恢复 |
| 2 | `js/appshell/switch_api.py` POST `/api/appshell/switch`, `/api/workspace/switch` | `disabled-in-enforce` | 旧切换入口不得成为受限 Echo 控制面 |
| 2 | approvals/manual review GET 列表：`js/web/routers/approvals.py`, `manual_reviews.py` | `readonly` | 仅安全审批事实 |
| 2 | approvals/manual review POST decision/resolve | `disabled-in-enforce` | C1 后只允许可信 AppShell 主人确认面 |
| 1 | `js/web/routers/chat.py` POST `/api/chat` | `draft-only` | 模型通道另受 §2.1 约束；chat 本身不能产生 ambient effect |
| 5 | cron GET `/jobs`, `/jobs/{job_id}`, `/history`, `/stats`, `/templates` | `readonly` | 只读调度元数据，结果必须脱敏 |
| 1 | cron POST `/parse` | `draft-only` | 只生成调度提案，不登记或运行 job |
| 4 | cron create/update/delete/run 路由 | `disabled-in-enforce` | C5 前没有可信 task/Intent 与 Cell-only callback 合同 |
| 3 | Desktop GET `/api/desktop/status`, `/api/desktop/wizard`, `/api/desktop/wizard/status` | `disabled-in-enforce` | 当前会触达 Accessibility/Screen Recording，wizard 还可能运行 native helper；C2 前禁用 |
| 4 | Desktop POST toggle/wizard action/enable/enable-writes | `disabled-in-enforce` | C1 可信宿主与 C2 Desktop Cell 前禁用 |
| 3 | Fleet GET `/status`, `/history`, `/sessions/{session_id}` | `readonly` | 只读脱敏元数据 |
| 3 | Fleet collaborate/delete/continue | `disabled-in-enforce` | 当前同进程 workers 有 ambient authority；跨设备委托不在 C |
| 30 | `js/web/routers/memory.py` 的全部 `/api/memory**` 与 session capsule 路由 | `disabled-in-enforce` | 读写都直接触达 MemoryStore；C3 整迁后逐项映射 Memory Cell |
| 1 | `js/web/routers/metrics.py` GET `/api/metrics/providers` | `readonly` | 只允许无 token 的聚合指标 |
| 1 | plugins GET `/` | `readonly` | 只列封印元数据 |
| 4 | plugins enable/disable/install/delete | `disabled-in-enforce` | 安装与状态变更须有 manifest/Cell 或永久关闭 |
| 2 | scenarios GET list/detail | `readonly` | 只读封印场景描述 |
| 1 | scenarios POST start | `disabled-in-enforce` | 场景效果未逐项映射前禁用 |
| 1 | setup GET `/api/setup/first-start` | `readonly` | 固定状态投影 |
| 6 | setup complete/skip/start/reopen/reset/test-model | `disabled-in-enforce` | 可信宿主与受审查模型通道完成前禁用 |
| 4 | system GET `/api/status`, `/api/capabilities`, `/api/appshell/prefs`, `/api/dashboard` | `readonly` | C5 验证稳定脱敏 |
| 1 | system GET `/api/diag` | `disabled-in-enforce` | 完成环境、路径和凭证脱敏审计前禁用 |
| 2 | tasks GET list/detail | `readonly` | 只读安全投影 |
| 3 | tasks pause/resume/delete | `disabled-in-enforce` | 可信控制面完成前禁用 |
| 20 | `js/web/server.py` 的安全 GET：`/`, `/api/audit`, `/api/files`, `/api/models`, `/api/providers/cloud-presets`, `/api/stats/tokens`, `/api/evolution/reports`, `/api/evolution/proposals`, `/api/evolution/insights`, `/api/agents/config`, `/api/skills`, `/api/skills/metrics`, `/api/skills/hermes`, `/api/skills/promotions`, `/api/skills/promotions/{event_id}`, `/api/skills/{skill_id}`, `/api/uploads`, `/api/file-preview`, `/api/health`, `/api/metrics/resources` | `readonly` | 仅安全投影；路径、日志和配置必须在 C5 做脱敏/越权负测 |
| 1 | `js/web/server.py` WebSocket `/ws` | `draft-only` | 只能产生对话/草案；所有工具效果仍受 inventory 与 Cell 仲裁 |
| 30 | `js/web/server.py` 其余路由：auth session/logout、cancel/delete session、`GET /api/sessions`、`GET /api/sessions/{session_id}/messages`、model switch、全部 provider mutation/discovery/test/scan、evolution run/reflect、agent config write、`/api/search`、Hermes refresh、promotion mutation、skill install/delete/trust/discover、upload write/delete、`/ws/fleet` | `disabled-in-enforce` | session 路由直接读取 Memory；其余逐项迁可信宿主/Cell，动态网络、凭证、文件与 worker authority 未关闭前禁用 |

HTTP 路由“不可被模型直接调用”不构成豁免；受限 Echo RCE 能直接调用同进程函数，因此所有副作用路由仍必须进入 C1/C4/C5 的进程、OS 与 handler 默认拒绝验证。

---

## 5. 非路由 authority inventory

### 5.1 cron / daemon callbacks

`js/daemon/core.py:165-176` 注册 10 个 callback；`js/cron/engine.py:423-469` 可自动调度到期 job。

| callback | 当前行为 | enforce 分类 | 裁决 |
|---|---|---|---|
| `health_check`, `backup`, `report`, `search`, `skill_evolve` | callback 主体是只读或当前 no-op，但 scheduler 每次仍更新 job 状态并持久化 result/log | `disabled-in-enforce` | C5 将 scheduler 元数据写入非权威隔离根并封印 callback digest 后，才可逐项重审 |
| `cleanup`, `dream` | 直接变更 Memory，scheduler 同时持久化运行状态 | `disabled-in-enforce` | C3 后映射 Memory Cell；scheduler 仍受 C5 约束 |
| `shell` | 以 system scope 走 Echo ToolEffect，无可信 Orin task/Intent，并写 job/result/log | `disabled-in-enforce` | C5 绑定可信 task/Intent，且只走 WP7 Build Cell |
| `chat`, `custom` | 启动 Echo turn，payload 可打开工具，并写 job/result/log | `disabled-in-enforce` | 若重开，只能无工具 `draft-only`，或全部效果经 Cell |

`system_scope` 不是 Orin Intent。cron DB 当前直接持久化 payload/owner/product/session/result（`js/cron/store.py:24-180,248-322`），所以调度 mutation/run 整体保持 `disabled-in-enforce`；未来若只保存无副作用排程元数据，才能单独评为 `draft-only`。

### 5.2 环境能力总表

| 环境能力 | 已观察的当前持有者/路径 | enforce 分类 | 后续映射或阻断 |
|---|---|---|---|
| 模型 provider 网络与 token | Echo 同进程 provider/SecretManager | `disabled-in-enforce` | §2.1 受审查产品基础通道；当前发布 blocked |
| Browser fetch | Echo fallback 或既有 Network Cell | `cell` | enforce 禁 raw fallback；`net.fetch` 仍无 ExportPass |
| Search/Tavily | Echo 直接网络 + key | `disabled-in-enforce` | 固定目的地 Network/Secret Cell 后再审 |
| Telegram bot | CLI 从 `--token` / `TELEGRAM_BOT_TOKEN` 取得 bot token，并启动 integration；同进程持 token、轮询 Telegram 网络、驱动 agent turn，并下载、提交和清理 workspace 上传（`js/ui/cli.py:1511-1529`；`js/integrations/telegram_bot.py:42-55,110-150,235-267,275-438`） | `disabled-in-enforce` | 完成受审查入口、固定账号 Connector/Secret 边界且全部后续效果进入既有 Cell 前禁用；它是双向产品入口/agent-turn 控制面，不是 `net.send` 或 ExportPass，不得借出门证给 Echo token/通用网络 |
| Auto-Fetch pipeline（gmail/slack/drive/github/notion/calendar/file + Obsidian/Memory 写回） | 当前未观察到产品实例化/启动点；调度器定义了周期/按需 connector 执行，Gmail/Slack/Drive/GitHub/Notion/Calendar 仍为 mock/TODO stub（`js/pipeline/connectors/gmail.py:65-72`；`js/pipeline/connectors/slack.py:42-46`；`js/pipeline/connectors/drive.py:44-48`；`js/pipeline/connectors/github.py:63-67`；`js/pipeline/connectors/notion.py:42-46`；`js/pipeline/connectors/calendar.py:60-64`），但 FileConnector 会递归读取本地文件，并直接写 Obsidian vault/manifest 与 semantic Memory（`js/pipeline/orchestrator.py:31-39,62-109,127-209,242-285`；`js/pipeline/connectors/file.py:31-43,49-84`；`js/pipeline/sync.py:27-80`；`js/memory/store.py:78-92,548-581`） | `disabled-in-enforce` | C3 Memory Cell 与 File Cell 映射完成前禁用；未来实现上述 HTTP connector 时还须逐项接入受审查的固定目标/账号 Connector/Secret 路径，不能因当前 stub 获豁免 |
| Office 读 | Echo 直接读 workspace | `readonly` | C4/C5 证明 OS 只读与库无副作用 |
| Office 写 | Echo 直接写 workspace | `disabled-in-enforce` | File Cell 草案链 |
| WebBridge | Echo 持 token 并控制 loopback browser daemon | `disabled-in-enforce` | C2/C4 拆分 Desktop/Network/File authority |
| MCP | 当前执行 tombstone；manifest 可描述 stdio/HTTPS | `disabled-in-enforce` | 封印 manifest + 既有 Cell |
| PROMPT skills | 读取 references、调用模型、产出文本 | `draft-only` | 固定 digest；模型通道受审 |
| CODE/WORKFLOW/META skills 与安装/演化 | 可起进程、联网、写 skill/state | `disabled-in-enforce` | 封印子步映射 Build/File/Network/Connector |
| cron/daemon mutation | 自动调度，可触发 Memory/shell/chat | `disabled-in-enforce` | C3/C5；未知 callback 默认禁用 |
| Fleet | 同进程 worker、workspace/state/history 写入 | `disabled-in-enforce` | 本机编排需非扩张 task/Intent；P6 委托排除 |
| Desktop | Echo 持 Accessibility/Screen Recording 与 native helper | `disabled-in-enforce` | C2 Desktop Cell；C0 不预建 |
| Memory | Echo 直接打开 DB/文件并自动读写 | `disabled-in-enforce` | C3 Memory Cell；C0 不预建 |
| 真实凭证 | provider、Search、WebBridge、SecretManager 可在 Echo 域读取 | `disabled-in-enforce` | Secret/Connector Cell 或受审查模型基础通道 |
| File staging、connector outbox | 既有 Cell 持有；相关敏感打开路径已有 no-follow/0600/0700 | `cell` | C1 逐子路径验证 owner/mode/symlink 与 env allowlist；不拆 `services.py` |
| SecretStore `secrets.jsonl` | 初建使用 O_EXCL/0600；既存路径以 `Path.open` 读写，没有 O_NOFOLLOW 证明 | `cell` | C1 补 owner/mode/no-symlink 与逐 Cell env 合同；此前凭证边界 blocked |
| Orin WAL/Membrane SQLite、lease-HMAC KeyBox、socket pointer | orind/Services/File 使用 `state/orin` 中的相应对象，但没有统一 no-follow/私有模式证明 | `cell` | C1 逐项补 owner/mode/no-symlink 与最小环境证据；当前 enforce 启动 blocked |

### 5.3 可写目录与 staging

| 目录/状态 | 已观察事实 | enforce 分类 | 裁决 |
|---|---|---|---|
| owner workspace（默认 `~/.js/workspace`） | File fallback、Office、uploads/attachments 可由 Echo 直接写 | `disabled-in-enforce` | 已迁 `file.commit` 继续为 `cell`；其他直写在 C4 前全禁 |
| `workspace/.js-code` | 即使启用 Build Cell，Echo 仍先创建目录和脚本（`js/tools/code.py:335-407,471-529`） | `disabled-in-enforce` | C4 移到 Build Cell 私有 staging；WP7 wire frame 不变 |
| Build Cell 默认 `./.build` | `ORIN_BUILD_WORKSPACE` 未由 daemon 设置时，相对 orind cwd 创建，未封印为 Cell 私有根（`js/orind/cells/build.py:51-68`；`js/orind/daemon.py:2637-2651`） | `cell` | 当前 enforce 启动 blocked；C4 固定到 Cell 私有 staging 并验证 fs deny-default，WP7 帧不变 |
| `workspace/.echo-tmp` 与 sandbox HOME | 当前位于真实 workspace（`js/echo/os_sandbox.py:328-334`） | `disabled-in-enforce` | 搬入不具生产 authority 的私有临时根后再审为 draft-only |
| uploads/attachments | 主进程写 workspace（`js/echo/attachment_gate.py:94`；`js/echo/upload_quota.py:87`） | `disabled-in-enforce` | File Cell 或非权威私有 staging；不得直写 owner-root |
| Memory DB 与 `state_dir/memory` | MemoryStore/EnhancedStore 直接读写（`js/memory/store.py:78-172,753-794`） | `disabled-in-enforce` | C3 Memory Cell |
| skills/plugins/evolution/RL/pipeline/Fleet/cron state | 当前主进程可写 state/workspace 多个子目录 | `disabled-in-enforce` | 逐项封印并映射 Cell；纯提案状态方可另审 draft-only |
| Echo ledger/event/checkpoint/log/cache | 仍在主进程 state；与 secret/memory 根未证明 OS 分离 | `disabled-in-enforce` | C4 分出最小专用根并做内容/权限审计后可逐项重分类 |
| File staging、connector outbox | File/Services 的相关敏感打开路径已有 no-follow 与 0600/0700 防护（`js/orind/cells/file.py:383-434,474-511`；`js/orind/cells/services.py:605-650,795-825`） | `cell` | C1 按实际子路径复验 owner/mode/symlink 与 env allowlist |
| SecretStore `secrets.jsonl` | 初建用 O_EXCL/0600；既存文件 chmod 后以 `Path.open` 读写，没有 O_NOFOLLOW（`js/orind/cells/services.py:88-125`） | `cell` | C1 验 owner/mode/no-symlink 与替换攻击；此前 enforce 凭证路径 blocked |
| Orin WAL/Membrane SQLite、lease-HMAC KeyBox、socket pointer | SQLite 仍直接 connect，`state/orin` 不具统一 no-follow/0600/0700 证明（`js/orind/store.py:171`；`js/orind/membrane.py:352`） | `cell` | C1 逐对象冻结路径、owner/mode/no-symlink、创建与清理合同；此前 enforce 启动 blocked |

目录权限或路径规范化只能作为纵深防御，不等于受限 Echo 没有该目录的 OS authority。

### 5.4 socket、IPC 与子进程

| 出口 | 已观察事实 | enforce 分类 | 裁决 |
|---|---|---|---|
| `orind.sock`, `cells.sock` | UDS chmod 0600；主 socket 校验同 euid/PID/hello/MAC，cells.sock 另校验 daemon-spawned PID→cap（`js/orind/daemon.py:251-288,389-413,509-599,2747-2813`） | `cell` | C1 验 owner/mode/no-symlink/replacement、身份、nonce/seq/MAC/replay；同 UID 不足 |
| 短 `cells.sock` 根与 `cells.sock.path` | UDS 路径过长时在 `mkdtemp(prefix="orind-cells-")` 下放 socket，并在请求路径写 0600 pointer（`js/orind/daemon.py:357-369`） | `cell` | C1 验临时根 owner/mode/no-symlink、pointer 替换、清理和重启合同 |
| `session-<pid>.key` | `_publish_session_key` 以 O_EXCL 创建 0600 会话密钥文件；它不是 socket pointer（`js/orind/daemon.py:586-599`） | `cell` | C1 验 one-shot、owner/mode/no-symlink、消费/清理、复制 key 与重放 |
| Build/File/Services Cell 进程 | daemon 固定 argv 启动，但三类都继承 `dict(os.environ)`（`js/orind/daemon.py:2637-2709`） | `cell` | C1 只给现有三类做逐 Cell allowlist；不预建 Desktop/Memory |
| Build 内命令 | Build Cell 进程本身完整继承 daemon 环境；credential blocklist 只生成嵌套 SandboxExecutor 的输入，SandboxExecutor 再只接收安全键（`js/orind/daemon.py:2637-2651`；`js/orind/cells/build.py:27-45,95-102`；`js/echo/os_sandbox.py:211-244`） | `cell` | C1 先把 Build Cell 进程改为 allowlist；C4 证明嵌套命令无网/凭证/生产写；保留 WP7 帧 |
| 可选 L2 Keychain smoke | `run_optional_l2_keychain_smoke` 只有定义/导出，仓库内未发现调用点；默认 runner 继承调用者环境，find 不使用 `-w`，且不是 SecretStore backend（`js/orind/cells/services.py:940-1001`） | `disabled-in-enforce` | 保持 opt-in smoke/untested；不得当作生产 Cell effect、受控取出或 Enclave 证明，不拆 `services.py` |
| lease-HMAC KeyBox `security` helper | daemon、Services、File 都实例化 KeyBox；只有 Darwin `tier=production` 才以 `security ... -w` 读写，默认 dev 不调用。File 接收 daemon 的 active tier，Services 当前默认 dev（`js/orind/keybox.py:123-176,201-211,245-270`；`js/orind/daemon.py:257,2682-2709`；`js/orind/cells/services.py:1037-1049`；`js/orind/cells/file.py:1087-1097`） | `cell` | 它不是 L2 Secret；C1 逐进程收紧 env、pin helper，并验证 tier 一致性与失败关闭，B KeyBox 语义不变 |
| Echo shell/code raw fallback | SandboxExecutor 在 Echo 域起进程 | `disabled-in-enforce` | enforce 只允许 Build Cell；Cell 失联不回退 |
| Desktop helpers | Echo 直启 `screencapture`/`cliclick`/`osascript`/`open`/`brew` | `disabled-in-enforce` | C2 Desktop Cell |
| File regex multiprocessing | 子进程继承环境和文件读 authority | `disabled-in-enforce` | C4 confinement 后方可重新评为 readonly |
| Web CLI daemon / AppShell host | `Popen`/uvicorn 当前继承宿主环境，Personal/Work/Echo 同进程 | `disabled-in-enforce` | C1 冻结 launcher、角色和 env allowlist |
| WebBridge loopback HTTP | token 0600，但 Echo 进程可读取并调用 | `disabled-in-enforce` | 文件模式不能代替进程隔离；C2/C4 后重审 |

### 5.5 DesktopTargetHandle 与 Memory 冻结

- **Desktop**：C0 登记的默认生产 observe/action/native helper 出口仍为 ambient 且在 enforce 分类中保持禁用。C2 显式 harness 已让 Desktop Cell 在可信 observe 后封印 `DesktopTargetHandle`，并补主人签发的 `ApplicationHandle`、原生 window/control bundle 硬拒、无 Controller 观察回退、digest upsert 对账、以及 HMAC `receipt.signed.v1` 验签。`desktop.action` 仍不可幂等，完整 consume 继续双控；全局 CGEvent 验证后竞态、真实模型 E2E 与正式打包 TCC 仍 **blocked**。C2 未完成，默认产品路由不变。
- **Memory**：C3 显式 harness 已有 `cell.memory` 读写隔离、AppShell session 全等、`ORIN_CELL_PRIVATE_STATE`、commit taint 复验与 SECRET 不洗白证据；生产 `js.memory.store` / `/api/memory*` / cron dream 仍 ambient。Memory 未整迁，C0 登记的主进程出口分类不变。
- `js/orin/receipts.py` 仍只承载 orind `DecisionReceipt`；`js/orin/draft.py` 现有 `receipt.signed.v1` / `SignedEffectReceiptV1` 用于 C2/C3 Cell 收据并由 orind 验签，禁止把 DecisionReceipt 冒充 Cell 收据。这不是 C-I09 Cell 独立软件签名身份。生产 enforce 收据链仍未接入。

---

## 6. C5 必须先红的“未登记 handler 默认拒绝”清单

C0 不向主测试套加入故意失败的 pytest。以下只登记为 C5 施工时必须先红、实现后转绿的用例：

1. `orin.enforce=true` 时，运行期注册一个没有封印 Effect Manifest/Cell 映射的文件写、网络、凭证或 subprocess handler；dispatch 必须拒绝且 handler 调用计数为 0。
2. inventory 冻结后动态注入、热加载、别名、改名或“同 callable 换工具名”，不得继承旧登记；digest 漂移必须 fail-fast 或 quarantine。
3. 直接绕过 Registry 调 raw handler，或从 Echo 调 `open(write)`、`socket.connect`、provider client、WebBridge token、`subprocess/exec`，都不能产生生产副作用。
4. 未知 tool/effect/cell cap、未协商 cap、manifest/registry digest 不全等，一律拒绝；不能落到旧 HMAC/raw handler。
5. 对应 Cell 关闭、崩溃或 orind 失联时，只读/只草稿或拒绝；不得恢复 Echo ambient fallback。`orin.enforce=false` 的冷启动对照仍须精确保持 `652d035`。
6. Personal 与 Work 任一 runtime 漏登记都拒绝；不能用另一 profile 的 inventory、task、Intent 或 handler 登记补齐。
7. 动态 plugin/MCP/skill、HTTP/admin 可达但模型不可见的副作用 handler 同样受 inventory 约束；自报 `read_only`、描述文本或 `system_scope` 不改变机器判定。
8. Desktop/Memory 在 C2/C3 完成前，mutation/read handler 必须显式禁用且调用计数为 0；不能悄悄使用 ambient FS/network/credential/native authority。
9. `consume(mode=cell)` 的 payload 同时含 `draft_id` 与 `cell`/正文/覆盖字段必须独立负测；当前实现有严格拒绝，但现有测试未找到专门节点，因此不得写成已测。

---

## 7. 阶段 B 基线确认

### 7.1 本轮只读回归

2026-08-24 在 `245c208` 文档 HEAD、`652d035` 运行时行为上运行现有测试选择集，结果：

```text
31 passed in 17.60s
```

选择集覆盖并继续以现有测试为准：

| B 不变量 | 已观察证据 |
|---|---|
| consume 3+1（B 冻结语义） | 本轮已测 `{draft_id}` 草案链、Connector/File raw payload 拒绝、`cell.net` R0 旁路和 WP7 独立原帧；`draft_id` 与 `cell`/正文混装在 `js/orin/protocol.py:904-923` 有源码拒绝，但独立专测 **untested**，已列入 C5 必红清单 |
| ExportPass 条件步：只用于外发；Personal 单次、Work 常设；fetch/file 不查询核销 | `test_personal_export_pass_is_single_use`、`test_work_export_pass_remains_valid_for_exact_binding`、`test_fetch_uses_strict_preflight_commit_without_export_pass`、File Cell no-export-pass 节点 |
| Personal `file.commit` `ExactCommitApprovalV1`；Work 仍预授权 | `tests/orin/test_orin_stageb_exact_approval.py::TestPersonalExactFileCommit`（整类） |
| WP7 Build 原帧 | `tests/orin/test_orin_stageb_wp10_integration.py::TestRollbackCompatibility::test_wp7_build_commit_frame_is_byte_for_byte_legacy_under_membrane` |
| UNKNOWN_COMMIT 仅在证明 absent 后回 PREPARED；COMMITTED 不回退 | `tests/orin/test_orin_stageb_wp10.py` 的 CommitStateGraph/CrashRestartMatrix；`test_orin_stageb_wp10_integration.py` 的两个 CrashRecovery 节点 |

本轮没有重跑全库，也没有新增“先红”测试。`git diff 652d035 -- js tests benchmarks` 在写文档前为空；文档完成后仍必须为空。

### 7.2 两条 auth 基线红

**已观察（历史基线，C0 未重跑）**：`benchmarks/orin/WP0_BASELINE.md:32-56` 记录全库 `2 failed, 6216 passed, 2 skipped, 113 deselected`，两条失败为：

1. `tests/test_net_guard.py::TestOriginCheck::test_no_origin_requires_api_key`；
2. `tests/web/test_auth_security.py::TestSessionCookieLogin::test_login_rejects_invalid_key`。

两条均是无 Origin 请求下，测试期望与当前 auth 检查顺序/有效 API key 语义不一致的既有基线。C0 不修、不改断言、不扩大失败集合，也不把它们算作阶段 C 验收通过。

---

## 8. C0 出口与阻断结论

| C0 门槛 | 状态 | 结论 |
|---|---|---|
| 人工评审与明确 C0 授权 | **已观察** | 已落档；C1 有独立 construction harness 证据，C2+ 仍禁止 |
| provider、Browser、Office、WebBridge、MCP、skills、cron/daemon/Fleet、`.js-code`、Desktop、Memory 全覆盖 | **已观察** | 已枚举并按四类人工分类 |
| 每项有未来 Cell 或 enforce 禁用裁决 | **已观察** | 见 §§3–5；未知默认禁用 |
| 未登记 handler 默认拒绝 | **拟议 / C5 必须测** | 已登记未来必红清单；C0 未制造红 pytest |
| AppShell/Echo 进程分离 | **显式 harness 已测 / 生产 blocked** | 真实 Echo 子进程边界只在 C1 harness 通过；默认产品仍同进程 |
| macOS 真实打包隔离 | **external-pending** | 现有 ad-hoc unsigned 包不构成生产证明 |
| Developer ID/notary 发布签名 | **external-pending** | 方案冻结，真实身份与产物未验证 |
| Desktop/Memory 整迁 | **blocked** | 分别留给 C2/C3；未完成前不得进入发布声明 |
| 阶段 B golden | **已观察** | 本轮选择集 31/31；两条 auth 红只登记 |

因此，WP-C0 的文档盘点与书面冻结已经形成证据，C1–C3 仅有显式 construction harness 检查点证据，C4–C7 只有局部 harness/书面标签，阶段 C 仍未实施。C2 与 Memory 整迁均未完成。当前不能宣称 Echo 进程失陷后的结构性收口，也不能进入 Stage C 上线声明。
