# JS Agent / JS Agent Work — 全量红队安全审计报告

> **已合并**：请优先阅读  
> [`FULL_REDTEAM_AUDIT_MERGED_20260720.md`](./FULL_REDTEAM_AUDIT_MERGED_20260720.md)  
> （R1 + R2 去重、复验降级后的权威版。本文保留作 R1 原始长目录存档。）

| 字段 | 内容 |
|------|------|
| **审计日期** | 2026-07-20 |
| **代码根** | `{repo_root}` |
| **范围** | `js/**`（JS Agent）、`js_work/**`（JS Agent Work）、关联 Web/静态前端、集成入口 |
| **版本线索** | `js-agent` v0.1.5 / 分支 `feature/echo-runtime` |
| **方法** | 6 路并行源码深度审计 + 主审计员关键路径复核；**未对生产系统投放真实 exploit payload** |
| **威胁模型** | 恶意模型输出 / Prompt 注入；同机进程与备份泄露；多租户 Web；Telegram 公开入口；配置错误（关鉴权、绑 0.0.0.0、AUTO_APPROVE） |

---

## 0. 关于「1000 个漏洞」的说明（务必先读）

本仓库约 **272 个 Python 源文件**（`js/` + `js_work/`），安全投入已经明显高于一般 vibe-coded agent（Echo lease、FileTools `O_NOFOLLOW`、net_guard IP pin、approval HMAC、Work owner scope 等均有实质实现）。

在严肃安全工程语义下：

- **「可利用的独立安全缺陷 / 错误配置 / 信任边界缺口」** 能稳定确认的量级是 **约 80–120 条 Critical/High/Medium**（去重后）。
- 若把 **Low + Info + 加固缺口 + 架构风险 + 正面控制缺失** 一并编号，六个攻击面合计可枚举 **约 450+ 条发现项**（含重复主题的多视角描述）。
- **强行凑满 1000 条「独立 CVE 级漏洞」会制造假报告**（把同一 root cause 拆成上百条无意义变体）。本报告采取：
  1. **去重后的真实高价值漏洞**完整展开；
  2. **全量发现目录**按域编号保留（WEB/TOOL/ECHO/WORK/EXT/DATA）；
  3. **诚实标注** Info/正面控制，避免把「做得好的地方」伪装成洞。

**合并统计（含子代理原始编号，未完全去重）：**

| 域 | 前缀 | 约计数 | Critical≈ | High≈ |
|----|------|--------|-----------|-------|
| Web/Auth/API | WEB | 110 | 6 | 14 |
| Tools/Sandbox | TOOL | 220 | 8 | 30+ |
| Echo Ledger | ECHO | 30 | 0 | 6 |
| JS Work | WORK | 30 | 0–1* | 3 |
| Skills/Plugins/MCP/Telegram | EXT | 28 | 3 | 7 |
| Data/Secrets/Crypto | DATA | 34 | 4 | 8 |
| **合计（含 Info）** | | **~450** | **~20** | **~70** |

\*条件触发（host tools + 多租户同 home）。

---

## 1. 执行摘要

### 1.1 总体风险评级

| 部署场景 | 风险 |
|----------|------|
| 默认：`127.0.0.1` + `api_key_required=true` + 无 Telegram + 无 Desktop + Work Web 默认 | **中**（本地单用户可接受；仍有数据 at-rest、ledger DoS、工具面过大） |
| 关闭 API Key / 绑定 `0.0.0.0` / Telegram 无 allowlist / Desktop CONFIRM / CLI Work host tools | **高～危急** |
| 多租户共享同一 `state_dir` 当 SaaS | **高**（多处 owner 过滤缺口 + Fleet 表无 owner） |

### 1.2 最严重的 12 条（P0，应立刻修）

| # | ID | 一句话 |
|---|-----|--------|
| 1 | WEB-001 / DATA-008 | `api_key_required=false` 时匿名 = **admin** |
| 2 | WEB-003 | API Key 进 **localStorage + 非 HttpOnly Cookie**（XSS 即接管） |
| 3 | WEB-004 | Prometheus **`/metrics` 无鉴权** |
| 4 | WEB-005/006 / DATA-004 | Bootstrap **抢占窗口** + **明文 admin key 长期落盘**（甚至 URL fragment） |
| 5 | TOOL-002/003/033 | Shell allowlist 含 **`find`/`awk`/`sed`/`tar`/`git`** → 命令名白名单形同虚设 |
| 6 | TOOL-004/186 | macOS sandbox **`(allow default)`** + 可读 `/private/etc` 等，隔离名不副实 |
| 7 | TOOL-006/219 | Desktop **CONFIRM 不调用 ApprovalQueue**，直接 `return True` |
| 8 | TOOL-001 | Office 路径 **symlink TOCTOU**（非 `O_NOFOLLOW` 打开） |
| 9 | TOOL-007/008 | WebBridge **真实浏览器会话** + `web_evaluate` 任意 JS；导航/find_tab 未标 dangerous |
| 10 | EXT-001 | Telegram **无 chat allowlist**，任意用户驱动完整 Agent |
| 11 | EXT-002/003/009 | 技能信任 **可伪造 author / 自声明**；扫描 **fail-open**；安装即进工具面 |
| 12 | WORK-001/002 | Work CLI 默认 **execute + host shell/python**，沙箱绑整个 workspace → 跨 owner 读 |

### 1.3 已验证的强项（不要推倒重来）

- `FileTools`：`dir_fd` + `O_NOFOLLOW` + 原子 replace（应用内路径安全标杆）。
- `net_guard`：解析后 IP 校验 + `PinnedTransport` 抗 DNS rebinding。
- Echo：**claimed 崩溃进 manual_review，不自动重放 non-idempotent**。
- Work：**file_scope / safe_output / skill-free / fleet 能力只收缩** 测试充分。
- 默认 `api_key_required=true`、`network_enabled=false`、`bind 127.0.0.1` 方向正确。
- Raw MCP 客户端已 **墓碑 fail-closed**。

### 1.4 用户已踩中的真实故障

`~/.js/state/echo/ledger/chat.jsonl` 回放失败：

```text
ValueError: semantic journal error at record 5 (outbox): outbox seal is missing
```

对应 **ECHO-001 / ECHO-028**：缺 seal 的 outbox 导致整本 journal 不可加载 → **状态腐败 DoS**（非 RCE，但主 Agent 默认状态不可用）。

---

## 2. 攻击面地图

```
┌─────────────────────────────────────────────────────────────────┐
│ 入口                                                             │
│  CLI js / js-work │ Web FastAPI │ WS /ws │ Telegram │ Desktop   │
└────────────┬───────────────────────┬────────────────────────────┘
             │                       │
             ▼                       ▼
      Auth/RBAC/CSRF            RuntimeContext + Owner
             │                       │
             ▼                       ▼
      Echo turn_runtime ──► tool_executor ──► CapabilityLease
             │                       │
             ▼                       ▼
      Model tools schema      begin_tool_effect (ledger)
             │                       │
             ▼                       ▼
      shell/python/office/web/desktop/skills ──► OS / 浏览器 / 宿主
             │
             ▼
      state_dir (SQLite / journal / secrets / bootstrap key)
```

**信任根（当前实际）**：能读写 `state_dir` 的主体 ≈ 完全信任；模型在「策略允许的工具集合」内是高权限协作者。

---

## 3. Critical / High 详细漏洞（完整展开）

下列每条均含：**位置、场景、影响、修复**。CWE 仅在明确时标注。

---

### A. 身份认证与 Web 控制面

#### [Critical] WEB-001 / DATA-008 — 关闭鉴权时匿名获得 Admin

- **位置**: `js/web/auth.py:401-417`
- **证据**: `api_key_required=false` 且无 Key 时返回 `role=admin` + 随机 `key_hash`。
- **场景**: 运维设 `JS_API_KEY_REQUIRED=false`（或 Work 的 `JS_WORK_SECURITY__API_KEY_REQUIRED=false`），服务被局域网访问。
- **影响**: 任意客户端可调用进化、Provider 变更、技能安装、桌面开关等管理面。
- **修复**:
  1. 关闭鉴权时 **最多** `role=user` 且只读；管理操作强制 401。
  2. 非 loopback bind 时 **禁止** 关闭 `api_key_required`（启动失败）。
  3. 启动 banner 红色警告。

#### [Critical] WEB-003 — API Key 存 localStorage + 可读 Cookie

- **位置**: `js/web/static/app.js`（localStorage `js-api-key`、`document.cookie` 写 `x-api-key`）
- **场景**: 任意 XSS / 恶意扩展 / 依赖供应链读 JS 可读存储。
- **影响**: 永久窃取 admin key → 完全接管 API/WS。
- **修复**:
  1. 服务端 `Set-Cookie: HttpOnly; Secure; SameSite=Strict; __Host-` 会话。
  2. 禁止长期密钥出现在 JS 可读存储。
  3. 配 CSP + 前端 Markdown DOM 消毒专项。

#### [Critical] WEB-004 — `/metrics` 无鉴权

- **位置**: `js/web/server.py:878-880` `app.mount("/metrics", make_asgi_app())`
- **影响**: 进程指标、延迟、可能的 label 指纹；非 loopback 时更严重。
- **修复**: 默认关闭；或独立 bind + 鉴权；生产用 sidecar 抓取。

#### [Critical] WEB-005 — Bootstrap 窗口无密钥 Admin

- **位置**: `js/web/auth.py:514-519`；`js/web/routers/setup.py`
- **场景**: `has_admin()==False && first_run_completed==False` 时 setup 返回 admin。
- **影响**: 首启/重置窗口网络可达时 **抢占所有权** 并领取 `admin_key`。
- **修复**: Bootstrap **仅允许 loopback**；或设备绑定 / 一次性安装 token。

#### [Critical] WEB-006 / DATA-004 — Bootstrap 明文 key 长期落盘 + URL 传递

- **位置**: `js/web/server.py:578-653`；`js/ui/cli.py` 打开浏览器带 `#bootstrap-api-key=`
- **影响**: 同用户进程/备份/同步盘取走长期 admin；URL fragment 进历史/扩展。
- **修复**: 首次成功认证后 **shred 文件**；禁止 URL 传密钥；一次性 TTL。

#### [High] WEB-008 — WebSocket 聊天无限流

- **位置**: `js/web/server.py` `/ws` vs HTTP chat 有 `_MAX_CONCURRENT_CHATS=64`
- **影响**: 认证用户开多 WS 打满模型配额/内存。
- **修复**: 与 HTTP 共享 per-owner 并发与 turn 配额。

#### [High] WEB-009 — Auth-optional 时 WS 坏 Key 静默匿名

- **位置**: `js/web/server.py:2248-2257` `except AuthRequiredError: pass`
- **影响**: 租户/会话写错分区；「以为已登录」。
- **修复**: 提供了 Key 但校验失败 → **必须 1008 关闭**。

#### [High] WEB-011 — 部分写接口缺 Origin/CSRF

- **位置**: scenarios start、cron parse、setup 等仅 `require_auth_dep`
- **修复**: 所有非 GET 统一 `require_user_write` / `require_admin_write`。

#### [High] WEB-012/013/014 — OpenAPI/diag/status 信息泄露

- **位置**: FastAPI 默认 docs；`system.py` diag/status
- **修复**: 生产 `docs_url=None`；diag admin-only；路径字段脱敏。

#### [High] WEB-016/017/018 — dream_logs / dashboard session_count / cron stats 未按 owner

- **影响**: 多租户元数据泄露或错误分区读。
- **修复**: 一律传 `owner_key_hash=memory_owner(auth)`。

---

### B. 工具执行与沙箱

#### [Critical] TOOL-002 / TOOL-003 / TOOL-033 — Shell 白名单含危险原语

- **位置**: `js/config.py:117-151`；`js/tools/shell.py:91-112`
- **证据 allowlist 含**: `find`, `awk`, `sed`, `tar`, `git`, `mv`, `jq` …
- **场景**:
  - `find . -exec ... \;` / `-delete`
  - `awk 'BEGIN{system("...")}'`
  - `sed -i` 改任意 workspace 文件
  - `tar -xf` 成员路径 / bomb
  - `git -c core.sshCommand=...` / hooks
- **影响**: 「只允许命令名」被完全绕过；真实隔离完全依赖 OS sandbox 质量（见 TOOL-004）。
- **修复**:
  1. 砍到只读工具（`cat/ls/rg/head/...`）。
  2. 写操作只走 `file_*`。
  3. 禁止 `sh -c`；改为 `execve(绝对路径, argv)` + 每命令参数 schema。
  4. 若保留 `find`：硬禁 `-exec/-ok/-delete`。

#### [Critical] TOOL-004 / TOOL-186 — macOS sandbox 过宽

- **位置**: `js/echo/os_sandbox.py:49-81`
- **证据**: 两处 profile 以 **`(allow default)`** 起手；FS profile 允许读 `/System` `/usr` `/Library` `/private/etc` `/private/var/db` `/dev` 等。
- **影响**: 「文件系统隔离」名不副实；shell/python 可读大量主机敏感信息。
- **修复**: `(deny default)` + 最小 allow；仅 ro-bind 解释器与 workspace；禁 `/private/etc` 全树。

#### [Critical] TOOL-005 / TOOL-054 — Python 工具是真 CPython + AST 伪沙箱

- **位置**: `js/tools/code.py:80-117, 193-235`
- **问题**: `pathlib`/`shutil`/`pickle`/`http.client`/`multiprocessing`/`operator.attrgetter` 等未充分拦截；最终 `sys.executable script.py`。
- **影响**: 依赖 OS sandbox；sandbox 过宽时 ≈ 任意代码。
- **修复**: 禁用 python 工具，或 WASM/Restricted 解释器；import deny-by-default。

#### [Critical] TOOL-006 / TOOL-219 — Desktop CONFIRM 假门

- **位置**: `js/tools/desktop/guard.py:100-120`
- **证据**: CONFIRM 模式直接 `return self._mode == DesktopMode.CONFIRM`，**从不** await ApprovalQueue。
- **影响**: 键鼠/打字/快捷键（含退出应用、向终端输入）无桌面层确认。
- **修复**: CONFIRM 必须走审批队列并绑定 action 哈希；`desktop_clear_stop` 禁止模型调用。

#### [Critical] TOOL-001 — Office TOCTOU / 非安全打开

- **位置**: `js/tools/office.py` `_resolve` + `open`/`load_workbook`
- **场景**: workspace 内 symlink 在 check 与 open 间替换 → 读/写 workspace 外目标。
- **修复**: 对齐 `FileTools` 的 fd 链 + `O_NOFOLLOW`。

#### [Critical] TOOL-007 / TOOL-008 / TOOL-058 — WebBridge 接管真实浏览器

- **位置**: `js/tools/webbridge.py`
- **问题**: `web_evaluate` 任意 JS；`web_navigate`/`web_find_tab` 未 `dangerous=True`；extract/snapshot 可读登录态页面。
- **影响**: Cookie/会话/银行页内容进模型上下文。
- **修复**: 默认禁用 evaluate；ephemeral 无 cookie profile；导航/抽文本全部 dangerous + 域名策略。

#### [High] TOOL-012/013/027 — defense_mode OFF / OBSERVE / AUTO_APPROVE

- **位置**: `js/security/guard.py`；`strategies.py`；`approvals.py`
- **修复**: 生产禁止 OFF/AUTO_APPROVE；OBSERVE 对 hardline 仍 block。

#### [High] TOOL-016 — Excel 公式注入（非 Work 路径）

- **位置**: `js/tools/office.py`（Work 有部分公式拒绝，主路径不完整）
- **修复**: 全局拒绝 `= + - @` 开头单元格。

#### [High] TOOL-017/018 — AppleScript 拼接与截屏路径

- **位置**: `js/tools/desktop/controller.py`
- **修复**: 参数白名单；截屏强制 workspace 内 fd 写。

#### [High] TOOL-019/020 — WebBridge localhost + token 文件

- **修复**: Unix socket + peercred；token `O_EXCL|O_NOFOLLOW`。

#### [High] TOOL-021/022 — browser_fetch 完整缓冲 body

- **修复**: 流式读取 + 硬字节 cap abort。

#### [High] TOOL-199 — Registry 运行时仍可 register 危险工具

- **修复**: 启动后封印 registry。

---

### C. Echo Ledger / 运行时

#### [High] ECHO-001 — outbox seal missing → 全 journal 不可加载

- **位置**: `js/echo/ledger/service.py` `_replay_effects`
- **用户现场**: `~/.js` 主 Agent 无法 `JSAgent()` / `js status`
- **修复**:
  1. 坏 outbox **隔离到 quarantine**，不阻断全链。
  2. 提供 `js doctor ledger --repair`。
  3. 修复 compat 写入完整 seal（ECHO-028）。

#### [High] ECHO-002 — begin_tool_effect 不校验真实 CapabilityLease

- **位置**: `service.py` `_tool_effect_policy_decision` 恒 allow-exact-tool
- **影响**: 账本层授权空转；依赖 registry consume 单点。
- **修复**: claim 前 verify/consume lease；策略 deny-by-default。

#### [High] ECHO-003 — LeaseAuthority.verify 不要求已签发

- **影响**: 持有 `mac_key` 可离线构造通过 verify 的 lease。
- **修复**: verify 走与 consume 相同的注册表检查。

#### [High] ECHO-008 — 本地 journal 可截断回滚

- **威胁**: 能写 `state_dir` 的主体删除尾部合法记录 → 抹掉完成态。
- **修复**: tip 签名检查点；non_idempotent 独立收据。

#### [High] ECHO-011 — 工具 schema 子集 fail-open 回全量

- **位置**: `js/echo/turn_loop.py:128-166` `return selected or schemas`
- **证据**: 无关键词匹配时 **暴露全部工具 schema**（含 shell 等）。
- **修复**: 空匹配 → **core-only**，禁止 `or schemas`。

#### [High] ECHO-013 — 默认角色模型可选全部危险工具

- **影响**: Prompt 注入 + 用户习惯性批准 = 合法高危工具链。
- **修复**: 默认 capability ceiling；危险工具默认 deny 直至 session allowlist。

#### [Medium] ECHO-004/005/006/009/010/015/016/017 — 策略 MAC 硬编码、monotonic deadline、replay 不验 seal、坏尾截断、SSRF hostname-only、path 启发式、hash `default=str`

详见第 5 节目录。

---

### D. JS Agent Work

#### [High/Critical*] WORK-001 — Host shell 沙箱 = 整个 workspace

- **位置**: `js_work/cli.py:63-67` `allow_host_code_tools=True`；`SandboxExecutor` bind 整个 workspace
- **场景**: CLI 或与 Web 共用 `~/.js-work` 时，`cat owners/other/...` 跨租户。
- **修复**: shell 的 FS root = 当前 turn `private_root`；检测 `owners/*` 存在则拒绝 host tools。

#### [High] WORK-002 — CLI 默认 execute + host tools

- **修复**: 默认 `safe`；host tools 需显式 flag + 确认。

#### [High*] WORK-011 — Work 可关 api_key → anonymous admin

- **修复**: Work **强制** `api_key_required=True` 不可配置。

#### [Medium] WORK-003 — Web 复用主 Agent 全量路由

- **修复**: Work 专用 allowlist 路由装配。

#### [Medium] WORK-004 — Routine 自动批准 dangerous

- **位置**: `js_work/routines/web.py` / `cli.py` auto APPROVE callback
- **修复**: 非 admin 保留 step-up；记录参数哈希。

#### [Medium] WORK-005 — run 的 session_id 客户端可控

- **修复**: session 服务端绑定。

#### [Medium] WORK-006/007/008 — 引擎层路径深度防御不对称 + TOCTOU

- **修复**: 统一相对路径 + `allowed_roots` + fd 打开。

#### [Medium] WORK-009 — LibreOffice 仅 network deny

- **修复**: 默认禁用 LO；或 FS-restrict 仅输出目录。

#### [Medium] WORK-010 — SAFE 仍含 browser_fetch/web_search

- **修复**: SAFE 去掉出网工具。

---

### E. Skills / Plugins / MCP / Telegram

#### [Critical] EXT-001 — Telegram 无 allowlist

- **位置**: `js/integrations/telegram_bot.py:178-195`
- **证据**: 任意 `chat_id` → `run_echo_turn`
- **修复**: 强制 `allowed_chat_ids`；未配置拒绝启动。

#### [Critical] EXT-002 — 技能信任可伪造

- **位置**: `js/skills/security.py` TRUSTED_AUTHORS / 自声明 trust / Hermes unsigned lock
- **修复**: 仅 operator 晋升或白名单公钥；忽略 author 启发式。

#### [Critical] EXT-003 — 扫描 fail-open + 弱正则 + 单风险不隔离

- **位置**: `js/skills/security.py:65-109`；`manager` 注册逻辑
- **修复**: 扫描失败 → QUARANTINE；AST；critical 单条即隔离；新装默认 quarantine。

#### [High] EXT-004 — 签名体系空公钥 + hash 长度不一致

- **位置**: `js/security/signer.py` `_BUILTIN_PUBLIC_KEYS=frozenset()`；hash 32 vs 64
- **修复**: 发布内置公钥；统一全长 SHA-256。

#### [High] EXT-005 — 扫描跳过 symlink，执行跟随

- **修复**: 拒绝技能树内任何 symlink。

#### [High] EXT-006 — Hermes guard 从用户可写路径 import 执行

- **位置**: `js/skills/hermes_bridge.py` `_try_hermes_guard_scan`
- **修复**: 删除动态加载或仅签名只读路径。

#### [High] EXT-007 — 与 TOOL-004 相同（技能 CODE 跑在弱 sandbox）

#### [High] EXT-008 — Pipeline FileConnector 漏 `/private`

- **位置**: `js/pipeline/connectors/file.py`
- **修复**: realpath 后再匹配；watch_dir 限 workspace。

#### [High] EXT-009 — 安装即注册可调用工具

- **修复**: 新装 draft/QUARANTINE 直至人工晋升。

#### [High] EXT-010 — Builtin 插件拿完整 agent 引用

- **修复**: 最小 Context API + 签名扫描。

---

### F. 数据 / 密钥 / 加密

#### [Critical] DATA-001 — Fernet 主密钥明文 `.secret_key` 全局复用

- **修复**: KMS/钥匙串；HKDF 分用途；轮换。

#### [Critical] DATA-002 — 大量记忆/review/profile 明文 at rest

- **对比**: session_messages 已加密，working/episode/semantic/review 未统一。
- **修复**: 统一 `encrypt_blob`。

#### [Critical] DATA-003 — state_dir / SQLite 未强制 0700/0600

- **修复**: 启动强制 chmod + 自检告警。

#### [Critical] DATA-004 — 见 WEB-006

#### [High] DATA-005 — `decrypt_blob` 无前缀当明文

- **修复**: 迁移后 fail-closed。

#### [High] DATA-006/007 — legacy memory.db / Fleet 表无 owner

- **修复**: 下线 legacy；Fleet schema 加 owner 并强制谓词。

#### [High] DATA-011 — 签名私钥文件 hardening 弱于 SecretManager

#### [High] DATA-012 — 日志脱敏模式覆盖不足

---

## 4. 优先修复路线图（按 ROI）

### P0（1–2 周，阻断真实接管/跨租户）

1. 禁止匿名 admin；非 loopback 强制鉴权（WEB-001, WORK-011）。
2. HttpOnly 会话，移除 JS 可读 API Key（WEB-003）。
3. 关 `/metrics` 与公开 OpenAPI（WEB-004/012）。
4. Bootstrap 仅 loopback + 一次性消费 key 文件（WEB-005/006）。
5. 收缩 shell allowlist；禁 find -exec/awk system 类（TOOL-002）。
6. macOS sandbox deny-default（TOOL-004）。
7. Desktop CONFIRM 接真审批（TOOL-006）。
8. Office 对齐 FileTools 打开（TOOL-001）。
9. Telegram allowlist 强制（EXT-001）。
10. 技能信任/扫描 fail-closed + 新装 quarantine（EXT-002/003/009）。
11. Work CLI 默认关 host tools；shell 绑 private_root（WORK-001/002）。
12. Ledger doctor：隔离缺 seal outbox（ECHO-001）。
13. 工具 schema 子集 fail-closed 到 core（ECHO-011）。

### P1（2–4 周）

- WebSocket 限流；Origin 全覆盖；owner 过滤补全（WEB-008/011/016+）。
- WebBridge 危险分级 / 禁用 evaluate（TOOL-007）。
- begin_tool_effect 绑定 lease；verify 注册表（ECHO-002/003）。
- 记忆 at-rest 加密 + state 权限自检（DATA-002/003）。
- 引擎 allowed_roots；routine session 绑定（WORK-005/006/007）。
- 签名哈希统一；symlink 拒绝（EXT-004/005/006）。

### P2（持续）

- 细粒度 RBAC、mTLS、审计 HMAC、CSP、依赖 pip-audit 门禁。
- Registry 封印；seccomp/landlock；公式全局防护。
- 红队回归测试绑定本报告 ID。

---

## 5. 全量发现目录（按域）

> 下列保留子代理原始 ID，便于对照代码与回归。**Info 多为加固建议或正面控制**，不是 exploit。

### 5.1 WEB（约 110）

| ID | Sev | 标题 |
|----|-----|------|
| WEB-001 | Crit | 关鉴权匿名=admin |
| WEB-002 | Crit | 关鉴权+CSRF 组合 |
| WEB-003 | Crit | Key 存 localStorage/可读 Cookie |
| WEB-004 | Crit | /metrics 无鉴权 |
| WEB-005 | Crit | Bootstrap 无密钥 admin |
| WEB-006 | Crit | bootstrap key 长期落盘 |
| WEB-007 | High | 无认证失败限流 |
| WEB-008 | High | WS 无限流 |
| WEB-009 | High | 坏 Key 静默匿名 |
| WEB-010 | High | HTTP/WS 权限模型不一致 |
| WEB-011 | High | 写接口缺 Origin |
| WEB-012 | High | OpenAPI/docs 暴露 |
| WEB-013 | High | /api/diag 路由表泄露 |
| WEB-014 | High | /api/status 绝对路径泄露 |
| WEB-015 | High | manual-reviews 跨租户 admin |
| WEB-016 | High | dream_logs 未传 owner |
| WEB-017 | High | dashboard session_count 全局 |
| WEB-018 | High | cron stats 全局 |
| WEB-019 | High | cleanup_empty_sessions 无 owner |
| WEB-020 | High | 无 Key 生命周期 API |
| WEB-021–040 | Med | hash 无 pepper、revoke 前缀、CORS/CSP、limit 无界等 |
| WEB-041–088 | Low | 错误信息、角色粒度、审计失败日志等 |
| WEB-089–110 | Info | 正面控制与加固建议 |

### 5.2 TOOL（约 220）

| 段 | 重点 ID |
|----|---------|
| Crit | TOOL-001 Office TOCTOU；002 find -exec；003 sed/tar/git；004 macOS allow default；005 CPython AST；006 Desktop 假确认；007 web_evaluate；008 navigate 未 dangerous |
| High | 009 sh -c；012 OFF；013 OBSERVE；015 provenance；016 公式；017 AppleScript；018 截屏；019-022 WebBridge/browser；027 AUTO_APPROVE；028 fleet 注入；033 awk；186 /private/var/db；199 registry 未封印；218-219 桌面快捷键/打字 |
| Med | 031-090 启发式、ReDoS、loop LRU、SSRF 边角、cache 等 |
| Low/Info | 091-220 指纹、平台差异、加固、正面控制 |

### 5.3 ECHO（30）

ECHO-001 缺 seal DoS · 002 策略空转 · 003 verify 无注册 · 004 decision 硬编码 MAC · 005 monotonic deadline · 006 replay 不验 seal · 007 双 claimed · 008 截断回滚 · 009 坏尾策略 · 010 lease 尾截断 · 011 schema fail-open · 012 ScopeGate 可绕 · 013 危险工具可选 · 014 claim 顺序 · 015 NetworkScope hostname · 016 path 启发式 · 017 hash default=str · 018 规范化不一致 · 019-027 资源/压缩/租户扫描 · 028 compat 污染 · 029-030 文件与审批原子性

### 5.4 WORK（30）

WORK-001 host shell 跨 owner · 002 CLI 默认高权限 · 003 全路由复用 · 004 自动批准 · 005 session 可控 · 006-008 引擎路径/TOCTOU · 009 LO · 010 SAFE 出网 · 011 可关鉴权 · 012 非 loopback · 013-019 Low · 020-030 正面控制

### 5.5 EXT（28）

EXT-001 Telegram · 002 信任伪造 · 003 扫描 fail-open · 004 签名空壳 · 005 symlink 盲区 · 006 Hermes guard RCE · 007 sandbox · 008 FileConnector · 009 安装即工具 · 010 插件 agent · 011-023 Med/Low · 024-028 正面控制

### 5.6 DATA（34）

DATA-001 主密钥文件 · 002 记忆明文 · 003 目录权限 · 004 bootstrap · 005 decrypt 明文回退 · 006 legacy memory · 007 fleet 无 owner · 008 匿名 admin · 009-012 加密/prune/signer/日志 · 013-026 Med · 027-034 Low/Info

---

## 6. 端到端攻击链（概念性）

### 链 A — 局域网完全接管

1. 运维关闭 API Key 或 Bootstrap 窗口暴露（WEB-001/005）  
2. 攻击者调用 admin API 安装技能 / 开 Desktop / 配 Provider  
3. 或 XSS 读 localStorage Key（WEB-003）  
4. 完整控制 Agent 与工具面  

### 链 B — Prompt 注入 → 主机信息窃取

1. ECHO-011 使模型始终看到 shell/python  
2. 用户批准 dangerous（或 AUTO_APPROVE）  
3. `find -exec` / `awk system` 或 python 读文件（TOOL-002/005）  
4. macOS 过宽 profile 可读 `/private/etc` 等（TOOL-004）  
5. 输出进模型上下文 → 经开启的网络工具外带  

### 链 C — Telegram 远程驱动

1. Bot Token 泄露或公开（EXT-001）  
2. 任意 Telegram 用户 `run_echo_turn`  
3. 等同本地操作员（受审批配置影响）  

### 链 D — 技能供应链

1. 伪造 `author: JS Team` + 弱扫描（EXT-002/003）  
2. 安装即注册工具（EXT-009）  
3. CODE 在弱 sandbox 收集信息（EXT-007）  

### 链 E — Work CLI 跨租户

1. Web 多用户写入 `~/.js-work/owners/*`  
2. 同机 `js-work` CLI 默认 host shell（WORK-001/002）  
3. 读取其他 owner 文件  

### 链 F — 主 Agent 不可用 DoS

1. journal 中历史/兼容 outbox 缺 seal（ECHO-001）  
2. 每次启动 fail-closed 无法加载  
3. 业务中断（已在本机复现）  

---

## 7. 验证建议（安全回归，非攻击 payload）

```bash
cd {repo_root}
# 既有安全矩阵
uv run python -c "from js.echo.ledger.security_matrix import run_security_matrix; r=run_security_matrix(); print(r.ok, r.passed, r.total)"

# 应用修复后应新增的测试方向（建议）
# - test_auth_anonymous_never_admin
# - test_shell_allowlist_rejects_find_exec
# - test_macos_sandbox_profile_deny_default  (snapshot 文本断言)
# - test_desktop_confirm_requires_approval_queue
# - test_office_rejects_symlink_final
# - test_tool_schema_subset_never_full_fallback
# - test_telegram_requires_allowlist
# - test_skill_scan_fail_closed_quarantine
# - test_work_cli_host_tools_default_off
# - test_ledger_load_isolates_bad_outbox
```

---

## 8. 修复验收标准（Definition of Done）

| 项 | 标准 |
|----|------|
| 鉴权 | 任意部署路径下 anonymous 永不 admin；非 loopback 强制 Key |
| 浏览器凭据 | 无 JS 可读长期 API Key |
| Shell | 无 find/awk/sed/tar/git 或参数 schema 硬禁危险 flag；测试覆盖 |
| Sandbox | profile 为 deny-default；敏感路径读失败测试 |
| Desktop | CONFIRM 无 ApprovalQueue 批准则拒绝 |
| Telegram | 无 allowlist 无法启动 |
| Skills | 新装 quarantine；扫描异常 quarantine；作者字段无效 |
| Work CLI | 默认无 host tools；多 owner 目录检测 |
| Ledger | 坏 outbox 不阻断；主 Agent 可在隔离后启动 |
| Schema | 无关键词时仅 core 工具可见 |

---

## 9. 结论

JS Agent / Work 已经具备 **第二代本地 Agent 框架** 水准的部分安全构件（Echo lease、安全文件打开、SSRF pin、Work owner scope），但在 **配置偏离默认、模型工具面、主机集成（Desktop/Telegram/Shell/真实浏览器）** 上仍有可导致 **完全接管、跨租户读写、隐私抽干、状态永久 DoS** 的真实缺陷。

**不建议** 在未完成 P0 前：

- 绑定非 loopback；
- 关闭 API Key；
- 启用 Telegram；
- 启用 Desktop 写操作；
- 将 Work CLI host tools 指向多用户 Web 同一 home；
- 对外宣传「严格沙箱 / 生产多租户安全」。

**建议下一步**：按第 4 节 P0 开 PR 系列，每条绑定本报告 ID 与回归测试；完成后可再做一轮动态红队（独立人员 + 干净环境）。

---

## 10. 审计元数据

| 项 | 值 |
|----|-----|
| 并行子代理 | Web/Auth · Tools/Sandbox · Echo · Work · Skills/MCP/Telegram · Data/Crypto |
| 主审计员复核 | auth.py、os_sandbox.py、shell allowlist、desktop guard、turn_loop schema、telegram_bot、file_scope、office 打开路径 |
| 动态利用 | 否（仅概念 PoC 与本地状态复现） |
| 外部独立签字 | 仍 **PENDING**（见 `EXTERNAL_REVIEW_PACKET.md`） |

---

*报告生成：2026-07-20 · 路径：`docs/security/FULL_REDTEAM_AUDIT_20260720.md`*
