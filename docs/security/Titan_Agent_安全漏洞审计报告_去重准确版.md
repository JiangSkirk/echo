# Titan Agent（JS Agent / JS Agent Work）安全漏洞审计报告

| 项目 | 内容 |
|------|------|
| **报告日期** | 2026-07-21 |
| **审计对象** | `/Users/jiangxuanzhen/titan-agent` |
| **产品** | JS Agent（`js/`）、JS Agent Work（`js_work/`）、Web UI、集成与编排 |
| **版本线索** | js-agent v0.1.5 / 分支 feature/echo-runtime |
| **统计口径** | **去重后真实安全问题（口径 C）** — 已去掉跨轮重复、同一事实多标签、测试清单与误报 |
| **方法** | 多轮源码审计 + 自动化枚举 + 运行/仿真复验 + **系统去重** |

---

## 一、执行摘要

本报告基于对 titan-agent 仓库的多轮安全审计，并在统计前完成**去重与复核**。

### 1.1 不重复漏洞数量（请以此为准）

| 级别 | 不重复数量 | 说明 |
|------|------------|------|
| **Critical（严重）** | **9** | 可导致权限接管、信任伪造、命令白名单失效、凭据泄露 |
| **High（高危）** | **279** | 高危面；其中部分为同类问题多点位，部分静态命中需结合上下文 |
| **Medium（中危）** | **1809** | 条件利用、隔离缺口、前端 sink、解析面等 |
| **Low（低危）** | **522** | 硬化缺口、弱约束 |
| **Info（信息）** | **190** | 去重后仍保留的较弱信息项 |
| **合计（不重复安全问题）** | **2809** | |
| **Critical + High（优先修复）** | **288** | |

**对比说明（避免误解）：**

| 数字 | 含义 | 是否当作漏洞个数 |
|------|------|------------------|
| 7206 | 历史全量目录（含重复、测试清单、攻击面 inventory） | **否** |
| **2809** | 去重后安全问题 | **是（推荐）** |
| **288** | 去重后严重+高危 | **优先修复集合** |

### 1.2 总体风险判断

| 部署场景 | 风险 |
|----------|------|
| 默认：本机 loopback + 开启 API Key + 不用 Telegram/Desktop | **中** |
| 关闭 API Key / 绑定非本机 / AUTO_APPROVE / Telegram / Work CLI 开 shell | **高～危急** |
| 多用户共享同一 state 目录当 SaaS | **高** |

### 1.3 已复验的强项（非漏洞）

- `FileTools`：`O_NOFOLLOW` + dir_fd 安全打开  
- `net_guard`：解析 IP + 连接 pin，抗 DNS rebinding  
- Echo：崩溃后 claimed 副作用默认不自动重放  
- Work Web：默认关闭 host shell/python  
- 默认 `api_key_required=true`  
- Markdown 渲染先 escape，经典 HTML 注入不成立  
- 默认 MANUAL 审批下，cron/telegram 的 **dangerous** 工具会被拒绝（除非 AUTO_APPROVE）  

---

## 二、去重方法（保证数量准确）

1. **删除清单类**：安全测试用例登记、路由/依赖/函数 inventory、纯文档项  
2. **语义合并**：同一事实被登记多次只保留一条（如 API Key 存 localStorage 曾出现 3 条标签）  
3. **跨轮合并**：同一位置多轮扫描只保留最高严重度，优先 runtime 核验  
4. **不同问题同位置分开**：例如 `shell.py:91` 的 `find -exec` 与 `awk system()` 计为 **2** 条 Critical  
5. **误报降级**：检测名单字符串、测试代码、非解压的 extract 命名等不计入有效漏洞  

---

## 三、Critical 漏洞详表（全部 9 条，均已核验）

每个 Critical 均给出：**编号 / 标题 / 位置 / 核验 / 问题说明 / 影响 / 修复建议**。

### C-01 — macOS 沙箱 profile 以 (allow default) 起手

| 项 | 内容 |
|----|------|
| **位置** | `js/echo/os_sandbox.py:51` |
| **严重度** | Critical |
| **核验** | 静态确认 |
| **问题** | 文件系统隔离名不副实，允许面过大（含大量系统读路径规则）。 |
| **影响** | 被隔离的 shell/python 仍可能读取过多主机信息，削弱沙箱价值。 |
| **修复** | 改为 deny-default；仅 bind 解释器与 workspace；禁止宽读 /private/etc、/Library 等。 |

### C-02 — Telegram Bot 无 chat/user allowlist

| 项 | 内容 |
|----|------|
| **位置** | `js/integrations/telegram_bot.py:178` |
| **严重度** | Critical |
| **核验** | 静态确认 |
| **问题** | 任意 Telegram 用户向 Bot 发消息即进入 run_echo_turn。 |
| **影响** | 未授权远程驱动 Agent（dangerous 工具在默认 MANUAL 下多被拒，但对话与非 dangerous 工具仍可用）。 |
| **修复** | 强制配置 allowed_chat_ids；未配置则拒绝启动。 |

### C-03 — 技能信任可被伪造 author 提升为 TRUSTED

| 项 | 内容 |
|----|------|
| **位置** | `js/skills/security.py:165` |
| **严重度** | Critical |
| **核验** | 运行复现 |
| **问题** | author 属于 TRUSTED_AUTHORS 且 license 可信、无 risk flag 时直接 TRUSTED。 |
| **影响** | 恶意技能可伪装高信任，降低隔离/审批警觉并进入工具面。 |
| **修复** | 删除作者启发式；仅人工晋升或白名单公钥签名可升 TRUSTED。 |

### C-04 — Shell 白名单被 find -exec 绕过

| 项 | 内容 |
|----|------|
| **位置** | `js/tools/shell.py:91（allowlist 在 js/config.py）` |
| **严重度** | Critical |
| **核验** | 运行复现 |
| **问题** | allowlist 只校验可执行文件名 find；不校验 -exec 参数。实测可执行成功。 |
| **影响** | 在 OS 沙箱失效或过宽时等价任意命令执行面。 |
| **修复** | 移除 find，或硬禁 -exec/-ok/-delete；回归测试锁定。 |

### C-05 — Shell 白名单被 awk system() 绕过

| 项 | 内容 |
|----|------|
| **位置** | `js/tools/shell.py:91（allowlist 含 awk）` |
| **严重度** | Critical |
| **核验** | 运行复现 |
| **问题** | awk 在白名单内；BEGIN{system(...)} 可衍生执行。实测输出可回显。 |
| **影响** | 同 C-04，命令名白名单失效。 |
| **修复** | 移除 awk/sed 等可编程解释器，或参数 schema 白名单。 |

### C-06 — 关闭 API Key 时匿名请求获得 admin 角色

| 项 | 内容 |
|----|------|
| **位置** | `js/web/auth.py:374-417` |
| **严重度** | Critical |
| **核验** | 静态确认（条件：api_key_required=false） |
| **问题** | require_auth 在鉴权关闭且无 Key 时返回 role=admin。 |
| **影响** | 任何能访问 HTTP API 的客户端可调用管理面。 |
| **修复** | 关鉴权最多 guest/只读；非 loopback 禁止关鉴权。 |

### C-07 — Bootstrap 窗口无密钥即可获得 admin

| 项 | 内容 |
|----|------|
| **位置** | `js/web/auth.py:484-519（setup）` |
| **严重度** | Critical |
| **核验** | 静态确认（条件：无 admin 且未完成 first_run） |
| **问题** | require_setup_auth 在 bootstrap 条件满足时返回 admin。 |
| **影响** | 首启/重置窗口若网络可达可被抢占初始化。 |
| **修复** | Bootstrap 仅允许 loopback；或设备绑定/安装 token。 |

### C-08 — 浏览器将 API Key 存入 localStorage

| 项 | 内容 |
|----|------|
| **位置** | `js/web/static/app.js:59` |
| **严重度** | Critical |
| **核验** | 静态确认 |
| **问题** | saveApiKey 写入 localStorage['js-api-key']。 |
| **影响** | 任意 XSS 或恶意扩展可读长期 admin Key → 完全接管。 |
| **修复** | 改为服务端 HttpOnly Cookie 会话；禁止 JS 可读长期密钥。 |

### C-09 — 浏览器将 API Key 写入非 HttpOnly Cookie

| 项 | 内容 |
|----|------|
| **位置** | `js/web/static/app.js:63` |
| **严重度** | Critical |
| **核验** | 静态确认 |
| **问题** | document.cookie 设置 x-api-key，无 HttpOnly/Secure。 |
| **影响** | XSS 可读 Cookie；同机跨端口场景下风险上升。 |
| **修复** | 仅服务端 Set-Cookie: HttpOnly; Secure; SameSite=Strict。 |

---

## 四、High 漏洞分类说明（共 279 条）

High 已按主题归类。**置信度**用于避免把「静态命中」都当成已确认注入。

| 分类 | 约条数 | 置信度 | 说明 |
|------|--------|--------|------|
| 疑似 SQL f-string/拼接 | 111 | 中（需复核） | 需复核：多为 schema 迁移固定表名，不一定是注入 |
| Work 子进程 / soffice | 71 | 高 | Work 调用外部进程/soffice 面 |
| 敏感调用点（system/eval 名） | 19 | 中（需复核） | 需复核：可能是检测名单/包装调用，非直接 RCE |
| 命令行构造点 | 17 | 中（需复核） | 命令拼装点，需结合沙箱看是否可利用 |
| Shell 白名单残余危险命令 | 5 | 高 | 已确认白名单过宽（find/awk 已运行复现同类问题） |
| 压缩包处理 | 13 | 中（需复核） | 压缩包处理面 |
| 前端/XSS/凭据 | 9 | 高 | 前端凭据或 XSS 相关 |
| 工具 Schema / 能力面 | 2 | 高 | 运行复现：工具暴露面过大 |
| Fleet 隔离 | 2 | 高 | 多租户/能力继承问题 |
| Echo Ledger | 2 | 高 | 运行/已知：Echo ledger 可用性 |
| 租户/数据隔离 | 3 | 高 | 租户隔离/数据生命周期 |
| 危险配置模式 | 4 | 高 | 危险可配置模式 |
| 其他 High | 19 | 中 | 静态登记，建议结合上下文确认 |

### 4.1 高置信 High（应优先修，已运行或逻辑确认）

1. **工具 Schema**：空输入返回全量工具；core 常驻 `shell`/`python`（`js/echo/turn_loop.py`，运行复现）  
2. **Echo Ledger**：`outbox seal missing` 导致默认 `~/.js` 下 JSAgent 无法启动（本机复现）  
3. **Shell 白名单残余**：`sed`/`tar`/`git`/`mv`/`jq` 等仍在 allowlist（与 C-04/C-05 同类）  
4. **ModelConfig 接受恶意 id**，可进入前端 onclick XSS 链（运行确认）  
5. **前端**：未转义 innerHTML / Web Storage 与 Critical 凭据问题叠加  
6. **Fleet**：跨 owner 杀 idle worker、全局 update_agent_config 清池  
7. **Work soffice**：多处调用 LibreOffice，沙箱弱于主 shell 路径  
8. **危险模式**：`defense_mode=off/observe`、`auto_approve` 可配置  
9. **租户**：checkpoint 全局 prune、部分表无 owner  

### 4.2 需人工复核的 High（勿直接当 SQL 注入 CVE）

- 标记为「SQL f-string」的约 **111** 条：抽查可见多为 `PRAGMA table_info` / `ALTER TABLE` / 迁移 `INSERT...SELECT`，**表名来自固定常量集合，不是用户输入拼接**。  
  - **准确表述**：存在「动态 SQL 字符串构造」代码味，**默认不记为已确认 SQL 注入**，应改为参数化或白名单表名后降级。  
- 「敏感调用 system()/eval」约 **19** 条：部分命中的是 `platform.system()` 或沙箱包装代码，**不一定是 os.system**。  
  - 修复前应人工确认符号含义。  

### 4.3 High 完整索引（路径级）

完整 279 条见附件列表；按文件聚合 Top：

| 文件 | High 条数 |
|------|----------|
| `js/memory/enhanced_store.py` | 63 |
| `js_work/routines/formula_cache.py` | 50 |
| `js/evolution/quality_scorer.py` | 18 |
| `js/echo/ledger/archive_store.py` | 13 |
| `js/echo/os_sandbox.py` | 12 |
| `js_work/routines/packing_details.py` | 12 |
| `js_work/routines/spreadsheet.py` | 12 |
| `js/tools/desktop/controller.py` | 9 |
| `js/config.py` | 8 |
| `js/tools/desktop/controller_native.py` | 7 |
| `js/compression/feedback.py` | 4 |
| `js/evolution/learner.py` | 4 |
| `js/plugins/security.py` | 4 |
| `js/orchestration/fleet.py` | 3 |
| `js/skills/manager.py` | 3 |
| `js/skills/packager.py` | 3 |
| `js/tools/webbridge.py` | 3 |
| `js/web/static/app.js` | 3 |
| `js_work/documents.py` | 3 |
| `js_work/routines/precise_edit.py` | 3 |
| `js/cron/store.py` | 2 |
| `js/echo/ledger/service.py` | 2 |
| `js/echo/turn_loop.py` | 2 |
| `js/persistence/task_store.py` | 2 |
| `js/security/approvals.py` | 2 |

---

## 五、Medium 概况（共 1809 条）

Medium 数量大，多为**同类检查在多处代码点的命中**。按主题汇总：

| 主题 | 约条数 | 含义 |
|------|--------|------|
| 其他 Medium | 308 | 需按模块收敛修复，不宜逐条当独立 CVE |
| owner 可选/隔离相关 | 269 | 需按模块收敛修复，不宜逐条当独立 CVE |
| 内置技能/插件风险模式 | 204 | 需按模块收敛修复，不宜逐条当独立 CVE |
| 前端 DOM sink | 172 | 需按模块收敛修复，不宜逐条当独立 CVE |
| 公式/外部命令相关 | 165 | 需按模块收敛修复，不宜逐条当独立 CVE |
| 删除/清理数据 | 121 | 需按模块收敛修复，不宜逐条当独立 CVE |
| 敏感调用点 | 119 | 需按模块收敛修复，不宜逐条当独立 CVE |
| 路径编码/展开 | 106 | 需按模块收敛修复，不宜逐条当独立 CVE |
| 文档解析/宏 | 101 | 需按模块收敛修复，不宜逐条当独立 CVE |
| 命令行构造 | 90 | 需按模块收敛修复，不宜逐条当独立 CVE |
| 动态导入 | 63 | 需按模块收敛修复，不宜逐条当独立 CVE |
| 插件加载 | 59 | 需按模块收敛修复，不宜逐条当独立 CVE |
| ReDoS/正则 | 32 | 需按模块收敛修复，不宜逐条当独立 CVE |

**说明**：Medium 已去重到「不同代码位置」；其中大量是「owner 可选」「DOM sink」「内置资产模式」等**模式重复**，工程上应按模块批量修，而不是 1800 个独立项目。

---

## 六、Low / Info

- **Low：522** — 参数无上界、环境变量面、弱约束等  
- **Info：190** — 去重后仍保留的弱信息项（已排除测试清单主体）  

---

## 七、优先修复路线图（P0）

### P0-A 身份与凭据（对应 Critical C-06～C-09）

1. 禁止匿名 admin；非 loopback 强制 API Key  
2. Bootstrap 仅 loopback + 一次性密钥  
3. HttpOnly 会话 Cookie，移除 localStorage/可读 Cookie 中的 API Key  
4. 消灭 inline onclick 拼装；model id 字符白名单；错误信息 escapeHtml  

### P0-B 执行面（C-01、C-04、C-05 + Shell 残余）

5. Shell allowlist 收缩为只读；硬禁 find -exec / awk system；加回归测试  
6. macOS sandbox 改为 deny-default  
7. 工具 schema：空输入不要全量；core 默认去掉 shell/python  

### P0-C 入口与信任（C-02、C-03）

8. Telegram 强制 allowlist  
9. 技能信任去掉 author 启发式；扫描 fail-closed；新装 quarantine  

### P0-D 租户与稳定性

10. Owner 身份统一（local-user）；dream_logs 传 owner  
11. Fleet 池/配置 per-owner；禁止跨租户杀 worker  
12. Ledger doctor：隔离坏 outbox，修复主 Agent 无法启动  
13. Work CLI 默认关闭 host tools；soffice 默认关或加强隔离  
14. provider 持久化前走 net_guard；异常路径 redact API key  
15. `/metrics` 鉴权或关闭  

---

## 八、攻击链（准确表述）

1. **XSS → 读 localStorage/Cookie Key → 接管 API**（C-08/C-09 + 前端 sink）  
2. **关鉴权或 Bootstrap 窗口 → 匿名/无密钥 admin**（C-06/C-07）  
3. **模型调用 shell → find/awk 绕过白名单 → 依赖沙箱质量**（C-04/C-05 + C-01）  
4. **Telegram 无白名单 → 任意用户驱动对话与工具**（C-02）  
5. **伪造技能 author → TRUSTED → 工具面信任过高**（C-03）  
6. **Ledger 损坏 → 主 Agent 不可用（DoS）**  
7. **多租户打满 Fleet / 全局 prune → 挤兑其他用户**  

---

## 九、附录 A：全部 Critical + High 清单（去重后 288 条）

| # | 严重度 | 标题 | 位置 | 核验 |
|---|--------|------|------|------|
| 1 | Critical | macOS sandbox allow default | `js/echo/os_sandbox.py:51` | static |
| 2 | Critical | Telegram 无 chat allowlist | `js/integrations/telegram_bot.py:178` | static |
| 3 | Critical | 伪造 author=JS Team 得 TRUSTED（运行复现） | `js/skills/security.py:165` | runtime |
| 4 | Critical | find -exec 绕过 shell 命令白名单（运行复现） | `js/tools/shell.py:91` | runtime |
| 5 | Critical | awk system() 绕过白名单（运行复现） | `js/tools/shell.py:91` | runtime |
| 6 | Critical | require_auth 在关鉴权时返回 admin（已复验） | `js/web/auth.py:374` | runtime-code |
| 7 | Critical | require_setup_auth bootstrap 可 admin（已复验） | `js/web/auth.py:484` | static |
| 8 | Critical | API Key 存 localStorage | `js/web/static/app.js:59` | static |
| 9 | Critical | API Key 非 HttpOnly Cookie | `js/web/static/app.js:63` | static |
| 10 | High | execute(f"...") SQL | `js/compression/feedback.py:104` | static |
| 11 | High | execute(f"...") SQL | `js/compression/feedback.py:106` | static |
| 12 | High | execute(f"...") SQL | `js/compression/feedback.py:411` | static |
| 13 | High | execute(f"...") SQL | `js/compression/feedback.py:429` | static |
| 14 | High | 防御模式可配置为 off | `js/config.py:1` | enum |
| 15 | High | 防御模式可配置为 observe | `js/config.py:1` | enum |
| 16 | High | ModelConfig 接受恶意 id 用于 XSS 链 | `js/config.py:66` | runtime |
| 17 | High | Shell allowlist 条目 `git`: hook/sshCommand | `js/config.py:118` | static |
| 18 | High | Shell allowlist 条目 `jq`: 文件/环境访问 | `js/config.py:118` | static |
| 19 | High | Shell allowlist 条目 `mv`: 覆盖文件 | `js/config.py:118` | static |
| 20 | High | Shell allowlist 条目 `sed`: 可 -i 改写 | `js/config.py:118` | static |
| 21 | High | Shell allowlist 条目 `tar`: 可路径穿越/炸弹 | `js/config.py:118` | static |
| 22 | High | execute(f"...") SQL | `js/cron/store.py:97` | static |
| 23 | High | execute(f"...") SQL | `js/cron/store.py:122` | static |
| 24 | High | execute(f"...") SQL | `js/echo/ledger/archive_store.py:673` | static |
| 25 | High | execute(f"...") SQL | `js/echo/ledger/archive_store.py:724` | static |
| 26 | High | execute(f"...") SQL | `js/echo/ledger/archive_store.py:725` | static |
| 27 | High | execute(f"...") SQL | `js/echo/ledger/archive_store.py:733` | static |
| 28 | High | execute(f"...") SQL | `js/echo/ledger/archive_store.py:784` | static |
| 29 | High | execute(f"...") SQL | `js/echo/ledger/archive_store.py:1118` | static |
| 30 | High | f-string SQL | `js/echo/ledger/archive_store.py:1119` | static |
| 31 | High | execute(f"...") SQL | `js/echo/ledger/archive_store.py:1734` | static |
| 32 | High | execute(f"...") SQL | `js/echo/ledger/archive_store.py:1743` | static |
| 33 | High | execute(f"...") SQL | `js/echo/ledger/archive_store.py:1749` | static |
| 34 | High | execute(f"...") SQL | `js/echo/ledger/archive_store.py:1761` | static |
| 35 | High | execute(f"...") SQL | `js/echo/ledger/archive_store.py:1765` | static |
| 36 | High | execute(f"...") SQL | `js/echo/ledger/archive_store.py:1773` | static |
| 37 | High | outbox seal missing 导致 JSAgent 无法启动（本机复现） | `js/echo/ledger/service.py:2734` | runtime |
| 38 | High | Ledger fail-closed 错误可导致可用性 DoS: outbox effect does not match seal | `js/echo/ledger/service.py:2790` | runtime-known |
| 39 | High | 敏感调用: system() | `js/echo/os_sandbox.py:113` | static |
| 40 | High | 敏感调用: system() | `js/echo/os_sandbox.py:120` | static |
| 41 | High | 敏感调用: system() | `js/echo/os_sandbox.py:163` | static |
| 42 | High | 命令行构造点 | `js/echo/os_sandbox.py:179` | static |
| 43 | High | 命令行构造点 | `js/echo/os_sandbox.py:184` | static |
| 44 | High | 敏感调用: system() | `js/echo/os_sandbox.py:201` | static |
| 45 | High | 命令行构造点 | `js/echo/os_sandbox.py:265` | static |
| 46 | High | 命令行构造点 | `js/echo/os_sandbox.py:270` | static |
| 47 | High | 敏感调用: system() | `js/echo/os_sandbox.py:340` | static |
| 48 | High | 敏感调用: system() | `js/echo/os_sandbox.py:350` | static |
| 49 | High | 敏感调用: system() | `js/echo/os_sandbox.py:351` | static |
| 50 | High | eval/exec 使用点 | `js/echo/os_sandbox.py:387` | static |
| 51 | High | 非空短句 core 仍含 shell/python | `js/echo/turn_loop.py:44` | runtime |
| 52 | High | 空用户输入工具 schema 返回全量 | `js/echo/turn_loop.py:138` | runtime |
| 53 | High | execute(f"...") SQL | `js/evolution/learner.py:118` | static |
| 54 | High | execute(f"...") SQL | `js/evolution/learner.py:120` | static |
| 55 | High | execute(f"...") SQL | `js/evolution/learner.py:655` | static |
| 56 | High | execute(f"...") SQL | `js/evolution/learner.py:673` | static |
| 57 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:328` | static |
| 58 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:345` | static |
| 59 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:354` | static |
| 60 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:374` | static |
| 61 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:379` | static |
| 62 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:406` | static |
| 63 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:412` | static |
| 64 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:682` | static |
| 65 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:768` | static |
| 66 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:876` | static |
| 67 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:896` | static |
| 68 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:959` | static |
| 69 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:1038` | static |
| 70 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:1079` | static |
| 71 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:1155` | static |
| 72 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:1285` | static |
| 73 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:1299` | static |
| 74 | High | execute(f"...") SQL | `js/evolution/quality_scorer.py:1300` | static |
| 75 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:775` | static |
| 76 | High | f-string SQL | `js/memory/enhanced_store.py:776` | static |
| 77 | High | f-string SQL | `js/memory/enhanced_store.py:777` | static |
| 78 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:872` | static |
| 79 | High | f-string SQL | `js/memory/enhanced_store.py:873` | static |
| 80 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:1009` | static |
| 81 | High | f-string SQL | `js/memory/enhanced_store.py:1010` | static |
| 82 | High | f-string SQL | `js/memory/enhanced_store.py:1011` | static |
| 83 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:1042` | static |
| 84 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:1130` | static |
| 85 | High | f-string SQL | `js/memory/enhanced_store.py:1131` | static |
| 86 | High | f-string SQL | `js/memory/enhanced_store.py:1132` | static |
| 87 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:1256` | static |
| 88 | High | f-string SQL | `js/memory/enhanced_store.py:1257` | static |
| 89 | High | f-string SQL | `js/memory/enhanced_store.py:1258` | static |
| 90 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:1286` | static |
| 91 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:1304` | static |
| 92 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:1435` | static |
| 93 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:1578` | static |
| 94 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:1588` | static |
| 95 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:1607` | static |
| 96 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:1706` | static |
| 97 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:2315` | static |
| 98 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:2331` | static |
| 99 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:2356` | static |
| 100 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:2770` | static |
| 101 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:2824` | static |
| 102 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:2909` | static |
| 103 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:2930` | static |
| 104 | High | f-string SQL | `js/memory/enhanced_store.py:2931` | static |
| 105 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:2955` | static |
| 106 | High | f-string SQL | `js/memory/enhanced_store.py:2956` | static |
| 107 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3001` | static |
| 108 | High | f-string SQL | `js/memory/enhanced_store.py:3002` | static |
| 109 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3017` | static |
| 110 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3028` | static |
| 111 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3050` | static |
| 112 | High | f-string SQL | `js/memory/enhanced_store.py:3051` | static |
| 113 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3070` | static |
| 114 | High | f-string SQL | `js/memory/enhanced_store.py:3071` | static |
| 115 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3076` | static |
| 116 | High | f-string SQL | `js/memory/enhanced_store.py:3077` | static |
| 117 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3112` | static |
| 118 | High | f-string SQL | `js/memory/enhanced_store.py:3113` | static |
| 119 | High | f-string SQL | `js/memory/enhanced_store.py:3149` | static |
| 120 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3173` | static |
| 121 | High | f-string SQL | `js/memory/enhanced_store.py:3174` | static |
| 122 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3266` | static |
| 123 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3277` | static |
| 124 | High | f-string SQL | `js/memory/enhanced_store.py:3278` | static |
| 125 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3403` | static |
| 126 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3419` | static |
| 127 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3446` | static |
| 128 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3465` | static |
| 129 | High | f-string SQL | `js/memory/enhanced_store.py:3466` | static |
| 130 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3680` | static |
| 131 | High | f-string SQL | `js/memory/enhanced_store.py:3681` | static |
| 132 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3691` | static |
| 133 | High | f-string SQL | `js/memory/enhanced_store.py:3692` | static |
| 134 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3794` | static |
| 135 | High | f-string SQL | `js/memory/enhanced_store.py:3795` | static |
| 136 | High | execute(f"...") SQL | `js/memory/enhanced_store.py:3799` | static |
| 137 | High | f-string SQL | `js/memory/enhanced_store.py:3800` | static |
| 138 | High | query_param API key 经 stream/WS 异常 str(exc) 可泄漏 | `js/models/providers.py:154` | static |
| 139 | High | update_agent_config 全局改模型且 agents.clear 不 close | `js/orchestration/fleet.py:265` | static |
| 140 | High | Fleet 池满时优先关闭其他 owner 的 idle worker | `js/orchestration/fleet.py:993` | static |
| 141 | High | fleet worker 继承 parent.capabilities | `js/orchestration/fleet.py:1296` | static |
| 142 | High | StateStore.prune 全局裁剪无 per-owner | `js/persistence/state_store.py:257` | static |
| 143 | High | TaskStore/AgentStore 无 owner_key_hash | `js/persistence/task_store.py:55` | static |
| 144 | High | execute(f"...") SQL | `js/persistence/task_store.py:86` | static |
| 145 | High | 子进程/系统调用点 | `js/plugins/security.py:29` | static |
| 146 | High | eval/exec 使用点 | `js/plugins/security.py:92` | static |
| 147 | High | 子进程/系统调用点 | `js/plugins/security.py:129` | static |
| 148 | High | 子进程/系统调用点 | `js/plugins/security.py:138` | static |
| 149 | High | 审批模式可配置为 auto_approve（误配风险） | `js/security/approvals.py:35` | enum |
| 150 | High | AUTO_APPROVE 下危险工具自动通过（含 cron） | `js/security/approvals.py:594` | runtime |
| 151 | High | execute(f"...") SQL | `js/security/audit.py:244` | static |
| 152 | High | eval/exec 使用点 | `js/security/guard.py:375` | static |
| 153 | High | eval/exec 使用点 | `js/security/guard.py:376` | static |
| 154 | High | eval/exec 使用点 | `js/security/rules.py:183` | static |
| 155 | High | execute(f"...") SQL | `js/skills/evolver.py:358` | static |
| 156 | High | 压缩包解压点（路径穿越/炸弹） | `js/skills/manager.py:11` | static |
| 157 | High | 压缩包解压点（路径穿越/炸弹） | `js/skills/manager.py:865` | static |
| 158 | High | 压缩包解压点（路径穿越/炸弹） | `js/skills/manager.py:870` | static |
| 159 | High | 压缩包解压点（路径穿越/炸弹） | `js/skills/packager.py:14` | static |
| 160 | High | 压缩包解压点（路径穿越/炸弹） | `js/skills/packager.py:149` | static |
| 161 | High | 压缩包解压点（路径穿越/炸弹） | `js/skills/packager.py:154` | static |
| 162 | High | execute(f"...") SQL | `js/skills/promotion_store.py:480` | static |
| 163 | High | f-string SQL | `js/skills/promotion_store.py:481` | static |
| 164 | High | 技能安全策略行: Fail-open: if scan itself crashes, return community-level result. | `js/skills/security.py:68` | static |
| 165 | High | eval/exec 使用点 | `js/tools/code.py:221` | static |
| 166 | High | 命令行构造点 | `js/tools/desktop/controller.py:41` | static |
| 167 | High | 敏感调用: system() | `js/tools/desktop/controller.py:52` | static |
| 168 | High | 命令行构造点 | `js/tools/desktop/controller.py:158` | static |
| 169 | High | 命令行构造点 | `js/tools/desktop/controller.py:168` | static |
| 170 | High | 命令行构造点 | `js/tools/desktop/controller.py:190` | static |
| 171 | High | 命令行构造点 | `js/tools/desktop/controller.py:203` | static |
| 172 | High | 命令行构造点 | `js/tools/desktop/controller.py:214` | static |
| 173 | High | 命令行构造点 | `js/tools/desktop/controller.py:232` | static |
| 174 | High | f-string 拼入危险命令 | `js/tools/desktop/controller.py:232` | static |
| 175 | High | 命令行构造点 | `js/tools/desktop/controller_native.py:229` | static |
| 176 | High | 命令行构造点 | `js/tools/desktop/controller_native.py:462` | static |
| 177 | High | f-string 拼入危险命令 | `js/tools/desktop/controller_native.py:462` | static |
| 178 | High | 命令行构造点 | `js/tools/desktop/controller_native.py:568` | static |
| 179 | High | 命令行构造点 | `js/tools/desktop/controller_native.py:575` | static |
| 180 | High | 命令行构造点 | `js/tools/desktop/controller_native.py:590` | static |
| 181 | High | 命令行构造点 | `js/tools/desktop/controller_native.py:597` | static |
| 182 | High | 敏感调用: system() | `js/tools/desktop/permissions.py:24` | static |
| 183 | High | 敏感调用: system() | `js/tools/desktop/wizard.py:191` | static |
| 184 | High | 敏感调用: system() | `js/tools/desktop/wizard.py:196` | static |
| 185 | High | WebBridge 工具 web_navigate 未见 dangerous=True | `js/tools/webbridge.py:196` | static |
| 186 | High | WebBridge 工具 web_find_tab 未见 dangerous=True | `js/tools/webbridge.py:270` | static |
| 187 | High | eval/exec 使用点 | `js/tools/webbridge.py:434` | static |
| 188 | High | 敏感调用: system() | `js/ui/cli.py:635` | static |
| 189 | High | execute(f"...") SQL | `js/utils/db.py:98` | static |
| 190 | High | execute(f"...") SQL | `js/utils/db.py:147` | static |
| 191 | High | dream_logs API 漏传 owner | `js/web/routers/memory.py:120` | static |
| 192 | High | prometheus 已安装时 /metrics 无鉴权挂载 | `js/web/server.py:880` | runtime |
| 193 | High | escapeHtml+onclick 实体解码断串 XSS（仿真） | `js/web/static/app.js:241` | runtime-sim |
| 194 | High | DOM 写入 sink | `js/web/static/app.js:424` | static-xss |
| 195 | High | innerHTML 内联事件处理器（XSS 面） | `js/web/static/app.js:1128` | static-xss-pattern |
| 196 | High | innerHTML 内联事件处理器（XSS 面） | `js/web/static/tabs/evolution.js:247` | static-xss-pattern |
| 197 | High | DOM 写入 sink | `js/web/static/tabs/status.js:120` | static-xss |
| 198 | High | DOM 写入 sink | `js/web/static/tabs/status.js:126` | static-xss |
| 199 | High | DOM 写入 sink | `js/web/static/utils/dom.js:30` | static-xss |
| 200 | High | DOM 写入 sink | `js/web/static/utils/dom.js:35` | static-xss |
| 201 | High | host code tools 开关: allow_host_code_tools=True, | `js_work/cli.py:66` | static |
| 202 | High | Work CLI allow_host_code_tools=True | `js_work/cli.py:66` | static |
| 203 | High | 公式/外部命令相关: "/EmbeddedFiles", | `js_work/documents.py:37` | static |
| 204 | High | 公式/外部命令相关: r"\b(?:DATABASE/DDE/DDEAUTO/HYPERLINK/INCLUDEPICTURE/INCLUDETEXT/LINK)\b", | `js_work/documents.py:101` | static |
| 205 | High | 压缩包解压点（路径穿越/炸弹） | `js_work/documents.py:345` | static |
| 206 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:11` | static |
| 207 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:59` | static |
| 208 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:71` | static |
| 209 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:349` | static |
| 210 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:349` | static |
| 211 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:352` | static |
| 212 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:358` | static |
| 213 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:359` | static |
| 214 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:359` | static |
| 215 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:360` | static |
| 216 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:363` | static |
| 217 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:363` | static |
| 218 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:371` | static |
| 219 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:375` | static |
| 220 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:379` | static |
| 221 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:379` | static |
| 222 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:381` | static |
| 223 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:383` | static |
| 224 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:385` | static |
| 225 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:388` | static |
| 226 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:394` | static |
| 227 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:394` | static |
| 228 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:405` | static |
| 229 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:405` | static |
| 230 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:419` | static |
| 231 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:431` | static |
| 232 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:432` | static |
| 233 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:434` | static |
| 234 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:438` | static |
| 235 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:439` | static |
| 236 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:441` | static |
| 237 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:445` | static |
| 238 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:448` | static |
| 239 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:450` | static |
| 240 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:452` | static |
| 241 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:456` | static |
| 242 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:460` | static |
| 243 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:461` | static |
| 244 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:478` | static |
| 245 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:486` | static |
| 246 | High | 压缩包解压点（路径穿越/炸弹） | `js_work/routines/formula_cache.py:550` | static |
| 247 | High | 压缩包解压点（路径穿越/炸弹） | `js_work/routines/formula_cache.py:557` | static |
| 248 | High | 压缩包解压点（路径穿越/炸弹） | `js_work/routines/formula_cache.py:579` | static |
| 249 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:621` | static |
| 250 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:625` | static |
| 251 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:625` | static |
| 252 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:636` | static |
| 253 | High | LibreOffice/soffice 调用点 | `js_work/routines/formula_cache.py:639` | static |
| 254 | High | Work 子进程/soffice | `js_work/routines/formula_cache.py:639` | static |
| 255 | High | 压缩包解压点（路径穿越/炸弹） | `js_work/routines/formula_cache.py:652` | static |
| 256 | High | LibreOffice/soffice 调用点 | `js_work/routines/packing_details.py:634` | static |
| 257 | High | Work 子进程/soffice | `js_work/routines/packing_details.py:634` | static |
| 258 | High | LibreOffice/soffice 调用点 | `js_work/routines/packing_details.py:823` | static |
| 259 | High | Work 子进程/soffice | `js_work/routines/packing_details.py:823` | static |
| 260 | High | LibreOffice/soffice 调用点 | `js_work/routines/packing_details.py:824` | static |
| 261 | High | Work 子进程/soffice | `js_work/routines/packing_details.py:824` | static |
| 262 | High | LibreOffice/soffice 调用点 | `js_work/routines/packing_details.py:828` | static |
| 263 | High | Work 子进程/soffice | `js_work/routines/packing_details.py:828` | static |
| 264 | High | LibreOffice/soffice 调用点 | `js_work/routines/packing_details.py:829` | static |
| 265 | High | Work 子进程/soffice | `js_work/routines/packing_details.py:829` | static |
| 266 | High | LibreOffice/soffice 调用点 | `js_work/routines/packing_details.py:830` | static |
| 267 | High | Work 子进程/soffice | `js_work/routines/packing_details.py:830` | static |
| 268 | High | 公式/外部命令相关: r"\b(?:CALL/DDE/EXEC/FILTERXML/HYPERLINK/REGISTER(?:\.ID)?/RTD/SHELL/URLDOWNLOA | `js_work/routines/precise_edit.py:39` | static |
| 269 | High | 压缩包解压点（路径穿越/炸弹） | `js_work/routines/precise_edit.py:238` | static |
| 270 | High | 压缩包解压点（路径穿越/炸弹） | `js_work/routines/precise_edit.py:288` | static |
| 271 | High | LibreOffice/soffice 调用点 | `js_work/routines/spreadsheet.py:964` | static |
| 272 | High | Work 子进程/soffice | `js_work/routines/spreadsheet.py:964` | static |
| 273 | High | LibreOffice/soffice 调用点 | `js_work/routines/spreadsheet.py:967` | static |
| 274 | High | Work 子进程/soffice | `js_work/routines/spreadsheet.py:967` | static |
| 275 | High | LibreOffice/soffice 调用点 | `js_work/routines/spreadsheet.py:968` | static |
| 276 | High | Work 子进程/soffice | `js_work/routines/spreadsheet.py:968` | static |
| 277 | High | LibreOffice/soffice 调用点 | `js_work/routines/spreadsheet.py:972` | static |
| 278 | High | Work 子进程/soffice | `js_work/routines/spreadsheet.py:972` | static |
| 279 | High | LibreOffice/soffice 调用点 | `js_work/routines/spreadsheet.py:973` | static |
| 280 | High | Work 子进程/soffice | `js_work/routines/spreadsheet.py:973` | static |
| 281 | High | LibreOffice/soffice 调用点 | `js_work/routines/spreadsheet.py:974` | static |
| 282 | High | Work 子进程/soffice | `js_work/routines/spreadsheet.py:974` | static |
| 283 | High | 公式/外部命令相关: Recovery: staging names are hidden dotfiles; ``sweep_staging`` removes | `js_work/safe_output.py:22` | static |
| 284 | High | LibreOffice/soffice 调用点 | `js_work/safe_output.py:177` | static |
| 285 | High | 公式/外部命令相关: # Web-only, model-hidden provider controls remain registered so Work's own | `js_work/tools.py:56` | static |
| 286 | High | curl/sh 管道安装 | `scripts/install-plugin.sh:3` | static |
| 287 | High | curl/sh 管道安装 | `scripts/install.sh:6` | static |
| 288 | High | curl/sh 管道安装 | `scripts/install.sh:110` | static |

---

## 十、附录 B：文件与数据

| 文件 | 说明 |
|------|------|
| 本报告（桌面副本） | 面向阅读的准确详细版 |
| `titan-agent/docs/security/_unique_findings_C.json` | 去重后 2809 条完整数据 |
| `titan-agent/docs/security/UNIQUE_VULN_STATS.md` | 去重统计说明 |
| `titan-agent/docs/security/VULN_CATALOG_FULL.md` | 历史全量目录（含重复，仅供追溯） |

---

**报告结束。数量请以「不重复：Critical 9 + High 279 + Medium 1809 + Low 522 + Info 190 = 2809」为准。**
