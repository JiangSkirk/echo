# JS Agent / Work — 第二轮漏洞挖掘报告（R2）

> **已合并**：请优先阅读  
> [`FULL_REDTEAM_AUDIT_MERGED_20260720.md`](./FULL_REDTEAM_AUDIT_MERGED_20260720.md)  
> （R1 + R2 去重、复验降级后的权威版。本文保留作 R2 分轮记录。）

| 字段 | 内容 |
|------|------|
| **日期** | 2026-07-20 |
| **范围** | 第一轮未深挖：审批并发、session、cron/fleet、前端 XSS、owner 三桶、CORS/Cookie |
| **方法** | 2 路源码子代理 + 主审计员**运行/逻辑复验**；对第一轮已确认项不重复展开 |
| **原则** | 只收录本轮有证据的发现；夸大项降级或删除 |

---

## 0. 与第一轮的关系

| 第一轮已确认（本轮不复述细节） | 本轮新/深挖 |
|------------------------------|------------|
| 关鉴权匿名 admin、localStorage Key、metrics | 前端 **onclick+escapeHtml 实体解码 XSS** |
| shell allowlist find/awk、macOS sandbox | **owner 三桶分裂** 与 API 接线错误 |
| ledger seal missing、Telegram 无 allowlist | **审批 decide 无 owner 可跨租户拒批** |
| 技能 author 可 TRUSTED、Work CLI host tools | **Fleet worker 继承父 turn 能力** |
| | **Cron MANUAL 默认 deny shell，AUTO_APPROVE 则无人值守** |
| | **CORS 无端口 localhost + credentials** |

---

## 1. 本轮核验结论总表

| ID | 标题 | 严重度 | 核验 |
|----|------|--------|------|
| **R2-XSS-01** | `onclick` + `escapeHtml` 实体解码断串 XSS | **High** | **确认**（实体解码 + ModelConfig 接受恶意 id） |
| **R2-XSS-02** | `showError` / wizard 错误原文进 innerHTML | **Medium** | **确认**（代码） |
| **R2-XSS-03** | CSP `unsafe-inline` 削弱纵深 | **Medium** | **确认** |
| **R2-OWN-01** | `memory_owner` / `runtime_owner` / `__legacy_local__` 三桶 | **High** | **确认** |
| **R2-OWN-02** | `get_dream_logs` API 漏传 owner | **High** | **确认**（读固定 legacy） |
| **R2-APR-01** | `decide` 无 owner 时可 resolve 他人 pending | **Medium** | **确认**（无 owner reject 成功；带错 owner 则 pending） |
| **R2-APR-02** | Telegram/Fleet channel → `unknown` → 危险工具默认 deny | **Info（正向）** | **确认** |
| **R2-CRON-01** | Cron shell 在 MANUAL 下 deny；`AUTO_APPROVE` 则无人值守执行 | **High（有条件）** | **确认** |
| **R2-CRON-02** | `/api/cron/stats` 全局聚合 | **High（多租户）** | **确认** |
| **R2-FLEET-01** | Chat 路径 `fleet_collaborate` worker 继承父 capabilities | **High** | **确认**（源码） |
| **R2-SESS-01** | WS/HTTP `session_id` 客户端可控（同 owner 污染） | **Medium** | **确认** |
| **R2-CORS-01** | CORS 无端口 `http://localhost` + credentials | **High（同机）** | **确认** |
| **R2-SCH-01** | 空 query 工具 schema 全量；非空 core 含 shell/python | **High（设计面）** | **确认**（修正子代理“短句回全量”） |
| ~~R2 子代理“短提示词 fail-open 全量”~~ | 短句含 shell 即“全量” | — | **否定**：短句是 **core** 不是全量 |

---

## 2. 详细发现（经核验）

### R2-XSS-01 — [High] 内联 `onclick`/`onchange` + `escapeHtml` 不防 JS 断串

**位置**

- `js/web/static/app.js`：`wizardSelectModel('${escapeHtml(m.id)}')` 等  
- 同类：`tabs/tasks.js`、`tabs/scenarios.js` 等  

**机理（已仿真）**

```text
payload id = ');alert(1);//
escapeHtml → &#039;);alert(1);//
属性解码后 → wizardSelectModel('');alert(1);//')
```

HTML 属性会先解码实体，再进入 JS 解析 → **单引号断串成立**。

**附加证据**

```python
ModelConfig(id="');alert(1);//", ...)  # 接受，无字符集约束
```

恶意/被劫持的 OpenAI 兼容端点返回带引号的 model id → 管理员在向导里点选即可 XSS → 读 `localStorage`/`document.cookie` 中的 API Key（第一轮 WEB-003）。

**修复**

1. 禁止字符串拼 `onclick`；改 `addEventListener` + `data-*`（可参考 `approvals.js`）  
2. 服务端强制 `model.id` ∈ `[A-Za-z0-9_./:-]{1,128}`  

---

### R2-XSS-02 — [Medium] 错误信息未转义写入 DOM

**位置**

- `js/web/static/utils/dom.js`：`showError` / `showLoading` 直接拼 `text`  
- `js/web/static/tabs/status.js:120-126`：`errMsg` / `e.message` 进 `innerHTML`  

**场景**：后端 `detail` 或异常文本若可被污染，形成反射/存储 XSS 辅助链。

**修复**：helper 内强制 `escapeHtml` 或 `textContent`。

---

### R2-XSS-03 — [Medium] CSP 含 `script-src 'unsafe-inline'`

**位置**：`js/web/templates/index.html` CSP meta  

**影响**：不拦截 inline handler / 注入脚本，削弱 R2-XSS-01 的纵深。

**修复**：nonce/hash，去掉 `unsafe-inline`；收紧 `connect-src`。

**正面**：`renderMarkdown` 先 `escapeHtml` 再加标签，经典 `<script>` 注入对 markdown 路径 **安全**（本轮复验）。

---

### R2-OWN-01 — [High] Owner 身份三桶分裂

| 路径 | 映射 |
|------|------|
| `memory_owner(anonymous)` | `None` |
| `runtime_owner` | `None` → **`local-user`** |
| `_session_owner(None)` | **`__legacy_local__`** |

**位置**：`js/web/auth.py`、`js/memory/enhanced_store.py`、`js/memory/profile_scope.py`（多本地身份共享 profile 目录）

**影响**

- Chat **写入**用 `runtime_owner` → `local-user`  
- Session 列表/部分读用 `memory_owner` → `None` → `__legacy_local__`  
- 关鉴权/匿名下：UI 列表、删除、capsule 与真实聊天数据可能 **不在同一桶**  
- 安全测试“库层隔离绿”，**Web 接线仍可能读写错误分区**

**修复**：全站单一 canonical local owner（建议 `local-user`）+ 数据迁移。

---

### R2-OWN-02 — [High] `/api/memory/enhanced` 梦境漏传 owner

**位置**：`js/web/routers/memory.py`  

```python
"dream_logs": agent.memory.get_dream_logs(limit=10),  # 无 owner_key_hash
```

底层：`owner_key_hash=None` → `_session_owner` → **`__legacy_local__`**。

**影响**：任意能调该 admin 接口的主体读到 **legacy 梦境池**，不是自己的 `key_hash`；本应隔离的梦境在 UI 不可见。

**修复**：`get_dream_logs(limit=10, owner_key_hash=owner)`。

---

### R2-APR-01 — [Medium] `decide` 在 `owner_key_hash is None` 时跳过 owner 校验

**位置**：`js/security/approvals.py:847-851`；cancel/timeout 路径 `tool_executor.py` 调 `decide` **不传 owner**

**实测**

```text
decide(request_id, REJECT, reason=turn_cancelled)  # 无 owner
→ 成功 reject 他人 pending

decide(..., owner_key_hash='ownerB') 对 ownerA 的请求
→ PENDING（正确拒绝跨 owner 批准）
```

**影响**：当前主要是 **跨租户拒批 DoS**（cancel 路径）；若未来有无 owner 的 approve 调用则升级。

**修复**：`decide`/`take_decision` **强制**非空 owner；cancel/timeout 传入正确 owner。

---

### R2-APR-02 — [Info·正向] Telegram / Fleet 危险工具默认拒

```text
channel telegram     → approval context "unknown" → MANUAL 下 no_handler deny
channel fleet_worker → "unknown" → deny
channel cron_shell   → "cron" → MANUAL 下 no_handler deny
channel web ws_*     → "web" → queue pending
```

**说明**：Telegram 仍可对话与使用 **非 dangerous** 工具；第一轮“无 allowlist 任意用户驱动 Agent”仍成立，但 **shell 级默认被拒**（除非 AUTO_APPROVE）。

---

### R2-CRON-01 — [High·有条件] Cron shell 与 AUTO_APPROVE

**位置**：`js/daemon/core.py` `_cb_shell`；`approvals.py` AUTO_APPROVE 短路在 CRON_DENY 之前

**实测**：`context=cron` + `MANUAL` → **reject no_handler**  
`AUTO_APPROVE` → 直接 **approve**

**影响**：默认配置下定时 shell 难跑通（功能/安全双刃）；一旦运维切 `auto_approve`，admin 创建的 shell 任务变为 **无人值守命令执行**（再叠加第一轮 allowlist 语义）。

**修复**：对 `context in {cron, unknown}` 的 dangerous 工具 **硬 deny**，与全局 AUTO_APPROVE 解耦；或默认 `CRON_DENY`。

---

### R2-CRON-02 — [High·多租户] Cron stats 无 owner 过滤

**位置**：`js/web/routers/cron.py` `get_stats()` 全库 COUNT；jobs 列表才按 owner

**影响**：已认证用户可见全局任务量/成功率等元数据。

**修复**：`get_stats(owner_key_hash=...)`。

---

### R2-FLEET-01 — [High] Chat `fleet_collaborate` 继承父 turn 工具集

**位置**：`js/orchestration/fleet.py`

```python
capabilities = frozenset(parent.capabilities) - {"fleet_collaborate"}
```

父 turn 的 capabilities 来自当轮 `allowed_tools`（含 core 的 shell/python）。  
对比：HTTP `/api/fleet/collaborate` 仅授 `fleet_collaborate`，worker 天花板更小。

**影响**：Chat 入口一次协作 → **N 个 worker 继承主会话工具面**；与 HTTP 入口语义分裂。MANUAL 下 worker 危险工具因 channel=unknown 仍 deny，但 **只读/搜索/browser 等非 dangerous 可并行放大**。

**修复**：Chat 路径 worker **强制最小只读信封**；或 fleet 工具 control-plane only。

---

### R2-SESS-01 — [Medium] `session_id` 客户端可控

**位置**：`js/web/server.py` WS `data.get("session_id")`；upload 亦然

**影响**：同 `owner_key_hash` 内可固定/污染会话历史、预种 upload 分区（非跨租户 fixation）。

**修复**：服务端签发 session；客户端只能 resume 已登记 id。

---

### R2-CORS-01 — [High·同机] 无端口 CORS + credentials + 可读 Cookie

**位置**：`server.py` 插入 `http://localhost` / `http://127.0.0.1`（无端口）；`allow_credentials=True`  
Cookie：`app.js` 写 `x-api-key` **非 HttpOnly**，host 级跨端口共享

**影响**：本机 `localhost:80` 恶意页 + credentialed GET 可读管理接口；与 XSS 叠加更危险。状态变更仍有 Origin 检查，但 **只读管理面** 可被掏。

**修复**：删无端口 origin；HttpOnly 会话 Cookie；敏感 GET 强制自定义头。

---

### R2-SCH-01 — [High] 工具 schema：空输入全量；core 常驻 shell/python

**实测**（本轮）

| 用户输入 | 结果 |
|----------|------|
| `""` | **全量**（含 fleet/excel/web/skill） |
| `"你好"` / `"hello"` | **core only**（仍含 **shell、python、file_write**） |
| `"写excel报表"` | core + excel |
| `"打开网页 …"` | core + web |

**修正第一轮/子代理表述**：不是“短句总是全量 fail-open”，而是：

1. **空输入全量**（真）  
2. **几乎每轮都暴露 shell/python**（设计面，比“偶尔全量”更日常）

**修复**：空输入 → core-only；core 默认去掉 shell/python，或需显式意图词才加入。

---

## 3. 本轮否定 / 未证实

| 主张 | 结论 |
|------|------|
| 短提示词 schema fail-open 回**全量**危险工具 | **否定**（回 core；shell 在 core 里） |
| Markdown 渲染直接 XSS | **否定**（先 escape） |
| Lease 双花 | **未发现** |
| 默认 MANUAL 下 cron shell 自动执行 | **否定**（no_handler deny） |
| decide 无 owner 可 **approve** 跨租户 | **未测到**；仅确认可 **reject** |

---

## 4. 第二轮优先修复（P0）

1. **R2-XSS-01**：消灭 inline onclick 拼装 + model id 白名单  
2. **R2-OWN-01/02**：统一 owner + 修 dream_logs  
3. **R2-SCH-01**：core 去掉默认 shell/python；空 query 不全量  
4. **R2-CORS-01 + 第一轮 WEB-003**：HttpOnly 会话，CORS 收紧  
5. **R2-FLEET-01**：worker 最小能力信封  
6. **R2-CRON-01**：cron/unknown 危险工具硬 deny（无视 AUTO_APPROVE）  
7. **R2-APR-01**：decide 强制 owner  

---

## 5. 攻击链（本轮新）

### 链 R2-A — 模型 ID → XSS → 接管

1. 管理员添加恶意 OpenAI 兼容 Provider（或被劫持）  
2. Discover 返回 id=`');/*...`  
3. 向导 radio `onchange` 断串执行（R2-XSS-01）  
4. 窃取 localStorage/cookie API Key  

### 链 R2-B — 同机 CORS 读面

1. 用户浏览器曾登录 Agent（cookie 有 key）  
2. 访问本机恶意 `http://localhost/`  
3. Credentialed fetch 读 `/api/audit`、`/api/memory/enhanced` 等  

### 链 R2-C — 配置漂移无人值守

1. 审批改为 AUTO_APPROVE  
2. Admin 建 cron shell 或 chat+allow_tools  
3. 定时执行 shell（R2-CRON-01）+ 第一轮 allowlist 语义  

---

## 6. 文件索引

| 主题 | 文件 |
|------|------|
| XSS | `js/web/static/app.js`, `utils/dom.js`, `tabs/status.js`, `templates/index.html` |
| Owner | `js/web/auth.py`, `js/web/routers/memory.py`, `js/memory/enhanced_store.py` |
| 审批 | `js/security/approvals.py`, `js/agent/tool_executor.py` |
| Cron | `js/daemon/core.py`, `js/web/routers/cron.py` |
| Fleet | `js/orchestration/fleet.py` |
| Schema | `js/echo/turn_loop.py` |
| CORS | `js/web/server.py` |

---

## 7. 统计（本轮）

| 级别 | 数量（核验后） |
|------|----------------|
| High | 8（含有条件） |
| Medium | 4 |
| Info/正向 | 1 |
| 否定子代理夸大 | 1 条主要机制 |

**两轮合计有效高价值问题**仍远低于“1000 CVE”，但覆盖了身份接线、前端注入链、定时/协作放大等**第一轮未钉死**的层。

---

*报告路径：`docs/security/FULL_REDTEAM_AUDIT_R2_20260720.md`*
