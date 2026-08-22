# JS Agent 渗透测试报告（授权红队审计）

- 日期：2026-08-20
- 范围：`js/` 全量（web/API、Echo 运行时、工具沙箱、skill 生态、安全模块、记忆系统、MCP、cron/daemon）
- 方法：4 路并行静态审计 + 主循环代码复核 + 13 个真实执行的 PoC（全部走真实代码路径：ShellTool/SkillManager/AuditLogger/EnhancedMemoryStore）
- PoC 目录：`docs/security/redteam/`（本报告每个 CONFIRMED 结论均可重跑复现）
- 威胁模型：① 能触达 web 端口的远程攻击者；② 通过聊天/工具输出注入控制模型行为的攻击者（prompt injection）；③ 能向系统投递 skill 的攻击者；④ 同机低权限进程。

---

## 结论速览

系统的核心安全主张**大部分成立**：Echo 边界无绕过、lease 原子消费无 TOCTOU、ledger MAC 链完整、web 认证核心（哈希存储、Origin 校验、owner 隔离）扎实、网络出站默认拒绝。**但仍存在 3 个高严重度突破口**，其中两个可达到**宿主任意代码执行**。

| # | 严重度 | 发现 | 状态 |
|---|--------|------|------|
| 1 | **Critical** | `git -C` 绕过 + 嵌套仓库 `.git` 可写 → 沙箱内 RCE + **宿主持久化植入（沙箱逃逸）** | CONFIRMED-EXEC / CONFIRMED-HOST-EXEC |
| 2 | **High** | Hermes guard 扫描以宿主完整权限 import 攻击者可控模块 → **宿主 RCE + 环境变量（API key）泄露** | CONFIRMED-EXEC |
| 3 | **High** | 语义记忆存储型 prompt injection 直达 system prompt，护栏永不 BLOCK | CONFIRMED |
| 4 | Medium | 审计链可被"全表删除 + 重启"无痕擦除 | CONFIRMED |
| 5 | Medium | skill 扫描器不扫 `.bash`；运行时检查只查 entry 的 sensitive_path | CONFIRMED-EXEC |
| 6 | Medium | skill 自带 `.venv/bin/python` 劫持解释器，完整性哈希对 `.venv` 失明 | CONFIRMED-HIJACK |
| 7 | Medium | `stat`/`ls` 泄露宿主任意路径元数据（`~/.ssh`、`/etc/passwd` 等） | CONFIRMED |
| 8 | Medium | `timeout` 参数无上限 → 4 次调用锁死工具层（DoS） | CONFIRMED |
| 9 | Medium | 应用层参数校验缺口（`${VAR:-/path}`、sort/wc 位置参数、`send-email`、`sed -f`、`tar -I`）— 当前由 OS 沙箱兜底 | CONFIRMED（被兜底） |
| 10 | Low | `require_auth_dep` 的 POST 端点缺 Origin 校验（仅 auth-optional 模式可 CSRF） | 代码证据 |
| 11 | Low | `/docs`、`/openapi.json` 无认证暴露完整 API schema | 代码证据 |
| 12 | Low | bootstrap 窗口期本机进程可伪造 Origin 抢注 admin；`bootstrap_admin_key.txt` 明文长期留存 | 代码证据 |

---

## 1. [Critical] git 白名单绕过 → 沙箱内 RCE + 宿主植入逃逸

**PoC**：`poc_shell_git_bypass.py`（全部通过真实 `ShellTool.execute` 路径，含 macOS sandbox-exec）

### 三个叠加的缺陷

**a) `git -C` 使子命令黑名单完全失效** — `js/tools/shell.py:103-118`
`_git_arg_error` 把"第一个不以 `-` 开头的 token"当作子命令。`git -C nested config user.email x` 中 `-C` 的值 `nested` 被误判为子命令，真正的 `config` 逃过 `_GIT_DENIED_SUBCOMMANDS = {"config", "alias"}` 检查。实测：`git -C nested config ...` 返回 success。

**b) R3-2 的 `.git` 写保护只覆盖 workspace 根目录** — `js/echo/os_sandbox.py:375-379`
SBPL profile 末尾追加 `(deny file-write* (subpath "<workspace>/.git"))`，只挡根 `.git`。`git init nested` 创建的 `nested/.git` 在沙箱内**完全可写**（实测确认）。于是沙箱内可以完成：`git -C nested config`（身份）→ `add`/`commit` → **`git -C nested rebase --exec '任意命令' HEAD~1`** → 沙箱内任意命令执行，只需要 `shell` 一个工具（绕过了 "shell 工具不应有代码执行能力" 的设计意图，`echo_exec_tools` 默认关闭的保护被架空）。

**c) 植入的仓库配置会在宿主侧执行（沙箱逃逸）** — `js/echo/os_sandbox.py:249-273`
`GIT_CONFIG_*` 环境变量覆盖（中和 `core.hooksPath`/`diff.external` 等）只在沙箱进程内生效。通过 (a) 写入 `nested/.git/config` 的 `diff.external = 'sh payload.sh'` **持久化在磁盘上**；用户在宿主上对该项目录执行 `git diff`（无需 TTY，`diff.external` 不需要 pager 条件）即以**宿主完整权限**执行 payload。PoC 中已端到端复现：沙箱内 `git diff` 不触发（env 覆盖生效，控制组 PASS），宿主 `git diff` 触发并创建 marker。

**完整攻击链**：聊天 prompt injection（钓鱼文档/网页/记忆注入，见发现 3）→ 模型调用 shell 工具：`git init evil` + `git -C evil config diff.external 'sh payload.sh'` + file_write 写 `payload.sh`（弹 payload 无需执行位）→ 用户日后在该目录运行任何 git 命令 → **宿主 RCE**。

**修复**：
- git 参数解析改为先消耗 `-C`/`-c`/`--git-dir` 等带值选项再判定子命令；或更稳妥：git 改用子命令**白名单**（status/log/diff/show/grep/add/commit/branch/checkout/mv/rm），显式拒绝 rebase/bisect/filter-branch/mergetool/send-email/am/instaweb/daemon/worktree。
- SBPL/bwrap profile 的 `.git` 写拒绝从"根目录"改为"workspace 内任意层级的 `.git` 组件"（SBPL 可用 regex 规则；Linux 侧同理）。
- 沙箱内 `git init/clone` 新建仓库时考虑默认禁止或标记。
- env 覆盖补 `merge.tool`、`sequence.editor`。

## 2. [High] Hermes guard 扫描 = 宿主 RCE

**PoC**：`poc_hermes_guard_rce.py` — CONFIRMED-EXEC

`js/skills/hermes_bridge.py:549-554`：`_try_hermes_guard_scan` 用 `subprocess.run([sys.executable, "-c", script, ...])` 执行一段会 `from skills_guard import scan_skill` 的代码，模块路径来自 `<HERMES_HOME>/hermes-agent/tools/`。**无沙箱、无环境过滤，继承父进程全部环境变量**（含 provider API key）。

PoC 实测：在临时 HOME 放置伪造 `skills_guard.py`（模块级 payload），调用扫描即执行，marker 文件内容确认拿到了 `SIMULATED_API_KEY` 环境变量。附加伤害：伪造 guard 返回 `verdict="safe"` 使恶意 skill 被评为 `TrustLevel.TRUSTED`（hermes_bridge.py:571）。

触发条件：`features.hermes_skills_enabled=true`（opt-in，默认关）+ 攻击者控制 `~/.hermes`（Hermes 供应链、被篡改的 Hermes 安装、或恶意 hermes skill 自带该模块）。默认配置下不可达，故定 High 而非 Critical。

**修复**：把 guard 扫描挪进 strict OS 沙箱（与 skill 执行同一底座），或改为不 import 的静态解析（AST 扫描 `skills_guard.py` 的输出格式约定）；subprocess 至少传 `env={}` 白名单。

## 3. [High] 语义记忆 → system prompt 存储型注入

**PoC**：`poc_memory_prompt_injection.py` — CONFIRMED

链路：
1. 对话内容经 organizer LLM 自动抽取进 semantic memory（value 字段，仅做密钥脱敏，无指令过滤）。
2. `js/agent/prompt_builder.py:377-405` 把 `memory.get_context_string()` 直接拼进 **system 消息**。
3. 唯一筛查 `BehaviorGuard.check_tool_result`（`js/security/guard.py:364-405`）**结构上不可能 BLOCK**——14 个关键词命中也只返回 WARN；而 prompt_builder.py:402 只在 `block` 时丢弃，WARN 照注。

实测：注入文本（避开关键词的措辞）原样进入 context；guard 判定 `allow`；即使故意命中关键词也只是 `warn` → 仍注入。

**效果**：一次会话植入 → 之后**每个会话**的 system prompt 都带攻击者指令，跨重启持久。配合发现 1 即构成完整杀伤链（注入指令驱动模型执行 git 植入）。

对比：session capsule 路径有 `<memory trust="untrusted">` 包裹 + drift 检测（turn_loop.py:641-652），semantic memory 路径完全没有——同一项目内信任标注不一致。

**修复**：memory context 以 untrusted 标记 + user 角色注入（与 capsule 对齐）；`check_tool_result` 增加 BLOCK 判定；organizer 对 value 做指令性内容过滤。

## 4. [Medium] 审计链全量擦除无痕

**PoC**：`poc_audit_chain_wipe.py` — CONFIRMED

`js/security/audit.py:121-143`：`_init_db` 在 `audit_chain_state` 行缺失时**无条件以现有数据重锚**；`verify_chain`（:287-288）对空链 + 空 anchor 返回 `(True, 0)`（合法）。

实测：写入 5 条事件 → `DELETE FROM audit_log; DELETE FROM audit_chain_state;` → 重新实例化（模拟重启）→ `verify_chain() == (True, 0)`，与全新安装不可区分。HMAC 只防"无密钥伪造"，防不了"清空重来"。另注：链 MAC 密钥与加密密钥同源于 `state_dir/.secret_key`——读到这一个文件即同时瓦解保密性与完整性。

**修复**：chain_state 缺失且 audit_log 非空/曾有数据时视为篡改（fail-closed 报警），遗留库迁移用一次性显式命令；`.secret_key` 派生不同用途密钥时考虑分离存储。

## 5. [Medium] skill 扫描器 `.bash` 盲区

**PoC**：`poc_skill_scan_venv.py` — CONFIRMED-EXEC

- `scan_skill`（security.py:72-78）只扫 `*.py`/`*.sh`/`*.js` + SKILL.md；执行器（executor.py:188）却接受 `.bash` entry → **安装期零扫描**。
- 运行时检查（security.py:206-213）只查 entry 文件的 `sensitive_path_access` 一类；`curl x | sh`、`rm -rf` 等 payload 在 `.bash` entry 里畅通（实测 `ok=True`）。
- 实测：含 3 类恶意特征的 `run.bash` 安装后 `risk_flags=[]`（同内容 `.sh` 被标 2 个 flag），且 `.bash` entry 在沙箱内真实执行（marker 落盘）。
- 另注：QUARANTINE 需 ≥3 flag；1-2 个 flag 的 skill 仍以 COMMUNITY 注册为模型可调用工具（执行层有 OS 沙箱 + 禁网兜底，所以这是纵深缺口而非直接宿主 RCE）。

**修复**：扫描覆盖 `.bash`（及 entry 指向的任何扩展名）；`credential_access` 补 `os.environ.get`/`os.getenv` 形式；`obfuscation` 补 `importlib.import_module`/`b85decode`/`fromhex`；考虑 ≥1 flag 即默认不可执行（需人工提升）。

## 6. [Medium] skill `.venv` 解释器劫持（完整性盲区）

**PoC**：`poc_skill_scan_venv.py` — CONFIRMED-HIJACK

- `HASH_EXCLUDED_DIRS` 含 `.venv`（spec.py:75,99）——完整性哈希对 `.venv` 完全失明；
- `_execute_code`（executor.py:191-196）**优先**使用 `spec.path/.venv/bin/python`；
- 本地安装 `copytree`（manager.py:1030-1036）不拒 `.venv`（远程 GitHub 安装反而拒，manager.py:908——不一致）。

实测：skill 自带伪造 `.venv/bin/python`（shell 脚本），安装后 `verify_integrity()=True`，执行时跑的是伪造解释器（输出 `FAKE_INTERPRETER_RAN`，真实 `main.py` 未执行）；安装后改写 `.venv/bin/python` 依然 `verify_integrity()=True`（对照组：改 `main.py` 立刻被检出）。缓解：伪造解释器仍在 strict 沙箱内跑（禁网、写限 workspace）。

**修复**：`compute_skill_dir_hash` 覆盖 `.venv/bin/python*`；或禁用 skill 本地解释器（统一用系统 python）；本地/远程安装策略对齐。

## 7. [Medium] 宿主元数据泄露

**PoC**：`poc_shell_git_bypass.py` — CONFIRMED

SBPL profile 全局 `(allow file-read-metadata)`（os_sandbox.py:60）。沙箱内 `stat /etc/passwd`、`stat ~/.ssh`、`ls /Library` 全部成功：攻击者（注入的模型）可探测宿主任意路径存在性、大小、权限、mtime，辅助后续攻击。

**修复**：`file-read-metadata` 按 subpath 收紧；或应用层对 workspace 外的 stat/ls/du 参数 fail-closed。

## 8. [Medium] timeout 无上限 → 工具层 DoS

`js/tools/shell.py:292`：`timeout=timeout or self.limits.shell_timeout` —— 模型可传 `timeout=10**8`（实测接受）。`js/tools/code.py:135` 同构。常驻进程占住 `max_concurrent_tools=4` 的信号量槽（registry.py:428），4 次调用即锁死全部工具执行。

**修复**：`min(timeout or default, hard_cap)`（如 3600s）。

## 9. [Medium] 应用层参数校验缺口（当前由 OS 沙箱兜底）

实测应用层全部放行、被 sandbox-exec 拦截：

- `cat ${X:-/etc/passwd}` —— `_fs_restricted_rejection`（os_sandbox.py:907-935）只拒 `$/`、`$\`、`$'`、`$"` 开头的 token，`${X:-...}` 不在其列；
- `sort /etc/passwd`、`wc /etc/passwd` —— 位置参数路径只对 read/write 命令集合检查，`sort`/`uniq`/`jq` 等不在集合内；
- `git send-email` —— 应用层放行（无网络执行失败但已到达执行阶段）；
- `sed -f script.sed`（`_sed_arg_error` 跳过所有 `-` 开头 token）、`tar -I`/`tar -F`（短选项集合缺 `I`/`F`）—— **GNU/Linux 可利用**，macOS BSD 工具无对应功能。

这些是纯纵深缺口：一旦 SBPL profile 为某合法需求放宽读路径，即成任意文件读。

**修复**：拒绝所有含 `${` 的 token；位置参数路径检查扩展到全部白名单命令；sed/tar 补齐选项覆盖。

## 10–12. [Low] web 面

- **`require_auth_dep` 的 POST 端点无 Origin 校验**（auth.py:933 vs :997/1015）：`/api/setup/test-model`（消耗云 provider 费用）、`/api/work/routines/draft`、`/api/cron/parse` 等。仅当运维设置 `JS_API_KEY_REQUIRED=false` 时可被跨站 POST 利用。修复：变更类端点统一走 `require_user_write`。
- **`/docs`、`/redoc`、`/openapi.json` 无认证**（server.py:908 未设 `docs_url=None`）：泄露完整 API schema 供侦察。修复：生产构建关闭或挂认证。
- **bootstrap 窗口**（auth.py:1103-1130）：无 admin key 且 `first_run_completed=false` 时 loopback 免凭据发 admin；`check_origin` 只校验头值，本机非浏览器进程可伪造 Origin 抢在真实用户前完成 setup。缓解已存在：启动时自动 provision admin（server.py:583-620）使窗口极短、仅 loopback、拒绝反代头。另 `bootstrap_admin_key.txt`（0600）明文长期留存 state_dir，建议首次登录后提示删除。

---

## 已验证打不动的边界（同样重要）

- **Echo 唯一边界**：web/WS/CLI/TUI/Telegram/daemon/fleet/skill 全入口均走 Echo；`ModelRouter.chat()` 无 permit 即拒、`registry.get_handler()` 返回永远拒绝的代理——未发现绕过路径。
- **Lease**：HMAC 域分隔、常量时间比较、RLock+flock 事务内原子消费，无 TOCTOU/重放。
- **网络出站**：lease 的 `network_hosts` 必须是 `security.network_allowlist`（默认空=默认拒绝）的子集——"模型自定 URL 自我授权外泄"**不成立**（agent-31 的初始怀疑被代码证伪，registry.py:404-406 + turn_runtime.py:189-193）。
- **文件工具**：dir_fd + `O_NOFOLLOW` 逐组件 + temp+rename，符号链接/`..`/大小写均堵死；`file_write` 拒绝任意层级 `.git` 组件（files.py:132-147）。
- **browser.py SSRF**：scheme 白名单 + getaddrinfo 全地址校验 + IP 钉扎防 DNS rebinding + 禁跳转 + 10MB 流式上限。
- **web 认证核心**：key 只存 SHA-256 哈希、会话 token 哈希级联吊销、WS 先 Origin 后认证、上传链 O_NOFOLLOW+配额账本、IDOR owner 过滤完整。
- **MCP**：已物理移除，残留 connector 全部 fail-closed。
- **远程 skill 安装**：GitHub 仓库名校验 + IP 钉扎 + tar 路径/大小/符号链接全校验。
- **存储型 XSS（memory.js:216/615）**：渲染缺陷真实存在，但追踪全部写入路径后确认**聊天攻击者不可达**（category 被 organizer 枚举钳制、source 硬编码、value/key 已转义、web 写入端点 admin-only）——降为纵深修复建议。

## 修复优先级

1. **立即**：发现 1（git `-C` + 嵌套 `.git`）——唯一一条从"聊天注入"到"宿主 RCE"的完整链。
2. **高**：发现 3（记忆注入，它是发现 1 的投递器）、发现 2（hermes 扫描进沙箱）。
3. **中**：发现 4/5/6（审计重锚 fail-closed、扫描补 `.bash`、哈希覆盖 `.venv`）、发现 8（timeout 钳制）。
4. **低**：发现 7/9/10/11/12 按纵深防御批次处理。

## 复现

```bash
.venv/bin/python docs/security/redteam/poc_shell_git_bypass.py      # 发现 1/7/8/9
.venv/bin/python docs/security/redteam/poc_hermes_guard_rce.py      # 发现 2
.venv/bin/python docs/security/redteam/poc_memory_prompt_injection.py  # 发现 3
.venv/bin/python docs/security/redteam/poc_audit_chain_wipe.py      # 发现 4
.venv/bin/python docs/security/redteam/poc_skill_scan_venv.py       # 发现 5/6
```

---

## 修复状态（2026-08-20 同日闭环）

全部 12 项发现均已处理；5 个 PoC 已改写为修复后验证脚本（原攻击载荷全部阻断），门禁三件套全绿（ruff / mypy / pytest：6119 passed, 2 skipped）。

| # | 状态 | 修复 |
|---|------|------|
| 1 | **已修复（含本轮残留闭环）** | `_git_arg_error` 重写：先消耗 `-C`/`--git-dir`/`--work-tree`/`--namespace` 带值选项，子命令改白名单（config/rebase/init/clone/send-email 等全拒）；`os_sandbox` 构建 profile 时遍历 workspace，对**任意层级** `.git` 目录/gitfile 生成 SBPL deny / bwrap ro-bind；env 强制对补 `sequence.editor`、`merge.tool`。**本轮复核发现残留**：嵌套 `.git` deny 是 wrap 时刻快照，同一次调用 `mkdir nested/.git && mv cfg nested/.git/config`（以及 `tar xf` 解出 `.git`）仍可种盘。已补：应用层拒绝 mkdir/touch/mv/tar/git 写路径中的 `.git` 组件、拒绝 tar extract、macOS SBPL 增加任意层级 `/.git` 正则写拒绝（POSIX ERE，无 `(?i)`）。PoC：`git -C nested config`、`rebase --exec`、`diff.external` 植入、重定向写嵌套 `.git`、同调用 mkdir+mv 种盘全部 BLOCKED |
| 2 | **已修复** | `_try_hermes_guard_scan` 改为经 `SandboxExecutor`（strict，fs_restricted + 禁网）包裹执行，环境用 `_build_env` 最小集（不含任何 API key）；沙箱后端不可用时返回 None 退回 JS 基础扫描（fail-closed，不再裸跑）。PoC REFUTED |
| 3 | **已修复（含残留）** | `check_tool_result` 分级：13 条高置信注入短语（中英）升 BLOCK，6 条代码形态标记保持 WARN；`prompt_builder` block→清空已有衔接，且记忆上下文改为 `<memory trust="untrusted">` 包裹 + 显式非授权声明；`turn_loop` capsule 路径对齐（BLOCK 丢弃 + SECURITY_ALERT 审计，WARN 保留）；`registry` 工具结果 BLOCK 改为 fail-closed 不返给模型。残留：完全改写措辞绕过关键词表的 paraphrase 仍可通过关键词层（只能靠 untrusted 框架 + 密钥脱敏缓解），语义级注入防御超出本轮范围 |
| 4 | **已修复** | `_init_db` fail-closed：state 缺失且 `audit_log` 非空 → RuntimeError 拒绝启动；state 缺失 + 空库 + `audit.initialized` 哨兵存在 → `logger.critical` 报疑似擦除（fail-visible）后重建；首初始化写哨兵。残留：连同哨兵文件一起删除的宿主级擦除降级为"全新安装"形态（宿主写权限超出 agent 遏制范围，报告注明） |
| 5 | **已修复** | 扫描 rglob 补 `*.bash`；`runtime_security_check` 对 entry 增加 `network_exfil` 运行时检查（curl\|sh 等直接阻断执行）；`credential_access` 补 `os.environ.get`/`os.getenv` 形态，`obfuscation` 补 `importlib.import_module`/`b85decode`/`fromhex` |
| 6 | **已修复** | `_execute_code` 恒用宿主 `sys.executable`，删除 skill 本地 `.venv` 解释器优先逻辑；本地安装与远程归档对齐，拒绝顶层 `.git`/`.venv`。PoC REFUTED |
| 7 | **已修复** | 应用层位置参数路径检查扩展到 `ls/stat/du/file/readlink/cut/diff/jq/sort/test/tr/uniq/wc`：`stat /etc/passwd`、`stat ~/.ssh`、`ls /etc` 均 BLOCKED（SBPL 全局 `file-read-metadata` 无法按路径收紧，保持不动，由应用层 fail-closed） |
| 8 | **已修复** | `shell.py` 与 `code.py` 的 timeout 均钳制为 `min(调用值, 配置上限)`——只能缩短不能拉长。PoC REFUTED |
| 9 | **已修复** | `_fs_restricted_rejection` 拒绝一切含 `${` 的 token（两种入参形态）；sed 拒 `-f`/`--file` 并扫描 `-e`/`--expression` 连体内容；tar 短选项黑名单补 `I`/`F`；`git send-email` 等由子命令白名单整体覆盖。PoC 全部 BLOCKED |
| 10 | **已修复** | `require_auth` 对变更方法统一先过 `check_origin`（镜像 `require_user_write`），一处修复覆盖 setup/routines/cron 等全部裸 `require_auth_dep` 端点；AppShell managed 分支语义不变 |
| 11 | **已修复** | `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)`，`/docs` 与 `/openapi.json` 返回 404（`system.py` 用的是 `app.openapi()` 方法，不受影响） |
| 12 | **部分处理** | bootstrap 窗口的既有缓解（自动 provision、仅 loopback、拒绝反代头）维持；`bootstrap_admin_key.txt`（0600）明文留存**不改代码**——建议后续首次登录后提示删除或迁入钥匙串/加密存储 |

**测试**：每个修复均配 pytest 用例（git 白名单/嵌套 .git deny/Hermes 沙箱化/扫描盲区/.venv 拒绝/BLOCK 分级/审计哨兵/Origin/404 等），`tests/test_security_shell_allowlist.py`、`tests/echo/test_os_sandbox.py`、`tests/test_skills.py`、`tests/test_hermes_bridge.py`、`tests/test_security_expanded.py`、`tests/test_security.py`、`tests/test_session_capsule.py`、`tests/test_tool_output_budget.py`、web 认证测试均有新增；`tests/test_redteam.py` 既有断言（接受 WARN 或 BLOCK）保持兼容。

**遗留行为变化（升级注意）**：存在旧版无 `audit_chain_state` 表且 `audit_log` 非空的数据库现在会拒绝启动（fail-closed 预期行为），需人工取证后删除旧库或显式迁移。shell 工具现在拒绝 `tar` extract（`-x` / `xf` / `--extract`），只保留打包/列出；请改用 file 工具或在宿主侧解包。
