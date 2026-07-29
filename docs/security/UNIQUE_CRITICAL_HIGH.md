# 不重复 Critical + High（口径 C，已去重）

共 **288** 条

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
| 204 | High | 公式/外部命令相关: r"\b(?:DATABASE|DDE|DDEAUTO|HYPERLINK|INCLUDEPICTURE|INCLUDETEXT|LINK)\b", | `js_work/documents.py:101` | static |
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
| 268 | High | 公式/外部命令相关: r"\b(?:CALL|DDE|EXEC|FILTERXML|HYPERLINK|REGISTER(?:\.ID)?|RTD|SHELL|URLDO | `js_work/routines/precise_edit.py:39` | static |
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
| 286 | High | curl|sh 管道安装 | `scripts/install-plugin.sh:3` | static |
| 287 | High | curl|sh 管道安装 | `scripts/install.sh:6` | static |
| 288 | High | curl|sh 管道安装 | `scripts/install.sh:110` | static |
