# JS Agent / JS Agent Work — 安全审计总报告（饱和停止版）

| 字段 | 内容 |
|------|------|
| **权威日期** | 2026-07-20 |
| **代码根** | `/Users/jiangxuanzhen/titan-agent` |
| **轮次** | R1–R3/R3M → R4–R8 → **R9–R16 穷尽扫描直至饱和** |
| **条目总数** | **7206**（`VULN-0001` … `VULN-7206`） |
| **全表** | [`VULN_CATALOG_FULL.md`](./VULN_CATALOG_FULL.md) |
| **JSON** | [`_enum_findings.json`](./_enum_findings.json) |
| **状态** | **静态穷尽已饱和 — 停止继续静态挖洞** |

---

## 1. 为什么现在停止「一直挖」

| 信号 | 数据 |
|------|------|
| 后期轮次新增质量 | **R16 仅新增 3 条**（DEBUG/JWT 等边角），属噪声级 |
| R14 膨胀 | ~2946 条多为 **安全测试用例清单（Info/正向）**，不是新 exploit |
| Critical 稳定 | 全程 **Critical = 10**，未再发现新的「一击接管」类 |
| High 稳定 | **294**（独立位置约 **264**），新增多为重复面登记 |
| 方法重复 | 路由/工具/IO/前端/依赖/Work/API/锁/AST 调用等扫描器已 **二扫无新 High** |

**结论：在当前仓库、当前静态方法下，已经「再挖也主要是重复与清单」，继续同一路径边际收益≈0。**

若还要突破，必须换方法（见 §6），而不是再跑同一套正则。

---

## 2. 全量分布（复查后）

| 严重度 | 数量 | 说明 |
|--------|------|------|
| **Critical** | **10** | 可接管/伪造信任/命令原语/明文凭据 |
| **High** | **294** | 高危缺陷与危险默契面 |
| **Medium** | **1830** | 条件利用、隔离/竞态/校验缺口 |
| **Low** | **522** | 硬化缺口 |
| **Info** | **4550** | 攻击面/依赖/测试/配置清单 |
| **合计** | **7206** | |

**非 Info（更像「问题/缺口」）≈ 2656 条。**

---

## 3. Critical 十项（始终有效）

1. macOS sandbox `(allow default)`  
2. Telegram 无 chat allowlist  
3. 技能 `author` 可伪造 TRUSTED（运行复现）  
4. `find -exec` 绕过 shell 白名单（运行复现）  
5. `awk system()` 绕过白名单（运行复现）  
6–7. 关鉴权 → 匿名 admin  
8. Bootstrap 无密钥 admin  
9–10. API Key → localStorage / 非 HttpOnly Cookie  

---

## 4. 各轮覆盖地图（已穷尽的面）

| 轮次 | 主题 |
|------|------|
| R1 | 鉴权、工具、Echo、Work、技能、数据 |
| R2 | XSS、owner 三桶、CORS、schema、审批 |
| R3/R3M | 全库枚举 + Fleet/模型泄密/prune |
| R4 | 依赖、反序列化、密码学、import |
| R5 | Work 公式/zip/soffice |
| R6 | Web API 参数/上传/响应 |
| R7 | memory/cron/evolution 并发与 prune |
| R8 | 前端 DOM/Storage/CSP |
| R9 | scripts/docker/ci/env 硬编码与管道 |
| R10 | Unicode/路径编码/符号链接/时序 |
| R11 | 内置技能/插件/场景资产风险模式 |
| R12 | AST 敏感调用（eval/exec/Popen…） |
| R13 | config/work 配置默认值面 |
| R14 | 安全相关测试用例全清单（正向控制证据） |
| R15 | 内网 IP/元数据字符串、安全标注 |
| R16 | DEBUG/JWT 边角（**仅 +3 → 饱和**） |

每轮均含 **复查/降级误报**（测试代码、检测名单字符串、文档、假 eval 等）。

---

## 5. 统一 P0（从 7206 条抽出的真正要修）

与此前一致，不因条数膨胀而改优先级：

1. 匿名永不 admin；Bootstrap 仅 loopback  
2. HttpOnly 会话；禁止 JS 可读 API Key  
3. 消灭 onclick 拼接 XSS；错误 DOM 全 escape  
4. 异常/stream redact（含 query_param key）  
5. CORS 去无端口 origin  
6. Shell allowlist 只读化；禁 find -exec / awk system  
7. sandbox deny-default  
8. Schema core 去掉默认 shell/python  
9. Owner 单一化 + dream_logs  
10. Fleet 池/配置隔离；禁止跨 owner 杀 worker  
11. prune / fleet 表 per-owner  
12. decide/callback 强制 owner  
13. Telegram allowlist  
14. 技能 fail-closed  
15. Work CLI 默认关 host tools；soffice 收紧  
16. Ledger doctor  
17. provider 写入前 net_guard  
18. metrics 鉴权  

---

## 6. 若还要「继续挖」——必须换武器

静态穷尽已停。下一阶段只建议：

| 方法 | 目标 |
|------|------|
| **动态 XSS/会话实操** | 真实浏览器打 R2-XSS / Cookie |
| **并发压测** | Fleet reap / approval / session_lock |
| **OSV/pip-audit 全量 + 修复** | 依赖 CVE（R4 已尝试，需 CI 固化） |
| **模糊测试** | shell parser、路径、上传、zip |
| **独立外部红队** | 干净环境黑盒 |

**不再建议**：对同一仓库再跑一轮同类 AST/正则枚举。

---

## 7. 文件导航

| 文件 | 用途 |
|------|------|
| **本文件** | 饱和停止总报告 + P0 |
| `VULN_CATALOG_FULL.md` | **7206 条完整目录** |
| `_enum_findings.json` | 结构化全量 |
| R1/R2 旧文 | 分轮叙事存档 |

---

## 8. 结论（直接回答）

1. **已经「一直挖」到静态方法饱和**：7206 条可定位发现；**R16 几乎挖空（+3）**。  
2. **不是「世界上再也没有 bug」**，而是 **当前代码树 + 静态手法再也挖不出新的有意义 High/Critical**。  
3. **真正要修的仍是那约 10 Critical + 关键 High 与 P0 列表**；7206 是审计覆盖与回归清单，不是 7206 个同等优先级的 RCE。  
4. **本轮起停止静态穷举**；若继续，请指定动态/依赖/外部红队方向。

---

*权威：`docs/security/FULL_REDTEAM_AUDIT_MERGED_20260720.md`*  
*全表：`docs/security/VULN_CATALOG_FULL.md`（7206）*
