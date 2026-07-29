# 不重复漏洞数量统计（最终准确版）

**复查日期：2026-07-21**

## 结论（请直接采用）

| 口径 | 不重复数量 | 说明 |
|------|------------|------|
| **推荐：不重复安全问题（C）** | **2809** | 去掉跨轮重复、同一事实多标签、清单/测试/误报 |
| 其中 Critical | **9** | |
| 其中 High | **279** | |
| 其中 Medium | **1809** | |
| 其中 Low | **522** | |
| 其中 Info（残余非清单） | **190** | |
| **Critical + High** | **288** | 优先修复集合 |
| 更严：根因合并（D） | **2719** | allowlist/脱敏缺口等拆条再合并 |
| 原始目录（含重复与清单） | **7206** | **不是**漏洞个数 |

## 去重规则（已执行）

1. **剔除清单/正向测试/误报降级项**（约 4000+ Info 测试与攻击面清单）
2. **语义合并**同一事实的多次登记（例如 localStorage Key 被记 3 次 → 1 次）
3. **同位置同标题**跨轮只留最高严重度 + 优先 runtime 核验
4. **不同问题同位置保留**（例如 `shell.py:91` 的 find 与 awk **分开计**）
5. 口径 D 额外把「allowlist 每个命令 / 脱敏每个模式」合成根因

## 重复规模

| 现象 | 数量 |
|------|------|
| 原始条目 | 7206 |
| 同一 path:line 多记多出的条数 | 627 |
| 已知语义重复组合并 | 含 API Key、匿名 admin、bootstrap、Telegram、sandbox、技能信任等 |
| 剔除的清单/误报/正向 | 主要来自 R14 测试清单、路由/依赖/函数 inventory |

## Critical 不重复清单（9 条）

- `js/echo/os_sandbox.py:51` — macOS sandbox allow default
- `js/integrations/telegram_bot.py:178` — Telegram 无 chat allowlist
- `js/skills/security.py:165` — 伪造 author=JS Team 得 TRUSTED（运行复现）
- `js/tools/shell.py:91` — find -exec 绕过 shell 命令白名单（运行复现）
- `js/tools/shell.py:91` — awk system() 绕过白名单（运行复现）
- `js/web/auth.py:374` — require_auth 在关鉴权时返回 admin（已复验）
- `js/web/auth.py:484` — require_setup_auth bootstrap 可 admin（已复验）
- `js/web/static/app.js:59` — API Key 存 localStorage
- `js/web/static/app.js:63` — API Key 非 HttpOnly Cookie

## 文件

- 推荐列表 JSON：`_unique_findings_C.json`（2809 条）
- 根因列表 JSON：`_unique_findings_D.json`（2719 条）
- Critical+High Markdown：`UNIQUE_CRITICAL_HIGH.md`（288 条）
