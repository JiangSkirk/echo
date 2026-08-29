# 多 owner 表面威胁模型

本文是仓库内可审计威胁模型，不是外部红队报告。
承重边界与姿态声明见 [`SECURITY.md`](../../SECURITY.md)。
已知不修项见 [`TECH_DEBT.md`](../../TECH_DEBT.md) ⚫ 表。

JS Agent 是**单租户本机 Harness**。同一 `state_dir` 上可以有多把 API key
（多个 `owner_key_hash`）。威胁是「一把钥匙读到另一把钥匙的状态」，
不是公有云多租户隔离。

## 1. 资产

| 资产 | 存哪 | 失败含义 |
|------|------|----------|
| 记忆 / dream / 提案 | `memory.db` / `memory_enhanced.db` | 跨 owner 泄漏私密对话 |
| Bots 房间 / Goal / 私聊 | `bots.db` | 房间串扰、私有记忆进公共 transcript |
| Fleet worker / 事件 | `state_dir` + 运行时 | owner 混淆、容量互踩 |
| Web 会话 / API key | `api_keys.db` | 会话固定、guest 提权 |
| Gateway 配对 / 入站 | 内存 PairingStore | 未配对发件人进 Echo；跨 owner 路由 |
| Cron 作业 | cron SQLite | 作业在错误 owner 下跑 Echo |
| Evolution 提案 | `evolution_proposals.db` | 审批队列串扰、误应用他人提案 |
| Friends 身份 / 密文 | `friends.db` | 重放、未确认好友、跨 owner seen-id |
| Ledger / 租约 | Echo journal | 跨 run 重放、跨 owner consume |

## 2. 威胁 → 测试映射

| ID | 表面 | 威胁 | 主要测试 |
|----|------|------|----------|
| T-BOT-1 | Bots 房间 | owner-b 读 owner-a 的 bot/房间/消息 | `tests/bots/test_bot_store_owner_isolation.py` |
| T-BOT-2 | Bots 私有记忆 | 房间 transcript 带入 bot 私有 session | `tests/bots/test_room_no_private_memory_leak.py` |
| T-BOT-3 | Bots 并发 | 并发创建后 list 仍 owner 分区 | `tests/multiuser/test_abuse_matrix.py` |
| T-FLT-1 | Fleet | worker / 事件绑定错误 owner | `tests/test_fleet_owner_isolation.py` |
| T-FLT-2 | Fleet WS | 套接字事件泄漏 | `tests/web/test_fleet_websocket_owner_isolation.py` |
| T-MEM-1 | Memory | semantic / search / blocks 跨 owner | `tests/test_memory_isolation.py` |
| T-MEM-2 | Dream | HTTP dream-log 未传调用者 owner | `tests/web/test_memory_dream_owner.py` |
| T-MEM-3 | Dream 并发 | 同 session_id 不同 owner 不串行 | `tests/multiuser/test_abuse_matrix.py` |
| T-WEB-1 | Web 会话 | 匿名 guest 拿到 admin | `tests/web/test_auth_security.py` |
| T-WEB-2 | Web 会话 | 会话 cookie 与另一把 API key 混淆 | `tests/multiuser/test_abuse_matrix.py` |
| T-WEB-3 | Web 会话 | 已撤销 cookie 仍可用 | `tests/web/test_auth_security.py` |
| T-GW-1 | Gateway | 未配对入站进入 Echo | `tests/gateway/test_gateway_cold_start.py` |
| T-GW-2 | Gateway | 配对码过期后时钟回拨复活 | `tests/faults/test_gateway_pairing.py` |
| T-GW-3 | Gateway | 两把 owner 的配对互不影响 | `tests/multiuser/test_abuse_matrix.py` |
| T-CRON-1 | Cron | 列出/删除别人的作业 | `tests/multiuser/test_abuse_matrix.py` |
| T-EVO-1 | Evolution | 批准/列出别人的提案 | `tests/evolution/test_cycle.py` + abuse matrix |
| T-FR-1 | Friends | seen-id / 密文跨 owner | `tests/friends/test_friends_v1.py` |
| T-LED-1 | Lease | 绑定字段被改仍能 consume | `tests/property/test_lease_binding.py` |
| T-RATE-1 | Fleet 协作 | owner-a 触顶限频连坐 owner-b | `tests/multiuser/test_abuse_matrix.py` |

未映射到自动化测试的残余（不假装已覆盖）：

- 独立外部红队 / 正式 TCC / TPM tip（TECH_DEBT ⚫）
- Stage C `orin.enforce`（默认关，`not_implemented`）
- 真实公网多 Host Friends 对打（仓库内是双临时 HOME）

## 3. 信任边界（再次声明）

对抗性模型输出的承重边界是 OS 隔离。本文件里的 owner 分区是**授权正确性**：
同一操作系统用户能读整个 `state_dir`。多 key 不是对抗边界。
