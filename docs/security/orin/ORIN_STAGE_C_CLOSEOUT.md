# Orin 阶段 C 完成声明 / 发布裁决（2026-08-28）

> 证据标签遵循 `ORIN_STAGE_C_SPEC.md` §1.1。  
> **Stage C is not implemented. Echo RCE is not closed.**  
> 本文件是 WP-C7 的发布决议，不是上线授权，也不是结构性收口证明。

机器可读同义声明：`js.orin.stage_c.stage_c_closeout_declaration()`。
默认生产快照（`OrinConfig()`）的 `verdict` 必须是 `not_implemented`。

## 1. 裁决

| 项 | 结论 |
|---|---|
| 阶段 C 实施状态 | **未实施**（不得改为“已实施”或“已实施候选”） |
| Echo RCE | **未收口** |
| `orin.enforce` / `--orin-enforce` | 默认 `false`；合取未齐时启动 **fail-fast** |
| Desktop / Memory 整迁 | **未勾选** SPEC §12 |
| 默认可宣称 | 仅限已观察的 harness / 软件接线；不得扩写成生产隔离 |

合取检查器在默认生产配置下列出的缺位至少包括：

- 配置总闸与 C 子开关（C-I01：默认全关）
- `appshell_echo_separated`（默认 Host 仍是单进程 ambient）
- `provider_tokens_out_of_echo`（Echo 仍可在进程内持有 provider token）
- `production_sandbox_carrier` / `echo_minimal_os`（P2-1：file/build 的 `container_vm` 或 L1 回退；无正式打包载体验收，不构成 Stage C 已实施）
- `official_tcc_packaging`（Developer ID / 公证 / 正式 TCC，external-pending）
- `k156_8_real_model_e2e`（真实模型 observe→act→observe，blocked）
- `k156_9_independent_red_team`（独立红队，external-pending）

软件把上述配置旗标全部置真，仍过不了后三项外部门。外部门未关闭前，禁止打开生产 `orin.enforce`。

## 2. 可以写 / 不得写

与 SPEC §1.2 一致。本声明**不得**使用下列句子：

- Stage C is implemented
- Echo RCE is closed
- `orin.enforce` is production-ready

只有 §6.1 合取与 K§15.6 十条全部不再含 `blocked` / `untested` / `external-pending` 之后，才允许把阶段 C 从规格改成“已实施候选”，且声明范围仍只限已验收的 macOS 生产构建、固定版本和测试边界。

## 3. 软件侧已观察（不是生产 enforce）

详见 `ORIN_STAGE_C_C6C7_EVIDENCE.md` 与各 WP 状态段。摘要：

| WP | 标签 | 边界 |
|---|---|---|
| C0 | 已观察 | inventory 冻结；未分类出口 enforce deny；digest 钉死 |
| C1 | harness 观察 | 身份 / 环境 allowlist / 显式进程分离；默认 launcher 仍单进程 |
| C2 | harness 观察 | Desktop Cell 接线；默认 DesktopTools 仍 ambient；#8 仍 blocked |
| C3 | harness 观察 | Memory Cell 接线；默认 memory API 仍 ambient |
| C4 | harness 观察 | deny-default `sandbox-exec` 探针；正式 TCC 仍 external-pending |
| C5 | 已观察 | 合取检查器 + enforce fail-fast；非 enforce 保持 `652d035` |
| C6 | harness 观察 | UNKNOWN_COMMIT 不盲重放；真 provider 幂等仍 blocked |
| C7 | 本文件 | 发布裁决 = **未实施**；K§10.4 数字 untested |

Bots 表面（ADR 0007）不是阶段 C 收口，不得引用为本声明的通过证据。

## 4. K§15.6 十条（本裁决日）

| # | 状态 |
|---:|---|
| 1 Echo OS 身份 | 本阶段必须测 / 正式打包未验收 |
| 2 收据 + 无未登记出口 | 本阶段必须测 / 默认生产仍有 ambient 路径 |
| 3 旧协议 / 缺见证 / 失联 | 本阶段必须测 / enforce 不可达 |
| 4 精确出门证 | 已具备（B 已测）子证据；OS 网络旁路未收口 |
| 5 不可逆重复 = 0 | 本阶段必须测 / 真 provider 仍 blocked |
| 6 K§10.4 | untested（禁止把夹具数字写成达标） |
| 7 效用与审批量 | untested |
| 8 真实桌面闭环 | blocked |
| 9 独立红队 | external-pending |
| 10 未完成项诚实标签 | 本文件维持 |

任一条仍为 `blocked` / `untested` / `external-pending`，即不得作上线或结构性收口声明。

## 5. 回退

保持 `orin.enforce=false` 冷启动。不发布强制模式。若未来试点曾打开 enforce，退出声明的唯一动作是冷重启为 `false`，并明确离开本阶段安全声明。
