# JS Agent 安全政策

本文档是对外正式的信任模型：说明承重边界、部署姿态、漏洞报告范围。
内部实施规格见 [`docs/security/orin/`](docs/security/orin/) 与 [`TECH_DEBT.md`](TECH_DEBT.md)，
它们不替代本文件。

JS Agent 是**单租户本地个人 Agent Harness**，不是多租户 SaaS。

## 1. 报告漏洞

请通过仓库的 GitHub Security Advisories 私密报告。JS Agent **不设漏洞赏金**。

有用的报告包含：

- 简要描述与严重度判断。
- 受影响组件（文件路径与行号范围）。
- 环境（`js-agent` 版本、commit SHA、操作系统、Python 版本）。
- 针对当前 `main` 或最新发行的复现。
- 明确指出越过了第 2 节哪一条信任边界。

请先读第 2、3 节。只证明进程内启发式可被绕过、且未越过承重边界的报告，
按第 3.2 节视为超出安全通道范围——欢迎作为普通 issue / PR。

## 2. 信任模型

### 2.1 定义

- **Agent 进程**：运行 JS Agent 的 Python 解释器，以及它加载的技能、插件、hook。
- **输入表面**：任何进入回合上下文的内容：操作者输入、网页抓取、入站消息、
  文件读取、MCP 响应、工具结果。
- **信任包络**：操作者通过以本机用户身份运行 JS Agent 而隐式授予的资源范围
  ——通常是该用户账号能触及的本机状态。
- **姿态**：文档或代码对「应如何对待 agent 输出」或「当前隔离级别」的显式声明。

### 2.2 承重边界：操作系统隔离

**对抗性模型输出的唯一承重安全边界是操作系统隔离。**
Echo 租约、ledger、guard、taint、工具白名单、审批门是**授权与纵深防御**，
不是对抗边界。任何在 agent 进程内筛查 LLM 输出的组件都是启发式。

JS Agent 支持两种 OS 隔离姿态：

#### 每工具 OS 沙箱（macOS 桌面默认）

`SandboxExecutor` 对 shell / code 等子进程 fail-closed 包裹：

- macOS：`sandbox-exec` 网络拒绝 + 文件系统 deny-default。
- Linux：`bwrap` + `unshare`；可用时叠加 cgroup / `RLIMIT_AS`。
- 沙箱后端不可用且 `strict_isolation=True` 时拒绝执行，不降级为裸跑。

产品路径（shell、code、技能执行）默认以 `strict_isolation=True` 调用。
这约束的是**子进程工具**，不是整个 agent 进程。模型调用、MCP、技能 import、
Host 本身仍在原生进程内。

关闭 `strict_isolation` 同时又接入不可信输入，属于不受支持的姿态。

#### 整进程容器姿态（接触不可信表面时的推荐姿态）

`Dockerfile` production 目标以非 root 运行，`docker-compose.yaml` 默认只绑定
`127.0.0.1`。这是可选部署，不是 macOS 桌面默认。

接触开放网络、入站消息、未审查 MCP、共享主机时，应使用整进程容器
（或后续 hardened compose），而不是只依赖每工具沙箱。

**默认未实施、不得宣称的事项：**

- `orin.enabled` 默认 `false`（配置类 `OrinConfig.enabled`）。
- `orin.enforce` 默认 `false`（配置类 `OrinConfig.enforce`）。Stage C cells /
  进程拆分的官方裁决是 `not_implemented`，见
  [`docs/security/orin/ORIN_STAGE_C_CLOSEOUT.md`](docs/security/orin/ORIN_STAGE_C_CLOSEOUT.md)。
- 不得宣称 Echo RCE 已收口。
- 无正式 TCC / Developer ID / 公证。
- 无独立外部红队背书。

### 2.3 授权与纵深（不是边界）

- **Echo 单一运行时边界**：模型、工具、附件、副作用只经 `run_echo_turn` /
  `execute_tool_effect`。缺失、不健康或不可验证的闸门 fail-closed。
- **单次租约**：绑定 product / owner / session / run / 工具 / 参数 / 预算。
- **污点与 conservative 审批**：不可信输入打标后，副作用走更严审批。
- **技能四级信任**：`builtin` → `trusted` → `community` → `quarantine`。
  TRUSTED 需要可信公钥目录内未吊销的公钥；自签最高 COMMUNITY。
- **进程内启发式**（审批正则、输出脱敏、技能扫描、shell allowlist）捕获合作模式
  下的失误，不构成对抗边界。绕过它们本身不是第 3.1 节漏洞。

### 2.4 默认关闭的入站表面

下列旗标默认 `false`，开启即扩大输入表面：

- `friends_enabled`（`JSSettings.friends_enabled`）
- `mobile_enabled`（`JSSettings.mobile_enabled`）
- `remote_collaboration_enabled`
- Telegram 等消息集成是可选 extra，不是默认冷启动路径。

`features.pipeline_enabled` 默认 `true` 只是能力旗标，不等于 Host 冷启动加载
`js.pipeline`。

### 2.5 供应链姿态

- 发布与安装路径要求 `uv.lock` + `uv sync --frozen`。
- Docker 镜像钉扎 `uv` 二进制版本并以 `--frozen` 安装。
- `scripts/install.sh` 拒绝远程 `curl | sh` 与无锁文件安装。
- `pyproject.toml` 中的版本区间是解析上界；可复现构建以锁文件为准。

## 3. 范围

### 3.1 在范围内

- 逃离已声明的 OS 隔离姿态（每工具沙箱或整进程容器）。
- 未授权访问 Host / AppShell API（绕过密钥、把 loopback 服务暴露给未授权调用方）。
- 凭据外泄：本应被剥离或加密的密钥出现在日志、沙箱子进程环境或不可信出站。
- 跨 owner 读取或写入（记忆、bots 房间、fleet、审批队列）。
- 代码行为与本政策或产品文档声明的姿态相反。

### 3.2 不在安全通道范围内

- 仅绕过进程内启发式（审批正则、脱敏、技能扫描、allowlist 字符串）。
- 单独的 prompt injection，若未链式导致 3.1 结果。
- 在所选姿态允许范围内的行为（例如原生桌面姿态下 agent 进程可读用户主目录）。
- 操作者显式关闭保护（`strict_isolation=False`、把 Host 绑到 `0.0.0.0`、关闭鉴权）。
- 第三方技能 / 插件在操作者未审查的情况下作恶。
- Stage C 未实施本身（已公开声明 `not_implemented`）。

## 4. 部署加固

- 匹配隔离姿态与输入信任：不可信入站优先整进程容器。
- 以非 root 跑容器；不要把 Docker socket 或密钥目录可写挂进容器。
- Host 默认 loopback；局域网暴露必须叠加密钥与网络安全。
- 审查第三方技能的代码，而不是只读 SKILL.md。
- 不要把 API 密钥写入主配置或版本库。

## 5. 披露

- **协调披露窗口**：自报告起 90 天，或修复发布之日，以先到者为准。
- **渠道**：GitHub Security Advisories。
- **致谢**：除非报告者要求匿名，否则在发行说明中致谢。
