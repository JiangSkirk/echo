# 部署指南

本文档介绍如何部署 JS Agent Harness——一套围绕本地模型提供记忆、上下文胶囊、工具执行、安全护栏、模型切换和任务复盘的本地个人 Agent Harness。

---

## Docker 快速开始

### 1. 构建镜像

```bash
docker build -t js-agent:latest .
```

不带 `--target` 的构建会产出最后一个 stage，即加固过的 production 镜像（非 root、冻结依赖）。开发镜像需显式指定 `--target dev`。

### 2. 运行容器

```bash
docker run -d \
  --name js-agent \
  -p 127.0.0.1:8000:8000 \
  -v "$(pwd)/workspace:/app/workspace" \
  -v "$(pwd)/state:/app/state" \
  -v "$(pwd)/state-work:/home/appuser/.js-work" \
  -e JS_LOG_LEVEL=INFO \
  -e JS_STATE_DIR=/app/state \
  -e JS_APPSHELL_PROVISION_KEY=1 \
  --restart unless-stopped \
  js-agent:latest
```

端口默认只绑定回环地址；确需对外暴露时去掉 `127.0.0.1:` 前缀，并务必保持 API key 鉴权开启。

首次启动若还没有 admin，镜像会把共享管理密钥写入 `./state/bootstrap_admin_key.txt`（0600）。用该密钥登录后再访问 `/api/*`。首次成功登录（`/api/appshell/session` 或 `/api/auth/session`）后该明文文件会被删除；`/api/appshell/bootstrap` 铸造时会保留文件，方便无头环境读取。

### 2b. 不可信内容部署姿态

默认 `docker-compose.yaml` 只做回环绑定。接触入站消息、未审查 MCP 或共享主机时，用加固整进程姿态：

```bash
docker compose -f docker-compose.hardened.yaml up -d --build
```

`docker-compose.hardened.yaml` 打开 `read_only`、`cap_drop: [ALL]`、`no-new-privileges`，并且不挂载 Docker socket。

本机诊断：

```bash
js doctor --security
```

`security.untrusted_ingestion_policy` 默认 `warn`：原生桌面可以启用不可信入站表面，但状态页持续警示。设为 `enforce` 时，非 `container-full` 姿态拒绝这些表面。详见 [SECURITY.md](../SECURITY.md)。

### 3. 查看日志

```bash
docker logs -f js-agent
```

### 4. 停止并移除容器

```bash
docker stop js-agent
docker rm js-agent
```

---

## Docker Compose 使用说明

### 启动生产环境

```bash
docker compose up -d js-agent
```

### 启动开发环境（支持热重载）

```bash
docker compose --profile dev up -d js-agent-dev
```

开发环境会将当前目录挂载到容器的 `/app` 目录，并启用代码热重载。任何本地代码修改都会即时生效，无需重新构建镜像。

### 查看服务状态

```bash
docker compose ps
```

### 查看服务日志

```bash
# 查看所有服务日志
docker compose logs -f

# 仅查看 js-agent 日志
docker compose logs -f js-agent
```

### 停止并移除服务

```bash
docker compose down
```

### 重新构建镜像

```bash
docker compose up -d --build js-agent
```

---

## 环境变量说明

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `JS_LOG_LEVEL` | `INFO` | 日志输出级别，可选值：`DEBUG`、`INFO`、`WARNING`、`ERROR`、`CRITICAL` |
| `JS_STATE_DIR` | `/app/state` | 容器内状态目录；compose 将其挂到宿主机 `./state` |
| `JS_APPSHELL_PROVISION_KEY` | `1`（镜像/compose） | 为 `1`/`true`/`yes`/`on` 时，AppShell 启动若无 admin 则铸造共享管理密钥并写入 `bootstrap_admin_key.txt`。本地默认关闭。该文件在首次 `/api/appshell/session` 或 `/api/auth/session` 登录后删除。 |

如需添加更多环境变量，可在 `docker-compose.yaml` 的 `environment` 节中配置，或通过 `.env` 文件加载：

```yaml
env_file:
  - .env
```

---

## 持久化卷说明

JS Agent Harness 使用三个数据卷来实现状态持久化：

| 卷 | 容器内路径 | 用途 |
|----|-----------|------|
| `workspace` | `/app/workspace` | 存放 Agent 运行时生成的工作文件、代码检查点（checkpoints）等 |
| `state` | `/app/state` | 存放 Personal 应用状态数据，如会话状态、记忆、缓存、bootstrap 密钥等 |
| `state-work` | `/home/appuser/.js-work` | 存放 Work 模式状态：凭据、记忆、ledger。不挂此卷则容器重建后 Work store 被清空 |

**重要提示**：

- 这些目录在 `.dockerignore` 中已被排除，不会被复制到镜像内，确保数据始终从宿主机卷挂载。
- 删除容器时，挂载卷的数据会保留在宿主机上，不会丢失。
- 备份时只需备份宿主机上的 `./workspace`、`./state` 和 `./state-work` 目录即可。
- 开发 profile（`js-agent-dev`）以 root 运行，Work home 挂到 `./state-work-dev:/root/.js-work`，不要与生产卷混用。

---

## 健康检查

生产环境服务已内置健康检查，每 30 秒探测一次容器内 `http://localhost:8000/`（未认证的静态首页；`/api/status`、`/api/health` 需要凭证，健康检查拿不到 200）。如果连续 3 次检查失败，容器会被标记为 `unhealthy`，便于编排系统（如 Kubernetes 或 Docker Swarm）自动处理故障恢复。

手动检查健康状态：

```bash
docker inspect --format='{{.State.Health.Status}}' js-agent
```

---

## Skill Promotion Operations（v0.1.5）

生产环境下，自动 curator 与 evolver **不会**直接改 skill 信任等级或覆盖 entry 文件；它们只产生 `proposed` 事件，需要操作员批准后才会通过 5 步门禁应用。

### 日常流程

1. `js skill promote list` 查看 open 提案；`--all` 可看历史全部事件，`--limit N` 控制条数。
2. `js skill promote show <event_id>` 查看完整事件 JSON（含 `details`、`reason`、`source`、`variant_id`、`artifact_path`）。
3. 决策：
   - 通过 → `js skill promote approve <event_id>`，触发 `SkillManager.apply_proposal`（跑 5 步 gate；失败时不修改 trust/文件）。
   - 拒绝 → `js skill promote reject <event_id> --reason "..."`，只改事件 status，不动 skill。
   - 已 apply 的事件要回滚 → `js skill promote revert <event_id>`，恢复 trust 与 entry 文件（若有 variant artifact 备份）。

### `failed_step` 含义

| 值 | 含义 | 应对 |
|---|---|---|
| `protected` | 命中 builtin 或 `hermes:` 受保护 skill | 永久不允许自动晋升，直接拒绝。 |
| `validate` | SKILL.md / entry 文件缺失或格式错误 | 修复源 skill 后重新生成提案。 |
| `security` | `scan_skill` 或 `runtime_security_check` 命中风险模式 | 审查 `details.risk_flags` / `details.runtime_warnings`；若误报可手动 `trust_skill`，否则保留 quarantine。 |
| `tests` | `run_skill_tests` 失败（pytest 在隔离临时目录跑） | 查看 `details.tests` 中的 pytest 输出。 |
| `smoke` | `execute_skill` 失败或超时 | 看 `details.smoke_error`；`details.timeout=True` 表示卡死，默认 30 s 截断，可通过构造 `PromotionGate(smoke_timeout=N)` 调整。 |

### 回滚边界

- `revert_promotion` 仅对 `status="applied"` 的事件生效。
- 信任降级（trust 反向 flip）总能恢复；entry 文件恢复依赖 `<spec.path>/.promotion_backups/<event_id>/<entry>` 备份，该备份在 `apply_proposal` 成功覆盖文件时写入。
- 若 skill 目录已被人手动改过（直接编辑 `main.py`），`revert` 仍会用备份覆盖；**操作前请用 `git diff` 确认 skill 目录**。

### Web API 权限

- `GET /api/skills/promotions` 和 `GET /api/skills/promotions/{event_id}` 走普通认证，但只能看自己 owner（`memory_owner(auth)`）的事件。
- `POST .../approve`、`POST .../reject`、`POST .../revert` 必须 admin 凭证（`require_admin`）。
- 响应正文不携带 `owner_key_hash`，owner 隔离由后端自动注入。
- 路由注册在 `/api/skills/{skill_id}` 通配之前，不会被吞。
