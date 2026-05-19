# 部署指南

本文档介绍如何使用 Docker 和 Docker Compose 部署 JS Agent。

---

## Docker 快速开始

### 1. 构建镜像

```bash
docker build -t js-agent:latest .
```

### 2. 运行容器

```bash
docker run -d \
  --name js-agent \
  -p 8080:8080 \
  -v "$(pwd)/workspace:/app/workspace" \
  -v "$(pwd)/state:/app/state" \
  -e JS_LOG_LEVEL=INFO \
  --restart unless-stopped \
  js-agent:latest
```

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

如需添加更多环境变量，可在 `docker-compose.yaml` 的 `environment` 节中配置，或通过 `.env` 文件加载：

```yaml
env_file:
  - .env
```

---

## 持久化卷说明

JS Agent 使用两个数据卷来实现状态持久化：

| 卷 | 容器内路径 | 用途 |
|----|-----------|------|
| `workspace` | `/app/workspace` | 存放 Agent 运行时生成的工作文件、代码检查点（checkpoints）等 |
| `state` | `/app/state` | 存放应用状态数据，如会话状态、缓存等 |

**重要提示**：

- 这两个目录在 `.dockerignore` 中已被排除，不会被复制到镜像内，确保数据始终从宿主机卷挂载。
- 删除容器时，挂载卷的数据会保留在宿主机上，不会丢失。
- 备份时只需备份宿主机上的 `./workspace` 和 `./state` 目录即可。

---

## 健康检查

生产环境服务已内置健康检查，每 30 秒探测一次 `http://localhost:8080/api/status`。如果连续 3 次检查失败，容器会被标记为 `unhealthy`，便于编排系统（如 Kubernetes 或 Docker Swarm）自动处理故障恢复。

手动检查健康状态：

```bash
docker inspect --format='{{.State.Health.Status}}' js-agent
```
