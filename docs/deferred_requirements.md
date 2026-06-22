# 延期需求记录（Deferred Requirements）

> 目的：登记当前明确"暂不实现、仅保留需求"的功能，避免遗忘；待时机成熟再排期。
>
> JS Agent 是本地个人 Agent Harness，延期需求不影响 Harness 核心驾驭能力。
>
> 决策日期：2026-06-05
> 决策人：用户（工厂负责人）
> 当前优先级：**P0 装好即用 / P1 知识·SOP 问答助手**。以下各项在 P1 完成并稳定前不实现。

---

## 1. NiceLabel Pro 4.1 条码自动化（原路线图 P2）

- **需求**：用 JS Agent Harness 驱动 NiceLabel Pro 4.1 完成条码 / 标签的自动生成与打印，服务工厂日常贴标。
- **现状**：**暂不实现**。NiceLabel Pro 仅 Windows 平台；当前开发与验收均在 macOS。
- **依赖 / 前置**：
  - 需要 Windows 部署能力（见第 2 项）。
  - 需确定 NiceLabel 的自动化接口形态（命令行 / Automation API / .NET SDK / 文件触发）——**待调研后补充**。
  - 需要数据来源对接（哪张表 / 哪个字段 → 条码内容）。
- **触发条件（何时重启）**：P1 上线并稳定后，且具备 Windows 测试机与一台连接 NiceLabel 的打印环境。
- **验收设想（待细化）**：给定数据 → 生成正确条码标签 → 打印成功；异常可重试与降级，失败有清晰中文提示。

## 2. Windows 部署支持

- **需求**：JS Agent Harness 可在 Windows 上安装运行（面向工厂 Windows 机器 / NiceLabel 环境）。
- **现状**：**暂不实现**。当前为 macOS 开发 + fresh-install 验收。
- **前置**：
  - Windows 版启动脚本（对应 `scripts/macos_start.sh`）。
  - 路径 / 服务 / 权限的跨平台处理核对（venv、状态目录、端口、开机自启等）。
- **触发条件**：需要落地第 1 项（NiceLabel），或需在 Windows 机器上部署时。

---

## 备注

- 以上仅为**需求登记**，不代表已排期，也不进入当前迭代。
- **跨平台原则**（配置驱动、不写死 macOS 路径）在日常开发中持续遵守，以降低将来 Windows 化的成本。
- 相关背景见项目记忆 `js-agent-factory-goal.md` 与 `docs/roadmap_quality_system.md`。
