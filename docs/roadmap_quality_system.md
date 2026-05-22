# JS Agent 质量体系建设路线图

> 原则：不堆新功能，专注补齐体系化能力 —— 测得准、看得清、控得住、恢复快。

---

## Phase 1：可观测性与安全基线（2-3 天）

### 1.1 可观测性仪表盘补全
**目标**：让系统内部状态对外可见、可度量、可告警。

- **Skill 级 Metrics**
  - 在 `js/utils/metrics.py` 新增 `skill_latency_seconds`、`skill_success_rate_gauge`、`skill_usage_total`
  - 在 `js/skills/manager.py` execute() 中注入 metrics 采集
  - Web UI `/api/skills/metrics` 端点暴露聚合数据

- **Memory 质量 Metrics**
  - 记忆命中率、检索延迟、fallback 到 keyword 的比例
  - `enhanced_store.py` 中埋点

- **Provider SLO 看板**
  - 每个 provider 的可用性百分比、P50/P95/P99 延迟
  - `/api/metrics/providers` 端点

- **Web UI 仪表盘**
  - 在现有 `index.html` 新增：Provider 健康热力图、Skill 成功率排行、Memory 检索质量趋势

### 1.2 安全策略测试体系
**目标**：每次代码变更后，自动验证防御策略不被绕过。

- **Red-team 测试套件** `tests/test_redteam.py`
  - 收集常见越狱模板：DAN、Developer Mode、Ignore previous instructions、Roleplay
  - 编码绕过：Base64、Hex、ROT13、URL encode 的危险命令
  - 注入攻击：工具结果中嵌入 prompt injection
  - 断言：所有越狱尝试必须被 `BehaviorGuard` 或 `DefenseStrategy` 拦截

- **Fuzz 测试** `tests/test_fuzz_guard.py`
  - 使用 `hypothesis` 或自定义生成器，对 `BehaviorGuard.check()` 输入随机/变异的工具名和参数
  - 目标：发现 Guard 的崩溃路径或漏报

- **安全回归 CI**
  - `pytest tests/test_redteam.py tests/test_fuzz_guard.py tests/test_strategies.py -v`

---

## Phase 2：Provider 健康与 Skill 权限体系（2-3 天）

### 2.1 Provider 健康检查 & 降级模式
**目标**：单点故障不影响服务，用户可感知降级。

- **Degraded Mode**
  - 当所有 provider 不可用时，`JSAgent` 进入 `degraded` 状态
  - 禁用非必要工具（web_search、browser），保留 read-only 工具
  - Web UI 状态栏显示 "⚠️ 模型连接异常，仅只读模式"
  - `/api/status` 返回 `degraded: true` 和具体原因

- **Failover 测试**
  - `tests/test_provider_failover.py`：模拟主 provider 故障，验证自动切换到备用 provider
  - 模拟主 provider 间歇性故障（5xx/429），验证断路器 + 重试 + 降级链路

- **Health Probe 强化**
  - `health_check()` 不仅测 `/models`，还测轻量级 `/embeddings` 或 `/chat/completions` 心跳
  - 支持配置自定义 health endpoint

### 2.2 Skill 权限与测试体系
**目标**：Skill 不是黑盒，权限可控、行为可验证。

- **Skill 沙箱强化**
  - `SandboxExecutor` 增加 `--network=none` 模式（使用 `unshare` 或 `firejail` 包装，macOS 用 `sandbox-exec` fallback）
  - 文件系统沙箱：`chroot` 到 skill 目录 + workspace，禁止绝对路径写入（除 `/tmp`）
  - `SkillSpec` 的 `network_allowed` 和 `timeout_seconds` 真正生效

- **Skill 回归测试自动化**
  - `js/skills/tester.py` 增强：不仅生成 stub，还能从 `SKILL.md` 的 `examples` 中提取输入/期望输出
  - `tests/test_skill_regression.py`：加载所有 builtin skills，执行其 examples，验证输出匹配
  - CI  nightly 运行：所有已安装 skill 的回归测试

- **Skill 权限审计**
  - 安装时扫描 `network_allowed`、`timeout_seconds`、`risk_flags`
  - Web UI Skills 面板显示权限图标（🔒 无网络、⏱️ 超时限制、⚠️ 风险标记）

---

## Phase 3：记忆质量与任务恢复（3-4 天）

### 3.1 记忆质量控制体系
**目标**：记住该记的，忘该忘的，检索准、不冲突。

- **相关性反馈循环**
  - `MemoryStore` 新增 `feedback(memory_id, helpful: bool)` API
  - 用户可在 Web UI 对检索结果点 👍/👎，影响该记忆的权重/优先级
  - 定期（dreaming cycle）根据反馈调整 embedding 权重

- **冲突检测**
  - 存储新记忆时，检索相似记忆；如果值 contradict（用 LLM 或规则判断），标记为 `conflicting`
  - Web UI 显示冲突记忆对，提示用户确认

- **LRU / 重要性淘汰**
  - `MemoryStore` 实现真正的 LRU：按 `last_accessed` 排序，超过 `max_memories` 时淘汰最旧的
  - 结合 `importance` 字段：重要记忆（用户明确标记或高频访问）延长生命周期
  - 可配置策略：`lru`、`importance_weighted`、`time_decay`

- **检索质量评估**
  - `tests/test_memory_quality.py`：构造已知语料库，查询，计算 top-k 准确率
  - 记录 retrieval precision/recall 到 metrics

### 3.2 真实任务 Benchmark
**目标**：可量化地衡量 Agent 在真实任务上的表现，防止退化。

- **Benchmark 框架** `benchmarks/`
  - `benchmarks/tasks/`：定义任务（输入、期望输出/行为、评分标准）
  - `benchmarks/runner.py`：自动化运行 Agent，收集结果，计算分数
  - 任务类型：
    - 文件操作（创建、读取、修改、删除）
    - 代码生成（写函数、修复 bug、添加测试）
    - 信息检索（搜索、总结、对比）
    - 多步推理（数学、逻辑、规划）

- **Golden Answer 机制**
  - 每个任务有 `expected_files`、`expected_output_contains`、`expected_tool_calls`
  - 评分：精确匹配（100%）、部分匹配（50%）、失败（0%）

- **回归基准**
  - `benchmarks/baseline.json`：记录当前版本的分数
  - CI 中运行 benchmark，如果分数下降 > 5%，标记为失败

### 3.3 任务中断恢复能力
**目标**：Agent 可以被随时中断，状态不丢，恢复后可继续。

- **AgentState 持久化**
  - `AgentState` 序列化到 SQLite（`state_runs` 表）：`session_id`, `run_id`, `turn_count`, `messages`, `tool_results`, `status`
  - `agent.run()` 开始时写入 `status=running`，结束时更新为 `completed`/`error`/`interrupted`

- **Cancel API**
  - `/api/cancel/{session_id}` POST 端点
  - `JSAgent` 内部维护 `cancel_tokens: dict[str, asyncio.Event]`
  - `run()` 每轮检查 `cancel_tokens[session_id].is_set()`，如果被取消则优雅退出

- **Checkpoint / Resume**
  - 每个 turn 完成后自动 checkpoint（保存当前 messages 和 tool_results）
  - `agent.resume(session_id)`：从数据库恢复状态，继续执行
  - Web UI 显示历史运行列表，支持 "继续对话"

- **SIGTERM 优雅关闭**
  - 收到 SIGTERM 时：
    1. 停止接受新请求
    2. 等待活跃 run 完成当前 turn 并 checkpoint
    3. 关闭 provider 连接
    4. 退出

---

## 实施优先级

```
Week 1
├── Day 1-2: Phase 1.1 可观测性补全 + Phase 1.2 Red-team 测试
├── Day 3-4: Phase 2.1 Provider 降级模式 + Failover 测试
├── Day 5:   Phase 2.2 Skill 沙箱强化 + 回归测试

Week 2
├── Day 1-2: Phase 3.1 记忆质量控制（反馈循环 + LRU + 冲突检测）
├── Day 3-4: Phase 3.2 Benchmark 框架 + 真实任务集
├── Day 5:   Phase 3.3 Cancel API + Checkpoint/Resume
```

## 验收标准

- [ ] Web UI 能看到 Provider 健康热力图、Skill 成功率、Memory 检索质量
- [ ] `pytest tests/test_redteam.py` 100% 通过
- [ ] 拔掉主 Provider 网线，Agent 自动降级，5 秒内切换到备用 Provider
- [ ] 恶意 Skill 无法访问网络或写出工作区外文件
- [ ] 所有 Builtin Skill 通过回归测试
- [ ] Memory 检索 top-3 准确率达到可接受基线（>70%）
- [ ] Benchmark 分数不低于基线
- [ ] 中断一个 10-turn 任务，恢复后从第 6 turn 继续
