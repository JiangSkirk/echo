# Echo Golden Fixtures

本目录存放 **`/api/chat` 与 `/ws` 外部契约的逐字节金标**。Echo-only 运行时必须产出与这些 fixture **完全相同**的字节序列。

任何 fixture 不一致 → Echo 不得上线。

---

## 用途定位

- **唯一兼容标尺**:`/api/chat` JSON 响应、`/ws` 帧序列的字段、顺序、类型、空值都被冻结于此。
- **不是性能基准**:省 Token、内存数字由 `benchmarks/runner --mock` 实测,不在本目录。
- **不是错误样例库**:已知错误场景(413、auth_required、provider_error)纳入 fixture,但属于"正常错误响应"的契约部分。

## 文件命名约定

```
tests/echo/golden/
  README.md                        # 本文件
  api_chat_<scenario>.json         # 单文件单场景,/api/chat 用例
  ws_<scenario>.json               # 单文件单场景,/ws 用例
```

`<scenario>` 取小写蛇形;一个 fixture 文件只覆盖一种场景。

### T1 必录清单(10 个)

| 文件 | 场景 |
| --- | --- |
| `api_chat_success.json` | 普通成功对话(单轮、无工具) |
| `api_chat_empty.json` | 空 message 校验 |
| `api_chat_413.json` | 超过 256 KiB payload |
| `api_chat_auth_required.json` | 缺鉴权 / require_user_write 拒绝 |
| `api_chat_provider_error.json` | 模型层抛错 → `humanize_error` 包装到 500 |
| `ws_message.json` | 单帧 `message` 完整往返 |
| `ws_stream_success.json` | 多帧 `stream` 含 status / token / usage / done；无 thinking 的模型不录入 thinking_delta |
| `ws_stream_error.json` | 流式中途模型抛错 |
| `ws_ping.json` | 心跳帧 |
| `ws_auth_fail.json` | WS 握手鉴权失败 |

## JSON Schema 约束

每个 fixture 文件结构:

```json
{
  "scenario": "api_chat_success",
  "kind": "api_chat",
  "input": {
    "method": "POST",
    "path": "/api/chat",
    "headers": {},
    "body": {},
    "frames_in": []
  },
  "expected": {
    "status": 200,
    "headers": {},
    "body": {},
    "frames_out": []
  },
  "mock": {
    "provider": "openai",
    "scripted_chunks": []
  },
  "notes": ""
}
```

**字段顺序冻结**:`scenario / kind / input / expected / mock / notes`。Python `json.dumps(..., sort_keys=False, indent=2, ensure_ascii=False)` 保持稳定。

说明:
- `kind`:取 `"api_chat"` 或 `"ws"`。
- `input.method` / `input.path`:`api_chat` 用 HTTP 方法/路径;`ws` 时 `method` 为 `null`、`path` 为 `"/ws"`。
- `input.frames_in`:仅 `ws` 用,客户端 → 服务端帧序列。
- `expected.status` / `expected.body`:仅 `api_chat` 用。
- `expected.frames_out`:仅 `ws` 用,服务端 → 客户端按顺序帧。
- `mock.scripted_chunks`:喂给 `_ScriptedProvider` 的 chunk 序列。

## 动态字段政策(逐字节兼容的关键)

`/api/chat` 与 `/ws` 真实响应里有以下动态字段,**录制时必须钉死固定源**,否则没法逐字节比对:

| 字段 | 处理 |
| --- | --- |
| `session_id` | mock 用固定 UUID `"00000000-0000-0000-0000-000000000001"` |
| `request_id` / `frame_id` | 计数器从 1 开始 |
| `created_at` / 时间戳 | 固定 epoch `1700000000` 或 ISO `"2023-11-14T22:13:20Z"` |
| `tokens.input / output / total` | mock provider 固定输出 |
| `cost` | 用固定汇率表,公式确定 |
| `nonce` / `lease_id` / `mac` | T7 引入前置零字符串占位;T7 后写真实校验逻辑 |

**禁止**:在 fixture 里写真实当下时间、真实随机 UUID、真实 token 计数。一旦录入,任何后续修改必须同步刷新 fixture 文件并在 `ECHO_FINAL_REPLACEMENT_REPORT.md` 记录原因。

## Mock Provider 规则

录制工具 `scripts/record_echo_golden.py`(T1 任务 #2 产出)用以下手法保证确定性:

1. **复用 `tests/web/test_chat_router.py` 的 `_ScriptedProvider` 模板** — 用 `AsyncMock(agent.run)` 把每一次 LLM 调用替换成预定义 chunk 列表。
2. **monkeypatch 时间源** — `time.time` / `datetime.utcnow` / `uuid.uuid4` 用 fixed seed。
3. **monkeypatch 计数器** — `request_id / frame_id` 显式从 1 开始。
4. **关闭真实网络** — 测试进程不允许出站 socket;mock provider 全本地。

详细脚本契约在 T1 任务 #2 产出时再写,本 README 不内联代码。

## 回放规则(`test_golden_fixtures.py` 行为)

- 对每个 fixture:
  1. 用相同 mock seed 启动 `FastAPI()` + `include_router(chat.router)` + `TestClient`(api_chat)或 `WebSocketTestSession`(ws)。
  2. 喂入 `input.body` / `input.frames_in`。
  3. 收集 `expected.body` / `expected.frames_out`。
  4. **逐字段、逐帧、按顺序断言相等**,不做模糊匹配。
- 任何一处字段不一致 → 测试 fail,T1 门禁未通过,禁止开 T2-S4。
- 任何字段类型变化(如 `int` → `str`)按破坏性变更处理,需在 `ECHO_FINAL_REPLACEMENT_REPORT.md` 记录原因。

## 触动边界

- **可写**:本目录全部 fixture + 本 README + `tests/echo/test_golden_fixtures.py`(T1 #5)+ `scripts/record_echo_golden.py`(T1 #2)。
- **可读不可改**:`js/web/routers/chat.py`、`js/web/server.py`、`js/agent/*`、`js/models/*`、`js/security/*`、`js/tools/*`、`tests/web/*`、`tests/conftest.py`。
- **绝对禁止**:`pyproject.toml`、`requirements*.txt`、`.claude/settings*.json`、`.playwright-mcp/`。

## 红线

1. fixture 录入后,任何"不一致"必须**优先怀疑 Echo 实现错**,不是改 fixture。
2. 如果旧引擎本身有 bug 需要修,先讨论是否纳入兼容契约 — bug 修了 fixture 才改,**不许"为了兼容把 bug 留住"**反向重写。
3. 录制脚本必须可重入:同样的 seed 跑两次产出**完全一致**的 fixture(diff 应为空)。
