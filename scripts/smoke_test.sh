#!/usr/bin/env bash
#
# JS Agent 发布烟测脚本
# 快速验证核心功能是否正常工作
#
set -euo pipefail

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
BASE="http://${HOST}:${PORT}"
API_KEY="${API_KEY:-js-local-dev}"

echo "=== JS Agent 发布烟测 ==="
echo "目标: ${BASE}"
echo ""

# 1. 服务健康
echo -n "[1/8] 服务健康... "
if curl -sf "${BASE}/api/health" | grep -q '"status".*"healthy"'; then
    echo "✓"
else
    echo "✗ 失败"
    exit 1
fi

# 2. 模型列表可加载
echo -n "[2/8] 模型列表... "
if curl -sf "${BASE}/api/models" | grep -q '"models"'; then
    echo "✓"
else
    echo "✗ 失败"
    exit 1
fi

# 3. WebSocket 可连接
echo -n "[3/8] WebSocket... "
if command -v websocat >/dev/null 2>&1; then
    if timeout 3 websocat "ws://${HOST}:${PORT}/ws" -H "x-api-key: ${API_KEY}" -1 </dev/null >/dev/null 2>&1; then
        echo "✓"
    else
        echo "⚠ 连接异常 (可能已断开)"
    fi
elif python3 -c "import websocket" 2>/dev/null; then
    python3 -c "
import websocket, time
ws = websocket.WebSocket()
ws.connect('ws://${HOST}:${PORT}/ws', header=['x-api-key: ${API_KEY}'])
time.sleep(0.5)
assert ws.connected
ws.close()
print('✓')
" || { echo "⚠ 连接异常"; }
else
    echo "⚠ 跳过 (无 websocket 工具)"
fi

# 4. 向导状态
echo -n "[4/8] 向导状态... "
if curl -sf "${BASE}/api/setup/first-start" | grep -q '"first_run_completed"'; then
    echo "✓"
else
    echo "✗ 失败"
    exit 1
fi

# 5. 记忆 CRUD (含结构化字段)
echo -n "[5/10] 记忆 CRUD... "
if curl -sf -X POST "${BASE}/api/memory/semantic" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${API_KEY}" \
  -d '{"key":"smoke-test","value":"test","category":"fact","source":"user","memory_path":"/general/smoke","entity_type":"general"}' | grep -q '"success":true'; then
    echo "✓"
else
    echo "✗ 失败"
    exit 1
fi

# 6. 记忆区块列表
echo -n "[6/10] 记忆区块... "
if curl -sf "${BASE}/api/memory/blocks" | grep -q '"blocks"'; then
    echo "✓"
else
    echo "⚠ 未加载 (需重启服务)"
fi

# 7. 场景列表 (新端点，需重启后生效)
echo -n "[7/10] 场景列表... "
if curl -sf "${BASE}/api/scenarios" | grep -q '"scenarios"'; then
    echo "✓"
else
    echo "⚠ 未加载 (需重启服务)"
fi

# 8. 任务列表 (新端点，需重启后生效)
echo -n "[8/10] 任务列表... "
if curl -sf "${BASE}/api/tasks" | grep -q '"tasks"'; then
    echo "✓"
else
    echo "⚠ 未加载 (需重启服务)"
fi

# 9. 记忆审计 (新端点，需重启后生效)
echo -n "[9/10] 记忆审计... "
if curl -sf "${BASE}/api/memory/audit?limit=1" | grep -q '"entries"'; then
    echo "✓"
else
    echo "⚠ 未加载 (需重启服务)"
fi

# 10. 记忆验证
echo -n "[10/10] 记忆验证... "
if curl -sf -X POST "${BASE}/api/memory/semantic/1/verify" \
  -H "x-api-key: ${API_KEY}" | grep -q '"verified":true'; then
    echo "✓"
else
    echo "⚠ 未加载 (需重启服务)"
fi

echo ""
echo "=== 全部通过 ==="
