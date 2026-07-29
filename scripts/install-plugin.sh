#!/usr/bin/env bash
# JS Agent Plugin Installer
# Usage (preferred):
#   ./install-plugin.sh <plugin-url>
# Do not pipe this script from the network into bash.

set -e

PLUGIN_URL="${1:-}"
API_ENDPOINT="${JS_AGENT_API:-http://127.0.0.1:8000/api/plugins/install}"
API_KEY="${JS_AGENT_KEY:-}"

if [ -z "$PLUGIN_URL" ]; then
    echo "Usage: $0 <plugin-url>"
    echo "  plugin-url: URL to a .zip or .tar.gz plugin archive"
    echo ""
    echo "Environment variables:"
    echo "  JS_AGENT_API  - API endpoint (default: http://127.0.0.1:8000/api/plugins/install)"
    echo "  JS_AGENT_KEY  - API key if authentication is required"
    exit 1
fi

echo "Installing plugin from: $PLUGIN_URL"
echo "API endpoint: $API_ENDPOINT"

HEADERS=(-H "Content-Type: application/json")
if [ -n "$API_KEY" ]; then
    HEADERS+=(-H "X-API-Key: $API_KEY")
fi

RESPONSE=$(curl -fsSL "${HEADERS[@]}" -X POST "$API_ENDPOINT" \
    -d "{\"url\": \"$PLUGIN_URL\"}" 2>/dev/null || true)

if [ -z "$RESPONSE" ]; then
    echo "Error: Failed to connect to JS Agent API at $API_ENDPOINT"
    echo "Make sure the server is running and accessible."
    exit 1
fi

# Try to parse JSON
if command -v python3 >/dev/null 2>&1; then
    SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('success','false'))" 2>/dev/null || echo "false")
    MESSAGE=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('message',''))" 2>/dev/null || echo "")
    PLUGIN_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('plugin_id',''))" 2>/dev/null || echo "")
elif command -v jq >/dev/null 2>&1; then
    SUCCESS=$(echo "$RESPONSE" | jq -r '.success // "false"')
    MESSAGE=$(echo "$RESPONSE" | jq -r '.message // ""')
    PLUGIN_ID=$(echo "$RESPONSE" | jq -r '.plugin_id // ""')
else
    # Fallback: grep
    SUCCESS="unknown"
    MESSAGE="$RESPONSE"
fi

if [ "$SUCCESS" = "True" ] || [ "$SUCCESS" = "true" ]; then
    echo "✅ $MESSAGE"
    if [ -n "$PLUGIN_ID" ]; then
        echo "Plugin ID: $PLUGIN_ID"
    fi
else
    echo "❌ Install failed"
    echo "Response: $RESPONSE"
    exit 1
fi
