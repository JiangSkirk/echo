#!/usr/bin/env python3
"""Quick diagnosis script for JS Agent model connectivity issues."""

import asyncio
from pathlib import Path

import httpx

# Check config
config_path = Path.home() / ".config" / "js" / "config.yaml"
print(f"Config exists: {config_path.exists()}")
if config_path.exists():
    import yaml
    cfg = yaml.safe_load(config_path.read_text())
    print(f"  Providers: {[p.get('name') for p in cfg.get('providers', [])]}")
    print(f"  Memory max chars: {cfg.get('memory', {}).get('max_memory_chars')}")

# Check LM Studio directly
async def check_lmstudio():
    url = "http://127.0.0.1:1234/v1/models"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
            print(f"LM Studio /v1/models: {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                models = [m.get("id") for m in data.get("data", [])]
                print(f"  Available models: {models}")
            else:
                print(f"  Response: {r.text[:200]}")
    except Exception as e:
        print(f"LM Studio connection failed: {e}")

async def check_webui():
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get("http://127.0.0.1:8000/api/models")
            print(f"Web UI /api/models: {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                print(f"  Providers: {len(data.get('providers', []))}")
                for p in data.get('providers', []):
                    print(f"    {p.get('name')}: online={p.get('online')}, models={len(p.get('models', []))}")
            else:
                print(f"  Response: {r.text[:200]}")
    except Exception as e:
        print(f"Web UI connection failed: {e}")

asyncio.run(check_lmstudio())
asyncio.run(check_webui())
