#!/usr/bin/env python3
"""真实模型集成测试脚本

直接调用真实的 DeepSeek API 和 LM Studio 本地模型，验证所有功能。
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from js.agent import JSAgent
from js.config import JSSettings
from js.orchestration.fleet import AgentFleet, AgentRole
from js.tools.webbridge import WebBridgeTool


def get_settings() -> JSSettings:
    """Load settings from default config."""
    try:
        return JSSettings.from_file()
    except Exception:
        state_dir = Path.home() / ".js" / "state"
        workspace = Path.home() / ".js" / "workspace"
        return JSSettings(workspace=workspace, state_dir=state_dir)


async def _safe_run(agent: JSAgent, prompt: str, model: str | None = None) -> tuple[bool, str]:
    """Safely run agent and return (success, details)."""
    try:
        state = await agent.run(prompt, model=model)
        detail = f"status={state.status}, turns={state.turn_count}, model={state.model}"
        return state.status == "completed", detail
    except Exception as e:
        return False, f"Exception: {type(e).__name__}: {e}"


async def test_cloud_basic() -> tuple[bool, str]:
    print("\n[TEST 1] Cloud model (deepseek) basic chat...")
    agent = JSAgent(get_settings())
    try:
        ok, detail = await _safe_run(agent, "Say 'Hello from DeepSeek' and nothing else.", "deepseek/deepseek-v4-flash")
        print(f"  {detail}")
        return ok, detail
    finally:
        await agent.close()


async def test_local_basic() -> tuple[bool, str]:
    print("\n[TEST 2] Local model (lmstudio) basic chat...")
    agent = JSAgent(get_settings())
    try:
        ok, detail = await _safe_run(agent, "Say 'Hello from LM Studio' and nothing else.", "lmstudio/qwen3.5-122b-a10b")
        print(f"  {detail}")
        return ok, detail
    finally:
        await agent.close()


async def test_cloud_streaming() -> tuple[bool, str]:
    print("\n[TEST 3] Cloud model streaming...")
    agent = JSAgent(get_settings())
    try:
        chunks = []
        async for chunk in agent.chat_stream("Count to 3.", model="deepseek/deepseek-v4-flash"):
            chunks.append(chunk)
            if len(chunks) >= 10:
                break
        print(f"  chunks={len(chunks)}")
        return len(chunks) > 0, f"chunks={len(chunks)}"
    except Exception as e:
        return False, f"Exception: {e}"
    finally:
        await agent.close()


async def test_local_streaming() -> tuple[bool, str]:
    print("\n[TEST 4] Local model streaming...")
    agent = JSAgent(get_settings())
    try:
        chunks = []
        async for chunk in agent.chat_stream("Count to 3.", model="lmstudio/qwen3.5-122b-a10b"):
            chunks.append(chunk)
            if len(chunks) >= 10:
                break
        print(f"  chunks={len(chunks)}")
        return len(chunks) > 0, f"chunks={len(chunks)}"
    except Exception as e:
        return False, f"Exception: {e}"
    finally:
        await agent.close()


async def test_cloud_with_tools() -> tuple[bool, str]:
    print("\n[TEST 5] Cloud model with tools...")
    agent = JSAgent(get_settings())
    try:
        ok, detail = await _safe_run(
            agent,
            "What files are in the current directory? Use file_list tool.",
            "deepseek/deepseek-v4-flash",
        )
        print(f"  {detail}")
        return ok, detail
    finally:
        await agent.close()


async def test_local_with_tools() -> tuple[bool, str]:
    print("\n[TEST 6] Local model with tools...")
    agent = JSAgent(get_settings())
    try:
        ok, detail = await _safe_run(
            agent,
            "What files are in the current directory? Use file_list tool.",
            "lmstudio/qwen3.5-122b-a10b",
        )
        print(f"  {detail}")
        return ok, detail
    finally:
        await agent.close()


async def test_model_switch() -> tuple[bool, str]:
    print("\n[TEST 7] Model switching in same session...")
    agent = JSAgent(get_settings())
    try:
        ok1, d1 = await _safe_run(agent, "Say 'cloud turn'.", "deepseek/deepseek-v4-flash")
        ok2, d2 = await _safe_run(agent, "Say 'local turn'.", "lmstudio/qwen3.5-122b-a10b")
        print(f"  Turn1: {d1}")
        print(f"  Turn2: {d2}")
        return ok1 and ok2, f"turn1={d1}, turn2={d2}"
    finally:
        await agent.close()


async def test_fleet_mixed_models() -> tuple[bool, str]:
    print("\n[TEST 8] Fleet with mixed cloud/local models...")
    settings = get_settings()
    main_agent = JSAgent(settings)
    fleet = AgentFleet(settings)

    try:
        # Copy providers from main agent to each fleet worker
        def _copy_providers(target_agent: JSAgent) -> None:
            for pname, prov in main_agent.router._providers.items():
                models = [m for mid, (p, m) in main_agent.router._model_map.items() if p == pname and "/" not in mid]
                if pname not in target_agent.router._providers:
                    target_agent.router.add_provider(pname, prov, models)

        fleet.update_agent_config({
            "coder": "deepseek/deepseek-v4-flash",
            "reviewer": "lmstudio/qwen3.5-122b-a10b",
        })

        coder = fleet.spawn("coder-1", role=AgentRole.CODER)
        reviewer = fleet.spawn("reviewer-1", role=AgentRole.REVIEWER)

        _copy_providers(coder.agent)
        _copy_providers(reviewer.agent)

        print(f"  Coder model: {coder.model}")
        print(f"  Reviewer model: {reviewer.model}")

        results = await asyncio.gather(
            _safe_run(coder.agent, "Write a Python hello function", coder.model),
            _safe_run(reviewer.agent, "Review this code: def hello(): print('hi')", reviewer.model),
            return_exceptions=True,
        )

        ok = True
        details = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                print(f"  Agent {i} FAILED: {r}")
                ok = False
                details.append(f"agent{i}=Exception:{r}")
            else:
                success, detail = r
                print(f"  Agent {i}: {detail}")
                if not success:
                    ok = False
                details.append(f"agent{i}={detail}")

        return ok, ", ".join(details)
    finally:
        await main_agent.close()


async def test_webbridge_available() -> tuple[bool, str]:
    print("\n[TEST 9] WebBridge availability...")
    agent = JSAgent(get_settings())
    try:
        web_tools = [name for name in agent.registry._handlers if name.startswith("web_")]
        print(f"  Web tools registered: {web_tools}")

        wb = WebBridgeTool()
        result = await wb.list_tabs(session="test")
        print(f"  WebBridge list_tabs: success={result.success}")
        if not result.success:
            print(f"  WebBridge error: {result.error}")

        return len(web_tools) >= 8 and result.success, f"tools={len(web_tools)}, list_tabs={result.success}"
    except Exception as e:
        return False, f"Exception: {e}"
    finally:
        await agent.close()


async def test_cloud_with_webbridge() -> tuple[bool, str]:
    print("\n[TEST 10] Cloud model with WebBridge...")
    agent = JSAgent(get_settings())
    try:
        ok, detail = await _safe_run(
            agent,
            "Navigate to https://example.com and tell me the page title. Use web_navigate then web_snapshot.",
            "deepseek/deepseek-v4-flash",
        )
        print(f"  {detail}")
        return ok, detail
    finally:
        await agent.close()


async def test_local_with_webbridge() -> tuple[bool, str]:
    print("\n[TEST 11] Local model with WebBridge...")
    agent = JSAgent(get_settings())
    try:
        ok, detail = await _safe_run(
            agent,
            "Navigate to https://example.com and tell me the page title. Use web_navigate then web_snapshot.",
            "lmstudio/qwen3.5-122b-a10b",
        )
        print(f"  {detail}")
        return ok, detail
    finally:
        await agent.close()


async def test_fleet_researcher_webbridge() -> tuple[bool, str]:
    print("\n[TEST 12] Fleet researcher with WebBridge...")
    settings = get_settings()
    main_agent = JSAgent(settings)
    fleet = AgentFleet(settings)

    try:
        def _copy_providers(target_agent: JSAgent) -> None:
            for pname, prov in main_agent.router._providers.items():
                models = [m for mid, (p, m) in main_agent.router._model_map.items() if p == pname and "/" not in mid]
                if pname not in target_agent.router._providers:
                    target_agent.router.add_provider(pname, prov, models)

        researcher = fleet.spawn("researcher-1", role=AgentRole.RESEARCHER, model="deepseek/deepseek-v4-flash")
        _copy_providers(researcher.agent)

        web_tools = [name for name in researcher.agent.registry._handlers if name.startswith("web_")]
        print(f"  Researcher web tools: {web_tools}")

        ok, detail = await _safe_run(
            researcher.agent,
            "Search for Python 3.12 release notes online and summarize.",
            researcher.model,
        )
        print(f"  {detail}")
        return ok, detail
    finally:
        await main_agent.close()


async def main():
    print("=" * 60)
    print("JS Agent Real Model Integration Test")
    print("=" * 60)

    tests = [
        ("Cloud basic chat", test_cloud_basic),
        ("Local basic chat", test_local_basic),
        ("Cloud streaming", test_cloud_streaming),
        ("Local streaming", test_local_streaming),
        ("Cloud with tools", test_cloud_with_tools),
        ("Local with tools", test_local_with_tools),
        ("Model switch", test_model_switch),
        ("Fleet mixed models", test_fleet_mixed_models),
        ("WebBridge available", test_webbridge_available),
        ("Cloud + WebBridge", test_cloud_with_webbridge),
        ("Local + WebBridge", test_local_with_webbridge),
        ("Fleet researcher + WebBridge", test_fleet_researcher_webbridge),
    ]

    results = []
    for name, test_fn in tests:
        try:
            ok, detail = await test_fn()
            results.append((name, ok, detail))
        except Exception as e:
            print(f"  UNEXPECTED ERROR: {e}")
            results.append((name, False, f"Unexpected: {e}"))

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    passed = 0
    for name, ok, detail in results:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}: {detail}")
        if ok:
            passed += 1

    print(f"\nTotal: {passed}/{len(results)} passed")
    return passed == len(results)


if __name__ == "__main__":
    ok = asyncio.run(main())
    sys.exit(0 if ok else 1)
