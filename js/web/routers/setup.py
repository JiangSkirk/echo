"""Setup wizard API router — model connection diagnostics and testing."""

from __future__ import annotations

import asyncio
import sys
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.agent.tool_executor import CONTROL_SETUP_STATE_TOOL
from js.echo.effect_interpreter import ModelEffect, ToolEffect
from js.models.providers import ChatMessage
from js.utils.log import get_logger
from js.web.auth import memory_owner, require_auth_dep, require_setup_auth, runtime_owner
from js.web.deps import get_agent, get_settings

logger = get_logger("js.web.setup")
router = APIRouter(tags=["setup"])


async def _mutate_setup_state(
    action: str,
    auth: dict[str, Any],
) -> tuple[dict[str, Any], Any]:
    """Execute one setup mutation through the model-hidden Echo tool boundary."""
    agent = get_agent()
    runtime = agent.echo_runtime
    context = runtime.build_context(
        channel=f"setup_{action}",
        owner_key_hash=runtime_owner(auth),
        role=str(auth.get("role") or "setup"),
        capabilities=(CONTROL_SETUP_STATE_TOOL,),
    )
    _message, result = await runtime.execute_tool_effect(
        ToolEffect.from_arguments(
            CONTROL_SETUP_STATE_TOOL,
            {"action": action},
            user_input=f"Apply setup state action: {action}",
            allowed_tools=(CONTROL_SETUP_STATE_TOOL,),
        ),
        context,
    )
    if not result.success:
        status_code = result.metadata.get("status_code", 500)
        if not isinstance(status_code, int) or not 400 <= status_code <= 599:
            status_code = 500
        raise HTTPException(status_code, result.error or "Setup state update failed")
    return dict(result.metadata), context


@router.get("/api/setup/first-start")
async def setup_first_start(auth: dict[str, Any] = Depends(require_setup_auth)) -> dict[str, Any]:
    """Return first-run status plus diagnostics for the wizard."""
    settings = get_settings()

    # Gather diagnostics
    diagnostics: dict[str, Any] = {
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "local_providers_detected": [],
        "has_configured_models": bool(settings.providers),
    }

    return {
        "first_run_completed": settings.first_run_completed,
        "diagnostics": diagnostics,
    }


@router.post("/api/setup/complete")
async def setup_complete(auth: dict[str, Any] = Depends(require_setup_auth)) -> dict[str, Any]:
    metadata, context = await _mutate_setup_state("complete", auth)
    result: dict[str, Any] = {"success": True}
    key_reference = metadata.get("admin_key_ref")
    if isinstance(key_reference, str) and key_reference:
        admin_key = get_agent().take_setup_admin_key(
            key_reference,
            owner_key_hash=context.owner_key_hash,
            product_id=context.product_id,
            session_id=context.session_id,
        )
        if not admin_key:
            raise HTTPException(500, "初始化凭据交接失败，请重试。")
        # Returned once so the browser can persist it (the bootstrap window is
        # now closed; subsequent requests must carry this key).
        result["admin_key"] = admin_key
    return result


@router.post("/api/setup/reset")
async def setup_reset(auth: dict[str, Any] = Depends(require_setup_auth)) -> dict[str, Any]:
    """Reset first-run flag so the wizard can be run again.

    Refuses to reset when an admin key already exists, preventing the
    abuse chain: reset → delete all admin keys → bootstrap re-entry.
    """
    from js.web.auth import AuthManager

    settings = get_settings()
    auth_mgr = AuthManager(settings.state_dir)

    # Only allow bootstrap (no admin key exists) OR admin-privileged users.
    # Non-admin users must not reach this endpoint when admin keys exist,
    # closing the "delete all admin keys → user triggers reset" privilege
    # escalation chain.
    if auth_mgr.has_admin() and auth.get("role") != "admin":
        raise HTTPException(
            403,
            "需要管理员权限才能重置初始化状态。",
        )

    if auth_mgr.has_admin():
        raise HTTPException(
            409,
            "已存在管理员密钥时无法重置首次运行状态。请先吊销所有管理员密钥再重试。",
        )
    await _mutate_setup_state("reset", auth)
    return {"success": True}


@router.post("/api/setup/test-model")
async def test_model(
    body: dict[str, Any], auth: dict[str, Any] = Depends(require_auth_dep)
) -> dict[str, Any]:
    """Test whether a specific model is reachable and responsive.

    Sends a minimal completion request and measures latency.
    """
    model_id = (body.get("model_id") or "").strip()
    if not model_id:
        raise HTTPException(400, "缺少必填参数 model_id")

    agent = get_agent()
    router = agent.router

    # Resolve model → provider
    decision = await router.select_model(preferred=model_id)
    if not decision or not decision.provider:
        raise HTTPException(404, f"未找到模型 '{model_id}'")

    # Grab context window from config
    cfg = router.get_model_config(model_id)
    context_window = cfg.context_window if cfg else 0

    # Check if provider has a valid API key (for cloud providers)
    provider_config = None
    for p in agent.settings.providers:
        if p.name == decision.provider_name:
            provider_config = p
            break
    is_cloud = provider_config and not getattr(decision.provider, "_is_local", False)
    if is_cloud:
        api_key = provider_config.api_key if provider_config else ""
        if not api_key or api_key in ("", "YOUR_API_KEY"):
            return {
                "ok": False,
                "latency_ms": 0,
                "error": "API Key 未配置，请在模型设置中添加",
                "context_window": context_window,
                "provider": decision.provider_name,
                "actual_model": decision.model,
                "response_preview": "",
                "needs_config": True,
            }

    # Send a minimal chat request — use a slightly longer prompt and no max_tokens
    # cap so reasoning models (gemma-4, deepseek-r1, etc.) have room to answer.
    start = time.time()
    try:
        messages = [ChatMessage(role="user", content="Say exactly: OK")]
        owner = memory_owner(auth) or "local-user"
        runtime = agent.echo_runtime
        runtime_context = runtime.build_context(
            channel="setup_model_test",
            owner_key_hash=owner,
            session_id=f"setup-model:{uuid.uuid4()}",
            run_id=str(uuid.uuid4()),
            role=str(auth.get("role") or "setup"),
            capabilities=(),
        )
        response_call = runtime.execute_model_effect(
            ModelEffect(
                messages=tuple(messages),
                model=model_id,
                temperature=0.7,
            ),
            runtime_context,
        )
        response = await asyncio.wait_for(response_call, timeout=60.0)
        latency_ms = int((time.time() - start) * 1000)
        content = (response.content or "").strip()
        # Some models return empty content when reasoning takes all tokens.
        # Accept any non-empty response or the literal "OK" case-insensitively.
        ok = bool(content) or "ok" in content.lower()
        error = None
        if not ok:
            # Distinguish between "empty because of length limit" and "genuine failure"
            error = "模型返回了空响应，可能是推理内容占用了输出额度"
        return {
            "ok": ok,
            "latency_ms": latency_ms,
            "error": error,
            "context_window": context_window,
            "provider": decision.provider_name,
            "actual_model": decision.model,
            "response_preview": content[:100]
            or getattr(response, "reasoning_content", "")[:100]
            or "",
        }
    except TimeoutError:
        return {
            "ok": False,
            "latency_ms": 60000,
            "error": "连接超时（60秒），模型可能繁忙或无法响应",
            "context_window": context_window,
            "provider": decision.provider_name,
            "actual_model": decision.model,
            "response_preview": "",
        }
    except Exception as e:
        latency_ms = int((time.time() - start) * 1000)
        err_str = str(e)
        # Map common error messages to Chinese for better UX
        if "401" in err_str or "Unauthorized" in err_str:
            err_msg = "API Key 无效或未授权"
        elif "404" in err_str or "Not Found" in err_str:
            err_msg = "模型不存在或已下线"
        elif "429" in err_str or "Rate limit" in err_str:
            err_msg = "请求太频繁，请稍后再试"
        elif "Connection" in err_str or "ConnectError" in err_str:
            err_msg = "无法连接到模型服务，请检查网络"
        else:
            err_msg = f"{type(e).__name__}: {err_str[:120]}"
        return {
            "ok": False,
            "latency_ms": latency_ms,
            "error": err_msg,
            "context_window": context_window,
            "provider": decision.provider_name,
            "actual_model": decision.model,
            "response_preview": "",
        }
