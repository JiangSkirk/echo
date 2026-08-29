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
from js.web.auth import memory_owner, require_setup_auth, require_user_write, runtime_owner
from js.web.deps import get_agent, get_settings
from js.web.schemas import SetupTestModelRequest

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


def _onboarding_payload(settings: Any, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build consistent onboarding fields from settings and optional mutation metadata."""
    status = str(
        (metadata or {}).get("onboarding_status")
        or getattr(settings, "onboarding_status", None)
        or "pending"
    )
    first_run = bool(
        (metadata or {}).get("first_run_completed")
        if metadata is not None and "first_run_completed" in metadata
        else getattr(settings, "first_run_completed", False)
    )
    # Terminal states dismiss the wizard; pending/in_progress keep blocking.
    blocking = status not in {"completed", "skipped"}
    return {
        "onboarding_status": status,
        "first_run_completed": first_run,
        "wizard_blocking": blocking,
    }


async def _setup_mutation_response(
    action: str,
    auth: dict[str, Any],
) -> dict[str, Any]:
    """Mutate setup state and return success + onboarding fields (+ one-time admin key)."""
    metadata, context = await _mutate_setup_state(action, auth)
    settings = get_settings()
    result: dict[str, Any] = {"success": True, **_onboarding_payload(settings, metadata)}
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


@router.get("/api/setup/first-start")
async def setup_first_start(auth: dict[str, Any] = Depends(require_setup_auth)) -> dict[str, Any]:
    """Return first-run / onboarding status plus diagnostics for the wizard.

    ``onboarding_status`` is the server-side authority:
    pending | in_progress | completed | skipped.
    localStorage must not be treated as the sole source of truth.
    """
    settings = get_settings()

    # Gather diagnostics — GET is side-effect free (no local model probes).
    diagnostics: dict[str, Any] = {
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "local_providers_detected": [],
        "has_configured_models": bool(settings.providers),
    }

    return {
        **_onboarding_payload(settings),
        "diagnostics": diagnostics,
    }


@router.post("/api/setup/complete")
async def setup_complete(auth: dict[str, Any] = Depends(require_setup_auth)) -> dict[str, Any]:
    if auth.get("role") == "guest":
        raise HTTPException(
            403,
            "Guest role is read-only; authenticate to complete setup",
        )
    return await _setup_mutation_response("complete", auth)


@router.post("/api/setup/skip")
async def setup_skip(auth: dict[str, Any] = Depends(require_setup_auth)) -> dict[str, Any]:
    """Dismiss the wizard without configuring providers/models.

    Skip only means the user deferred initial configuration. It must not:
    create providers, invent model API keys, expand Work permissions,
    create workspaces, or approve tools/leases.
    """
    if auth.get("role") == "guest":
        raise HTTPException(
            403,
            "Guest role is read-only; authenticate to skip setup",
        )
    return await _setup_mutation_response("skip", auth)


@router.post("/api/setup/start")
async def setup_start(auth: dict[str, Any] = Depends(require_setup_auth)) -> dict[str, Any]:
    """Mark onboarding as in_progress when the user enters the wizard flow."""
    if auth.get("role") == "guest":
        raise HTTPException(
            403,
            "Guest role is read-only; authenticate to start setup",
        )
    settings = get_settings()
    status = str(getattr(settings, "onboarding_status", "pending") or "pending")
    # Mid-flow start is idempotent; terminal states use /reopen from Settings.
    if status in {"completed", "skipped"}:
        return {"success": True, **_onboarding_payload(settings)}
    return await _setup_mutation_response("start", auth)


@router.post("/api/setup/reopen")
async def setup_reopen(auth: dict[str, Any] = Depends(require_setup_auth)) -> dict[str, Any]:
    """Re-open the model wizard after skip/complete without reopening auth bootstrap.

    Used by Settings → 重新运行向导. Keeps first_run_completed=True so admin
    bootstrap cannot be re-entered, while wizard_blocking becomes true again.
    """
    if auth.get("role") == "guest":
        raise HTTPException(
            403,
            "Guest role is read-only; authenticate to reopen setup",
        )
    if auth.get("role") != "admin":
        raise HTTPException(
            403,
            "需要管理员权限才能重新打开初始化向导。",
        )
    return await _setup_mutation_response("reopen", auth)


@router.post("/api/setup/reset")
async def setup_reset(auth: dict[str, Any] = Depends(require_setup_auth)) -> dict[str, Any]:
    """Reset first-run flag so the wizard can be run again.

    Refuses to reset when an admin key already exists, preventing the
    abuse chain: reset → delete all admin keys → bootstrap re-entry.
    """
    from js.web.auth import AuthManager

    if auth.get("role") == "guest":
        raise HTTPException(
            403,
            "Guest role is read-only; authenticate to reset setup",
        )

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
    return {"success": True, **_onboarding_payload(get_settings())}


@router.post("/api/setup/test-model")
async def test_model(
    body: SetupTestModelRequest, auth: dict[str, Any] = Depends(require_user_write)
) -> dict[str, Any]:
    """Test whether a specific model is reachable and responsive.

    Sends a minimal completion request and measures latency.
    """
    model_id = body.model_id.strip()
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
