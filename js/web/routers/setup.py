"""Setup wizard API router — model connection diagnostics and testing."""

from __future__ import annotations

import asyncio
import sys
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from js.models.discovery import LocalModelDiscovery
from js.models.providers import ChatMessage
from js.utils.log import get_logger
from js.web.auth import require_auth_dep, require_setup_auth
from js.web.deps import get_agent, get_settings

logger = get_logger("js.web.setup")
router = APIRouter(tags=["setup"])


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

    # Probe local providers (lightweight, short timeout)
    discovery = LocalModelDiscovery(timeout=3.0)
    try:
        discovered = await discovery.discover_all()
        for d in discovered:
            diagnostics["local_providers_detected"].append({
                "type": d.provider_type,
                "url": d.base_url,
                "models": len(d.models),
            })
    except Exception as e:
        logger.debug(f"Local discovery failed during first-start check: {e}")
    finally:
        await discovery.close()

    return {
        "first_run_completed": settings.first_run_completed,
        "diagnostics": diagnostics,
    }


@router.post("/api/setup/complete")
async def setup_complete(auth: dict[str, Any] = Depends(require_setup_auth)) -> dict[str, Any]:
    from js.web.auth import AuthManager

    settings = get_settings()
    # Ensure a usable admin key exists BEFORE closing the bootstrap window, so
    # completing setup can never leave a "first_run_completed but no admin key"
    # state that locks the whole site behind 401.
    admin_key: str | None = None
    if settings.security.api_key_required:
        admin_key = await asyncio.to_thread(
            AuthManager(settings.state_dir).ensure_bootstrap_admin_key
        )
    settings.first_run_completed = True
    try:
        await asyncio.to_thread(settings.save, None, ["first_run_completed"])
    except PermissionError:
        try:
            fallback = settings.state_dir / "config.yaml"
            await asyncio.to_thread(settings.save, fallback, ["first_run_completed"])
        except OSError as e:
            raise HTTPException(
                500,
                f"Unable to save settings: home directory and state directory are both read-only. {e}",
            ) from e
    except OSError as e:
        raise HTTPException(500, f"Unable to save settings: {e}") from e
    result: dict[str, Any] = {"success": True}
    if admin_key:
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
            "Admin role required to reset setup state.",
        )

    if auth_mgr.has_admin():
        raise HTTPException(
            409,
            "Cannot reset first-run when admin keys exist. "
            "Revoke all admin keys first, then retry.",
        )
    settings.first_run_completed = False
    try:
        await asyncio.to_thread(settings.save, None, ["first_run_completed"])
    except PermissionError:
        try:
            fallback = settings.state_dir / "config.yaml"
            await asyncio.to_thread(settings.save, fallback, ["first_run_completed"])
        except OSError as e:
            raise HTTPException(500, f"Unable to save settings: {e}") from e
    except OSError as e:
        raise HTTPException(500, f"Unable to save settings: {e}") from e
    return {"success": True}


@router.post("/api/setup/test-model")
async def test_model(body: dict[str, Any], auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Test whether a specific model is reachable and responsive.

    Sends a minimal completion request and measures latency.
    """
    model_id = (body.get("model_id") or "").strip()
    if not model_id:
        raise HTTPException(400, "model_id is required")

    agent = get_agent()
    router = agent.router

    # Resolve model → provider
    decision = await router.select_model(preferred=model_id)
    if not decision or not decision.provider:
        raise HTTPException(404, f"Model '{model_id}' not found")

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
        response = await asyncio.wait_for(
            decision.provider.chat(
                messages=[ChatMessage(role="user", content="Say exactly: OK")],
                model=decision.model,
                temperature=0.7,
            ),
            timeout=60.0,
        )
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
            "response_preview": content[:100] or getattr(response, "reasoning_content", "")[:100] or "",
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
