"""Memory API router — CRUD, audit, conflicts, metrics, embedder recovery.

Unknown/forbidden client fields (owner, mode, workspace, role) are rejected
with HTTP 422 via the strict request models.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from js.agent.tool_executor import CONTROL_MEMORY_MUTATE_TOOL
from js.echo.effect_interpreter import ToolEffect
from js.utils.log import get_logger
from js.web.auth import (
    memory_owner,
    require_admin,
    require_admin_write,
    require_auth_dep,
    require_user_write,
    runtime_owner,
)
from js.web.deps import get_agent, optional_query_session_id, require_path_session_id
from js.web.runtime_context import web_channel
from js.web.schemas import (
    MemoryBlockRequest,
    MemoryCompressionProposalRequest,
    MemoryFilePutRequest,
    MemoryProposalApproveRequest,
    MemorySemanticCreateRequest,
    MemorySemanticUpdateRequest,
)

logger = get_logger("js.web.memory")


def _refuse_ambient_memory_under_enforce() -> None:
    from js.orin.stage_c import product_memory_cell_required

    agent = get_agent()
    if product_memory_cell_required(getattr(agent.settings, "orin", None)):
        raise HTTPException(503, "ambient Memory API is closed under orin.enforce")


router = APIRouter(
    tags=["memory"],
    dependencies=[Depends(_refuse_ambient_memory_under_enforce)],
)


async def _mutate_memory(
    action: str,
    payload: dict[str, Any],
    auth: dict[str, Any],
    *,
    session_id: str = "",
) -> dict[str, Any]:
    """Execute a private memory mutation through an opaque Echo payload."""
    agent = get_agent()
    from js.orin.stage_c import product_memory_cell_required

    if product_memory_cell_required(getattr(agent.settings, "orin", None)):
        raise HTTPException(503, "ambient Memory API is closed under orin.enforce")
    owner = runtime_owner(auth)
    runtime = agent.echo_runtime
    context = runtime.build_context(
        channel=web_channel(agent.settings, f"memory_{action}"),
        owner_key_hash=owner,
        session_id=session_id,
        role=str(auth.get("role") or "user"),
        capabilities=(CONTROL_MEMORY_MUTATE_TOOL,),
    )
    payload_ref = agent.stage_memory_mutation_payload(
        owner,
        payload,
        product_id=context.product_id,
        session_id=context.session_id,
    )
    if not isinstance(payload_ref, str) or not payload_ref:
        raise HTTPException(503, "Memory mutation admission is unavailable")
    try:
        _message, result = await runtime.execute_tool_effect(
            ToolEffect.from_arguments(
                CONTROL_MEMORY_MUTATE_TOOL,
                {"action": action, "payload_ref": payload_ref},
                user_input=f"Apply owner-bound memory action: {action}",
                allowed_tools=(CONTROL_MEMORY_MUTATE_TOOL,),
            ),
            context,
        )
    finally:
        agent.discard_memory_mutation_payload(
            payload_ref,
            owner,
            product_id=context.product_id,
            session_id=context.session_id,
        )

    if not result.success:
        status_code = result.metadata.get("status_code", 500)
        if not isinstance(status_code, int) or not 400 <= status_code <= 599:
            status_code = 500
        raise HTTPException(status_code, result.error or "Memory update failed")
    result_ref = result.metadata.get("result_ref")
    if not isinstance(result_ref, str) or not result_ref:
        raise HTTPException(500, "Memory result handoff failed")
    response = agent.take_memory_mutation_result(
        result_ref,
        owner,
        product_id=context.product_id,
        session_id=context.session_id,
    )
    if not isinstance(response, dict):
        raise HTTPException(500, "Memory result handoff failed")
    return response


@router.get("/api/memory")
async def memory(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    agent = get_agent()
    owner = memory_owner(auth)
    return {"context": agent.memory.get_context_string(max_chars=4000, owner_key_hash=owner)}


@router.get("/api/memory/enhanced")
async def memory_enhanced(
    session_id: str | None = Depends(optional_query_session_id),
    limit: int = Query(default=20, ge=1, le=100),
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    agent = get_agent()
    owner = memory_owner(auth)
    result: dict[str, Any] = {
        "context": agent.memory.get_context_string(max_chars=4000, owner_key_hash=owner),
        "episodes": [
            {
                "id": e.id,
                "session_id": e.session_id,
                "summary": e.summary,
                "topics": e.topics,
                "tokens_used": e.tokens_used,
                "turn_count": e.turn_count,
                "created_at": e.created_at,
                "importance": e.importance,
            }
            for e in agent.memory.get_episodes(limit=limit, owner_key_hash=owner)
        ],
        "dream_logs": agent.memory.get_dream_logs(limit=limit, owner_key_hash=owner),
        "semantic_memories": agent.memory.get_all_semantic(limit=limit, owner_key_hash=owner),
        "working_memories": agent.memory.get_all_working(limit=limit, owner_key_hash=owner),
        "memory_files": agent.memory.list_memory_files(owner_key_hash=owner),
    }
    if session_id:
        result["session_working"] = agent.memory.get_working(
            session_id, limit=20, owner_key_hash=owner
        )
    return result


@router.get("/api/memory/files")
async def memory_file_list(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    agent = get_agent()
    return {"files": agent.memory.list_memory_files(owner_key_hash=memory_owner(auth))}


@router.get("/api/memory/files/{name}")
async def memory_file_get(
    name: str, auth: dict[str, Any] = Depends(require_auth_dep)
) -> dict[str, Any]:
    agent = get_agent()
    try:
        content = agent.memory.read_memory_file(name, owner_key_hash=memory_owner(auth))
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return {"name": name, "content": content}


@router.put("/api/memory/files/{name}")
async def memory_file_put(
    name: str, body: MemoryFilePutRequest, auth: dict[str, Any] = Depends(require_admin_write)
) -> dict[str, Any]:
    content = body.content
    return await _mutate_memory(
        "file_put",
        {"name": name, "content": content},
        auth,
    )


@router.post("/api/memory/semantic")
async def memory_semantic_post(
    body: MemorySemanticCreateRequest, auth: dict[str, Any] = Depends(require_admin_write)
) -> dict[str, Any]:
    key = body.key.strip()
    value = body.value.strip()
    if not key or not value:
        raise HTTPException(400, "key and value are required")
    return await _mutate_memory(
        "semantic_create",
        {
            "key": key,
            "value": value,
            "category": body.category.strip(),
            "source": body.source.strip(),
            "memory_path": body.memory_path,
            "entity_type": body.entity_type,
            "entity_name": body.entity_name,
            "parent_id": body.parent_id,
            "relation_type": body.relation_type,
            "evidence": body.evidence,
        },
        auth,
    )


@router.delete("/api/memory/semantic/{memory_id}")
async def memory_semantic_delete(
    memory_id: int, auth: dict[str, Any] = Depends(require_admin_write)
) -> dict[str, Any]:
    return await _mutate_memory(
        "semantic_delete",
        {"memory_id": memory_id},
        auth,
    )


@router.put("/api/memory/semantic/{memory_id}")
async def memory_semantic_put(
    memory_id: int,
    body: MemorySemanticUpdateRequest,
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    value = body.value.strip()
    if not value:
        raise HTTPException(400, "value is required")
    return await _mutate_memory(
        "semantic_update",
        {
            "memory_id": memory_id,
            "value": value,
            "category": body.category,
            "memory_path": body.memory_path,
            "entity_type": body.entity_type,
            "entity_name": body.entity_name,
            "parent_id": body.parent_id,
            "relation_type": body.relation_type,
        },
        auth,
    )


@router.get("/api/memory/search")
async def memory_search(
    q: str = "",
    category: str | None = None,
    path_prefix: str | None = None,
    limit: int = 10,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Search semantic memories with optional block filtering."""
    agent = get_agent()
    results = await asyncio.to_thread(
        agent.memory.search_semantic,
        query=q,
        category=category,
        limit=limit,
        path_prefix=path_prefix,
        block_priority=True,
        owner_key_hash=memory_owner(auth),
    )
    return {
        "query": q,
        "results": [
            {
                "id": r.id,
                "key": r.key,
                "value": r.value,
                "category": r.category,
                "confidence": r.confidence,
                "source": r.source,
                "memory_path": r.memory_path,
                "entity_type": r.entity_type,
                "entity_name": r.entity_name,
                "parent_id": r.parent_id,
                "relation_type": r.relation_type,
                "last_verified_at": r.last_verified_at,
            }
            for r in results
        ],
    }


# ── Structured Blocks ──


@router.get("/api/memory/blocks")
async def memory_blocks(
    prefix: str | None = None,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Return hierarchical block statistics."""
    agent = get_agent()
    blocks = await asyncio.to_thread(
        agent.memory.get_blocks, prefix, owner_key_hash=memory_owner(auth)
    )
    return {"blocks": blocks}


@router.get("/api/memory/block/{path_prefix:path}")
async def memory_block_contents(
    path_prefix: str,
    limit: int = 50,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Return memories under a given path prefix."""
    agent = get_agent()
    memories = await asyncio.to_thread(
        agent.memory.get_by_block, path_prefix, limit, owner_key_hash=memory_owner(auth)
    )
    return {"path_prefix": path_prefix, "memories": memories}


@router.post("/api/memory/semantic/{memory_id}/verify")
async def memory_semantic_verify(
    memory_id: int,
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    """Mark a memory as verified (updates last_verified_at)."""
    return await _mutate_memory(
        "semantic_verify",
        {"memory_id": memory_id},
        auth,
    )


# ── Proposed changes (review queue) ──


@router.get("/api/memory/proposals")
async def memory_proposals(
    status: str = "pending",
    limit: int = 50,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """List staged memory proposals awaiting (or past) user confirmation."""
    agent = get_agent()
    proposals = await asyncio.to_thread(
        agent.memory.list_proposals, status, memory_owner(auth), limit
    )
    return {"proposals": proposals, "status": status}


@router.post("/api/memory/proposals/{proposal_id}/approve")
async def memory_proposal_approve(
    proposal_id: int,
    body: MemoryProposalApproveRequest | None = None,
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    """Approve a pending proposal, committing it to the memory library.

    An optional JSON body acts as edit-before-confirm overrides, e.g.
    ``{"value": "...", "memory_path": "/people/family", "category": "fact"}``.
    """
    overrides = body.model_dump(exclude_none=True) if body is not None else None
    return await _mutate_memory(
        "proposal_approve",
        {"proposal_id": proposal_id, "overrides": overrides},
        auth,
    )


@router.post("/api/memory/proposals/{proposal_id}/reject")
async def memory_proposal_reject(
    proposal_id: int,
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    """Reject a pending proposal."""
    return await _mutate_memory(
        "proposal_reject",
        {"proposal_id": proposal_id},
        auth,
    )


@router.post("/api/memory/organize")
async def memory_organize(
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    """Manually organize memories from the recent conversation buffer.

    Pulls the same recent turns the idle/dream cycle would process (without
    consuming them) and runs structured extraction → proposal queue. Returns
    counts so the UI can show progress (turns analyzed, staged, auto-applied).
    """
    return await _mutate_memory("organize", {}, auth)


# ── Block operations (move / merge) ──


@router.post("/api/memory/blocks/move")
async def memory_block_move(
    body: MemoryBlockRequest,
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    """Re-path every memory under one block prefix to another."""
    src = body.src.strip()
    dst = body.dst.strip()
    if not src or not dst:
        raise HTTPException(400, "src and dst are required")
    return await _mutate_memory(
        "block_move",
        {"src": src, "dst": dst},
        auth,
    )


@router.post("/api/memory/blocks/merge")
async def memory_block_merge(
    body: MemoryBlockRequest,
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    """Merge one block into another (all memories adopt the target prefix)."""
    src = body.src.strip()
    dst = body.dst.strip()
    if not src or not dst:
        raise HTTPException(400, "src and dst are required")
    return await _mutate_memory(
        "block_merge",
        {"src": src, "dst": dst},
        auth,
    )


# ── Audit & Conflicts ──


@router.get("/api/memory/audit")
async def memory_audit(
    memory_id: int | None = None,
    table: str = "semantic",
    limit: int = 50,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Query audit log for memory changes."""
    agent = get_agent()
    entries = await asyncio.to_thread(
        agent.memory.get_audit_log,
        memory_id=memory_id,
        table_name=table,
        limit=limit,
        owner_key_hash=memory_owner(auth),
    )
    return {"entries": entries}


@router.get("/api/memory/conflicts")
async def memory_conflicts(
    limit: int = 50,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """List all memories marked as conflicting."""
    agent = get_agent()
    conflicts = await asyncio.to_thread(
        agent.memory.get_conflicting_memories,
        limit=limit,
        owner_key_hash=memory_owner(auth),
    )
    return {"conflicts": conflicts}


# ── Metrics & Recovery ──


@router.get("/api/memory/metrics")
async def memory_metrics(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    """Return memory subsystem metrics for observability dashboard."""
    agent = get_agent()
    embedder_health = agent.memory.embedder.health()

    # Pull Prometheus metric samples (best-effort)
    from prometheus_client import REGISTRY

    def _sample(name: str, label_filters: dict[str, str] | None = None) -> float:
        total = 0.0
        try:
            for family in REGISTRY.collect():
                if family.name == name:
                    for sample in family.samples:
                        if label_filters is None or all(
                            sample.labels.get(k) == v for k, v in label_filters.items()
                        ):
                            total += sample.value
        except Exception:
            logger.warning("Operation failed", exc_info=True)
        return total

    return {
        "embedder": {
            "provider": embedder_health.provider,
            "active": embedder_health.active,
            "fallback_provider": embedder_health.fallback_provider,
            "failure_count": embedder_health.failure_count,
        },
        "prometheus": {
            "memory_store_latency_seconds_count": _sample("memory_store_latency_seconds_count"),
            "memory_store_latency_seconds_sum": _sample("memory_store_latency_seconds_sum"),
            "memory_retrieve_latency_seconds_count": _sample(
                "memory_retrieve_latency_seconds_count"
            ),
            "memory_retrieve_latency_seconds_sum": _sample("memory_retrieve_latency_seconds_sum"),
            "memory_search_fallback_total": _sample("memory_search_fallback_total"),
        },
        "counts": {
            "episodes": len(
                agent.memory.get_episodes(limit=1000, owner_key_hash=memory_owner(auth))
            ),
            "semantic_memories": len(
                agent.memory.get_all_semantic(limit=1000, owner_key_hash=memory_owner(auth))
            ),
            "working_memories": len(
                agent.memory.get_all_working(limit=1000, owner_key_hash=memory_owner(auth))
            ),
            "dream_logs": len(
                agent.memory.get_dream_logs(limit=1000, owner_key_hash=memory_owner(auth))
            ),
        },
    }


@router.post("/api/memory/embedder/recover")
async def memory_embedder_recover(
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    """Manually trigger embedder recovery probe."""
    return await _mutate_memory("embedder_recover", {}, auth)


# ------------------------------------------------------------------
# Session Capsule
# ------------------------------------------------------------------


@router.get("/api/sessions/{session_id}/capsule")
async def get_session_capsule(
    session_id: str = Depends(require_path_session_id),
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Get the session capsule for the current session (owner-isolated).

    Lite MVP: returns capsule text, owner, updated_at, version, source_range,
    generated_by_model, recent_turns_kept, estimated_tokens_saved,
    refresh_reason, secrets_redacted, and enabled flag. Drift, TTL, and
    quality metadata are computed/assessed at persistence time but are not
    returned by this endpoint.
    """
    agent = get_agent()
    owner = memory_owner(auth)
    capsule = await asyncio.to_thread(
        agent.memory.get_capsule,
        session_id=session_id,
        owner_key_hash=owner,
    )
    if capsule is None:
        return {
            "session_id": session_id,
            "capsule_text": "",
            "updated_at": None,
            "enabled": agent.settings.memory.capsule_enabled,
        }
    return {
        "session_id": capsule["session_id"],
        "capsule_text": capsule["capsule_text"],
        "updated_at": capsule["updated_at"],
        "version": capsule.get("version"),
        "source_range": capsule.get("source_range"),
        "generated_by_model": capsule.get("generated_by_model"),
        "recent_turns_kept": capsule.get("recent_turns_kept"),
        "estimated_tokens_saved": capsule.get("estimated_tokens_saved"),
        "refresh_reason": capsule.get("refresh_reason"),
        "secrets_redacted": capsule.get("secrets_redacted"),
        "enabled": agent.settings.memory.capsule_enabled,
    }


@router.post("/api/sessions/{session_id}/capsule/refresh")
async def refresh_session_capsule(
    session_id: str = Depends(require_path_session_id),
    auth: dict[str, Any] = Depends(require_user_write),
) -> dict[str, Any]:
    """Regenerate the session capsule from current session messages.

    Returns structured status and metadata. Secrets are redacted before storage.
    """
    agent = get_agent()
    owner = memory_owner(auth)
    owner_key_hash = owner or "local-user"
    try:
        messages = await asyncio.to_thread(
            agent.memory.get_session_messages,
            session_id=session_id,
            owner_key_hash=owner,
        )
        from js.models.providers import ChatMessage

        chat_messages = [
            ChatMessage(role=m["role"], content=m["content"])
            for m in messages
            if m.get("role") in ("user", "assistant") and m.get("content")
        ]
        if not chat_messages:
            return {
                "session_id": session_id,
                "status": "no_messages",
                "refreshed": False,
                "reason": "no messages",
            }
        runtime_context = agent.echo_runtime.build_context(
            channel="session_capsule_refresh",
            owner_key_hash=owner_key_hash,
            session_id=session_id,
        )
        capsule_text = await agent._summarize_context(
            chat_messages,
            runtime_context=runtime_context,
        )
        if not capsule_text:
            return {
                "session_id": session_id,
                "status": "empty_summary",
                "refreshed": False,
                "reason": "empty summary",
            }
        stored = await _mutate_memory(
            "capsule_store",
            {
                "session_id": session_id,
                "capsule_text": capsule_text,
                "refresh_reason": "manual_refresh",
            },
            auth,
            session_id=session_id,
        )
        return {
            "session_id": session_id,
            "status": "success",
            "refreshed": True,
            "capsule_text": capsule_text,
            "metadata": stored.get("metadata", {}),
        }
    except Exception as e:
        logger.warning("Failed to refresh session capsule", exc_info=True)
        status = 503 if "No models configured" in str(e) else 500
        raise HTTPException(status, "Failed to refresh session capsule") from e


@router.delete("/api/sessions/{session_id}/capsule")
async def delete_session_capsule(
    session_id: str = Depends(require_path_session_id),
    auth: dict[str, Any] = Depends(require_user_write),
) -> dict[str, Any]:
    """Clear the session capsule for the current session."""
    return await _mutate_memory(
        "capsule_delete",
        {"session_id": session_id},
        auth,
        session_id=session_id,
    )


# ── R6 compression routes ──


@router.post("/api/memory/compression/proposals")
async def compression_create_proposal(
    body: MemoryCompressionProposalRequest,
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    """Create a compression proposal from source refs and a summary."""
    return await _mutate_memory(
        "compression_create",
        body.model_dump(),
        auth,
    )


@router.post("/api/memory/compression/proposals/{proposal_id}/approve")
async def compression_approve_proposal(
    proposal_id: str,
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    """Approve a compression proposal (admin only)."""
    return await _mutate_memory(
        "compression_approve",
        {"proposal_id": proposal_id},
        auth,
    )


@router.post("/api/memory/compression/proposals/{proposal_id}/reject")
async def compression_reject_proposal(
    proposal_id: str,
    auth: dict[str, Any] = Depends(require_admin_write),
) -> dict[str, Any]:
    """Reject a compression proposal (admin only)."""
    return await _mutate_memory(
        "compression_reject",
        {"proposal_id": proposal_id},
        auth,
    )


@router.get("/api/memory/compression/proposals")
async def compression_list_proposals(
    status: str = "pending",
    limit: int = 50,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """List compression proposals for the current owner."""
    agent = get_agent()
    owner = memory_owner(auth)
    if not isinstance(owner, str) or not owner:
        raise HTTPException(401, "Authenticated owner is required")
    from js.memory.layers import CompressionScopeV1

    mode = "personal"
    workspace = None
    scope = CompressionScopeV1(owner=owner, mode=mode, workspace=workspace)
    proposals = agent.memory.list_compression_proposals(
        scope=scope,
        status=status,
        limit=min(max(limit, 1), 100),
    )
    return {
        "proposals": [
            {
                "proposal_id": p.proposal_id,
                "status": p.status,
                "coverage": p.coverage_estimate,
                "conflict_flags": list(p.conflict_flags),
                "source_token_count": p.source_token_count,
                "summary_token_count": p.summary_token_count,
                "created_at": p.created_at,
            }
            for p in proposals
        ],
    }


@router.get("/api/memory/compression/capsules/{capsule_id}/rehydrate")
async def compression_rehydrate_capsule(
    capsule_id: str,
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Rehydrate a compression capsule with full summary and sources."""
    agent = get_agent()
    owner = memory_owner(auth)
    if not isinstance(owner, str) or not owner:
        raise HTTPException(401, "Authenticated owner is required")
    from js.memory.layers import MemoryCompressionAuthorityV1

    auth_obj = MemoryCompressionAuthorityV1(
        task_ref_hash="sha256:" + "0" * 64,
        owner=owner,
        mode="personal",
        workspace=None,
        role=str(auth.get("role") or "user"),
        session="web",
        run="web",
    )
    rehydrated = agent.memory.rehydrate_compression_capsule(
        capsule_id,
        authority=auth_obj,
    )
    if rehydrated is None:
        raise HTTPException(404, "Capsule not found")
    return {
        "capsule_id": rehydrated.capsule_id,
        "proposed_summary": rehydrated.proposed_summary,
        "sources": [
            {
                "kind": str(s.ref.kind),
                "record_id": s.ref.record_id,
                "content_hash": s.content_hash,
            }
            for s in rehydrated.sources
        ],
    }
