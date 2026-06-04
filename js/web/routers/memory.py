"""Memory API router — CRUD, audit, conflicts, metrics, embedder recovery."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from js.utils.log import get_logger
from js.web.auth import memory_owner, require_admin, require_auth_dep
from js.web.deps import get_agent

logger = get_logger("js.web.memory")
router = APIRouter(tags=["memory"])


@router.get("/api/memory")
async def memory(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    agent = get_agent()
    owner = memory_owner(auth)
    return {"context": agent.memory.get_context_string(max_chars=4000, owner_key_hash=owner)}


@router.get("/api/memory/enhanced")
async def memory_enhanced(
    session_id: str | None = None,
    auth: dict[str, Any] = Depends(require_auth_dep),
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
            for e in agent.memory.get_episodes(limit=20)
        ],
        "dream_logs": agent.memory.get_dream_logs(limit=10),
        "semantic_memories": agent.memory.get_all_semantic(limit=20, owner_key_hash=owner),
        "working_memories": agent.memory.get_all_working(limit=20),
        "memory_files": agent.memory.list_memory_files(),
    }
    if session_id:
        result["session_working"] = agent.memory.get_working(session_id, limit=20)
    return result


@router.get("/api/memory/files")
async def memory_file_list(auth: dict[str, Any] = Depends(require_auth_dep)) -> dict[str, Any]:
    agent = get_agent()
    return {"files": agent.memory.list_memory_files()}


@router.get("/api/memory/files/{name}")
async def memory_file_get(
    name: str, auth: dict[str, Any] = Depends(require_auth_dep)
) -> dict[str, Any]:
    agent = get_agent()
    try:
        content = agent.memory.read_memory_file(name)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return {"name": name, "content": content}


@router.put("/api/memory/files/{name}")
async def memory_file_put(
    name: str, body: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)
) -> dict[str, Any]:
    agent = get_agent()
    try:
        await asyncio.to_thread(agent.memory.write_memory_file, name, body.get("content", ""))
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return {"name": name, "saved": True}


@router.post("/api/memory/semantic")
async def memory_semantic_post(
    body: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)
) -> dict[str, Any]:
    agent = get_agent()
    key = (body.get("key") or "").strip()
    value = (body.get("value") or "").strip()
    category = (body.get("category") or "fact").strip()
    source = (body.get("source") or "user").strip()
    if not key or not value:
        raise HTTPException(400, "key and value are required")
    result = await asyncio.to_thread(
        agent.memory.store_semantic,
        key=key,
        value=value,
        category=category,
        source=source,
        memory_path=body.get("memory_path"),
        entity_type=body.get("entity_type"),
        entity_name=body.get("entity_name"),
        parent_id=body.get("parent_id"),
        relation_type=body.get("relation_type"),
        owner_key_hash=memory_owner(auth),
        evidence=(body.get("evidence") or ""),
    )
    return {"success": True, "key": key, **result}


@router.delete("/api/memory/semantic/{memory_id}")
async def memory_semantic_delete(
    memory_id: int, auth: dict[str, Any] = Depends(require_admin)
) -> dict[str, Any]:
    agent = get_agent()
    ok = await asyncio.to_thread(
        agent.memory.delete_semantic, memory_id, source="user",
        owner_key_hash=memory_owner(auth),
    )
    if not ok:
        raise HTTPException(404, "memory not found")
    return {"success": True}


@router.put("/api/memory/semantic/{memory_id}")
async def memory_semantic_put(
    memory_id: int, body: dict[str, Any], auth: dict[str, Any] = Depends(require_admin)
) -> dict[str, Any]:
    agent = get_agent()
    value = (body.get("value") or "").strip()
    category = body.get("category")
    if not value:
        raise HTTPException(400, "value is required")
    ok = await asyncio.to_thread(
        agent.memory.update_semantic,
        memory_id,
        value,
        category=category,
        source="user",
        memory_path=body.get("memory_path"),
        entity_type=body.get("entity_type"),
        entity_name=body.get("entity_name"),
        parent_id=body.get("parent_id"),
        relation_type=body.get("relation_type"),
        owner_key_hash=memory_owner(auth),
    )
    if not ok:
        raise HTTPException(404, "memory not found")
    return {"success": True}


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
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Mark a memory as verified (updates last_verified_at)."""
    agent = get_agent()
    ok = await asyncio.to_thread(
        agent.memory.verify_semantic, memory_id, "user",
        owner_key_hash=memory_owner(auth),
    )
    if not ok:
        raise HTTPException(404, "memory not found")
    return {"success": True, "verified": True}


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
    body: dict[str, Any] | None = Body(default=None),
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Approve a pending proposal, committing it to the memory library.

    An optional JSON body acts as edit-before-confirm overrides, e.g.
    ``{"value": "...", "memory_path": "/people/family", "category": "fact"}``.
    """
    agent = get_agent()
    overrides = body if isinstance(body, dict) and body else None
    result = await asyncio.to_thread(
        agent.memory.approve_proposal,
        proposal_id,
        owner_key_hash=memory_owner(auth),
        overrides=overrides,
    )
    if not result.get("success"):
        raise HTTPException(404, result.get("error", "proposal not found"))
    return result


@router.post("/api/memory/proposals/{proposal_id}/reject")
async def memory_proposal_reject(
    proposal_id: int,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Reject a pending proposal."""
    agent = get_agent()
    result = await asyncio.to_thread(
        agent.memory.reject_proposal, proposal_id, owner_key_hash=memory_owner(auth)
    )
    if not result.get("success"):
        raise HTTPException(404, result.get("error", "proposal not found"))
    return result


@router.post("/api/memory/organize")
async def memory_organize(
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Manually organize memories from the recent conversation buffer.

    Pulls the same recent turns the idle/dream cycle would process (without
    consuming them) and runs structured extraction → proposal queue. Returns
    counts so the UI can show progress (turns analyzed, staged, auto-applied).
    """
    agent = get_agent()
    ds = getattr(agent, "_dream_scheduler", None)
    buffer = ds.snapshot_buffer() if ds is not None and hasattr(ds, "snapshot_buffer") else []
    if not buffer:
        return {
            "success": True, "turns": 0, "proposed": 0,
            "auto_applied": 0, "pending": 0, "skipped": "no recent conversation",
        }
    if not hasattr(agent, "_extract_memories"):
        raise HTTPException(501, "Agent does not support memory extraction.")
    report = await agent._extract_memories(buffer)
    return {"success": True, "turns": len(buffer), **report}


# ── Block operations (move / merge) ──

@router.post("/api/memory/blocks/move")
async def memory_block_move(
    body: dict[str, Any],
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Re-path every memory under one block prefix to another."""
    src = (body.get("src") or "").strip()
    dst = (body.get("dst") or "").strip()
    if not src or not dst:
        raise HTTPException(400, "src and dst are required")
    agent = get_agent()
    moved = await asyncio.to_thread(
        agent.memory.move_block, src, dst, owner_key_hash=memory_owner(auth)
    )
    return {"success": True, "moved": moved, "src": src, "dst": dst}


@router.post("/api/memory/blocks/merge")
async def memory_block_merge(
    body: dict[str, Any],
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Merge one block into another (all memories adopt the target prefix)."""
    src = (body.get("src") or "").strip()
    dst = (body.get("dst") or "").strip()
    if not src or not dst:
        raise HTTPException(400, "src and dst are required")
    agent = get_agent()
    moved = await asyncio.to_thread(
        agent.memory.merge_blocks, src, dst, owner_key_hash=memory_owner(auth)
    )
    return {"success": True, "merged": moved, "src": src, "dst": dst}


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
            "episodes": len(agent.memory.get_episodes(limit=1000)),
            "semantic_memories": len(agent.memory.get_all_semantic(limit=1000)),
            "working_memories": len(agent.memory.get_all_working(limit=1000)),
            "dream_logs": len(agent.memory.get_dream_logs(limit=1000)),
        },
    }


@router.post("/api/memory/embedder/recover")
async def memory_embedder_recover(
    auth: dict[str, Any] = Depends(require_auth_dep),
) -> dict[str, Any]:
    """Manually trigger embedder recovery probe."""
    agent = get_agent()
    # Attempt 1: rebuild from scratch
    try:
        new_embedder = await asyncio.to_thread(agent._setup_embedder)
        from js.memory.embeddings import KeywordEmbedder
        if not isinstance(new_embedder, KeywordEmbedder):
            agent.memory.replace_embedder(new_embedder)
            health = new_embedder.health()
            return {
                "success": True,
                "provider": health.provider,
                "active": health.active,
                "fallback_provider": health.fallback_provider,
                "failure_count": health.failure_count,
                "recovered": True,
                "method": "rebuild",
            }
    except Exception:
        logger.warning("Operation failed", exc_info=True)

    # Attempt 2: probe the existing embedder.
    embedder = agent.memory.embedder
    if hasattr(embedder, "force_recover"):
        ok = embedder.force_recover()
        health = embedder.health()
        return {
            "success": ok,
            "provider": health.provider,
            "active": health.active,
            "fallback_provider": health.fallback_provider,
            "failure_count": health.failure_count,
            "recovered": ok,
            "method": "force_recover",
        }

    health = embedder.health()
    return {
        "success": False,
        "provider": health.provider,
        "active": health.active,
        "fallback_provider": health.fallback_provider,
        "failure_count": health.failure_count,
        "recovered": False,
        "method": "none",
    }
