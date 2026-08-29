"""AgentFleet implementation."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import time
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from js.agent import JSAgent
from js.config import JSSettings
from js.echo.turn_context import (
    RuntimeContext,
    current_owner_key_hash,
    current_runtime_context,
)
from js.echo.turn_runtime import run_echo_turn
from js.orchestration.fleet.identity import (
    _FLEET_MODES,
    _FLEET_OWNER,
    _FLEET_PRODUCT,
    _FLEET_REQUEST,
    _FLEET_SESSION,
    _FLEET_TURN,
    _LOCAL_FLEET_OWNER,
    _MAX_FLEET_SUBTASK_CHARS,
    _MAX_FLEET_TASK_CHARS,
    _SAFE_FLEET_ROLE_RE,
    _SAFE_FLEET_SESSION_RE,
    _current_fleet_event_identity,
    bind_fleet_event_identity,
    validate_fleet_event_identity,
)
from js.orchestration.fleet.models import (
    AgentInstance,
    AgentRole,
    FleetCapacityError,
    FleetEventSubscription,
    Task,
)
from js.orchestration.fleet_history import SecureFleetHistoryStore
from js.utils.log import get_logger

logger = get_logger("js.orchestration")


class AgentFleet:
    """Manages a small pool of agents for parallel task execution.

    Usage is fully automatic — callers never spawn, dispatch, or manage agents.
    Just call `collaborate(task)` and get the synthesized result.
    """

    def __init__(
        self,
        settings: JSSettings,
        agent_config: dict[str, str] | None = None,
        max_workers: int = 4,
        skills: Any | None = None,
        inherit_skills: bool = True,
        worker_configurer: Callable[[JSAgent, AgentRole, RuntimeContext | None], None]
        | None = None,
    ) -> None:
        self.settings = settings
        self.agent_config = agent_config or {}
        self.agents: dict[str, AgentInstance] = {}
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max_workers)
        self._max_workers = max_workers
        self._worker_close_timeout = 5.0
        self._inherit_skills = inherit_skills
        self._skills_source = skills if inherit_skills else None  # parent agent's SkillManager
        self._worker_configurer = worker_configurer
        from threading import Lock as TLock

        self._spawn_lock = TLock()
        self._event_callbacks: list[FleetEventSubscription] = []
        # State dirs
        self._fleet_dir = settings.state_dir / "fleet"
        self._fleet_dir.mkdir(parents=True, exist_ok=True)
        self._history_dir = self._fleet_dir / "history"
        self._history_store = SecureFleetHistoryStore(self._history_dir)

    @staticmethod
    def _partition_slug(kind: str, value: str) -> str:
        payload = f"{kind}:{len(value)}:{value}".encode()
        return hashlib.sha256(payload).hexdigest()[:24]

    def _resolve_scope(
        self,
        *,
        owner_key_hash: str | None = None,
        product_id: str | None = None,
        allow_local_direct: bool = False,
    ) -> tuple[str, str]:
        parent = current_runtime_context()
        inherited_owner = _FLEET_OWNER.get()
        inherited_product = _FLEET_PRODUCT.get()
        if parent is not None:
            if owner_key_hash and owner_key_hash != parent.owner_key_hash:
                raise PermissionError("Fleet owner cannot exceed the parent runtime context")
            if inherited_owner and inherited_owner != parent.owner_key_hash:
                raise PermissionError("Fleet owner lineage does not match the parent context")
            if product_id and product_id != parent.product_id:
                raise PermissionError("Fleet product cannot exceed the parent runtime context")
            if inherited_product and inherited_product != parent.product_id:
                raise PermissionError("Fleet product lineage does not match the parent context")

        owner = owner_key_hash or inherited_owner
        if owner is None and parent is not None:
            owner = parent.owner_key_hash
        if owner is None and parent is None:
            owner = current_owner_key_hash()
        if not owner:
            if not allow_local_direct or parent is not None:
                raise RuntimeError("Fleet owner context is required")
            owner = _LOCAL_FLEET_OWNER

        product = product_id or inherited_product
        if product is None and parent is not None:
            product = parent.product_id
        if product is None:
            product = str(getattr(getattr(self, "settings", None), "product_id", "js-agent"))
        if not product:
            raise RuntimeError("Fleet product context is required")
        return product, owner

    @staticmethod
    async def _close_instance(instance: AgentInstance) -> None:
        close = getattr(instance.agent, "close", None)
        if not callable(close):
            return
        result = close()
        if inspect.isawaitable(result):
            await result

    def _execution_scope(self, instance: AgentInstance) -> tuple[str, str]:
        parent = current_runtime_context()
        owner = _FLEET_OWNER.get()
        if owner is None and parent is not None:
            owner = parent.owner_key_hash
        if owner is None and parent is None:
            owner = current_owner_key_hash()
        if owner is None and instance.owner_key_hash == _LOCAL_FLEET_OWNER:
            owner = _LOCAL_FLEET_OWNER
        if not owner:
            raise RuntimeError("Fleet worker execution requires owner lineage")

        product = _FLEET_PRODUCT.get()
        if product is None and parent is not None:
            product = parent.product_id
        if product is None and instance.owner_key_hash == _LOCAL_FLEET_OWNER:
            product = instance.product_id
        if not product:
            raise RuntimeError("Fleet worker execution requires product lineage")
        if (instance.product_id, instance.owner_key_hash) != (product, owner):
            raise RuntimeError("Fleet worker lineage does not match the active product/owner")
        return product, owner

    # ------------------------------------------------------------------ #
    # Event callbacks (backward compat for websocket dashboard)
    # ------------------------------------------------------------------ #

    def on_event(
        self,
        callback: Callable[[dict[str, Any]], Awaitable[None]],
        *,
        product_id: str | None = None,
        owner_key_hash: str | None = None,
    ) -> FleetEventSubscription:
        product, owner = self._resolve_scope(
            product_id=product_id,
            owner_key_hash=owner_key_hash,
            allow_local_direct=True,
        )
        subscription = FleetEventSubscription(
            callback=callback,
            product_id=product,
            owner_key_hash=owner,
        )
        self._event_callbacks.append(subscription)
        return subscription

    def off_event(
        self,
        subscription_or_callback: FleetEventSubscription
        | Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if isinstance(subscription_or_callback, FleetEventSubscription):
            self._event_callbacks = [
                subscription
                for subscription in self._event_callbacks
                if subscription is not subscription_or_callback
            ]
            return
        self._event_callbacks = [
            subscription
            for subscription in self._event_callbacks
            if subscription.callback is not subscription_or_callback
        ]

    def update_agent_config(self, config: dict[str, str]) -> None:
        """Update the role-to-model mapping for future spawned agents."""
        self.agent_config.update(config)
        # Clear existing agent pool so new requests pick up updated models
        with self._spawn_lock:
            self.agents.clear()

    async def _emit(
        self,
        event: dict[str, Any],
        *,
        product_id: str | None = None,
        owner_key_hash: str | None = None,
    ) -> None:
        product, owner = self._resolve_scope(
            product_id=product_id,
            owner_key_hash=owner_key_hash,
            allow_local_direct=True,
        )
        subscriptions = [
            subscription
            for subscription in self._event_callbacks[:]
            if subscription.product_id == product and subscription.owner_key_hash == owner
        ]
        request_id, turn_id, session_id = _current_fleet_event_identity()
        public_event = {
            key: value for key, value in event.items() if key not in {"owner", "owner_key_hash"}
        }
        public_event.update(
            {
                "request_id": request_id,
                "turn_id": turn_id,
                "session_id": session_id,
            }
        )
        for subscription in subscriptions:
            try:
                await subscription.callback(dict(public_event))
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Public API — one method
    # ------------------------------------------------------------------ #

    _MAX_SUBTASKS = 20

    @classmethod
    def _validate_collaboration_request(
        cls,
        main_task: str,
        subtasks: list[str] | None,
        session_id: str | None,
        role_mapping: dict[int | str, str] | None,
        mode: str,
    ) -> tuple[
        str,
        list[str] | None,
        str | None,
        dict[int, str] | None,
        str,
    ]:
        if not isinstance(main_task, str):
            raise TypeError("fleet task must be a string")
        normalized_task = main_task.strip()
        if not normalized_task or len(normalized_task) > _MAX_FLEET_TASK_CHARS:
            raise ValueError("fleet task is empty or exceeds the size limit")

        normalized_subtasks: list[str] | None = None
        if subtasks is not None:
            if not isinstance(subtasks, list):
                raise TypeError("fleet subtasks must be a list")
            if not subtasks or len(subtasks) > cls._MAX_SUBTASKS:
                raise ValueError("fleet subtask count is invalid")
            normalized_subtasks = []
            for subtask in subtasks:
                if not isinstance(subtask, str):
                    raise TypeError("fleet subtasks must contain only strings")
                normalized = subtask.strip()
                if not normalized or len(normalized) > _MAX_FLEET_SUBTASK_CHARS:
                    raise ValueError("fleet subtask is empty or exceeds the size limit")
                normalized_subtasks.append(normalized)

        if session_id is not None and (
            not isinstance(session_id, str) or not _SAFE_FLEET_SESSION_RE.fullmatch(session_id)
        ):
            raise ValueError("invalid fleet session id")

        if not isinstance(mode, str) or mode not in _FLEET_MODES:
            raise ValueError("invalid fleet collaboration mode")

        normalized_roles: dict[int, str] | None = None
        if role_mapping is not None:
            if not isinstance(role_mapping, dict):
                raise TypeError("fleet role_mapping must be an object")
            if len(role_mapping) > cls._MAX_SUBTASKS:
                raise ValueError("fleet role mapping exceeds the size limit")
            normalized_roles = {}
            max_index = (
                len(normalized_subtasks) if normalized_subtasks is not None else cls._MAX_SUBTASKS
            )
            for raw_index, raw_role in role_mapping.items():
                if isinstance(raw_index, bool):
                    raise ValueError("invalid fleet role index")
                if isinstance(raw_index, int):
                    index = raw_index
                elif isinstance(raw_index, str) and raw_index.isascii() and raw_index.isdigit():
                    index = int(raw_index)
                else:
                    raise ValueError("invalid fleet role index")
                if index < 0 or index >= max_index or index in normalized_roles:
                    raise ValueError("invalid or duplicated fleet role index")
                if not isinstance(raw_role, str) or not _SAFE_FLEET_ROLE_RE.fullmatch(raw_role):
                    raise ValueError("invalid fleet role")
                normalized_roles[index] = raw_role

        return (
            normalized_task,
            normalized_subtasks,
            session_id,
            normalized_roles,
            mode,
        )

    async def collaborate(
        self,
        main_task: str,
        subtasks: list[str] | None = None,
        session_id: str | None = None,
        role_mapping: dict[int | str, str] | None = None,
        mode: str = "auto",
        owner_key_hash: str | None = None,
    ) -> dict[str, Any]:
        (
            normalized_task,
            normalized_subtasks,
            normalized_session_id,
            normalized_role_mapping,
            normalized_mode,
        ) = self._validate_collaboration_request(
            main_task,
            subtasks,
            session_id,
            role_mapping,
            mode,
        )
        parent_context = current_runtime_context()
        inherited_owner = current_owner_key_hash()
        if parent_context is not None:
            if owner_key_hash and owner_key_hash != parent_context.owner_key_hash:
                raise PermissionError("Fleet owner cannot exceed the parent runtime context")
            if inherited_owner and inherited_owner != parent_context.owner_key_hash:
                raise PermissionError("Fleet owner lineage does not match the parent context")
            if not parent_context.owner_key_hash:
                raise RuntimeError("Fleet owner context is required")
            owner = parent_context.owner_key_hash
        elif owner_key_hash:
            owner = owner_key_hash
        elif inherited_owner:
            owner = inherited_owner
        else:
            owner = _LOCAL_FLEET_OWNER
        product = (
            parent_context.product_id
            if parent_context is not None
            else str(getattr(self.settings, "product_id", "js-agent"))
        )
        if not product:
            raise RuntimeError("Fleet product context is required")
        inherited_identity = (
            _FLEET_REQUEST.get(),
            _FLEET_TURN.get(),
            _FLEET_SESSION.get(),
        )
        if any(value is not None for value in inherited_identity):
            if any(value is None for value in inherited_identity):
                raise RuntimeError("Fleet event identity context is incomplete")
            request_id, turn_id, inherited_session = validate_fleet_event_identity(
                *inherited_identity
            )
            if normalized_session_id and normalized_session_id != inherited_session:
                raise PermissionError("Fleet session cannot override its parent event identity")
            resolved_session = inherited_session
        else:
            request_id = f"fleet-request-{uuid.uuid4().hex}"
            turn_id = f"fleet-turn-{uuid.uuid4().hex}"
            resolved_session = normalized_session_id or str(uuid.uuid4())
        owner_token = _FLEET_OWNER.set(owner)
        product_token = _FLEET_PRODUCT.set(product)
        try:
            with bind_fleet_event_identity(request_id, turn_id, resolved_session):
                return await self._collaborate_scoped(
                    normalized_task,
                    subtasks=normalized_subtasks,
                    session_id=resolved_session,
                    role_mapping=normalized_role_mapping,
                    mode=normalized_mode,
                    owner_key_hash=owner,
                )
        finally:
            _FLEET_PRODUCT.reset(product_token)
            _FLEET_OWNER.reset(owner_token)

    async def _collaborate_scoped(
        self,
        main_task: str,
        *,
        subtasks: list[str] | None,
        session_id: str,
        role_mapping: dict[int, str] | None,
        mode: str,
        owner_key_hash: str,
    ) -> dict[str, Any]:
        """Execute a task with an auto-formed team.

        Args:
            main_task: The high-level task description.
            subtasks: Optional pre-defined subtask strings. If omitted, the task
                is auto-decomposed into 2-4 parallel subtasks.
            session_id: Optional existing session ID to continue.
            role_mapping: Optional mapping of subtask index -> role name.
                          If omitted, all subtasks use "worker".
            mode: Collaboration strategy — "auto" | "debate" | "sequential" | "manager".

        Returns:
            {"session_id": str, "final": str, "subtasks": dict[str, str], "review": str | None}
        """
        sid = session_id
        if not _SAFE_FLEET_SESSION_RE.fullmatch(sid):
            raise ValueError("invalid fleet session id")
        group_id = str(uuid.uuid4())

        logger.info(f"Fleet collaborate mode={mode}: {main_task[:60]}")
        await self._emit(
            {
                "type": "collaborate_progress",
                "session_id": sid,
                "stage": "decomposing",
                "message": f"[{mode}] 正在分析任务并拆分子任务...",
            }
        )

        # Route to mode-specific handler
        if mode == "debate":
            result = await self._collaborate_debate(
                sid, group_id, main_task, subtasks, role_mapping
            )
        elif mode == "sequential":
            result = await self._collaborate_sequential(
                sid, group_id, main_task, subtasks, role_mapping
            )
        elif mode == "manager":
            result = await self._collaborate_manager(
                sid, group_id, main_task, subtasks, role_mapping
            )
        elif mode == "auto":
            result = await self._collaborate_auto(sid, group_id, main_task, subtasks, role_mapping)
        else:
            raise ValueError("invalid fleet collaboration mode")

        # Save history and emit result
        descs = list(result.get("subtasks", {}).keys()) or [main_task]
        await self._save_history(sid, main_task, descs, result, owner_key_hash=owner_key_hash)
        await self._emit({"type": "collaborate_result", **result})
        logger.info(
            f"Fleet done mode={mode}: {main_task[:60]} -> {len(result.get('final', ''))} chars"
        )
        return result

    # ------------------------------------------------------------------ #
    # Collaboration modes
    # ------------------------------------------------------------------ #

    async def _collaborate_auto(
        self,
        sid: str,
        group_id: str,
        main_task: str,
        subtasks: list[str] | None,
        role_mapping: dict[int, str] | None,
    ) -> dict[str, Any]:
        """Default: auto-decompose + parallel execute + review + synthesize."""
        descs = subtasks or self._auto_decompose(main_task)
        await self._emit(
            {
                "type": "collaborate_progress",
                "session_id": sid,
                "stage": "dispatched",
                "message": f"已拆分为 {len(descs)} 个子任务，正在分配Agent...",
                "subtasks": descs,
                "mode": "auto",
            }
        )

        role_map = role_mapping or {}
        agents_used: list[AgentInstance] = []
        reviewer: AgentInstance | None = None
        tasks: list[Task] = []
        try:
            role_agents: dict[str, AgentInstance] = {}
            for idx, _desc in enumerate(descs):
                role_val = role_map.get(idx, "worker")
                if role_val not in role_agents:
                    role_agents[role_val] = await self._acquire_agent(role_val, group_id)
                agents_used.append(role_agents[role_val])

            tasks = [
                Task(
                    id=str(uuid.uuid4()),
                    description=desc,
                    role_hint=AgentRole.from_value(role_map.get(idx, "worker")),
                    group_id=group_id,
                )
                for idx, desc in enumerate(descs)
            ]
            await self._emit(
                {
                    "type": "collaborate_progress",
                    "session_id": sid,
                    "stage": "executing",
                    "message": f"{len(descs)} 个Agent正在并行执行任务...",
                    "total": len(descs),
                    "completed": 0,
                    "mode": "auto",
                }
            )
            results = await self._run_parallel(tasks, agents_used)
            await self._emit(
                {
                    "type": "collaborate_progress",
                    "session_id": sid,
                    "stage": "executing",
                    "message": "所有子任务执行完成",
                    "total": len(descs),
                    "completed": len(descs),
                    "mode": "auto",
                }
            )

            review = ""
            if self._needs_review(main_task):
                await self._emit(
                    {
                        "type": "collaborate_progress",
                        "session_id": sid,
                        "stage": "reviewing",
                        "message": "审查Agent正在检查结果...",
                        "mode": "auto",
                    }
                )
                reviewer = await self._acquire_agent("reviewer", group_id)
                review_prompt = f"主任务：{main_task}\n\n以下是各子任务的执行结果：\n"
                for t in tasks:
                    review_prompt += f"\n[{t.description}]\n{results.get(t.id, '')[:1000]}\n"
                review_prompt += (
                    "\n请审查以上结果：\n"
                    "1. 是否有错误或遗漏？\n"
                    "2. 是否需要补充？\n"
                    "3. 给出改进建议（如有）。\n"
                    "如果没有问题，直接回复 'OK'。"
                )
                review = await self._run_agent(reviewer, review_prompt, timeout=120.0)

            await self._emit(
                {
                    "type": "collaborate_progress",
                    "session_id": sid,
                    "stage": "synthesizing",
                    "message": "正在综合所有结果为最终答案...",
                    "mode": "auto",
                }
            )
            synthesis_prompt = f"主任务：{main_task}\n\n各子任务结果：\n"
            for t in tasks:
                synthesis_prompt += f"\n[{t.description}]\n{results.get(t.id, '')[:1200]}\n"
            if review and "OK" not in review.upper():
                synthesis_prompt += f"\n审查意见：\n{review[:800]}\n"
            synthesis_prompt += "\n请将以上结果综合为一份完整、连贯的最终答案。"

            final = await self._run_agent(agents_used[0], synthesis_prompt, timeout=180.0)
            subtask_map = {t.description: results.get(t.id, "") for t in tasks}

            return {
                "session_id": sid,
                "final": final,
                "subtasks": subtask_map,
                "review": review if review and "OK" not in review.upper() else None,
                "mode": "auto",
            }
        finally:
            for a in {worker.id: worker for worker in agents_used}.values():
                a.status = "idle"
                a.current_task = None
                a.last_active_at = time.time()
            if reviewer is not None:
                reviewer.status = "idle"
                reviewer.current_task = None
                reviewer.last_active_at = time.time()

    async def _collaborate_debate(
        self,
        sid: str,
        group_id: str,
        main_task: str,
        subtasks: list[str] | None,
        role_mapping: dict[int, str] | None,
    ) -> dict[str, Any]:
        """Debate mode: multiple agents answer the SAME task from different angles, then synthesize."""
        # Debate uses 2-3 agents on the same task with different perspectives
        descs = subtasks or [main_task]
        if len(descs) == 1:
            # Force multiple perspectives on the same task
            descs = [
                f"【角度1：技术实现】{main_task}",
                f"【角度2：用户体验】{main_task}",
                f"【角度3：成本与可行性】{main_task}",
            ]
        await self._emit(
            {
                "type": "collaborate_progress",
                "session_id": sid,
                "stage": "dispatched",
                "message": f"辩论模式：{len(descs)} 个Agent从不同角度分析同一问题...",
                "subtasks": descs,
                "mode": "debate",
            }
        )

        role_map = role_mapping or {}
        agents_used: list[AgentInstance] = []
        tasks: list[Task] = []
        try:
            for idx, desc in enumerate(descs):
                role_val = role_map.get(idx, f"debater_{idx}")
                agent = await self._acquire_agent(role_val, group_id)
                agents_used.append(agent)
                tasks.append(
                    Task(
                        id=str(uuid.uuid4()),
                        description=desc,
                        role_hint=AgentRole.from_value(role_val),
                        group_id=group_id,
                    )
                )

            await self._emit(
                {
                    "type": "collaborate_progress",
                    "session_id": sid,
                    "stage": "executing",
                    "message": f"{len(descs)} 个Agent正在并行发表观点...",
                    "total": len(descs),
                    "completed": 0,
                    "mode": "debate",
                }
            )
            results = await self._run_parallel(tasks, agents_used)
            await self._emit(
                {
                    "type": "collaborate_progress",
                    "session_id": sid,
                    "stage": "executing",
                    "message": "所有观点收集完成",
                    "total": len(descs),
                    "completed": len(descs),
                    "mode": "debate",
                }
            )

            # Synthesize debate results
            await self._emit(
                {
                    "type": "collaborate_progress",
                    "session_id": sid,
                    "stage": "synthesizing",
                    "message": "正在综合多方观点为最终结论...",
                    "mode": "debate",
                }
            )
            synthesis_prompt = f"主任务：{main_task}\n\n以下是多位专家从不同角度给出的分析：\n"
            for t in tasks:
                synthesis_prompt += f"\n[{t.description}]\n{results.get(t.id, '')[:1500]}\n"
            synthesis_prompt += (
                "\n请综合以上不同角度的观点，给出一份平衡、全面的最终结论。"
                "如果不同观点之间存在冲突，请指出并给出你的判断。"
            )
            final = await self._run_agent(agents_used[0], synthesis_prompt, timeout=180.0)
            subtask_map = {t.description: results.get(t.id, "") for t in tasks}

            return {
                "session_id": sid,
                "final": final,
                "subtasks": subtask_map,
                "review": None,
                "mode": "debate",
            }
        finally:
            for a in {worker.id: worker for worker in agents_used}.values():
                a.status = "idle"
                a.current_task = None
                a.last_active_at = time.time()

    async def _collaborate_sequential(
        self,
        sid: str,
        group_id: str,
        main_task: str,
        subtasks: list[str] | None,
        role_mapping: dict[int, str] | None,
    ) -> dict[str, Any]:
        """Sequential mode: pipeline — each agent's output feeds into the next."""
        descs = subtasks or self._auto_decompose(main_task)
        await self._emit(
            {
                "type": "collaborate_progress",
                "session_id": sid,
                "stage": "dispatched",
                "message": f"串行模式：{len(descs)} 个步骤依次执行...",
                "subtasks": descs,
                "mode": "sequential",
            }
        )

        role_map = role_mapping or {}
        agents_used: list[AgentInstance] = []
        results: dict[str, str] = {}
        try:
            for idx, desc in enumerate(descs):
                role_val = role_map.get(idx, "worker")
                agent = await self._acquire_agent(role_val, group_id)
                agents_used.append(agent)

                # Build prompt: previous outputs + current step
                if idx == 0:
                    prompt = f"主任务：{main_task}\n\n步骤 {idx + 1}/{len(descs)}：{desc}\n\n请开始执行这一步。"
                else:
                    prev_results = "\n\n".join(
                        f"步骤 {i + 1} 结果：\n{results.get(descs[i], '')[:800]}"
                        for i in range(idx)
                    )
                    prompt = (
                        f"主任务：{main_task}\n\n"
                        f"之前步骤的结果：\n{prev_results}\n\n"
                        f"步骤 {idx + 1}/{len(descs)}：{desc}\n\n"
                        "请基于之前的结果继续执行这一步。"
                    )

                await self._emit(
                    {
                        "type": "collaborate_progress",
                        "session_id": sid,
                        "stage": "executing",
                        "message": f"步骤 {idx + 1}/{len(descs)} 执行中...",
                        "total": len(descs),
                        "completed": idx,
                        "mode": "sequential",
                    }
                )
                task = Task(
                    id=str(uuid.uuid4()),
                    description=desc,
                    role_hint=AgentRole.from_value(role_val),
                    group_id=group_id,
                )
                _, result = await self._execute_single(task, agent, override_prompt=prompt)
                results[desc] = result
                agent.status = "idle"
                agent.current_task = None
                agent.last_active_at = time.time()

            await self._emit(
                {
                    "type": "collaborate_progress",
                    "session_id": sid,
                    "stage": "synthesizing",
                    "message": "正在综合所有步骤结果为最终答案...",
                    "mode": "sequential",
                }
            )
            synthesis_prompt = f"主任务：{main_task}\n\n各步骤结果：\n"
            for desc in descs:
                synthesis_prompt += f"\n[{desc}]\n{results.get(desc, '')[:1200]}\n"
            synthesis_prompt += "\n请将以上步骤结果综合为一份完整、连贯的最终答案。"
            final_agent = await self._acquire_agent(role_map.get(0, "worker"), group_id)
            final = await self._run_agent(final_agent, synthesis_prompt, timeout=180.0)
            final_agent.status = "idle"
            final_agent.current_task = None
            final_agent.last_active_at = time.time()

            return {
                "session_id": sid,
                "final": final,
                "subtasks": results,
                "review": None,
                "mode": "sequential",
            }
        finally:
            for a in agents_used:
                a.status = "idle"
                a.current_task = None
                a.last_active_at = time.time()

    async def _collaborate_manager(
        self,
        sid: str,
        group_id: str,
        main_task: str,
        subtasks: list[str] | None,
        role_mapping: dict[int, str] | None,
    ) -> dict[str, Any]:
        """Manager mode: a manager agent plans, assigns, then synthesizes."""
        descs = subtasks or self._auto_decompose(main_task)
        await self._emit(
            {
                "type": "collaborate_progress",
                "session_id": sid,
                "stage": "dispatched",
                "message": f"经理模式：Manager 规划 {len(descs)} 个子任务...",
                "subtasks": descs,
                "mode": "manager",
            }
        )

        role_map = role_mapping or {}
        manager: AgentInstance | None = None
        workers: list[AgentInstance] = []
        try:
            manager = await self._acquire_agent("manager", group_id)
            # Manager does a quick plan (could be expanded)
            plan_prompt = (
                f"你是项目经理。主任务：{main_task}\n\n"
                f"已拆分为以下子任务：\n"
                + "\n".join(f"{i + 1}. {d}" for i, d in enumerate(descs))
                + "\n\n请确认计划合理，如有调整建议请说明。如果没有问题，回复 'PLAN_OK'。"
            )
            plan_check = await self._run_agent(manager, plan_prompt, timeout=60.0)
            # Even if plan_check isn't 'PLAN_OK', we proceed — the manager's feedback
            # will be included in the synthesis.

            # Dispatch workers in parallel
            tasks = [
                Task(
                    id=str(uuid.uuid4()),
                    description=desc,
                    role_hint=AgentRole.from_value(role_map.get(idx, "worker")),
                    group_id=group_id,
                )
                for idx, desc in enumerate(descs)
            ]
            for idx, _ in enumerate(descs):
                role_val = role_map.get(idx, "worker")
                w = await self._acquire_agent(role_val, group_id)
                workers.append(w)

            await self._emit(
                {
                    "type": "collaborate_progress",
                    "session_id": sid,
                    "stage": "executing",
                    "message": f"Manager 监督 {len(descs)} 个Worker并行执行...",
                    "total": len(descs),
                    "completed": 0,
                    "mode": "manager",
                }
            )
            results = await self._run_parallel(tasks, workers)
            await self._emit(
                {
                    "type": "collaborate_progress",
                    "session_id": sid,
                    "stage": "executing",
                    "message": "所有Worker执行完成",
                    "total": len(descs),
                    "completed": len(descs),
                    "mode": "manager",
                }
            )

            # Manager synthesizes
            await self._emit(
                {
                    "type": "collaborate_progress",
                    "session_id": sid,
                    "stage": "synthesizing",
                    "message": "Manager 正在综合最终答案...",
                    "mode": "manager",
                }
            )
            synthesis_prompt = (
                f"你是项目经理。主任务：{main_task}\n\n"
                f"你的计划确认：{plan_check[:500]}\n\n"
                "各Worker的执行结果：\n"
            )
            for t in tasks:
                synthesis_prompt += f"\n[{t.description}]\n{results.get(t.id, '')[:1200]}\n"
            synthesis_prompt += "\n请综合所有结果，给出最终交付物。确保结果完整、准确、可执行。"
            final = await self._run_agent(manager, synthesis_prompt, timeout=180.0)
            subtask_map = {t.description: results.get(t.id, "") for t in tasks}

            return {
                "session_id": sid,
                "final": final,
                "subtasks": subtask_map,
                "review": None,
                "mode": "manager",
            }
        finally:
            if manager is not None:
                manager.status = "idle"
                manager.current_task = None
                manager.last_active_at = time.time()
            for w in workers:
                w.status = "idle"
                w.current_task = None
                w.last_active_at = time.time()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    async def _acquire_agent(self, role_value: str, _group_id: str) -> AgentInstance:
        """Get an idle agent of the given role, or spawn a new one."""
        role = AgentRole.from_value(role_value)
        product_id, owner_key_hash = self._resolve_scope()
        async with self._lock:
            # Reuse only an idle worker from the exact product/owner boundary.
            for a in self.agents.values():
                if (
                    a.status == "idle"
                    and a.role.value == role.value
                    and a.product_id == product_id
                    and a.owner_key_hash == owner_key_hash
                ):
                    self._apply_worker_envelope(a)
                    a.status = "busy"
                    a.last_active_at = time.time()
                    return a
            if len(self.agents) < self._max_workers:
                spawned = self._spawn_agent(
                    role.value,
                    role,
                    product_id=product_id,
                    owner_key_hash=owner_key_hash,
                )
                spawned.status = "busy"
                return spawned

            idle = sorted(
                (a for a in self.agents.values() if a.status == "idle"),
                key=lambda a: (
                    a.owner_key_hash == owner_key_hash and a.product_id == product_id,
                    a.last_active_at,
                ),
            )
            if not idle:
                raise FleetCapacityError(
                    f"Fleet capacity exhausted for product '{product_id}'; all workers are busy"
                )

            victim = idle[0]
            self.agents.pop(victim.id, None)
            try:
                await asyncio.wait_for(
                    self._close_instance(victim),
                    timeout=self._worker_close_timeout,
                )
            except Exception as e:
                victim.status = "error"
                self.agents[victim.id] = victim
                logger.warning(
                    "Fleet worker %s could not be closed for safe replacement",
                    victim.id,
                    exc_info=True,
                )
                raise FleetCapacityError(
                    "Fleet capacity is unavailable because an idle worker could not be closed"
                ) from e
            spawned = self._spawn_agent(
                role.value,
                role,
                product_id=product_id,
                owner_key_hash=owner_key_hash,
            )
            spawned.status = "busy"
            return spawned

    def _spawn(self, name: str, role: AgentRole) -> AgentInstance:
        """Backward compat alias for _spawn_agent."""
        return self._spawn_agent(name, role)

    def _spawn_worker(self) -> AgentInstance:
        """Backward compat — spawn a worker agent."""
        return self._spawn_agent("worker", AgentRole.WORKER)

    def _spawn_reviewer(self) -> AgentInstance:
        """Backward compat — spawn a reviewer agent."""
        return self._spawn_agent("reviewer", AgentRole.REVIEWER)

    @staticmethod
    def _generate_role_persona(role_value: str) -> str:
        """Generate a role identity and work-attitude prompt based on role name."""
        from js.bots.identity import fleet_persona_block

        return fleet_persona_block(role_value)

    def _spawn_agent(
        self,
        name: str,
        role: AgentRole,
        *,
        product_id: str | None = None,
        owner_key_hash: str | None = None,
    ) -> AgentInstance:
        from js.utils.ids import agent_id as _det_agent_id

        product_id, owner_key_hash = self._resolve_scope(
            product_id=product_id,
            owner_key_hash=owner_key_hash,
            allow_local_direct=True,
        )
        model = self.agent_config.get(role.value)
        product_slug = self._partition_slug("product", product_id)
        owner_slug = self._partition_slug("owner", owner_key_hash)
        scoped_name = f"{product_slug}:{owner_slug}:{name}"
        agent_id = _det_agent_id(scoped_name, role.value, model)
        role_settings = self._role_settings(
            agent_id,
            product_id=product_id,
            owner_key_hash=owner_key_hash,
        )
        agent = JSAgent(role_settings)

        if self._worker_configurer is not None:
            self._worker_configurer(agent, role, current_runtime_context())

        self._apply_worker_envelope_to_agent(agent, product_id=product_id)

        # Copy skills from parent agent so fleet workers can use all skills.
        if self._inherit_skills and self._skills_source is not None:
            try:
                for spec in self._skills_source.get_all().values():
                    agent.skills.register_auto_skill(spec)
            except Exception as e:
                logger.warning(f"Failed to copy skills to agent {agent_id}: {e}")

        # Auto-generate role persona based on role name
        persona = self._generate_role_persona(role.value)
        agent.SYSTEM_PROMPT = agent.SYSTEM_PROMPT + persona

        # Add fleet hint
        fleet_hint = (
            "\n\n你是协作团队的一员。你有独立的工作空间。"
            "不要浪费时间浏览目录结构，直接开始执行任务。"
            "创建新文件时请确保路径正确。保持简洁。"
            "注意：如果用户只是简单问候或提问，不需要调用任何工具，直接礼貌回答即可。"
        )
        if self._inherit_skills and self._skills_source is not None:
            fleet_hint += "你可以调用所有已注册的技能工具来完成任务。"
        agent.SYSTEM_PROMPT = agent.SYSTEM_PROMPT + fleet_hint
        instance = AgentInstance(
            id=agent_id,
            name=name,
            role=role,
            agent=agent,
            product_id=product_id,
            owner_key_hash=owner_key_hash,
            model=model,
            capabilities=self._effective_worker_capabilities(agent),
        )
        with self._spawn_lock:
            self.agents[agent_id] = instance
        logger.info(f"Spawned {name} ({role.value}) id={agent_id} persona={len(persona)} chars")
        return instance

    @staticmethod
    def _effective_worker_capabilities(agent: Any) -> list[str]:
        ceiling = frozenset(getattr(agent, "_echo_capability_ceiling", ()))
        registry = getattr(agent, "registry", None)
        list_tools = getattr(registry, "list_tools", None)
        if not callable(list_tools):
            return sorted(ceiling)
        registered = {
            str(tool.name)
            for tool in list_tools()
            if isinstance(getattr(tool, "name", None), str) and tool.name
        }
        return sorted(registered & set(ceiling))

    def _apply_worker_envelope(self, instance: AgentInstance) -> None:
        self._apply_worker_envelope_to_agent(
            instance.agent,
            product_id=instance.product_id,
        )
        instance.capabilities = self._effective_worker_capabilities(instance.agent)

    @staticmethod
    def _apply_worker_envelope_to_agent(agent: Any, *, product_id: str) -> None:
        """Bind a Fleet worker to the active parent's non-expanding envelope."""
        parent = current_runtime_context()
        if parent is None:
            object.__setattr__(agent, "_role", "local-user")
            object.__setattr__(
                agent,
                "_work_profile",
                str(getattr(getattr(agent, "settings", None), "work_profile", "default")),
            )
            object.__setattr__(agent, "_echo_capability_ceiling", frozenset())
            object.__setattr__(agent, "_echo_network_allowlist_ceiling", frozenset())
            object.__setattr__(agent, "_echo_role_ceiling", "local-user")
            object.__setattr__(
                agent,
                "_echo_profile_ceiling",
                str(getattr(agent, "_work_profile", "default")),
            )
            object.__setattr__(agent, "_echo_deadline_ceiling_ms", None)
            object.__setattr__(agent, "_echo_cancel_token", None)
            return
        if parent.product_id != product_id:
            raise PermissionError("Fleet worker product does not match its parent context")

        capabilities = frozenset(parent.capabilities) - {"fleet_collaborate"}
        object.__setattr__(agent, "_fleet_parent_context", parent)
        object.__setattr__(agent, "_role", parent.role)
        object.__setattr__(agent, "_work_profile", parent.profile)
        object.__setattr__(agent, "_echo_role_ceiling", parent.role)
        object.__setattr__(agent, "_echo_profile_ceiling", parent.profile)
        object.__setattr__(agent, "_echo_capability_ceiling", capabilities)
        object.__setattr__(
            agent,
            "_echo_network_allowlist_ceiling",
            frozenset(parent.network_allowlist),
        )
        object.__setattr__(agent, "_echo_deadline_ceiling_ms", parent.deadline_ms)
        object.__setattr__(agent, "_echo_cancel_token", parent.cancel_token)

    def _role_settings(
        self,
        agent_id: str,
        *,
        product_id: str,
        owner_key_hash: str,
    ) -> JSSettings:
        from copy import deepcopy

        settings = deepcopy(self.settings)
        object.__setattr__(settings, "product_id", product_id)
        product_slug = self._partition_slug("product", product_id)
        owner_slug = self._partition_slug("owner", owner_key_hash)
        partition = Path(product_slug) / owner_slug / agent_id
        settings.state_dir = self._fleet_dir / partition
        settings.state_dir.mkdir(parents=True, exist_ok=True)
        settings.workspace = settings.workspace / "fleet" / partition
        settings.workspace.mkdir(parents=True, exist_ok=True)
        # Inherit parent's defense mode but enforce a minimum floor of OBSERVE.
        # If the parent is OFF (completely unguarded), fleet children must
        # still have at least monitoring-level protection.
        from js.config import DefenseMode as _DefenseMode

        if settings.security.defense_mode in (_DefenseMode.OFF, _DefenseMode.OBSERVE):
            settings.security.defense_mode = _DefenseMode.ENFORCE
        settings.max_turns = 60
        return settings

    async def _run_parallel(
        self,
        tasks: list[Task],
        workers: list[AgentInstance],
    ) -> dict[str, str]:
        """Run tasks in parallel, assigning one worker per task.

        Uses structured concurrency: if the parent is cancelled, all child
        tasks are cancelled and drained before re-raising.
        """
        child_tasks: list[asyncio.Task[tuple[str, str]]] = []
        for t, w in zip(tasks, workers, strict=False):
            w.current_task = t.id
            w.task_description = t.description
            t.status = "running"
            t.assigned_to = w.id
            child_tasks.append(asyncio.create_task(self._execute_single(t, w)))

        results: dict[str, str] = {}
        try:
            for coro in asyncio.as_completed(child_tasks):
                task_id, result = await coro
                results[task_id] = result
        except BaseException:
            # Parent cancelled or error: cancel all still-running children
            for ct in child_tasks:
                if not ct.done():
                    ct.cancel()
            # Drain all children, collecting exceptions (don't re-raise child errors)
            for ct in child_tasks:
                try:
                    await ct
                except BaseException:
                    pass
            raise

        return results

    async def _execute_single(
        self, task: Task, worker: AgentInstance, override_prompt: str | None = None
    ) -> tuple[str, str]:
        """Run one worker inside exactly one Fleet event-identity scope.

        Public collaboration binds the authoritative request/turn/session
        triple before it fans out workers.  A few internal callers (including
        the real-time stream harness) execute one worker directly, so give
        that *single invocation* its own context-local identity rather than
        weakening ``_emit`` or sharing a lazy process-global fallback.
        """
        inherited_identity = (
            _FLEET_REQUEST.get(),
            _FLEET_TURN.get(),
            _FLEET_SESSION.get(),
        )
        if any(value is not None for value in inherited_identity):
            if any(value is None for value in inherited_identity):
                raise RuntimeError("Fleet event identity context is incomplete")
            validate_fleet_event_identity(*inherited_identity)
            return await self._execute_single_scoped(task, worker, override_prompt)

        parent = current_runtime_context()
        session_id = parent.session_id if parent is not None else str(uuid.uuid4())
        request_id = f"fleet-request-{uuid.uuid4().hex}"
        turn_id = f"fleet-turn-{uuid.uuid4().hex}"
        with bind_fleet_event_identity(request_id, turn_id, session_id):
            return await self._execute_single_scoped(task, worker, override_prompt)

    async def _execute_single_scoped(
        self, task: Task, worker: AgentInstance, override_prompt: str | None = None
    ) -> tuple[str, str]:
        """Run one task on one worker. Returns (task_id, result_text).

        Emits real-time events:
            agent_start       — task assigned
            agent_token       — final-response text delta (PR-4.4)
            agent_thinking    — model reasoning/thinking delta (PR-4.4 live,
                                also post-scan fallback for non-streaming turns)
            agent_tool_call   — tool name + arguments (live + post-scan)
            agent_tool_result — tool result preview
            agent_usage       — token usage from the stream (PR-4.4)
            agent_error       — streaming error from the provider (PR-4.4)
            agent_done        — task complete
        """
        timeout = 600.0
        task.status = "running"
        await self._emit(
            {
                "type": "agent_start",
                "agent_id": worker.id,
                "agent_name": worker.name,
                "agent_role": worker.role.value,
                "task_id": task.id,
                "task_description": task.description,
            }
        )

        async def emit_done() -> None:
            await self._emit(
                {
                    "type": "agent_done",
                    "agent_id": worker.id,
                    "agent_name": worker.name,
                    "agent_role": worker.role.value,
                    "task_id": task.id,
                    "task_description": task.description,
                    "result": task.result or "",
                    "status": task.status,
                }
            )

        # Progress callback — streams tool calls in real time
        async def _progress_cb(tool_name: str, result: Any) -> None:
            preview = ""
            try:
                if hasattr(result, "output") and result.output:
                    preview = str(result.output)[:300]
                elif hasattr(result, "error") and result.error:
                    preview = str(result.error)[:300]
                else:
                    preview = str(result)[:300]
            except Exception:
                preview = "..."
            await self._emit(
                {
                    "type": "agent_tool_result",
                    "agent_id": worker.id,
                    "agent_name": worker.name,
                    "agent_role": worker.role.value,
                    "task_id": task.id,
                    "tool_name": tool_name,
                    "preview": preview,
                    "success": getattr(result, "success", True),
                }
            )

        # PR-4.4: live stream + event callbacks. The stream callback gets the
        # redacted text deltas of the final assistant response; the event
        # callback gets PR-4.3 structured payloads (thinking/tool_call/usage/
        # error). We feed both into the existing /ws/fleet event bus so the
        # dashboard can render each agent's thinking/typing in real time
        # instead of waiting for the turn to finish.
        emitted_thinking_signatures: set[str] = set()
        emitted_tool_call_signatures: set[str] = set()

        async def _stream_cb(token: str) -> None:
            if not token:
                return
            await self._emit(
                {
                    "type": "agent_token",
                    "agent_id": worker.id,
                    "agent_name": worker.name,
                    "agent_role": worker.role.value,
                    "task_id": task.id,
                    "content": token,
                }
            )

        async def _event_cb(payload: dict[str, Any]) -> None:
            kind = payload.get("kind")
            if kind == "thinking_delta":
                text = payload.get("text") or ""
                if not text:
                    return
                # Track signature so the post-scan loop below does not
                # double-emit the same reasoning content.
                emitted_thinking_signatures.add(text[:80])
                await self._emit(
                    {
                        "type": "agent_thinking",
                        "agent_id": worker.id,
                        "agent_name": worker.name,
                        "agent_role": worker.role.value,
                        "task_id": task.id,
                        "content": text[:2000],
                    }
                )
            elif kind == "tool_call_delta":
                tc = payload.get("tool_call") or {}
                name = tc.get("name") or ""
                args = tc.get("arguments_delta") or ""
                if not name and not args:
                    return
                sig = f"{tc.get('id') or ''}:{name}:{args[:40]}"
                emitted_tool_call_signatures.add(sig)
                await self._emit(
                    {
                        "type": "agent_tool_call",
                        "agent_id": worker.id,
                        "agent_name": worker.name,
                        "agent_role": worker.role.value,
                        "task_id": task.id,
                        "tool_name": name or "(streaming)",
                        "arguments": str(args)[:500],
                    }
                )
            elif kind == "usage":
                usage = payload.get("usage") or {}
                if not usage:
                    return
                await self._emit(
                    {
                        "type": "agent_usage",
                        "agent_id": worker.id,
                        "agent_name": worker.name,
                        "agent_role": worker.role.value,
                        "task_id": task.id,
                        "usage": usage,
                    }
                )
            elif kind == "error":
                err = payload.get("error") or ""
                if not err:
                    return
                await self._emit(
                    {
                        "type": "agent_error",
                        "agent_id": worker.id,
                        "agent_name": worker.name,
                        "agent_role": worker.role.value,
                        "task_id": task.id,
                        "content": str(err)[:500],
                    }
                )

        try:
            parent_ctx = current_runtime_context()
            _product_id, owner = self._execution_scope(worker)
            session_id = _FLEET_SESSION.get() or (
                parent_ctx.session_id if parent_ctx is not None else None
            )
            async with self._semaphore:
                state = await asyncio.wait_for(
                    run_echo_turn(
                        worker.agent,
                        override_prompt or task.description,
                        channel="fleet_worker",
                        owner_key_hash=owner,
                        session_id=session_id or None,
                        model=worker.model,
                        progress_callback=_progress_cb,
                        stream_callback=_stream_cb,
                        event_callback=_event_cb,
                    ),
                    timeout=timeout,
                )
            # Extract final assistant message
            for msg in reversed(state.messages):
                if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                    task.result = msg.content
                    break

            # Post-scan fallback: for turns the live callbacks did NOT
            # cover (tool-using turns go through router.chat, not the
            # streaming path), surface reasoning_content / tool_calls
            # from the message log. Anything already emitted live is
            # deduplicated by signature so the UI does not see doubles.
            for msg in state.messages:
                if msg.role == "assistant":
                    # Emit reasoning content if present. PR-4.4: the prior
                    # one-line ternary mis-parsed (Python parsed it as
                    # ``getattr(...) or (msg.get(...) if isinstance else None)``
                    # so ChatMessage objects always took the None branch and
                    # post-scan reasoning never fired). Split explicitly.
                    if isinstance(msg, dict):
                        rc = msg.get("reasoning_content")
                    else:
                        rc = getattr(msg, "reasoning_content", None)
                    if rc:
                        text = str(rc)[:2000]
                        if text[:80] not in emitted_thinking_signatures:
                            await self._emit(
                                {
                                    "type": "agent_thinking",
                                    "agent_id": worker.id,
                                    "agent_name": worker.name,
                                    "agent_role": worker.role.value,
                                    "task_id": task.id,
                                    "content": text,
                                }
                            )
                    # Emit tool calls
                    if isinstance(msg, dict):
                        tcs = msg.get("tool_calls")
                    else:
                        tcs = getattr(msg, "tool_calls", None)
                    if tcs:
                        for tc in tcs:
                            if isinstance(tc, dict):
                                fn = tc.get("function", {})
                                name = fn.get("name", "unknown")
                                args = str(fn.get("arguments", "{}"))
                                sig = f"{tc.get('id') or ''}:{name}:{args[:40]}"
                                if sig in emitted_tool_call_signatures:
                                    continue
                                await self._emit(
                                    {
                                        "type": "agent_tool_call",
                                        "agent_id": worker.id,
                                        "agent_name": worker.name,
                                        "agent_role": worker.role.value,
                                        "task_id": task.id,
                                        "tool_name": name,
                                        "arguments": args[:500],
                                    }
                                )
                elif msg.role == "tool":
                    # Some tool results may not have gone through progress_callback
                    pass

            # Persist conversation log for history replay
            task.conversation_log = [
                {
                    "role": m.role,
                    "content": (m.content or "")[:500] if isinstance(m.content, str) else "",
                    "tool_calls": [
                        {
                            "name": tc.get("function", {}).get("name", "unknown"),
                            "arguments": str(tc.get("function", {}).get("arguments", "{}"))[:200],
                        }
                        for tc in (m.tool_calls or [])
                        if isinstance(tc, dict)
                    ]
                    if m.tool_calls
                    else None,
                }
                for m in state.messages
            ]
            # Determine status: be lenient — if we got a non-empty reply, mark as done
            # even if state.status is not strictly "completed" (e.g. hit max_turns)
            if state.status == "completed":
                task.status = "done"
            elif state.status == "error":
                task.status = "failed"
                if not task.result:
                    task.result = state.error_message or "Unknown error"
            elif state.status == "cancelled":
                task.status = "cancelled"
                if not task.result:
                    task.result = "Task was cancelled"
            else:
                # "running" or any other state — if we have a result, accept it
                task.status = "done" if task.result else "failed"
                if not task.result:
                    task.result = f"Agent finished with status '{state.status}' but no output"
        except asyncio.CancelledError:
            task.status = "cancelled"
            if not task.result:
                task.result = "Task was cancelled"
            await emit_done()
            raise
        except TimeoutError:
            task.status = "failed"
            task.result = f"Task timed out after {timeout}s"
            logger.error("Fleet task %s timed out", task.id)
        except Exception as e:
            task.status = "failed"
            task.result = "Fleet task failed safely"
            logger.error("Fleet task %s failed: %s", task.id, type(e).__name__)
        await emit_done()
        return task.id, task.result or ""

    async def _run_agent(self, agent: AgentInstance, prompt: str, timeout: float = 300.0) -> str:
        """Run a one-off prompt on an agent and return the response."""
        parent_ctx = current_runtime_context()
        _product_id, owner = self._execution_scope(agent)
        session_id = _FLEET_SESSION.get() or (
            parent_ctx.session_id if parent_ctx is not None else None
        )
        state = await asyncio.wait_for(
            run_echo_turn(
                agent.agent,
                prompt,
                channel="fleet_coordinator",
                owner_key_hash=owner,
                session_id=session_id or None,
                model=agent.model,
            ),
            timeout=timeout,
        )
        for msg in reversed(state.messages):
            if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                return msg.content
        return ""

    # ------------------------------------------------------------------ #
    # Simple heuristics — no LLM needed
    # ------------------------------------------------------------------ #

    @staticmethod
    def _auto_decompose(task: str) -> list[str]:
        """Split a complex task into 2-4 subtasks using simple heuristics."""
        task = task.strip()
        # If task already contains clear sections separated by newlines or bullets
        parts = [p.strip("- *•") for p in task.split("\n") if p.strip() and len(p.strip()) > 10]
        if len(parts) >= 2 and len(parts) <= 6:
            return parts[:4]

        # Check for numbered steps
        import re

        numbered = re.findall(
            r"(?:^|\n)\s*(?:\d+[.、]|Step\s+\d+[.:])\s*([^\n]+)", task, re.IGNORECASE
        )
        if len(numbered) >= 2 and len(numbered) <= 6:
            return [s.strip() for s in numbered[:4]]

        # Check for "and then / first / second / finally"
        splitters = re.split(
            r"(?:,\s*(?:and\s+)?then\s+|\s*;\s*|first(?:ly)?[,，:]\s*|second(?:ly)?[,，:]\s*|third(?:ly)?[,，:]\s*|finally[,，:]\s*)",
            task,
            flags=re.IGNORECASE,
        )
        pieces = [s.strip() for s in splitters if len(s.strip()) > 10]
        if len(pieces) >= 2 and len(pieces) <= 5:
            return pieces[:4]

        # Fallback: if task is long, split by sentences and group
        sentences = [s.strip() for s in re.split(r"[。！？.!?]\s*", task) if len(s.strip()) > 10]
        if len(sentences) >= 4:
            mid = len(sentences) // 2
            return [
                "。 ".join(sentences[:mid]) + "。",
                "。 ".join(sentences[mid:]) + "。",
            ]
        if len(sentences) >= 2:
            return [s + "。" for s in sentences[:4]]

        # Can't decompose — run as single task
        return [task]

    @staticmethod
    def _needs_review(task: str) -> bool:
        """Heuristic: code-related tasks benefit from review."""
        task_lower = task.lower()
        code_keywords = [
            "code",
            "程序",
            "代码",
            "function",
            "class",
            "implement",
            "refactor",
            "debug",
            "fix",
            "api",
            "script",
            "module",
            "write",
            "创建",
            "实现",
            "编写",
            "开发",
        ]
        return any(kw in task_lower for kw in code_keywords)

    # ------------------------------------------------------------------ #
    # Status (for observability — read-only)
    # ------------------------------------------------------------------ #

    def get_status(self, owner_key_hash: str | None = None) -> dict[str, Any]:
        product_id, owner = self._resolve_scope(
            owner_key_hash=owner_key_hash,
            allow_local_direct=True,
        )
        return {
            "agents": [
                {
                    "id": a.id,
                    "name": a.name,
                    "role": a.role.value,
                    "status": a.status,
                    "task_id": a.current_task,
                }
                for a in self.agents.values()
                if a.product_id == product_id and a.owner_key_hash == owner
            ],
        }

    # ------------------------------------------------------------------ #
    # History
    # ------------------------------------------------------------------ #

    async def _save_history(
        self,
        session_id: str,
        main_task: str,
        subtasks: list[str],
        result: dict[str, Any],
        *,
        owner_key_hash: str | None = None,
    ) -> None:
        """Persist a collaboration session to disk."""
        product_id, owner = self._resolve_scope(
            owner_key_hash=owner_key_hash,
            allow_local_direct=True,
        )
        record = {
            "session_id": session_id,
            "main_task": main_task,
            "subtasks": subtasks,
            "final": result.get("final", ""),
            "review": result.get("review"),
            "subtask_results": result.get("subtasks", {}),
            "created_at": time.time(),
            "product_id": product_id,
            "owner_key_hash": owner,
        }
        # Sanitize secrets before persisting to disk
        try:
            from js.security.secrets import SecretManager

            _sm = SecretManager(self._fleet_dir.parent)
            record["final"] = _sm.detect_and_redact(record["final"], f"fleet:final:{session_id}")
            if record.get("review"):
                record["review"] = _sm.detect_and_redact(
                    str(record["review"]), f"fleet:review:{session_id}"
                )
        except Exception:
            pass
        await asyncio.to_thread(
            self._history_store.write,
            self._partition_slug("product", product_id),
            self._partition_slug("owner", owner),
            session_id,
            record,
        )

    @staticmethod
    def _validated_history_record(
        data: dict[str, Any],
        *,
        session_id: str | None,
        product_id: str,
        owner: str,
    ) -> dict[str, Any] | None:
        raw_session_id = data.get("session_id")
        main_task = data.get("main_task")
        subtasks = data.get("subtasks")
        final = data.get("final")
        review = data.get("review")
        created_at = data.get("created_at")
        if (
            not isinstance(raw_session_id, str)
            or not _SAFE_FLEET_SESSION_RE.fullmatch(raw_session_id)
            or (session_id is not None and raw_session_id != session_id)
            or data.get("product_id") != product_id
            or data.get("owner_key_hash") != owner
            or not isinstance(main_task, str)
            or len(main_task) > _MAX_FLEET_TASK_CHARS
            or not isinstance(subtasks, list)
            or len(subtasks) > AgentFleet._MAX_SUBTASKS
            or any(
                not isinstance(subtask, str)
                or not subtask
                or len(subtask) > _MAX_FLEET_SUBTASK_CHARS
                for subtask in subtasks
            )
            or not isinstance(final, str)
            or len(final) > 8_000_000
            or (review is not None and not isinstance(review, str))
            or (isinstance(review, str) and len(review) > 8_000_000)
            or isinstance(created_at, bool)
            or not isinstance(created_at, int | float)
        ):
            return None
        return dict(data)

    def list_history(
        self, limit: int = 50, owner_key_hash: str | None = None
    ) -> list[dict[str, Any]]:
        """List recent collaboration sessions, newest first."""
        entries: list[dict[str, Any]] = []
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            return entries
        limit = min(limit, 200)
        product_id, owner = self._resolve_scope(
            owner_key_hash=owner_key_hash,
            allow_local_direct=True,
        )
        records = self._history_store.list_records(
            self._partition_slug("product", product_id),
            self._partition_slug("owner", owner),
        )
        for raw_data in records:
            data = self._validated_history_record(
                raw_data,
                session_id=None,
                product_id=product_id,
                owner=owner,
            )
            if data is None:
                continue
            entries.append(
                {
                    "session_id": data["session_id"],
                    "main_task": data["main_task"],
                    "subtask_count": len(data["subtasks"]),
                    "created_at": data["created_at"],
                    "has_review": data.get("review") is not None,
                }
            )
            if len(entries) >= limit:
                break
        return entries

    def get_session(
        self, session_id: str, owner_key_hash: str | None = None
    ) -> dict[str, Any] | None:
        """Get full details of a collaboration session."""
        product_id, owner = self._resolve_scope(
            owner_key_hash=owner_key_hash,
            allow_local_direct=True,
        )
        if not isinstance(session_id, str) or not _SAFE_FLEET_SESSION_RE.fullmatch(session_id):
            return None
        data = self._history_store.read(
            self._partition_slug("product", product_id),
            self._partition_slug("owner", owner),
            session_id,
        )
        if data is None:
            return None
        return self._validated_history_record(
            data,
            session_id=session_id,
            product_id=product_id,
            owner=owner,
        )

    def delete_session(self, session_id: str, owner_key_hash: str | None = None) -> bool:
        """Delete a collaboration session from disk."""
        product_id, owner = self._resolve_scope(
            owner_key_hash=owner_key_hash,
            allow_local_direct=True,
        )
        if not isinstance(session_id, str) or not _SAFE_FLEET_SESSION_RE.fullmatch(session_id):
            return False
        return self._history_store.delete(
            self._partition_slug("product", product_id),
            self._partition_slug("owner", owner),
            session_id,
            expected_product_id=product_id,
            expected_owner=owner,
        )

    def _history_scope_dir(self, product_id: str, owner_key_hash: str) -> Path:
        return (
            self._history_dir
            / self._partition_slug("product", product_id)
            / self._partition_slug("owner", owner_key_hash)
        )

    def _history_path(
        self,
        session_id: str,
        *,
        product_id: str,
        owner_key_hash: str,
        create_parent: bool = False,
    ) -> Path:
        if not _SAFE_FLEET_SESSION_RE.fullmatch(session_id):
            raise ValueError("invalid fleet session id")
        parent = self._history_scope_dir(product_id, owner_key_hash)
        if create_parent:
            self._history_store.ensure_scope(
                self._partition_slug("product", product_id),
                self._partition_slug("owner", owner_key_hash),
            )
        return parent / f"{session_id}.json"

    async def continue_session(
        self,
        session_id: str,
        follow_up: str,
        owner_key_hash: str | None = None,
    ) -> dict[str, Any]:
        """Continue a previous collaboration session with a follow-up task."""
        prev = self.get_session(session_id, owner_key_hash=owner_key_hash)
        if prev is None:
            raise ValueError(f"Session {session_id} not found")

        # Build context from previous session
        context = f"之前的主任务：{prev['main_task']}\n\n之前的最终答案：\n{prev.get('final', '')[:2000]}\n\n"
        context += f"用户的新需求：{follow_up}\n\n请基于之前的成果，继续完成新需求。"

        # Use same subtask structure or auto-decompose
        prev_subtasks = prev.get("subtasks", [])
        return await self.collaborate(
            main_task=context,
            subtasks=prev_subtasks or None,
            session_id=session_id,
            owner_key_hash=owner_key_hash,
        )

    def get_agent_config(self) -> dict[str, str]:
        """Return current role-to-model mapping."""
        return dict(self.agent_config)

    def reap_idle_agents(self, idle_timeout: float, max_idle: int) -> int:
        """Close and remove idle agents that exceed the timeout or count limits.

        Returns the number of agents that were reaped.
        """
        now = time.time()
        # Collect idle agents sorted by last-active time (oldest first)
        idle = sorted(
            [
                a
                for a in self.agents.values()
                if a.status == "idle" and now - a.last_active_at > idle_timeout
            ],
            key=lambda a: a.last_active_at,
        )
        # Determine how many to reap to stay within max_idle
        to_reap = max(0, len(idle) - max_idle)
        reaped = 0
        for a in idle[:to_reap]:
            try:
                agent_obj = getattr(a, "agent", None)
                if agent_obj is not None and hasattr(agent_obj, "close"):
                    close_result = agent_obj.close()
                    if asyncio.iscoroutine(close_result):
                        # Best-effort sync close in a sync context — create a
                        # one-shot event loop if needed, or skip.
                        try:
                            import asyncio as _asyncio

                            _loop = _asyncio.get_event_loop()
                            if _loop.is_running():
                                _asyncio.ensure_future(close_result)
                            else:
                                _loop.run_until_complete(close_result)
                        except RuntimeError:
                            pass
                self.agents.pop(a.id, None)
                reaped += 1
            except Exception:
                logger.warning("Failed to reap agent %s", a.id, exc_info=True)
        if reaped:
            logger.info("Reaped %d idle agents (%d remain)", reaped, len(self.agents))
        return reaped

    async def close_all(self) -> None:
        """Close all agents (called on shutdown)."""
        for a in self.agents.values():
            try:
                if hasattr(a.agent, "close"):
                    close_result = a.agent.close()
                    if asyncio.iscoroutine(close_result):
                        await close_result
            except Exception:
                logger.warning(f"Failed to close agent {a.id}", exc_info=True)
