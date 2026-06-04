"""Simplified multi-agent fleet — one call, auto-team, no manual management."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from js.agent import JSAgent
from js.config import JSSettings
from js.utils.log import get_logger

logger = get_logger("js.orchestration")


class AgentRole(StrEnum):
    """Dynamic role enum — supports arbitrary role names via AgentRole('name')."""

    WORKER = "worker"
    REVIEWER = "reviewer"

    @classmethod
    def from_value(cls, value: str) -> AgentRole:
        """Create or return a role by string value."""
        try:
            return cls(value)
        except ValueError:
            # Dynamically create a new enum member
            obj = str.__new__(cls, value)
            obj._value_ = value
            obj._name_ = value
            return obj  # type: ignore[return-value]


@dataclass
class AgentInstance:
    id: str
    name: str
    role: AgentRole
    agent: JSAgent
    model: str | None = None
    status: str = "idle"  # idle, busy, error
    current_task: str | None = None
    task_description: str = ""
    capabilities: list[str] = field(default_factory=list)
    last_active_at: float = field(default_factory=time.time)


@dataclass
class Task:
    id: str
    description: str
    role_hint: AgentRole
    priority: int = 5
    deps: list[str] = field(default_factory=list)
    result: str | None = None
    status: str = "pending"  # pending, running, done, failed
    assigned_to: str | None = None
    group_id: str | None = None
    conversation_log: list[dict[str, Any]] = field(default_factory=list)


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
    ) -> None:
        self.settings = settings
        self.agent_config = agent_config or {}
        self.agents: dict[str, AgentInstance] = {}
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max_workers)
        self._max_workers = max_workers
        self._skills_source = skills  # parent agent's SkillManager
        from collections.abc import Awaitable, Callable
        from threading import Lock as TLock

        self._spawn_lock = TLock()
        self._event_callbacks: list[Callable[[dict[str, Any]], Awaitable[None]]] = []
        # State dirs
        self._fleet_dir = settings.state_dir / "fleet"
        self._fleet_dir.mkdir(parents=True, exist_ok=True)
        self._history_dir = self._fleet_dir / "history"
        self._history_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Event callbacks (backward compat for websocket dashboard)
    # ------------------------------------------------------------------ #

    def on_event(self, callback: Any) -> None:
        self._event_callbacks.append(callback)

    def off_event(self, callback: Any) -> None:
        if callback in self._event_callbacks:
            self._event_callbacks.remove(callback)

    def update_agent_config(self, config: dict[str, str]) -> None:
        """Update the role-to-model mapping for future spawned agents."""
        self.agent_config.update(config)
        # Clear existing agent pool so new requests pick up updated models
        with self._spawn_lock:
            self.agents.clear()

    async def _emit(self, event: dict[str, Any]) -> None:
        for cb in self._event_callbacks[:]:
            try:
                await cb(event)
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Public API — one method
    # ------------------------------------------------------------------ #

    _MAX_SUBTASKS = 20

    async def collaborate(
        self,
        main_task: str,
        subtasks: list[str] | None = None,
        session_id: str | None = None,
        role_mapping: dict[int, str] | None = None,
        mode: str = "auto",
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
        sid = session_id or str(uuid.uuid4())
        group_id = str(uuid.uuid4())

        # Enforce subtask count limit to prevent resource exhaustion
        if subtasks and len(subtasks) > self._MAX_SUBTASKS:
            logger.warning(
                "Truncating %d subtasks to %d (max)",
                len(subtasks), self._MAX_SUBTASKS,
            )
            subtasks = subtasks[: self._MAX_SUBTASKS]

        logger.info(f"Fleet collaborate mode={mode}: {main_task[:60]}")
        await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "decomposing", "message": f"[{mode}] 正在分析任务并拆分子任务..."})

        # Route to mode-specific handler
        if mode == "debate":
            result = await self._collaborate_debate(sid, group_id, main_task, subtasks, role_mapping)
        elif mode == "sequential":
            result = await self._collaborate_sequential(sid, group_id, main_task, subtasks, role_mapping)
        elif mode == "manager":
            result = await self._collaborate_manager(sid, group_id, main_task, subtasks, role_mapping)
        else:
            result = await self._collaborate_auto(sid, group_id, main_task, subtasks, role_mapping)

        # Save history and emit result
        descs = list(result.get("subtasks", {}).keys()) or [main_task]
        await self._save_history(sid, main_task, descs, result)
        await self._emit({"type": "collaborate_result", **result})
        logger.info(f"Fleet done mode={mode}: {main_task[:60]} -> {len(result.get('final', ''))} chars")
        return result

    # ------------------------------------------------------------------ #
    # Collaboration modes
    # ------------------------------------------------------------------ #

    async def _collaborate_auto(
        self, sid: str, group_id: str, main_task: str,
        subtasks: list[str] | None, role_mapping: dict[int, str] | None,
    ) -> dict[str, Any]:
        """Default: auto-decompose + parallel execute + review + synthesize."""
        descs = subtasks or self._auto_decompose(main_task)
        await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "dispatched", "message": f"已拆分为 {len(descs)} 个子任务，正在分配Agent...", "subtasks": descs, "mode": "auto"})

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

            unique_agents = list({a.id: a for a in agents_used}.values())

            tasks = [
                Task(id=str(uuid.uuid4()), description=desc,
                     role_hint=AgentRole.from_value(role_map.get(idx, "worker")), group_id=group_id)
                for idx, desc in enumerate(descs)
            ]
            await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "executing", "message": f"{len(descs)} 个Agent正在并行执行任务...", "total": len(descs), "completed": 0, "mode": "auto"})
            results = await self._run_parallel(tasks, agents_used)
            await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "executing", "message": "所有子任务执行完成", "total": len(descs), "completed": len(descs), "mode": "auto"})

            review = ""
            if self._needs_review(main_task):
                await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "reviewing", "message": "审查Agent正在检查结果...", "mode": "auto"})
                reviewer = await self._acquire_agent("reviewer", group_id)
                review_prompt = (
                    f"主任务：{main_task}\n\n"
                    f"以下是各子任务的执行结果：\n"
                )
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

            await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "synthesizing", "message": "正在综合所有结果为最终答案...", "mode": "auto"})
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
            for a in unique_agents:
                a.status = "idle"
                a.current_task = None
                a.last_active_at = time.time()
            if reviewer is not None:
                reviewer.status = "idle"
                reviewer.current_task = None
                reviewer.last_active_at = time.time()

    async def _collaborate_debate(
        self, sid: str, group_id: str, main_task: str,
        subtasks: list[str] | None, role_mapping: dict[int, str] | None,
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
        await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "dispatched", "message": f"辩论模式：{len(descs)} 个Agent从不同角度分析同一问题...", "subtasks": descs, "mode": "debate"})

        role_map = role_mapping or {}
        agents_used: list[AgentInstance] = []
        tasks: list[Task] = []
        try:
            for idx, desc in enumerate(descs):
                role_val = role_map.get(idx, f"debater_{idx}")
                agent = await self._acquire_agent(role_val, group_id)
                agents_used.append(agent)
                tasks.append(Task(id=str(uuid.uuid4()), description=desc, role_hint=AgentRole.from_value(role_val), group_id=group_id))

            unique_agents = list({a.id: a for a in agents_used}.values())

            await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "executing", "message": f"{len(descs)} 个Agent正在并行发表观点...", "total": len(descs), "completed": 0, "mode": "debate"})
            results = await self._run_parallel(tasks, agents_used)
            await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "executing", "message": "所有观点收集完成", "total": len(descs), "completed": len(descs), "mode": "debate"})

            # Synthesize debate results
            await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "synthesizing", "message": "正在综合多方观点为最终结论...", "mode": "debate"})
            synthesis_prompt = (
                f"主任务：{main_task}\n\n"
                "以下是多位专家从不同角度给出的分析：\n"
            )
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
            for a in unique_agents:
                a.status = "idle"
                a.current_task = None
                a.last_active_at = time.time()

    async def _collaborate_sequential(
        self, sid: str, group_id: str, main_task: str,
        subtasks: list[str] | None, role_mapping: dict[int, str] | None,
    ) -> dict[str, Any]:
        """Sequential mode: pipeline — each agent's output feeds into the next."""
        descs = subtasks or self._auto_decompose(main_task)
        await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "dispatched", "message": f"串行模式：{len(descs)} 个步骤依次执行...", "subtasks": descs, "mode": "sequential"})

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
                    prompt = f"主任务：{main_task}\n\n步骤 {idx+1}/{len(descs)}：{desc}\n\n请开始执行这一步。"
                else:
                    prev_results = "\n\n".join(
                        f"步骤 {i+1} 结果：\n{results.get(descs[i], '')[:800]}"
                        for i in range(idx)
                    )
                    prompt = (
                        f"主任务：{main_task}\n\n"
                        f"之前步骤的结果：\n{prev_results}\n\n"
                        f"步骤 {idx+1}/{len(descs)}：{desc}\n\n"
                        "请基于之前的结果继续执行这一步。"
                    )

                await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "executing", "message": f"步骤 {idx+1}/{len(descs)} 执行中...", "total": len(descs), "completed": idx, "mode": "sequential"})
                task = Task(id=str(uuid.uuid4()), description=desc, role_hint=AgentRole.from_value(role_val), group_id=group_id)
                _, result = await self._execute_single(task, agent, override_prompt=prompt)
                results[desc] = result
                agent.status = "idle"
                agent.current_task = None
                agent.last_active_at = time.time()

            await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "synthesizing", "message": "正在综合所有步骤结果为最终答案...", "mode": "sequential"})
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
        self, sid: str, group_id: str, main_task: str,
        subtasks: list[str] | None, role_mapping: dict[int, str] | None,
    ) -> dict[str, Any]:
        """Manager mode: a manager agent plans, assigns, then synthesizes."""
        descs = subtasks or self._auto_decompose(main_task)
        await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "dispatched", "message": f"经理模式：Manager 规划 {len(descs)} 个子任务...", "subtasks": descs, "mode": "manager"})

        role_map = role_mapping or {}
        manager: AgentInstance | None = None
        workers: list[AgentInstance] = []
        try:
            manager = await self._acquire_agent("manager", group_id)
            # Manager does a quick plan (could be expanded)
            plan_prompt = (
                f"你是项目经理。主任务：{main_task}\n\n"
                f"已拆分为以下子任务：\n" +
                "\n".join(f"{i+1}. {d}" for i, d in enumerate(descs)) +
                "\n\n请确认计划合理，如有调整建议请说明。如果没有问题，回复 'PLAN_OK'。"
            )
            plan_check = await self._run_agent(manager, plan_prompt, timeout=60.0)
            # Even if plan_check isn't 'PLAN_OK', we proceed — the manager's feedback
            # will be included in the synthesis.

            # Dispatch workers in parallel
            tasks = [
                Task(id=str(uuid.uuid4()), description=desc,
                     role_hint=AgentRole.from_value(role_map.get(idx, "worker")), group_id=group_id)
                for idx, desc in enumerate(descs)
            ]
            for idx, _ in enumerate(descs):
                role_val = role_map.get(idx, "worker")
                w = await self._acquire_agent(role_val, group_id)
                workers.append(w)

            await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "executing", "message": f"Manager 监督 {len(descs)} 个Worker并行执行...", "total": len(descs), "completed": 0, "mode": "manager"})
            results = await self._run_parallel(tasks, workers)
            await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "executing", "message": "所有Worker执行完成", "total": len(descs), "completed": len(descs), "mode": "manager"})

            # Manager synthesizes
            await self._emit({"type": "collaborate_progress", "session_id": sid, "stage": "synthesizing", "message": "Manager 正在综合最终答案...", "mode": "manager"})
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
        async with self._lock:
            # Re-use idle agent of same role
            for a in self.agents.values():
                if a.status == "idle" and a.role.value == role.value:
                    a.status = "busy"
                    a.last_active_at = time.time()
                    return a
            # Spawn new agent if pool allows
            if len(self.agents) < self._max_workers:
                return self._spawn_agent(role.value, role)
        # Pool full — wait for any idle agent
        for _ in range(60):
            async with self._lock:
                for a in self.agents.values():
                    if a.status == "idle":
                        a.status = "busy"
                        a.last_active_at = time.time()
                        return a
            await asyncio.sleep(1)
        raise RuntimeError(f"No agent available for role '{role_value}'")

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
        rv = role_value.lower().strip()

        # Exact match persona definitions
        personas: dict[str, str] = {
            "worker": (
                "\n\n【你的身份】执行专家\n"
                "你是一名高效的任务执行者。你的工作目标是准确、快速地完成分配给你的具体任务。\n"
                "【工作态度】注重结果、追求准确、不偏离目标。遇到困难时先尝试解决，必要时请求澄清。"
            ),
            "reviewer": (
                "\n\n【你的身份】质量审查员\n"
                "你是一名严格的质量把关者。你的工作目标是检查他人产出的正确性、完整性和规范性。\n"
                "【工作态度】严谨细致、敢于质疑、不留遗漏。发现问题直接指出，没有问题时简洁确认。"
            ),
            "manager": (
                "\n\n【你的身份】项目经理\n"
                "你是一名统筹全局的协调者。你的工作目标是制定合理计划、分配资源、监督执行并综合结果。\n"
                "【工作态度】全局视野、决策果断、对结果负责。确保每个环节衔接顺畅，最终交付物完整可用。"
            ),
            "sales": (
                "\n\n【你的身份】销售顾问\n"
                "你是一名以客户为中心的销售专家。你的工作目标是深入了解客户需求，推荐最合适的产品或方案。\n"
                "【工作态度】热情主动、倾听需求、诚信推荐。不夸大产品能力，帮助客户做出最优决策。"
            ),
            "researcher": (
                "\n\n【你的身份】研究员\n"
                "你是一名深入调研的分析专家。你的工作目标是收集全面信息，提供有据可依的深入分析。\n"
                "【工作态度】客观中立、追根溯源、引用可靠。不确定的信息明确标注，不编造事实。"
            ),
            "coder": (
                "\n\n【你的身份】程序员\n"
                "你是一名注重工程质量的开发者。你的工作目标是编写清晰、可维护、可靠的代码。\n"
                "【工作态度】遵循最佳实践、注重边界处理、写出自解释代码。代码即文档，测试即保障。"
            ),
            "designer": (
                "\n\n【你的身份】设计师\n"
                "你是一名以用户为中心的设计专家。你的工作目标是创造美观、易用、一致的视觉和交互体验。\n"
                "【工作态度】细节控、同理心强、追求美感与功能平衡。每个像素都有意义，每个交互都流畅自然。"
            ),
            "tester": (
                "\n\n【你的身份】测试工程师\n"
                "你是一名专找漏洞的质量卫士。你的工作目标是发现潜在缺陷，确保交付物稳定可靠。\n"
                "【工作态度】破坏欲强、边界敏感、场景覆盖全。没有测不到的场景，只有没想到的边界。"
            ),
            "architect": (
                "\n\n【你的身份】系统架构师\n"
                "你是一名高瞻远瞩的技术规划者。你的工作目标是设计可扩展、高可用、易维护的系统架构。\n"
                "【工作态度】权衡利弊、着眼长远、化繁为简。好的架构是生长出来的，不是堆砌出来的。"
            ),
            "security": (
                "\n\n【你的身份】安全专家\n"
                "你是一名警惕的风险识别者。你的工作目标是发现安全隐患，提出加固建议。\n"
                "【工作态度】零信任、深度防御、最小权限。安全不是附加功能，而是系统设计的基础。"
            ),
            "performance": (
                "\n\n【你的身份】性能优化专家\n"
                "你是一名追求极致效率的优化师。你的工作目标是识别瓶颈，提升系统运行效率。\n"
                "【工作态度】数据驱动、量化改进、拒绝过早优化。先测量再优化，没有数据不谈性能。"
            ),
            "doc_writer": (
                "\n\n【你的身份】技术文档工程师\n"
                "你是一名化繁为简的写作专家。你的工作目标是产出清晰、准确、易于理解的技术文档。\n"
                "【工作态度】读者视角、逻辑清晰、示例为王。好的文档让读者不需要问问题。"
            ),
            "analyst": (
                "\n\n【你的身份】数据分析师\n"
                "你是一名从数据中提取洞察的分析专家。你的工作目标是基于数据给出有理有据的结论和建议。\n"
                "【工作态度】逻辑严密、假设检验、可视化表达。让数据自己说话，同时指出数据的局限性。"
            ),
        }

        if rv in personas:
            return personas[rv]

        # Keyword-based inference for unknown roles
        keyword_map: dict[str, str] = {
            "销售": "sales", "sale": "sales", "客服": "sales", "support": "sales",
            "研究": "researcher", "research": "researcher", "调研": "researcher",
            "代码": "coder", "程序": "coder", "开发": "coder", "dev": "coder", "engineer": "coder",
            "设计": "designer", "design": "designer", "ui": "designer", "ux": "designer",
            "测试": "tester", "test": "tester", "qa": "tester", "质检": "tester",
            "架构": "architect", "arch": "architect",
            "安全": "security", "sec": "security", "风控": "security",
            "性能": "performance", "perf": "performance", "优化": "performance",
            "文档": "doc_writer", "doc": "doc_writer", "写作": "doc_writer", "writer": "doc_writer",
            "分析": "analyst", "数据": "analyst", "洞察": "analyst",
            "审查": "reviewer", "review": "reviewer", "审核": "reviewer",
            "经理": "manager", "管理": "manager", "主管": "manager", "lead": "manager",
            "执行": "worker", "worker": "worker", "干活的": "worker", "实干": "worker",
        }
        for kw, mapped in keyword_map.items():
            if kw in rv:
                return personas[mapped]

        # Fallback generic persona
        return (
            f"\n\n【你的身份】{role_value}\n"
            f"你是团队中负责 '{role_value}' 工作的专家。你需要以专业态度完成分配给你的任务。\n"
            "【工作态度】认真负责、追求专业、团队协作。发挥你的专长，为整体目标贡献力量。"
        )

    def _spawn_agent(self, name: str, role: AgentRole) -> AgentInstance:
        from js.utils.ids import agent_id as _det_agent_id

        model = self.agent_config.get(role.value)
        agent_id = _det_agent_id(name, role.value, model)
        role_settings = self._role_settings(agent_id)
        agent = JSAgent(role_settings)
        agent._role = role.value

        # Copy skills from parent agent so fleet workers can use all skills
        if self._skills_source is not None:
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
            "你可以调用所有已注册的技能工具来完成任务。"
            "注意：如果用户只是简单问候或提问，不需要调用任何工具，直接礼貌回答即可。"
        )
        agent.SYSTEM_PROMPT = agent.SYSTEM_PROMPT + fleet_hint
        instance = AgentInstance(
            id=agent_id,
            name=name,
            role=role,
            agent=agent,
            model=model,
        )
        with self._spawn_lock:
            self.agents[agent_id] = instance
        logger.info(f"Spawned {name} ({role.value}) id={agent_id} persona={len(persona)} chars")
        return instance

    def _role_settings(self, agent_id: str) -> JSSettings:
        from copy import deepcopy


        settings = deepcopy(self.settings)
        settings.state_dir = self._fleet_dir / agent_id
        settings.state_dir.mkdir(parents=True, exist_ok=True)
        settings.workspace = settings.workspace / "fleet" / agent_id
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
        """Run tasks in parallel, assigning one worker per task."""
        coros: list[asyncio.Task[tuple[str, str]]] = []
        for t, w in zip(tasks, workers, strict=False):
            w.current_task = t.id
            w.task_description = t.description
            t.status = "running"
            t.assigned_to = w.id
            coros.append(asyncio.create_task(self._execute_single(t, w)))

        results: dict[str, str] = {}
        for coro in asyncio.as_completed(coros):
            task_id, result = await coro
            results[task_id] = result

        return results

    async def _execute_single(self, task: Task, worker: AgentInstance, override_prompt: str | None = None) -> tuple[str, str]:
        """Run one task on one worker. Returns (task_id, result_text).

        Emits real-time events:
            agent_start    — task assigned
            agent_thinking — model reasoning content (if any)
            agent_tool_call   — tool name + arguments
            agent_tool_result — tool result preview
            agent_done     — task complete
        """
        timeout = 600.0
        await self._emit({
            "type": "agent_start",
            "agent_id": worker.id,
            "agent_name": worker.name,
            "agent_role": worker.role.value,
            "task_id": task.id,
            "task_description": task.description,
        })

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
            await self._emit({
                "type": "agent_tool_result",
                "agent_id": worker.id,
                "agent_name": worker.name,
                "agent_role": worker.role.value,
                "task_id": task.id,
                "tool_name": tool_name,
                "preview": preview,
                "success": getattr(result, "success", True),
            })

        try:
            async with self._semaphore:
                state = await asyncio.wait_for(
                    worker.agent.run(
                        override_prompt or task.description,
                        model=worker.model,
                        progress_callback=_progress_cb,
                    ),
                    timeout=timeout,
                )
            # Extract final assistant message
            for msg in reversed(state.messages):
                if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                    task.result = msg.content
                    break

            # Stream reasoning content and tool calls from the message log
            for msg in state.messages:
                if msg.role == "assistant":
                    # Emit reasoning content if present
                    rc = getattr(msg, "reasoning_content", None) or msg.get("reasoning_content") if isinstance(msg, dict) else None
                    if rc:
                        await self._emit({
                            "type": "agent_thinking",
                            "agent_id": worker.id,
                            "agent_name": worker.name,
                            "agent_role": worker.role.value,
                            "task_id": task.id,
                            "content": str(rc)[:2000],
                        })
                    # Emit tool calls
                    tcs = getattr(msg, "tool_calls", None) or msg.get("tool_calls") if isinstance(msg, dict) else None
                    if tcs:
                        for tc in tcs:
                            if isinstance(tc, dict):
                                fn = tc.get("function", {})
                                await self._emit({
                                    "type": "agent_tool_call",
                                    "agent_id": worker.id,
                                    "agent_name": worker.name,
                                    "agent_role": worker.role.value,
                                    "task_id": task.id,
                                    "tool_name": fn.get("name", "unknown"),
                                    "arguments": str(fn.get("arguments", "{}"))[:500],
                                })
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
                    ] if m.tool_calls else None,
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
                task.status = "failed"
                if not task.result:
                    task.result = "Task was cancelled"
            else:
                # "running" or any other state — if we have a result, accept it
                task.status = "done" if task.result else "failed"
                if not task.result:
                    task.result = f"Agent finished with status '{state.status}' but no output"
        except TimeoutError:
            task.status = "failed"
            task.result = f"Task timed out after {timeout}s"
            logger.error(f"Task {task.id} timed out")
        except Exception as e:
            task.status = "failed"
            task.result = str(e)
            logger.error(f"Task {task.id} failed: {e}")
        await self._emit({
            "type": "agent_done",
            "agent_id": worker.id,
            "agent_name": worker.name,
            "agent_role": worker.role.value,
            "task_id": task.id,
            "task_description": task.description,
            "result": task.result or "",
            "status": task.status,
        })
        return task.id, task.result or ""

    async def _run_agent(self, agent: AgentInstance, prompt: str, timeout: float = 300.0) -> str:
        """Run a one-off prompt on an agent and return the response."""
        state = await asyncio.wait_for(
            agent.agent.run(prompt, model=agent.model),
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

        numbered = re.findall(r"(?:^|\n)\s*(?:\d+[.、]|Step\s+\d+[.:])\s*([^\n]+)", task, re.IGNORECASE)
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
            "code", "程序", "代码", "function", "class", "implement",
            "refactor", "debug", "fix", "api", "script", "module",
            "write", "创建", "实现", "编写", "开发",
        ]
        return any(kw in task_lower for kw in code_keywords)

    # ------------------------------------------------------------------ #
    # Status (for observability — read-only)
    # ------------------------------------------------------------------ #

    def get_status(self) -> dict[str, Any]:
        return {
            "agents": [
                {
                    "id": a.id,
                    "name": a.name,
                    "role": a.role.value,
                    "status": a.status,
                    "task": a.task_description[:80] if a.task_description else None,
                }
                for a in self.agents.values()
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
    ) -> None:
        """Persist a collaboration session to disk."""
        import json as _json

        record = {
            "session_id": session_id,
            "main_task": main_task,
            "subtasks": subtasks,
            "final": result.get("final", ""),
            "review": result.get("review"),
            "subtask_results": result.get("subtasks", {}),
            "created_at": time.time(),
        }
        path = self._history_dir / f"{session_id}.json"
        # Sanitize secrets before persisting to disk
        try:
            from js.security.secrets import SecretManager
            _sm = SecretManager(self._fleet_dir.parent)
            record["final"] = _sm.detect_and_redact(record["final"], f"fleet:final:{session_id}")
            if record.get("review"):
                record["review"] = _sm.detect_and_redact(str(record["review"]), f"fleet:review:{session_id}")
        except Exception:
            pass
        await asyncio.to_thread(path.write_text, _json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        # Rotate: keep only the most recent 200 history files
        try:
            files = sorted(self._history_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
            for old in files[200:]:
                old.unlink(missing_ok=True)
        except Exception:
            pass

    def list_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """List recent collaboration sessions, newest first."""
        import json as _json

        entries: list[dict[str, Any]] = []
        for path in sorted(self._history_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                data = _json.loads(path.read_text(encoding="utf-8"))
                entries.append({
                    "session_id": data["session_id"],
                    "main_task": data["main_task"],
                    "subtask_count": len(data.get("subtasks", [])),
                    "created_at": data.get("created_at", 0),
                    "has_review": data.get("review") is not None,
                })
            except Exception:
                continue
            if len(entries) >= limit:
                break
        return entries

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get full details of a collaboration session."""
        import json as _json

        path = self._history_dir / f"{session_id}.json"
        if not path.exists():
            return None
        try:
            data: dict[str, Any] = _json.loads(path.read_text(encoding="utf-8"))
            return data
        except Exception:
            return None

    def delete_session(self, session_id: str) -> bool:
        """Delete a collaboration session from disk."""
        path = self._history_dir / f"{session_id}.json"
        if not path.exists():
            return False
        try:
            path.unlink()
            return True
        except Exception:
            return False

    async def continue_session(self, session_id: str, follow_up: str) -> dict[str, Any]:
        """Continue a previous collaboration session with a follow-up task."""
        prev = self.get_session(session_id)
        if prev is None:
            raise ValueError(f"Session {session_id} not found")

        # Build context from previous session
        context = f"之前的主任务：{prev['main_task']}\n\n之前的最终答案：\n{prev.get('final', '')[:2000]}\n\n"
        context += f"用户的新需求：{follow_up}\n\n请基于之前的成果，继续完成新需求。"

        # Use same subtask structure or auto-decompose
        prev_subtasks = prev.get("subtasks", [])
        return await self.collaborate(main_task=context, subtasks=prev_subtasks or None, session_id=session_id)

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
            [a for a in self.agents.values()
             if a.status == "idle" and now - a.last_active_at > idle_timeout],
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
