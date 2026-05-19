"""Multi-agent fleet management with message bus."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from js.agent import JSAgent
from js.config import JSSettings
from js.utils.log import get_logger

logger = get_logger("js.orchestration")


class AgentRole(StrEnum):
    ORCHESTRATOR = "orchestrator"
    CODER = "coder"
    REVIEWER = "reviewer"
    RESEARCHER = "researcher"
    TESTER = "tester"
    GENERALIST = "generalist"


@dataclass
class AgentInstance:
    id: str
    name: str
    role: AgentRole
    agent: JSAgent
    model: str | None = None
    status: str = "idle"  # idle, busy, error
    current_task: str | None = None
    capabilities: list[str] = field(default_factory=list)
    message_queue: asyncio.Queue[dict[str, Any]] = field(default_factory=asyncio.Queue)


@dataclass
class Task:
    id: str
    description: str
    role_hint: AgentRole
    priority: int = 5
    deps: list[str] = field(default_factory=list)
    result: str | None = None
    status: str = "pending"  # pending, assigned, running, done, failed
    assigned_to: str | None = None


class AgentFleet:
    """Manages a pool of specialized agents with message passing."""

    def __init__(self, settings: JSSettings) -> None:
        self.settings = settings
        self.agents: dict[str, AgentInstance] = {}
        self.tasks: dict[str, Task] = {}
        self._bus: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._lock = asyncio.Lock()
        self._running = False
        self._background_tasks: set[asyncio.Task[Any]] = set()

    def spawn(
        self,
        name: str,
        role: AgentRole,
        model: str | None = None,
        capabilities: list[str] | None = None,
    ) -> AgentInstance:
        """Create a new agent in the fleet."""
        agent_id = str(uuid.uuid4())
        # Customize settings per role
        role_settings = self._role_settings(role)
        agent = JSAgent(role_settings)
        instance = AgentInstance(
            id=agent_id,
            name=name,
            role=role,
            agent=agent,
            model=model,
            capabilities=capabilities or [],
        )
        self.agents[agent_id] = instance
        logger.info(f"Spawned agent {name} ({role}) with ID {agent_id}")
        return instance

    def _role_settings(self, role: AgentRole) -> JSSettings:
        """Create specialized settings for different roles."""
        settings = JSSettings.from_file()
        if role == AgentRole.CODER:
            settings.max_turns = 80
        elif role == AgentRole.REVIEWER:
            settings.max_turns = 30
        elif role == AgentRole.RESEARCHER:
            settings.max_turns = 40
        return settings

    async def dispatch(self, task: Task) -> str:
        """Dispatch a task to the best available agent."""
        async with self._lock:
            self.tasks[task.id] = task

        # Find best agent
        best_agent: AgentInstance | None = None
        for agent in self.agents.values():
            if agent.status == "idle" and (agent.role == task.role_hint or agent.role == AgentRole.GENERALIST):
                best_agent = agent
                break

        if not best_agent:
            # Spawn a new generalist
            best_agent = self.spawn(f"worker-{task.role_hint}", task.role_hint)

        task.assigned_to = best_agent.id
        task.status = "running"
        best_agent.status = "busy"
        best_agent.current_task = task.id

        # Run task in background
        bg_task = asyncio.create_task(self._execute_task(task, best_agent))
        self._background_tasks.add(bg_task)
        bg_task.add_done_callback(self._background_tasks.discard)
        return task.id

    async def _execute_task(self, task: Task, agent: AgentInstance) -> None:
        try:
            logger.info(f"Agent {agent.name} starting task {task.id}")
            state = await agent.agent.run(task.description, model=agent.model)

            task.result = ""
            for msg in reversed(state.messages):
                if msg.role == "assistant" and isinstance(msg.content, str) and msg.content:
                    task.result = msg.content
                    break

            task.status = "done" if state.status == "completed" else "failed"
            agent.status = "idle"
            agent.current_task = None

            await self._bus.put({
                "type": "task_complete",
                "task_id": task.id,
                "agent_id": agent.id,
                "result": task.result,
            })
        except Exception as e:
            task.status = "failed"
            task.result = str(e)
            agent.status = "error"
            logger.error(f"Task {task.id} failed: {e}")
            # Notify bus so collaborate() doesn't hang forever
            await self._bus.put({
                "type": "task_complete",
                "task_id": task.id,
                "agent_id": agent.id,
                "result": task.result,
            })

    async def collaborate(
        self,
        main_task: str,
        subtasks: list[tuple[str, AgentRole]],
    ) -> dict[str, Any]:
        """Break a task into subtasks and execute in parallel."""
        tasks: list[Task] = []
        for desc, role in subtasks:
            t = Task(
                id=str(uuid.uuid4()),
                description=desc,
                role_hint=role,
            )
            tasks.append(t)
            await self.dispatch(t)

        # Wait for all
        results: dict[str, str] = {}
        pending = {t.id for t in tasks}
        while pending:
            msg = await self._bus.get()
            if msg["type"] == "task_complete" and msg["task_id"] in pending:
                pending.remove(msg["task_id"])
                results[msg["task_id"]] = msg["result"]

        # Synthesize final result with orchestrator
        orchestrator = next(
            (a for a in self.agents.values() if a.role == AgentRole.ORCHESTRATOR),
            None,
        )
        if not orchestrator:
            orchestrator = self.spawn("orchestrator", AgentRole.ORCHESTRATOR)

        synthesis_prompt = f"Main task: {main_task}\n\nSubtask results:\n"
        for tid, result in results.items():
            synthesis_prompt += f"\n[{tid}]:\n{result[:2000]}\n"
        synthesis_prompt += "\nSynthesize these results into a coherent final answer."

        final_state = await orchestrator.agent.run(synthesis_prompt)
        final_result = ""
        for chat_msg in reversed(final_state.messages):
            if chat_msg.role == "assistant" and isinstance(chat_msg.content, str) and chat_msg.content:
                final_result = chat_msg.content
                break

        return {"final": final_result, "subtasks": results}

    async def broadcast(self, message: str, exclude: str | None = None) -> None:
        """Broadcast a message to all agents."""
        for agent in self.agents.values():
            if agent.id != exclude:
                await agent.message_queue.put({"type": "broadcast", "content": message})

    def get_status(self) -> dict[str, Any]:
        return {
            "agents": [
                {
                    "id": a.id,
                    "name": a.name,
                    "role": a.role.value,
                    "status": a.status,
                    "task": a.current_task,
                }
                for a in self.agents.values()
            ],
            "tasks": [
                {
                    "id": t.id,
                    "status": t.status,
                    "assigned_to": t.assigned_to,
                    "description": t.description[:100],
                }
                for t in self.tasks.values()
            ],
        }
