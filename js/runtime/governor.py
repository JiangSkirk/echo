"""Resource governance: memory monitoring, idle agent reaping, database pruning."""

from __future__ import annotations

import asyncio
import gc
import os
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.utils.log import get_logger

logger = get_logger("js.runtime.governor")


@dataclass
class ResourceSnapshot:
    timestamp: float
    process_rss_mb: float
    process_vms_mb: float
    system_memory_percent: float
    system_memory_available_mb: float
    cpu_percent: float
    disk_free_state_dir_gb: float
    disk_free_root_gb: float
    active_sessions: int
    active_agents: int
    idle_agents: int
    in_flight_tasks: int


class ResourceGovernor:
    """Unified resource governance: monitoring, cleanup, and self-protection.

    Runs as a background asyncio task inside JSAgent.  It collects resource
    metrics every *interval_seconds*, reaps idle fleet agents every 5 minutes,
    and prunes databases every 6 hours.  When system memory crosses
    configurable thresholds it automatically de-compresses (reaps idle agents,
    clears caches, forces gc) and can ultimately trigger an emergency
    shutdown to avoid the OOM killer.
    """

    def __init__(
        self,
        agent: Any,
        fleet_getter: Callable[[], Any] | None = None,
        state_dir: Path | None = None,
    ) -> None:
        self._agent = agent
        self._fleet_getter = fleet_getter
        self._state_dir = state_dir

        self._task: asyncio.Task[Any] | None = None
        self._lock = asyncio.Lock()

        # Timing
        self._interval_seconds = 30.0
        self._last_reap_time = 0.0
        self._reap_interval = 300.0  # 5 minutes
        self._last_prune_time = 0.0
        self._prune_interval = 21_600.0  # 6 hours

        # Memory pressure thresholds (percent of system memory)
        self._warn_percent = 70.0
        self._pressure_percent = 80.0
        self._critical_percent = 90.0
        self._emergency_percent = 95.0

        # History ring buffer (200 samples ≈ 100 minutes)
        self._history: deque[ResourceSnapshot] = deque(maxlen=200)
        self._history_lock = threading.Lock()

        # Idle agent limits
        self._max_idle_agents = 8
        self._idle_timeout_seconds = 1_800.0  # 30 minutes

        # When True new requests are temporarily rejected (503)
        self._paused = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
        self._task = asyncio.create_task(self._loop())
        self._task.add_done_callback(self._on_done)

    def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()

    def _on_done(self, task: asyncio.Task[Any]) -> None:
        if task.done() and not task.cancelled():
            exc = task.exception()
            if exc is not None:
                logger.error("ResourceGovernor crashed: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self._interval_seconds)
            except asyncio.CancelledError:
                break

            if self._paused:
                continue

            try:
                await self._run_cycle()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("ResourceGovernor cycle failed: %s", e, exc_info=True)

    async def _run_cycle(self) -> None:
        now = time.time()

        # 1. Resource monitoring
        snapshot = self._collect_snapshot()
        if snapshot is not None:
            with self._history_lock:
                self._history.append(snapshot)
            self._evaluate_pressure(snapshot)

        # 2. Idle agent reaping (every 5 min)
        if now - self._last_reap_time >= self._reap_interval:
            await self._reap_idle_agents()
            self._last_reap_time = now

        # 3. Database pruning (every 6 h)
        if now - self._last_prune_time >= self._prune_interval:
            await self._prune_databases()
            self._last_prune_time = now

    # ------------------------------------------------------------------
    # Monitoring
    # ------------------------------------------------------------------

    def _collect_snapshot(self) -> ResourceSnapshot | None:
        try:
            import psutil
        except ImportError:
            return None

        try:
            proc = psutil.Process(os.getpid())
            mem_info = proc.memory_info()
            sys_mem = psutil.virtual_memory()
            cpu = proc.cpu_percent(interval=0.1)

            state_dir_free = float("inf")
            root_free = float("inf")
            if self._state_dir:
                try:
                    state_dir_free = psutil.disk_usage(str(self._state_dir)).free / (1024**3)
                except Exception:
                    pass
            try:
                root_free = psutil.disk_usage("/").free / (1024**3)
            except Exception:
                pass

            active_sessions = len(getattr(self._agent, "_cancel_tokens", {}))

            active_agents = 0
            idle_agents = 0
            in_flight = 0
            fleet = self._get_fleet()
            if fleet is not None:
                for a in getattr(fleet, "agents", {}).values():
                    status = getattr(a, "status", "")
                    if status == "idle":
                        idle_agents += 1
                    elif status == "busy":
                        active_agents += 1
                in_flight = sum(
                    1
                    for t in getattr(fleet, "tasks", {}).values()
                    if getattr(t, "status", "") in ("running", "assigned")
                )

            return ResourceSnapshot(
                timestamp=time.time(),
                process_rss_mb=mem_info.rss / (1024**2),
                process_vms_mb=mem_info.vms / (1024**2),
                system_memory_percent=sys_mem.percent,
                system_memory_available_mb=sys_mem.available / (1024**2),
                cpu_percent=cpu,
                disk_free_state_dir_gb=state_dir_free,
                disk_free_root_gb=root_free,
                active_sessions=active_sessions,
                active_agents=active_agents,
                idle_agents=idle_agents,
                in_flight_tasks=in_flight,
            )
        except Exception as e:
            logger.debug("Failed to collect snapshot: %s", e)
            return None

    def _evaluate_pressure(self, snapshot: ResourceSnapshot) -> None:
        mem_pct = snapshot.system_memory_percent

        # Emit Prometheus gauges
        try:
            from js.utils.metrics import get_metrics
            m = get_metrics()
            m.governor_memory_percent.set(mem_pct)
            m.governor_cpu_percent.set(snapshot.cpu_percent)
            m.governor_active_agents.set(snapshot.active_agents)
            m.governor_idle_agents.set(snapshot.idle_agents)
            m.governor_in_flight_tasks.set(snapshot.in_flight_tasks)
        except Exception:
            pass

        if mem_pct >= self._emergency_percent:
            logger.critical(
                "EMERGENCY: system memory %.1f%%. Process RSS: %.1fMB. "
                "Initiating emergency shutdown.",
                mem_pct,
                snapshot.process_rss_mb,
            )
            asyncio.create_task(self._emergency_shutdown())
        elif mem_pct >= self._critical_percent:
            logger.error(
                "CRITICAL: system memory %.1f%%. Pausing new requests and "
                "killing oldest agents.",
                mem_pct,
            )
            self._paused = True
            asyncio.create_task(self._critical_decompression())
        elif mem_pct >= self._pressure_percent:
            logger.warning(
                "MEMORY PRESSURE: %.1f%%. Reaping idle agents and clearing caches.",
                mem_pct,
            )
            asyncio.create_task(self._pressure_decompression())
        elif mem_pct >= self._warn_percent:
            logger.warning(
                "Memory warning: %.1f%% used (%.0fMB available)",
                mem_pct,
                snapshot.system_memory_available_mb,
            )

        if snapshot.disk_free_state_dir_gb < 5.0 or snapshot.disk_free_root_gb < 5.0:
            logger.warning(
                "Disk low: state_dir=%.1fGB, root=%.1fGB",
                snapshot.disk_free_state_dir_gb,
                snapshot.disk_free_root_gb,
            )

    # ------------------------------------------------------------------
    # Cleanup actions
    # ------------------------------------------------------------------

    async def _reap_idle_agents(self) -> None:
        fleet = self._get_fleet()
        if fleet is None:
            return
        try:
            reaped = await fleet.reap_idle_agents(
                idle_timeout=self._idle_timeout_seconds,
                max_idle=self._max_idle_agents,
            )
            if reaped:
                logger.info("Reaped %d idle agents", reaped)
                try:
                    from js.utils.metrics import get_metrics
                    get_metrics().governor_reaped_total.inc(reaped)
                except Exception:
                    pass
        except Exception as e:
            logger.warning("Idle agent reaping failed: %s", e, exc_info=True)

    async def _prune_databases(self) -> None:
        pruned_total = 0

        # 1. StateStore checkpoints
        try:
            store = getattr(self._agent, "_state_store", None)
            if store is not None and hasattr(store, "prune"):
                pruned = store.prune(keep=1_000)
                if pruned:
                    logger.info("Pruned %d old checkpoints", pruned)
                    pruned_total += pruned
        except Exception as e:
            logger.warning("Checkpoint prune failed: %s", e, exc_info=True)

        # 2. AgentStore
        fleet = self._get_fleet()
        if fleet is not None:
            try:
                agent_store = getattr(fleet, "_agent_store", None)
                if agent_store is not None and hasattr(agent_store, "prune"):
                    pruned = agent_store.prune(keep=500)
                    if pruned:
                        logger.info("Pruned %d old agent records", pruned)
                        pruned_total += pruned
            except Exception as e:
                logger.warning("AgentStore prune failed: %s", e, exc_info=True)

            # 3. EventStore
            try:
                event_store = getattr(fleet, "_event_store", None)
                if event_store is not None and hasattr(event_store, "prune"):
                    pruned = event_store.prune()
                    if pruned:
                        logger.info("Pruned %d old event files", pruned)
                        pruned_total += pruned
            except Exception as e:
                logger.warning("EventStore prune failed: %s", e, exc_info=True)

        # 4. AuditLogger
        try:
            audit = getattr(self._agent, "audit", None)
            if audit is not None and hasattr(audit, "prune"):
                pruned = audit.prune()
                if pruned:
                    logger.info("Pruned %d old audit records", pruned)
                    pruned_total += pruned
        except Exception as e:
            logger.warning("Audit prune failed: %s", e, exc_info=True)

        # 5. MemoryStore cleanup
        try:
            memory = getattr(self._agent, "memory", None)
            if memory is not None:
                if hasattr(memory, "cleanup_empty_sessions"):
                    cleaned = memory.cleanup_empty_sessions()
                    if cleaned:
                        logger.info("Cleaned up %d empty memory sessions", cleaned)

                enhanced = getattr(memory, "enhanced", None)
                if enhanced is not None and hasattr(
                    enhanced, "_evict_semantic_if_needed"
                ):
                    evicted = enhanced._evict_semantic_if_needed(max_memories=1_000)
                    if evicted:
                        logger.info("Evicted %d semantic memories", evicted)
        except Exception as e:
            logger.warning("Memory cleanup failed: %s", e, exc_info=True)

        # 6. SQLite WAL checkpoint
        if self._state_dir is not None:
            try:
                await self._checkpoint_wal()
            except Exception as e:
                logger.warning("WAL checkpoint failed: %s", e, exc_info=True)

        if pruned_total:
            logger.info("Database maintenance complete. Total pruned: %d", pruned_total)

    async def _checkpoint_wal(self) -> None:
        import sqlite3

        db_paths: list[Path] = []
        if self._state_dir is not None:
            db_paths.extend(self._state_dir.rglob("*.db"))

        checked: set[Path] = set()
        for path in db_paths:
            db = path.with_suffix(".db") if path.suffix != ".db" else path
            if db in checked or not db.exists():
                continue
            checked.add(db)
            try:
                with sqlite3.connect(str(db), timeout=5.0) as conn:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass  # Not WAL or locked — safe to ignore

    async def _pressure_decompression(self) -> None:
        """Memory pressure relief: reap idle agents, force gc, clear caches."""
        await self._reap_idle_agents()
        gc.collect()

        # Clear router health cache
        try:
            router = getattr(self._agent, "router", None)
            if router is not None and hasattr(router, "_health_cache"):
                router._health_cache.clear()
        except Exception:
            pass

        # Clear any TTLCache instances hanging off the agent
        try:
            from cachetools import TTLCache

            for attr in dir(self._agent):
                obj = getattr(self._agent, attr, None)
                if isinstance(obj, TTLCache):
                    obj.clear()
        except Exception:
            pass

    async def _critical_decompression(self) -> None:
        """Critical memory: kill oldest agents, more aggressive gc."""
        await self._pressure_decompression()

        fleet = self._get_fleet()
        if fleet is None:
            return

        try:
            agents = list(getattr(fleet, "agents", {}).values())
            idle = [a for a in agents if getattr(a, "status", "") == "idle"]
            idle.sort(key=lambda a: getattr(a, "last_active_at", 0.0))
            to_kill = idle[:-2] if len(idle) > 2 else []
            for a in to_kill:
                try:
                    agent_obj = getattr(a, "agent", None)
                    if agent_obj is not None and hasattr(agent_obj, "close"):
                        close_result = agent_obj.close()
                        if asyncio.iscoroutine(close_result):
                            await close_result
                    getattr(fleet, "agents", {}).pop(getattr(a, "id", ""), None)
                    logger.warning(
                        "Killed agent %s due to memory pressure",
                        getattr(a, "name", "?"),
                    )
                except Exception:
                    pass
        except Exception:
            pass

        gc.collect()

    async def _emergency_shutdown(self) -> None:
        """Emergency: save checkpoints and trigger graceful shutdown."""
        logger.critical("EMERGENCY SHUTDOWN: saving checkpoints")
        try:
            state_cache = getattr(self._agent, "_state_cache", {})
            for sid in list(getattr(self._agent, "_cancel_tokens", {}).keys()):
                try:
                    state = state_cache.get(sid)
                    if state is not None:
                        await self._agent.save_checkpoint(state)
                except Exception:
                    pass
        except Exception:
            pass

        try:
            import signal

            os.kill(os.getpid(), signal.SIGTERM)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_history(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._history_lock:
            return [
                self._snapshot_to_dict(s) for s in list(self._history)[-limit:]
            ]

    @staticmethod
    def _snapshot_to_dict(s: ResourceSnapshot) -> dict[str, Any]:
        return {
            "timestamp": s.timestamp,
            "process_rss_mb": round(s.process_rss_mb, 1),
            "system_memory_percent": round(s.system_memory_percent, 1),
            "cpu_percent": round(s.cpu_percent, 1),
            "disk_free_state_dir_gb": round(s.disk_free_state_dir_gb, 1),
            "active_sessions": s.active_sessions,
            "active_agents": s.active_agents,
            "idle_agents": s.idle_agents,
            "in_flight_tasks": s.in_flight_tasks,
        }

    def _get_fleet(self) -> Any | None:
        if self._fleet_getter is not None:
            try:
                return self._fleet_getter()
            except Exception:
                return None
        return None

    @property
    def paused(self) -> bool:
        return self._paused

    def resume(self) -> None:
        """Clear the pause flag (e.g. after memory drops)."""
        self._paused = False
