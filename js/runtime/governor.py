"""Resource governance: memory monitoring, idle agent reaping, database pruning."""

from __future__ import annotations

import asyncio
import gc
import os
import threading
import time
from collections import deque
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from js.utils.log import get_logger

logger = get_logger("js.runtime.governor")


async def _run_blocking[T](
    operation: Callable[..., T],
    /,
    *args: Any,
    **kwargs: Any,
) -> T:
    """Run blocking work without abandoning its thread during cancellation."""
    worker: asyncio.Task[T] = asyncio.create_task(asyncio.to_thread(operation, *args, **kwargs))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        try:
            await worker
        except Exception:
            logger.warning("Cancelled governor worker failed while draining", exc_info=True)
        raise


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
    maintains high-write bounded state every minute, and performs full database
    maintenance every 6 hours.  When
    system memory crosses
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
        self._pressure_tasks: dict[str, asyncio.Task[None]] = {}
        self._pressure_action_lock = asyncio.Lock()
        self._lock = asyncio.Lock()

        # Timing
        self._interval_seconds = 30.0
        self._last_reap_time = 0.0
        self._reap_interval = 300.0  # 5 minutes
        self._last_session_maintenance_time = 0.0
        self._session_maintenance_interval = 60.0  # 1 minute
        self._last_prune_time = 0.0
        self._prune_interval = 21_600.0  # 6 hours
        self._stale_session_threshold_seconds = 300.0

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
        for task in tuple(self._pressure_tasks.values()):
            if not task.done():
                task.cancel()

    async def wait_stopped(self) -> None:
        """Wait until the main loop and every pressure task have exited."""
        tasks: set[asyncio.Task[Any]] = set(self._pressure_tasks.values())
        if self._task is not None:
            tasks.add(self._task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._pressure_tasks = {
            name: task for name, task in self._pressure_tasks.items() if not task.done()
        }

    def _start_pressure_task(
        self,
        name: str,
        operation: Callable[[], Coroutine[Any, Any, None]],
    ) -> None:
        current = self._pressure_tasks.get(name)
        if current is not None and not current.done():
            return

        async def _run_serialized() -> None:
            async with self._pressure_action_lock:
                await operation()

        task: asyncio.Task[None] = asyncio.create_task(
            _run_serialized(),
            name=f"governor-{name}",
        )
        self._pressure_tasks[name] = task

        def _discard(completed: asyncio.Task[None]) -> None:
            if self._pressure_tasks.get(name) is completed:
                self._pressure_tasks.pop(name, None)
            if completed.cancelled():
                return
            try:
                completed.result()
            except Exception:
                logger.error(
                    "ResourceGovernor %s task crashed",
                    name,
                    exc_info=True,
                )

        task.add_done_callback(_discard)

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

            try:
                await self._run_cycle()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("ResourceGovernor cycle failed: %s", e, exc_info=True)

    async def _run_cycle(self) -> None:
        now = time.time()

        # 1. Resource monitoring
        snapshot = await _run_blocking(self._collect_snapshot)
        if snapshot is not None:
            with self._history_lock:
                self._history.append(snapshot)
            self._evaluate_pressure(snapshot)

        # 2. Idle agent reaping (every 5 min)
        if now - self._last_reap_time >= self._reap_interval:
            await self._reap_idle_agents()
            self._last_reap_time = now

        # 3. Database pruning (every 6 h). Full maintenance includes session bounds.
        full_prune_ran = False
        if now - self._last_prune_time >= self._prune_interval:
            await self._prune_databases()
            self._last_prune_time = now
            self._last_session_maintenance_time = now
            full_prune_ran = True

        # 4. High-write bounded-state maintenance (every minute between full prunes)
        if (
            not full_prune_ran
            and now - self._last_session_maintenance_time >= self._session_maintenance_interval
        ):
            await self._maintain_hot_state()
            self._last_session_maintenance_time = now

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
            # Only trigger emergency shutdown when the titan-agent process
            # itself is consuming significant memory (>500MB RSS).  If the
            # process is small, the pressure is coming from OTHER processes
            # and self-terminating would not help.
            if snapshot.process_rss_mb > 500:
                logger.critical(
                    "EMERGENCY: system memory %.1f%%. Process RSS: %.1fMB. "
                    "Initiating emergency shutdown.",
                    mem_pct,
                    snapshot.process_rss_mb,
                )
                self._start_pressure_task("emergency", self._emergency_shutdown)
            else:
                logger.warning(
                    "System memory at emergency level (%.1f%%) but process RSS "
                    "is only %.1fMB — external memory pressure, not shutting down.",
                    mem_pct,
                    snapshot.process_rss_mb,
                )
        elif mem_pct >= self._critical_percent:
            logger.error(
                "CRITICAL: system memory %.1f%%. Pausing new requests and killing oldest agents.",
                mem_pct,
            )
            self._paused = True
            self._start_pressure_task("critical", self._critical_decompression)
        elif mem_pct >= self._pressure_percent:
            logger.warning(
                "MEMORY PRESSURE: %.1f%%. Reaping idle agents and clearing caches.",
                mem_pct,
            )
            self._start_pressure_task("pressure", self._pressure_decompression)
        elif mem_pct >= self._warn_percent:
            logger.warning(
                "Memory warning: %.1f%% used (%.0fMB available)",
                mem_pct,
                snapshot.system_memory_available_mb,
            )
        else:
            # Auto-resume when memory drops below warning threshold
            if self._paused:
                logger.info(
                    "Memory pressure relieved (%.1f%%), resuming new requests.",
                    mem_pct,
                )
                self._paused = False

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
            reaped = await _run_blocking(
                fleet.reap_idle_agents,
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

    async def _maintain_session_bounds(self) -> None:
        """Enforce bounded owner state without touching active sessions."""
        try:
            lifecycle_store = getattr(self._agent, "lifecycle_store", None)
            memory = getattr(self._agent, "memory", None)
            enhanced = getattr(memory, "enhanced", None)
            if (
                enhanced is not None
                and hasattr(enhanced, "maintain_session_bounds")
                and lifecycle_store is not None
                and hasattr(lifecycle_store, "running_pairs_for_maintenance")
            ):
                protected_sessions = await _run_blocking(
                    lifecycle_store.running_pairs_for_maintenance
                )
                pruned = await _run_blocking(
                    enhanced.maintain_session_bounds,
                    protected_sessions=protected_sessions,
                )
                if pruned:
                    logger.info("Pruned %d old memory sessions", pruned)
        except Exception as e:
            logger.warning("Memory session maintenance failed: %s", e, exc_info=True)

        try:
            quality_scorer = getattr(self._agent, "_quality_scorer", None)
            if quality_scorer is not None and hasattr(quality_scorer, "prune"):
                pruned = await _run_blocking(quality_scorer.prune)
                if pruned:
                    logger.info("Pruned %d old quality records", pruned)
        except Exception as e:
            logger.warning("Quality history maintenance failed: %s", e, exc_info=True)

    async def _maintain_hot_state(self) -> None:
        """Bound high-write stores and checkpoint WALs on a short clock.

        Every store is isolated so a damaged optional subsystem cannot prevent
        the remaining retention gates or the final WAL checkpoint from running.
        """
        await self._maintain_session_bounds()

        stores: tuple[tuple[str, Any], ...] = (
            ("LifecycleStore", getattr(self._agent, "lifecycle_store", None)),
            ("ReviewStore", getattr(self._agent, "review_store", None)),
            ("AuditLogger", getattr(self._agent, "audit", None)),
            ("SelfLearner", getattr(self._agent, "learner", None)),
            (
                "CompressionFeedback",
                getattr(self._agent, "compression_feedback", None),
            ),
            ("PromptOptimizer", getattr(self._agent, "optimizer", None)),
            ("Metacognition", getattr(self._agent, "metacognition", None)),
            ("EventStore", getattr(self._agent, "event_store", None)),
        )
        for label, store in stores:
            if store is None or not hasattr(store, "prune"):
                continue
            try:
                pruned = await _run_blocking(store.prune)
                if pruned:
                    logger.info("Pruned %d old %s records", pruned, label)
            except Exception as error:
                logger.warning(
                    "%s bounded maintenance failed: %s",
                    label,
                    error,
                    exc_info=True,
                )

        if self._state_dir is not None:
            try:
                from js.web.stats_store import TokenStatsStore

                stats_store = TokenStatsStore(self._state_dir)
                pruned = await _run_blocking(stats_store.prune)
                if pruned:
                    logger.info("Pruned %d old token usage records", pruned)
            except Exception as error:
                logger.warning(
                    "TokenStatsStore bounded maintenance failed: %s",
                    error,
                    exc_info=True,
                )

            try:
                await self._checkpoint_wal()
            except Exception as error:
                logger.warning(
                    "Bounded-state WAL checkpoint failed: %s",
                    error,
                    exc_info=True,
                )

    async def _prune_databases(self) -> None:
        pruned_total = 0
        lifecycle_store = getattr(self._agent, "lifecycle_store", None)

        # Recover stale runs before collecting memory-retention protection.
        try:
            if lifecycle_store is not None and hasattr(
                lifecycle_store,
                "recover_all_aborted_sessions",
            ):
                recovered = await _run_blocking(
                    lifecycle_store.recover_all_aborted_sessions,
                    threshold_seconds=self._stale_session_threshold_seconds,
                )
                if recovered:
                    logger.info("Recovered %d stale lifecycle records", len(recovered))
        except Exception as e:
            logger.warning("LifecycleStore stale recovery failed: %s", e, exc_info=True)

        # 1. StateStore checkpoints
        try:
            store = getattr(self._agent, "_state_store", None)
            if store is not None and hasattr(store, "prune"):
                pruned = await _run_blocking(store.prune, keep=1_000)
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
                    pruned = await _run_blocking(agent_store.prune, keep=500)
                    if pruned:
                        logger.info("Pruned %d old agent records", pruned)
                        pruned_total += pruned
            except Exception as e:
                logger.warning("AgentStore prune failed: %s", e, exc_info=True)

        # 3. EventStore: the primary store lives on the agent. Retain fleet
        # compatibility for older integrations, but never prune one instance twice.
        event_stores: list[tuple[str, Any]] = [
            ("agent", getattr(self._agent, "event_store", None)),
        ]
        if fleet is not None:
            event_stores.append(("fleet", getattr(fleet, "_event_store", None)))

        seen_event_stores: set[tuple[str, str | int]] = set()
        for source, event_store in event_stores:
            if event_store is None or not hasattr(event_store, "prune"):
                continue
            base_dir = getattr(event_store, "base_dir", None)
            identity: tuple[str, str | int]
            if isinstance(base_dir, (str, Path)):
                identity = ("base_dir", str(Path(base_dir).expanduser().absolute()))
            else:
                identity = ("instance", id(event_store))
            if identity in seen_event_stores:
                continue
            seen_event_stores.add(identity)
            try:
                pruned = await _run_blocking(event_store.prune)
                if pruned:
                    logger.info("Pruned %d old %s event files", pruned, source)
                    pruned_total += pruned
            except Exception as e:
                logger.warning("%s EventStore prune failed: %s", source, e, exc_info=True)

        # 4. AuditLogger
        try:
            audit = getattr(self._agent, "audit", None)
            if audit is not None and hasattr(audit, "prune"):
                pruned = await _run_blocking(audit.prune)
                if pruned:
                    logger.info("Pruned %d old audit records", pruned)
                    pruned_total += pruned
        except Exception as e:
            logger.warning("Audit prune failed: %s", e, exc_info=True)

        # 4b. Evolution and compression observations
        for label, store in (
            ("SelfLearner", getattr(self._agent, "learner", None)),
            (
                "CompressionFeedback",
                getattr(self._agent, "compression_feedback", None),
            ),
            ("PromptOptimizer", getattr(self._agent, "optimizer", None)),
            ("Metacognition", getattr(self._agent, "metacognition", None)),
        ):
            if store is None or not hasattr(store, "prune"):
                continue
            try:
                pruned = await _run_blocking(store.prune)
                if pruned:
                    logger.info("Pruned %d old %s records", pruned, label)
                    pruned_total += pruned
            except Exception as e:
                logger.warning("%s prune failed: %s", label, e, exc_info=True)

        # 5. MemoryStore cleanup. Each operation is isolated so a failure in
        # one retention mechanism cannot suppress the others.
        memory = getattr(self._agent, "memory", None)
        enhanced = getattr(memory, "enhanced", None)
        if memory is not None and hasattr(memory, "cleanup_empty_sessions"):
            try:
                cleaned = await _run_blocking(memory.cleanup_empty_sessions)
                if cleaned:
                    logger.info("Cleaned up %d empty memory sessions", cleaned)
            except Exception as e:
                logger.warning("Empty memory session cleanup failed: %s", e, exc_info=True)

        await self._maintain_session_bounds()

        if enhanced is not None and hasattr(enhanced, "_evict_semantic_if_needed"):
            try:
                evicted = await _run_blocking(
                    enhanced._evict_semantic_if_needed,
                    max_memories=1_000,
                )
                if evicted:
                    logger.info("Evicted %d semantic memories", evicted)
            except Exception as e:
                logger.warning("Semantic memory eviction failed: %s", e, exc_info=True)

        # 6. Session lifecycle metadata
        try:
            if lifecycle_store is not None and hasattr(lifecycle_store, "prune"):
                pruned = await _run_blocking(lifecycle_store.prune)
                if pruned:
                    logger.info("Pruned %d old lifecycle records", pruned)
                    pruned_total += pruned
        except Exception as e:
            logger.warning("LifecycleStore prune failed: %s", e, exc_info=True)

        # 7. Review capsules
        try:
            review_store = getattr(self._agent, "review_store", None)
            if review_store is not None and hasattr(review_store, "prune"):
                pruned = await _run_blocking(review_store.prune)
                if pruned:
                    logger.info("Pruned %d old review capsules", pruned)
                    pruned_total += pruned
        except Exception as e:
            logger.warning("ReviewStore prune failed: %s", e, exc_info=True)

        # 8. Token usage statistics
        if self._state_dir is not None:
            try:
                from js.web.stats_store import TokenStatsStore

                stats_store = TokenStatsStore(self._state_dir)
                pruned = await _run_blocking(stats_store.prune)
                if pruned:
                    logger.info("Pruned %d old token usage records", pruned)
                    pruned_total += pruned
            except Exception as e:
                logger.warning("TokenStatsStore prune failed: %s", e, exc_info=True)

        # 9. SQLite WAL checkpoint
        if self._state_dir is not None:
            try:
                await self._checkpoint_wal()
            except Exception as e:
                logger.warning("WAL checkpoint failed: %s", e, exc_info=True)

        if pruned_total:
            logger.info("Database maintenance complete. Total pruned: %d", pruned_total)

    async def _checkpoint_wal(self) -> None:
        await _run_blocking(self._checkpoint_wal_sync)

    def _checkpoint_wal_sync(self) -> None:
        import sqlite3
        import stat

        if self._state_dir is None:
            return
        try:
            state_root = self._state_dir.resolve(strict=True)
        except OSError:
            return
        db_paths = list(self._state_dir.rglob("*.db"))

        checked: set[Path] = set()
        for path in db_paths:
            db = path.with_suffix(".db") if path.suffix != ".db" else path
            try:
                relative = db.relative_to(self._state_dir)
                component = self._state_dir
                unsafe_component = False
                for name in relative.parts:
                    component /= name
                    metadata = component.lstat()
                    if stat.S_ISLNK(metadata.st_mode):
                        unsafe_component = True
                        break
                if unsafe_component or not stat.S_ISREG(metadata.st_mode):
                    continue
                if metadata.st_nlink != 1:
                    continue
                resolved = db.resolve(strict=True)
                resolved.relative_to(state_root)
            except (FileNotFoundError, OSError, ValueError):
                continue
            if resolved in checked:
                continue
            checked.add(resolved)
            try:
                with sqlite3.connect(str(resolved), timeout=5.0) as conn:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass  # Not WAL or locked — safe to ignore

    async def _pressure_decompression(self) -> None:
        """Memory pressure relief: reap idle agents, force gc, clear caches."""
        await self._reap_idle_agents()
        await _run_blocking(gc.collect)

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

        await _run_blocking(gc.collect)

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
            return [self._snapshot_to_dict(s) for s in list(self._history)[-limit:]]

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
