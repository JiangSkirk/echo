"""Shared typing contract for the JSAgent mixins.

``AgentBase`` is the common base every agent mixin inherits.  It carries the
real ``SYSTEM_PROMPT`` plus type-only declarations for every attribute and
cross-module method, so each mixin can freely reference ``self.<attr>`` and
sibling/core methods while staying mypy-clean.  All concrete behaviour lives in
the mixins (``state``/``prompt_builder``/``tool_executor``/``finalizer``/
``runner``) and the ``JSAgent`` core in ``js.agent.__init__``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import asyncio
    from collections.abc import Awaitable, Callable

    from cachetools import TTLCache

    from js.agent.state import AgentState
    from js.compression.compressor import CompressionConfig, ContextCompressor
    from js.compression.feedback import CompressionFeedback
    from js.config import JSSettings
    from js.echo.durable_thread import EchoDurableExecutor
    from js.echo.ledger.service import EchoSafetyService
    from js.echo.turn_context import RuntimeContext
    from js.echo.turn_runtime import EchoRuntime
    from js.evolution.learner import SelfLearner
    from js.evolution.metacognition import MetacognitionLoop
    from js.evolution.optimizer import PromptOptimizer
    from js.memory.scheduler import DreamScheduler
    from js.memory.store import MemoryStore
    from js.models.provider_manager import ProviderManager
    from js.models.providers import ChatMessage
    from js.models.router import ModelRouter
    from js.persistence.lifecycle_store import SessionLifecycleStore
    from js.persistence.review_store import ReviewStore
    from js.security.approvals import ApprovalQueue
    from js.security.audit import AuditLogger
    from js.security.guard import BehaviorGuard
    from js.security.secrets import SecretManager
    from js.skills.composer import SkillComposer
    from js.skills.curator import SkillCurator
    from js.skills.evolver import SkillEvolver
    from js.skills.manager import SkillManager
    from js.tools.registry import ToolRegistry, ToolResult


class AgentBase:
    """Common base providing the shared SYSTEM_PROMPT + typing contract."""

    SYSTEM_PROMPT = """You are JS, a helpful and capable AI assistant. You have access to tools for file operations, shell commands, code execution, and more.

Key rules:
1. Use tools when needed - don't guess about file contents or system state
2. Always check if a file exists before reading it
3. Prefer read-only tools for investigation before making changes
4. Explain your reasoning clearly
5. If a task is too complex, suggest breaking it down
6. Never expose secrets, API keys, or tokens in your responses
7. Respect the user's workspace - don't modify files outside it without permission

Programming workflow (critical for code tasks):
- STEP 1: EXPLORE. Use file_view to see directory structure, file_read or file_view to inspect code. Use code_search to find relevant code. Never write code blindly.
- STEP 2: PLAN. Think before editing. If the change is small and precise, use file_edit with an exact search/replace block. If the change is large or creates a new file, use file_write.
- STEP 3: EDIT. When editing existing files, prefer file_edit over file_write. The search block must match EXACTLY (including whitespace and newlines). If the search is ambiguous, read more context first.
- STEP 4: VERIFY. After making changes, run tests or lint checks using shell or python tools. If errors appear, fix them immediately. Do not declare success until verification passes.
- STEP 5: MINIMIZE. Make the smallest possible change to achieve the goal. Avoid rewriting entire files when a small edit suffices. This saves tokens and reduces error rates.

File tool guidelines:
- file_view: Use for browsing directories (tree view) or reading files WITH line numbers. Great for exploring project structure.
- file_read: Use for reading file content without line numbers.
- file_edit: Use for precise replacements. The "search" parameter must be a UNIQUE exact match in the file. Include enough surrounding lines to ensure uniqueness.
- file_write: Use for creating new files or complete rewrites only.
- code_search: Use to find where functions, classes, or variables are defined/used across the codebase.
- shell: Use for running tests (pytest, cargo test, npm test), linters, build commands, and git operations.

Web search tool:
- web_search: Search the web for current information, news, facts, or documentation. Returns top results with title, URL, and snippet. Use this when the user asks about recent events, current data, or anything you don't already know.

Browser automation tools (Kimi WebBridge — controls your real Chrome browser):
- web_navigate: Open a URL in the browser. Use new_tab=true on first navigation. Supports any website including those requiring login.
- web_snapshot: Capture the page accessibility tree with @e element references. ALWAYS use this after navigating to understand the page before clicking or filling.
- web_click: Click an element using @e reference (from snapshot) or CSS selector.
- web_fill: Fill input fields or textareas. Works on regular inputs and contenteditable editors.
- web_screenshot: Take a screenshot of the current page. Use when you need to "see" the page visually.
- web_evaluate: Execute JavaScript in the browser context. Use for complex interactions or extracting data.
- web_extract_text: Extract visible text from the page using JavaScript. CRITICAL FALLBACK: when web_snapshot returns an empty or very sparse tree (common on JavaScript-heavy sites like Douyin/TikTok, React/Vue SPAs), use this tool to get the actual page content.
- web_find_tab: Reuse an already-open tab instead of creating a new one.

Browser workflow (efficient — minimize steps):
1. Use web_navigate to open the site (or web_find_tab if already open)
2. Use web_snapshot to see the page structure
3. If the snapshot is too sparse (<200 chars), use web_extract_text ONCE to get the actual content
4. Use web_click/web_fill to interact ONLY when necessary
5. Use web_screenshot if visual confirmation is needed
6. Report findings and STOP. Do NOT navigate to the same URL repeatedly.

Search vs Fetch: Prefer web_search for finding information; use browser_fetch only when the user gives a specific URL. Do NOT use browser_fetch as a substitute for web_search.
"""

    if TYPE_CHECKING:
        # --- Attributes (set in JSAgent.__init__ / _init_subsystems / _setup_tools) ---
        settings: JSSettings
        logger: Any
        _role: str | None
        _echo_durable_executor: EchoDurableExecutor
        echo_runtime: EchoRuntime
        router: ModelRouter
        echo_safety_service: EchoSafetyService
        provider_manager: ProviderManager
        guard: BehaviorGuard
        audit: AuditLogger
        secrets: SecretManager
        memory: MemoryStore
        _dream_scheduler: DreamScheduler
        _organizer: Any
        _memory_bootstrapped: bool
        plugins: Any
        registry: ToolRegistry
        skills: SkillManager
        search: Any
        learner: SelfLearner
        optimizer: PromptOptimizer
        evolver: SkillEvolver
        composer: SkillComposer
        _clawhub: Any | None
        compression_config: CompressionConfig
        compressor: ContextCompressor
        compression_feedback: CompressionFeedback
        metacognition: MetacognitionLoop
        curator: SkillCurator
        approvals: ApprovalQueue
        defense_strategies: Any
        _cancel_tokens: dict[
            str,
            tuple[asyncio.Event, str, str | None, str],
        ]
        _active_run_tasks: dict[
            str,
            tuple[asyncio.Task[Any], str, str | None],
        ]
        _background_model_tasks: set[asyncio.Task[Any]]
        _shutdown_requested: bool
        _last_skill_evolution_check_monotonic: float | None
        _system_message_cache: TTLCache[tuple[str, str, str], str]
        _degraded: bool
        degraded_reason: str
        _current_allowed_tools: set[str]
        _consecutive_tool_failures: int
        state_store: Any
        lifecycle_store: SessionLifecycleStore
        review_store: ReviewStore
        event_store: Any
        _lane_executor: Any
        _quality_scorer: Any
        _governor: Any | None
        _fleet_getter: Any | None
        _desktop_tools: Any | None
        _browser_tool: Any
        _webbridge_tool: Any

        # --- Cross-module methods (defined in mixins / core; stubbed for typing) ---
        async def _check_degraded(self) -> None: ...
        async def save_checkpoint(self, state: AgentState) -> None: ...
        async def load_checkpoint(self, session_id: str) -> AgentState | None: ...
        def _get_tools_schema(self, model: str | None = None) -> list[dict[str, Any]] | None: ...
        async def _execute_tool_call(
            self,
            tc: dict[str, Any],
            session_id: str,
            run_id: str,
            user_input: str,
            progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
            *,
            allowed_tools: set[str] | None = None,
            owner_key_hash: str | None = None,
        ) -> tuple[ChatMessage, ToolResult]: ...
        def _build_system_message(
            self,
            query: str = "",
            session_id: str = "",
            attachments: list[str] | None = None,
            model: str | None = None,
        ) -> str: ...
        def _build_vision_content(
            self,
            user_input: str,
            attachments: list[str],
            supports_vision: bool,
            session_id: str | None = None,
        ) -> str | list[dict[str, Any]]: ...
        async def _build_attachment_context(
            self, attachments: list[str], session_id: str | None = None
        ) -> str: ...
        def _format_messages_for_summary(self, messages: list[ChatMessage]) -> str: ...
        async def _summarize_context(
            self,
            messages: list[ChatMessage],
            identifiers: list[str] | None = None,
            *,
            runtime_context: RuntimeContext | None = None,
        ) -> str: ...
        async def _finalize_run(
            self,
            state: AgentState,
            session_id: str,
            run_id: str,
            user_input: str,
            history_ua_count: int,
        ) -> None: ...
        async def _run_skill_evolution_for(
            self, skill_id: str, spec: Any | None = None
        ) -> None: ...
        def _register_search_tool(self) -> None: ...
        async def run(
            self,
            user_input: str,
            session_id: str | None = None,
            model: str | None = None,
            attachments: list[str] | None = None,
            _resume_state: AgentState | None = None,
            stream_callback: Callable[[str], Awaitable[None]] | None = None,
            progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
            event_callback: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
            disable_tools: bool = False,
        ) -> AgentState: ...
        async def _do_run(
            self,
            user_input: str,
            session_id: str | None = None,
            model: str | None = None,
            attachments: list[str] | None = None,
            _resume_state: AgentState | None = None,
            stream_callback: Callable[[str], Awaitable[None]] | None = None,
            progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
            event_callback: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
            disable_tools: bool = False,
        ) -> AgentState: ...
