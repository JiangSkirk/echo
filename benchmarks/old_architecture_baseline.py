#!/usr/bin/env python3
"""Measure a detached pre-Echo tree from this external trusted harness.

The harness, workload corpus, and vendored tokenizer remain in the current audited
checkout.  ``--measured-root`` names an untouched clean detached Git tree whose real
``js`` package is imported and exercised with a deterministic local fake provider.
"""

# ruff: noqa: E402, I001 -- clean-export root must be bound before project imports.

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import AsyncIterator
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.dont_write_bytecode = True

HARNESS_PATH = Path(__file__).resolve()
HARNESS_ROOT = HARNESS_PATH.parents[1]

TOKENIZER_METHOD = "tiktoken_cl100k_base_canonical_json"
TOKENIZER_ENCODING = "cl100k_base"
LONG_HISTORY_MESSAGES = 40
LONG_HISTORY_WORDS_PER_MESSAGE = 80
MODEL_PROMPT_LATENCY_MS_PER_TOKEN = 0.002
HISTORY_MARKER_PREFIX = "benchmark long history message "
EXPECTED_HISTORY_MARKERS = tuple(
    f"{HISTORY_MARKER_PREFIX}{index}" for index in range(LONG_HISTORY_MESSAGES)
)
_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}", re.IGNORECASE)
_RELEASE_SOURCE_DIGEST_VERSION = b"ECHO-RELEASE-SOURCE-V2\0"
_TOKENIZER_TREE_DIGEST_VERSION = b"ECHO-TOKENIZER-TREE-V1\0"
_RELEASE_SOURCE_DIGEST_SURFACES = (
    Path(".github"),
    Path(".gitignore"),
    Path("Dockerfile"),
    Path("LICENSE"),
    Path("ORIGIN_LEDGER.md"),
    Path("README.md"),
    Path("THIRD_PARTY_NOTICES.md"),
    Path("benchmarks"),
    Path("docs/adr/0001-echo-ledger-boundary.md"),
    Path("docs/echo/ECHO_10_ROUND_AUDIT.md"),
    Path("docs/echo/ECHO_FINAL_REPLACEMENT_REPORT.md"),
    Path("docs/echo/ECHO_SELF_DEVELOPED_BOUNDARY.md"),
    Path("docs/echo/ECHO_UNIFIED_EXECUTION_CONTRACT.md"),
    Path("docs/rfc/echo-ledger-major-change-template.md"),
    Path("docs/security/ECHO_BASELINE_65CC545.json"),
    Path("docs/security/ECHO_E2E_LEDGER_PUBKEY.json"),
    Path("docs/security/ECHO_SOAK_INTEGRITY_PUBKEY.json"),
    Path("docs/security/LICENSE_SCAN.md"),
    Path("docs/security/SBOM.spdx.json"),
    Path("js"),
    Path("js_work"),
    Path("pyproject.toml"),
    Path("resources"),
    Path("scripts"),
    Path("tests"),
    Path("uv.lock"),
)
_RELEASE_SOURCE_DIGEST_EXCLUDE = frozenset(
    {
        Path("docs/security/ECHO_LIVE_ACCEPTANCE.json"),
        Path("docs/security/ECHO_SLO_BENCHMARK.json"),
        Path("docs/echo/ECHO_10_ROUND_AUDIT.md"),
        Path("docs/echo/ECHO_FINAL_REPLACEMENT_REPORT.md"),
    }
)


def _git_environment() -> dict[str, str]:
    """Return a read-only Git environment without ambient repository overrides."""
    environment = os.environ.copy()
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ):
        environment.pop(name, None)
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return environment


def _git_output(root: Path, *args: str) -> str:
    """Run Git with ambient repository overrides removed."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_git_environment(),
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"could not inspect measured export with git: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown git failure"
        raise RuntimeError(f"could not inspect measured export with git: {detail}")
    return result.stdout.strip()


def _iter_release_source_files(root: Path) -> list[Path]:
    """Mirror the audited V2 release-source digest traversal without importing Echo."""
    resolved_root = root.resolve()
    seen: set[str] = set()
    files: list[Path] = []
    for relative in _RELEASE_SOURCE_DIGEST_SURFACES:
        candidate = resolved_root / relative
        if candidate.is_file() and not candidate.is_symlink():
            key = candidate.relative_to(resolved_root).as_posix()
            if key not in seen and Path(key) not in _RELEASE_SOURCE_DIGEST_EXCLUDE:
                seen.add(key)
                files.append(candidate)
        elif candidate.is_dir():
            for path in candidate.rglob("*"):
                if (
                    not path.is_file()
                    or path.is_symlink()
                    or "__pycache__" in path.parts
                    or path.suffix in {".pyc", ".pyo"}
                    or path.name == ".DS_Store"
                ):
                    continue
                key = path.relative_to(resolved_root).as_posix()
                if key in seen or Path(key) in _RELEASE_SOURCE_DIGEST_EXCLUDE:
                    continue
                seen.add(key)
                files.append(path)
    return sorted(files, key=lambda item: item.relative_to(resolved_root).as_posix())


def release_source_digest(root: Path) -> str:
    """Compute the audited V2 release-source digest for the measured export."""
    resolved_root = root.resolve()
    digest = hashlib.sha256(_RELEASE_SOURCE_DIGEST_VERSION)
    for path in _iter_release_source_files(resolved_root):
        relative_bytes = path.relative_to(resolved_root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative_bytes).to_bytes(8, "big"))
        digest.update(relative_bytes)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def tokenizer_resource_digest(root: Path) -> str:
    """Compute the audited content digest of the vendored tokenizer resources."""
    resolved_root = root.resolve()
    tokenizer_root = resolved_root / "resources" / "tokenizer"
    digest = hashlib.sha256(_TOKENIZER_TREE_DIGEST_VERSION)
    if not tokenizer_root.is_dir():
        return digest.hexdigest()
    files = sorted(
        (
            path
            for path in tokenizer_root.rglob("*")
            if path.is_file() and not path.is_symlink() and path.name != ".DS_Store"
        ),
        key=lambda item: item.relative_to(resolved_root).as_posix(),
    )
    for path in files:
        relative_bytes = path.relative_to(resolved_root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative_bytes).to_bytes(8, "big"))
        digest.update(relative_bytes)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def workload_corpus_digest() -> str:
    """Bind the current external corpus and stable old-path request identifiers."""
    payload = {
        "history": _history(),
        "long_session_id": "old-long-{group}-{index}",
        "long_request": "benchmark api full {index}",
        "short_session_id": "old-short-{group}-{index}",
        "short_request": "benchmark api short {index}",
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _require_external_harness_inputs(measured_root: Path) -> None:
    """Require trusted benchmark inputs to remain outside the measured tree."""
    resolved_root = measured_root.resolve()
    for path, label in (
        (HARNESS_PATH, "harness"),
        (HARNESS_ROOT / "resources" / "tokenizer", "tokenizer resources"),
    ):
        resolved = path.resolve()
        if resolved == resolved_root or resolved_root in resolved.parents:
            raise RuntimeError(f"external {label} must be outside measured root")
    tokenizer_root = HARNESS_ROOT / "resources" / "tokenizer"
    if not tokenizer_root.is_dir() or not any(tokenizer_root.iterdir()):
        raise RuntimeError("external harness is missing vendored tokenizer resources")
    symlinks = sorted(
        path.relative_to(HARNESS_ROOT).as_posix()
        for path in tokenizer_root.rglob("*")
        if path.is_symlink()
    )
    if symlinks:
        raise RuntimeError("external tokenizer contains symlink paths: " + ", ".join(symlinks))


def _require_clean_detached_release_export(root: Path) -> tuple[str, str]:
    """Return commit/tree after rejecting any dirty, untracked, ignored, or symlink path."""
    resolved_root = root.resolve()
    if root.is_symlink():
        raise RuntimeError("measured export root must not be a symlink")
    repository_root = _git_output(resolved_root, "rev-parse", "--show-toplevel")
    if Path(repository_root).resolve() != resolved_root:
        raise RuntimeError("measured export root is not its Git worktree root")
    head = _git_output(resolved_root, "rev-parse", "--verify", "HEAD^{commit}")
    tree = _git_output(resolved_root, "rev-parse", "--verify", "HEAD^{tree}")
    try:
        symbolic_head = subprocess.run(
            ["git", "symbolic-ref", "--quiet", "HEAD"],
            cwd=resolved_root,
            check=False,
            capture_output=True,
            text=True,
            env=_git_environment(),
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"could not verify detached export: {exc}") from exc
    if symbolic_head.returncode == 0:
        raise RuntimeError("baseline measurement requires a detached clean export")
    status = _git_output(
        resolved_root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
        "--ignore-submodules=none",
    )
    dirty: list[str] = []
    untracked: list[str] = []
    ignored: list[str] = []
    for entry in status.split("\0"):
        if not entry:
            continue
        code, path = entry[:2], entry[3:]
        if code == "??":
            untracked.append(path)
        elif code == "!!":
            ignored.append(path)
        else:
            dirty.append(path)
    if untracked:
        raise RuntimeError("untracked measured-tree files: " + ", ".join(sorted(untracked)))
    if ignored:
        raise RuntimeError("ignored measured-tree files: " + ", ".join(sorted(ignored)))
    if dirty:
        raise RuntimeError("dirty measured-tree files: " + ", ".join(sorted(dirty)))
    index = _git_output(resolved_root, "ls-files", "--stage", "-z")
    symlinks: list[str] = []
    for entry in index.split("\0"):
        if not entry:
            continue
        metadata, separator, path = entry.partition("\t")
        if separator and metadata.split(maxsplit=1)[0] == "120000":
            symlinks.append(path)
    if symlinks:
        raise RuntimeError("measured tree symlink paths: " + ", ".join(sorted(symlinks)))
    return head, tree


def _sha256_required(path: Path, *, label: str) -> str:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"measured export is missing required {label}: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def measured_export_provenance(root: Path, *, expected_commit: str) -> dict[str, Any]:
    """Produce provenance for a clean detached tree and independent harness inputs."""
    if not _COMMIT_PATTERN.fullmatch(expected_commit):
        raise RuntimeError("expected commit must be a full 40-character hexadecimal object id")
    if root.is_symlink():
        raise RuntimeError("measured export root must not be a symlink")
    resolved_root = root.resolve()
    _require_external_harness_inputs(resolved_root)
    commit, tree = _require_clean_detached_release_export(resolved_root)
    if expected_commit.lower() != commit:
        raise RuntimeError(
            f"measured commit {commit} does not match expected commit {expected_commit}"
        )
    try:
        tokenizer_version = importlib.metadata.version("tiktoken")
    except importlib.metadata.PackageNotFoundError as exc:
        raise RuntimeError("tiktoken must be installed to measure the baseline") from exc
    executable = Path(sys.executable).resolve()
    platform_identity = platform.platform(aliased=True, terse=False)
    return {
        "schema_version": "echo-old-baseline-provenance-v2",
        "commit": commit,
        "tree": tree,
        "source_digest_algorithm": _RELEASE_SOURCE_DIGEST_VERSION.decode("ascii").rstrip("\0"),
        "source_digest": release_source_digest(resolved_root),
        "uv_lock_sha256": _sha256_required(resolved_root / "uv.lock", label="uv.lock"),
        "measured_root": str(resolved_root),
        "import_root": str((resolved_root / "js" / "__init__.py").resolve()),
        "harness_root": str(HARNESS_ROOT),
        "baseline_script_sha256": _sha256_required(HARNESS_PATH, label="baseline harness"),
        "harness_sha256": _sha256_required(HARNESS_PATH, label="baseline harness"),
        "import_root_sha256": _sha256_required(
            resolved_root / "js" / "__init__.py",
            label="measured js import root",
        ),
        "workload": {
            "history_message_count": LONG_HISTORY_MESSAGES,
            "history_words_per_message": LONG_HISTORY_WORDS_PER_MESSAGE,
            "corpus_sha256": workload_corpus_digest(),
        },
        "tokenizer": {
            "method": TOKENIZER_METHOD,
            "encoding": TOKENIZER_ENCODING,
            "tiktoken_version": tokenizer_version,
            "resource_digest_algorithm": _TOKENIZER_TREE_DIGEST_VERSION.decode("ascii").rstrip(
                "\0"
            ),
            "resource_root": str((HARNESS_ROOT / "resources" / "tokenizer").resolve()),
            "resource_tree_sha256": tokenizer_resource_digest(HARNESS_ROOT),
        },
        "interpreter": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "executable_sha256": _sha256_required(executable, label="Python executable"),
        },
        "platform": {
            "identity": platform_identity,
            "identity_sha256": hashlib.sha256(platform_identity.encode("utf-8")).hexdigest(),
        },
    }


def _tokenizer() -> Any:
    """Lazy, offline-first tokenizer: never touch the network at import.

    Uses the version-pinned vendored BPE cache (resources/tokenizer/, named
    by tiktoken's own cache-key convention) when present; otherwise tiktoken
    resolves its own cache or raises -- we never silently substitute an
    imprecise counter for the token gate.
    """
    import os

    if not os.environ.get("TIKTOKEN_CACHE_DIR"):
        vendored = Path(__file__).resolve().parents[1] / "resources" / "tokenizer"
        if vendored.is_dir() and any(vendored.iterdir()):
            os.environ["TIKTOKEN_CACHE_DIR"] = str(vendored)
    import tiktoken  # noqa: PLC0415 -- deliberate lazy import; hermetic import time

    return tiktoken.get_encoding("cl100k_base")


def _path_is_within(path: Path, root: Path) -> bool:
    resolved_path = path.resolve()
    resolved_root = root.resolve()
    return resolved_path == resolved_root or resolved_root in resolved_path.parents


def require_measured_module_origins(root: Path, modules: list[Any]) -> str:
    """Reject a measured ``js`` package if any loaded module escaped its root."""
    resolved_root = root.resolve()
    import_root = resolved_root / "js" / "__init__.py"
    seen_js = False
    for module in modules:
        name = getattr(module, "__name__", "")
        if name != "js" and not name.startswith("js."):
            continue
        seen_js = True
        raw_file = getattr(module, "__file__", None)
        if not isinstance(raw_file, str) or not raw_file:
            namespace_paths = [Path(path).resolve() for path in getattr(module, "__path__", ())]
            if namespace_paths and all(
                _path_is_within(path, resolved_root) for path in namespace_paths
            ):
                continue
            raise RuntimeError(f"import escaped measured root: {name} has no regular origin")
        origin = Path(raw_file).resolve()
        if not _path_is_within(origin, resolved_root):
            raise RuntimeError(
                f"import escaped measured root: {name}={origin} root={resolved_root}"
            )
        if not origin.is_file():
            raise RuntimeError(f"import escaped measured root: {name} origin is not a file")
    if not seen_js:
        raise RuntimeError("measured js package was not imported")
    js_modules = [module for module in modules if getattr(module, "__name__", "") == "js"]
    if len(js_modules) != 1 or Path(str(js_modules[0].__file__)).resolve() != import_root:
        raise RuntimeError("measured js package import root is not js/__init__.py")
    return str(import_root)


@dataclass(frozen=True)
class MeasuredRuntime:
    root: Path
    import_root: str
    FastAPI: Any
    TestClient: Any
    JSAgent: Any
    JSSettings: Any
    MemoryConfig: Any
    SecurityConfig: Any
    ChatMessage: Any
    ChatResponse: Any
    StreamEvent: Any
    AuthManager: Any
    chat_router: Any


def _load_measured_runtime(root: Path) -> MeasuredRuntime:
    """Bind ``sys.path`` to the measured root before the first ``js`` import."""
    resolved_root = root.resolve()
    preloaded = [
        module
        for name, module in sys.modules.items()
        if module is not None and (name == "js" or name.startswith("js."))
    ]
    if preloaded:
        require_measured_module_origins(resolved_root, preloaded)

    retained_paths: list[str] = []
    for entry in sys.path:
        if not entry:
            retained_paths.append(entry)
            continue
        try:
            candidate = Path(entry).resolve()
        except OSError:
            retained_paths.append(entry)
            continue
        if _path_is_within(candidate, HARNESS_ROOT) and not _path_is_within(
            candidate, Path(sys.prefix)
        ):
            continue
        retained_paths.append(entry)
    sys.path[:] = [str(resolved_root), *retained_paths]
    importlib.invalidate_caches()

    fastapi_module = importlib.import_module("fastapi")
    testclient_module = importlib.import_module("fastapi.testclient")
    js_module = importlib.import_module("js")
    agent_module = importlib.import_module("js.agent")
    config_module = importlib.import_module("js.config")
    providers_module = importlib.import_module("js.models.providers")
    events_module = importlib.import_module("js.models.stream_events")
    auth_module = importlib.import_module("js.web.auth")
    chat_module = importlib.import_module("js.web.routers.chat")
    del js_module

    measured_modules = [
        module
        for name, module in sys.modules.items()
        if module is not None and (name == "js" or name.startswith("js."))
    ]
    import_root = require_measured_module_origins(resolved_root, measured_modules)
    return MeasuredRuntime(
        root=resolved_root,
        import_root=import_root,
        FastAPI=fastapi_module.FastAPI,
        TestClient=testclient_module.TestClient,
        JSAgent=agent_module.JSAgent,
        JSSettings=config_module.JSSettings,
        MemoryConfig=config_module.MemoryConfig,
        SecurityConfig=config_module.SecurityConfig,
        ChatMessage=providers_module.ChatMessage,
        ChatResponse=providers_module.ChatResponse,
        StreamEvent=events_module.StreamEvent,
        AuthManager=auth_module.AuthManager,
        chat_router=chat_module.router,
    )


@dataclass
class ProviderStats:
    calls: int = 0
    prompt_tokens: list[int] = field(default_factory=list)
    payload_evidence: list[dict[str, Any]] = field(default_factory=list)


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    return json.dumps(content, ensure_ascii=False, sort_keys=True, default=str)


def _prompt_tokens(
    messages: list[Any],
    tools: list[dict[str, Any]] | None,
) -> int:
    payload = {
        "messages": [
            {
                "role": message.role,
                "content": _content_text(message.content),
                "name": message.name,
                "tool_calls": message.tool_calls,
                "tool_call_id": message.tool_call_id,
                "reasoning_content": message.reasoning_content,
            }
            for message in messages
        ],
        "tools": tools or [],
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    )
    return max(1, len(_tokenizer().encode(canonical)))


def _provider_payload_evidence(
    messages: list[Any],
    tools: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    message_identities = [
        {"role": message.role, "content": _content_text(message.content)} for message in messages
    ]
    observed_markers: list[str] = []
    for identity in message_identities:
        content = str(identity["content"])
        search_from = 0
        while True:
            marker_start = content.find(HISTORY_MARKER_PREFIX, search_from)
            if marker_start < 0:
                break
            digits_start = marker_start + len(HISTORY_MARKER_PREFIX)
            digits_end = digits_start
            while digits_end < len(content) and content[digits_end].isdigit():
                digits_end += 1
            if digits_end > digits_start:
                observed_markers.append(content[marker_start:digits_end])
            search_from = max(digits_end, digits_start + 1)
    marker_json = json.dumps(
        observed_markers,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    messages_json = json.dumps(
        message_identities,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    payload_json = json.dumps(
        {"messages": message_identities, "tools": tools or []},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return {
        "message_count": len(messages),
        "history_marker_count": len(observed_markers),
        "history_marker_counts": dict(sorted(Counter(observed_markers).items())),
        "history_marker_sha256": hashlib.sha256(marker_json).hexdigest(),
        "message_identity_sha256": hashlib.sha256(messages_json).hexdigest(),
        "provider_payload_sha256": hashlib.sha256(payload_json).hexdigest(),
    }


def _validate_payloads(
    long_evidence: list[dict[str, Any]],
    short_evidence: list[dict[str, Any]],
    *,
    expected_payloads: int,
) -> list[str]:
    failures: list[str] = []
    expected_counts = dict.fromkeys(EXPECTED_HISTORY_MARKERS, 1)
    if len(long_evidence) != expected_payloads or len(short_evidence) != expected_payloads:
        failures.append("provider payload count does not match measured requests")
    for index, evidence in enumerate(long_evidence):
        if evidence.get("history_marker_counts") != expected_counts:
            failures.append(f"long provider payload {index} history markers invalid")
    for index, evidence in enumerate(short_evidence):
        if evidence.get("history_marker_count") != 0:
            failures.append(f"short provider payload {index} contains long history markers")
    return failures


class FakeProvider:
    def __init__(self, runtime: MeasuredRuntime, stats: ProviderStats) -> None:
        self.runtime = runtime
        self.stats = stats

    async def chat(
        self,
        messages: list[Any],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> Any:
        import asyncio

        del temperature, max_tokens
        prompt_tokens = _prompt_tokens(messages, tools)
        self.stats.calls += 1
        self.stats.prompt_tokens.append(prompt_tokens)
        self.stats.payload_evidence.append(_provider_payload_evidence(messages, tools))
        await asyncio.sleep((prompt_tokens * MODEL_PROMPT_LATENCY_MS_PER_TOKEN) / 1000.0)
        return self.runtime.ChatResponse(
            content="benchmark response",
            tool_calls=[],
            model=model,
            usage={"prompt_tokens": prompt_tokens, "completion_tokens": 4},
            finish_reason="stop",
        )

    async def chat_stream(
        self,
        messages: list[Any],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        response = await self.chat(messages, model, tools, temperature, max_tokens)
        yield response.content

    async def chat_stream_events(
        self,
        messages: list[Any],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[Any]:
        response = await self.chat(messages, model, tools, temperature, max_tokens)
        yield self.runtime.StreamEvent(kind="text_delta", text=response.content, model=model)
        yield self.runtime.StreamEvent(kind="done", finish_reason="stop", model=model)

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class FakeRouter:
    def __init__(self, provider: FakeProvider) -> None:
        self.provider = provider

    async def chat(
        self,
        messages: list[Any],
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        **_kwargs: Any,
    ) -> Any:
        return await self.provider.chat(
            messages,
            model or "bench-model",
            tools,
            temperature,
        )

    def get_model_config(self, _model_id: str) -> None:
        return None


def _settings(runtime: MeasuredRuntime, base: Path) -> Any:
    return runtime.JSSettings(
        workspace=base / "workspace",
        state_dir=base / "state",
        providers=[],
        models=[],
        max_turns=3,
        security=runtime.SecurityConfig(api_key_required=False),
        memory=runtime.MemoryConfig(capsule_enabled=False),
    )


def _history() -> list[dict[str, str]]:
    return [
        {
            "role": "user" if index % 2 == 0 else "assistant",
            "content": f"benchmark long history message {index} "
            + ("context " * LONG_HISTORY_WORDS_PER_MESSAGE),
        }
        for index in range(LONG_HISTORY_MESSAGES)
    ]


def _client(runtime: MeasuredRuntime, settings: Any, agent: Any) -> ExitStack:
    stack = ExitStack()
    app = runtime.FastAPI()
    app.include_router(runtime.chat_router)
    stack.enter_context(patch("js.web.server._settings", settings))
    stack.enter_context(patch("js.web.deps._settings", settings))
    stack.enter_context(patch("js.web.routers.chat.get_agent", return_value=agent))
    stack.enter_context(patch("js.web.routers.chat.get_stats_store", return_value=None))
    auth = runtime.AuthManager(settings.state_dir)
    user_key = auth.create_key("old-architecture-benchmark", role="user")
    client = runtime.TestClient(
        app,
        base_url="http://localhost",
        headers={"Origin": "http://localhost", "X-API-Key": user_key},
    )
    stack.enter_context(client)
    stack.client = client  # type: ignore[attr-defined]
    stack.user_key = user_key  # type: ignore[attr-defined]
    stack.owner_key_hash = auth.verify(user_key)["key_hash"]  # type: ignore[attr-defined]
    return stack


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percentile)))
    return ordered[index]


def _latency_summary(values: list[float]) -> dict[str, float]:
    return {
        "mean_ms": round(statistics.fmean(values), 3),
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": round(_percentile(values, 0.95), 3),
        "max_ms": round(max(values), 3),
    }


def _token_summary(values: list[int]) -> dict[str, float | str]:
    floats = [float(value) for value in values]
    return {
        "source": "tokenizer",
        "method": TOKENIZER_METHOD,
        "p50": round(statistics.median(floats), 3),
        "p95": round(_percentile(floats, 0.95), 3),
    }


def _run_group(
    runtime: MeasuredRuntime,
    base: Path,
    *,
    iterations: int,
    warmup: int,
    group: int,
) -> dict[str, Any]:
    settings = _settings(runtime, base / "long")
    stats = ProviderStats()
    agent = runtime.JSAgent(settings)
    agent.router = FakeRouter(FakeProvider(runtime, stats))
    failures: list[str] = []
    latencies: list[float] = []
    with _client(runtime, settings, agent) as stack:
        client: Any = stack.client  # type: ignore[attr-defined]

        def long_request(index: int) -> Any:
            session_id = f"old-long-{group}-{index}"
            agent.memory.store_messages(
                session_id,
                _history(),
                owner_key_hash=stack.owner_key_hash,  # type: ignore[attr-defined]
            )
            return client.post(
                "/api/chat",
                json={"message": f"benchmark api full {index}", "session_id": session_id},
            )

        for index in range(warmup):
            long_request(-index - 1)
        long_calls_before = stats.calls
        long_payloads_before = len(stats.payload_evidence)
        for index in range(iterations):
            start = time.perf_counter()
            response = long_request(index)
            latencies.append((time.perf_counter() - start) * 1000.0)
            if (
                response.status_code != 200
                or response.json().get("response") != "benchmark response"
            ):
                failures.append(f"long HTTP {response.status_code}")
        long_tokens = stats.prompt_tokens[long_calls_before:]
        long_payload_evidence = stats.payload_evidence[long_payloads_before:]

    short_settings = _settings(runtime, base / "short")
    short_stats = ProviderStats()
    short_agent = runtime.JSAgent(short_settings)
    short_agent.router = FakeRouter(FakeProvider(runtime, short_stats))
    with _client(runtime, short_settings, short_agent) as stack:
        short_client: Any = stack.client  # type: ignore[attr-defined]

        def short_request(index: int) -> Any:
            return short_client.post(
                "/api/chat",
                json={
                    "message": f"benchmark api short {index}",
                    "session_id": f"old-short-{group}-{index}",
                },
            )

        for index in range(warmup):
            short_request(-index - 1)
        short_calls_before = short_stats.calls
        short_payloads_before = len(short_stats.payload_evidence)
        for index in range(iterations):
            response = short_request(index)
            if (
                response.status_code != 200
                or response.json().get("response") != "benchmark response"
            ):
                failures.append(f"short HTTP {response.status_code}")
        short_tokens = short_stats.prompt_tokens[short_calls_before:]
        short_payload_evidence = short_stats.payload_evidence[short_payloads_before:]

    failures.extend(
        _validate_payloads(
            long_payload_evidence,
            short_payload_evidence,
            expected_payloads=iterations,
        )
    )
    long_summary = _token_summary(long_tokens)
    short_summary = _token_summary(short_tokens)
    if not all(
        float(long_summary[percentile]) > float(short_summary[percentile])
        for percentile in ("p50", "p95")
    ):
        failures.append("long-context prompt tokens must exceed short-context prompt tokens")

    return {
        "group": group,
        "api_full_agent": _latency_summary(latencies),
        "prompt_tokens": long_summary,
        "short_prompt_tokens": short_summary,
        "long_provider_payload_evidence": long_payload_evidence,
        "short_provider_payload_evidence": short_payload_evidence,
        "failures": failures,
    }


def run(
    *,
    measured_root: Path,
    expected_commit: str,
    iterations: int,
    warmup: int,
    runs: int,
) -> dict[str, Any]:
    if iterations <= 0 or runs <= 0 or warmup < 0:
        raise ValueError("iterations/runs must be positive and warmup must be non-negative")
    provenance = measured_export_provenance(measured_root, expected_commit=expected_commit)
    resolved_root = Path(provenance["measured_root"])
    runtime = _load_measured_runtime(resolved_root)
    if runtime.import_root != provenance["import_root"]:
        raise RuntimeError("measured runtime import root does not match provenance preflight")
    with tempfile.TemporaryDirectory(prefix="old-architecture-baseline-") as raw:
        groups = [
            _run_group(
                runtime,
                Path(raw) / f"group-{group}",
                iterations=iterations,
                warmup=warmup,
                group=group,
            )
            for group in range(1, runs + 1)
        ]
    measured_modules = [
        module
        for name, module in sys.modules.items()
        if module is not None and (name == "js" or name.startswith("js."))
    ]
    if require_measured_module_origins(resolved_root, measured_modules) != runtime.import_root:
        raise RuntimeError("measured runtime import root changed during measurement")
    provenance_after = measured_export_provenance(resolved_root, expected_commit=expected_commit)
    if provenance_after != provenance:
        raise RuntimeError("measured tree or external harness inputs changed during measurement")
    latency_p95 = [float(group["api_full_agent"]["p95_ms"]) for group in groups]
    latency_p50 = [float(group["api_full_agent"]["p50_ms"]) for group in groups]
    latency_mean = [float(group["api_full_agent"]["mean_ms"]) for group in groups]
    latency_max = [float(group["api_full_agent"]["max_ms"]) for group in groups]
    long_p50 = [float(group["prompt_tokens"]["p50"]) for group in groups]
    long_p95 = [float(group["prompt_tokens"]["p95"]) for group in groups]
    short_p50 = [float(group["short_prompt_tokens"]["p50"]) for group in groups]
    short_p95 = [float(group["short_prompt_tokens"]["p95"]) for group in groups]
    failures = [failure for group in groups for failure in group["failures"]]
    return {
        "schema_version": "echo-old-baseline-v2",
        "source": "independent_clean_commit_export",
        "commit": provenance["commit"],
        "tree": provenance["tree"],
        "source_digest": provenance["source_digest"],
        "provenance": provenance,
        "iterations": iterations,
        "warmup": warmup,
        "runs": runs,
        "paid_provider_calls": 0,
        "failures": failures,
        "script_sha256": provenance["baseline_script_sha256"],
        "import_root": runtime.import_root,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "methodology": (
            "External trusted harness over the measured tree's real /api/chat path; deterministic "
            "local fake provider; old architecture sends all 40 fixed history messages; "
            "fresh-session short prompts; cl100k_base canonical provider payload. Current Echo's "
            "separate benchmark intentionally verifies only its latest-14 history window."
        ),
        "limitations": (
            "Local single-process evidence only; tokenizer counts are not provider billing "
            "tokens and latency excludes network/provider variance."
        ),
        "api_full_agent": {
            "mean_ms": round(statistics.median(latency_mean), 3),
            "p50_ms": round(statistics.median(latency_p50), 3),
            "p95_ms": round(statistics.median(latency_p95), 3),
            "max_ms": round(max(latency_max), 3),
            "group_p95_ms": latency_p95,
        },
        "prompt_tokens": {
            "source": "tokenizer",
            "method": TOKENIZER_METHOD,
            "p50": round(statistics.median(long_p50), 3),
            "p95": round(statistics.median(long_p95), 3),
        },
        "short_prompt_tokens": {
            "source": "tokenizer",
            "method": TOKENIZER_METHOD,
            "p50": round(statistics.median(short_p50), 3),
            "p95": round(statistics.median(short_p95), 3),
        },
        "run_summaries": groups,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measured-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = run(
        measured_root=args.measured_root,
        expected_commit=args.expected_commit,
        iterations=args.iterations,
        warmup=args.warmup,
        runs=args.runs,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
