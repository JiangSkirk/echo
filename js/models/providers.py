"""Model provider adapters with retry, fallback, circuit breaker, and error handling."""

from __future__ import annotations

import asyncio
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, Literal, NoReturn

import httpx
from openai import AsyncOpenAI
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from js.config import ModelProviderConfig
from js.models.circuit_breaker import CircuitBreaker
from js.models.stream_events import StreamEvent
from js.utils.log import get_logger
from js.utils.metrics import get_metrics, start_span

# Transport ABC (Hermes v0.14-style protocol abstraction)
_transport_available = False
try:
    from js.models.transports import ChatCompletionsTransport, get_transport

    _transport_available = True
except Exception:
    pass


def _redact_key(key: str | None) -> str:
    from js.models.capability import redact_api_key

    return redact_api_key(key)


def _sanitize_provider_exc(
    exc: BaseException,
    *,
    api_key: str | None,
    query_param_name: str | None = None,
) -> str:
    from js.models.capability import SafeProviderError, sanitize_provider_error

    if isinstance(exc, SafeProviderError):
        return str(exc)
    return sanitize_provider_error(
        str(exc),
        api_key=api_key,
        query_param_name=query_param_name,
    )


def _raise_as_safe_provider_error(
    exc: BaseException,
    *,
    api_key: str | None,
    query_param_name: str | None = None,
    retryable: bool | None = None,
) -> NoReturn:
    """Convert *exc* at the provider adapter exit and raise :class:`SafeProviderError`."""
    from js.models.capability import raise_safe_provider_error

    raise_safe_provider_error(
        exc,
        api_key=api_key,
        query_param_name=query_param_name,
        retryable=is_retryable_provider_error(exc) if retryable is None else retryable,
    )


def _is_local_provider(base_url: str) -> bool:
    """Detect local model servers (LM Studio, Ollama, etc.) by URL."""
    if not base_url:
        return False
    return any(h in base_url for h in ("127.0.0.1", "localhost", "0.0.0.0", "::1"))


def is_retryable_provider_error(exc: BaseException) -> bool:
    """Retry on network errors, protocol errors, timeouts, 5xx, and 429 rate limits."""
    from js.models.capability import SafeProviderError

    if isinstance(exc, SafeProviderError):
        return bool(exc.retryable)
    if isinstance(
        exc,
        (
            httpx.NetworkError,
            httpx.TimeoutException,
            asyncio.TimeoutError,
            httpx.RemoteProtocolError,
            httpx.ConnectError,
        ),
    ):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500 or exc.response.status_code == 429
    return False


logger = get_logger("js.models")


@dataclass
class ChatMessage:
    role: str
    content: str | list[dict[str, Any]]
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = None
    name: str | None = None
    reasoning_content: str | None = None
    # Orin Stage A taint tag: a u64 source bitmask (js.orin.taint). Local
    # bookkeeping only — providers serialize explicit fields above and
    # NEVER this one (Orin decision 11: taint must not reach model APIs).
    taint: int = 0


@dataclass
class ChatResponse:
    content: str
    tool_calls: list[dict[str, Any]]
    model: str
    usage: dict[str, int]
    finish_reason: str
    reasoning_content: str = ""
    usage_source: Literal[
        "provider_actual",
        "tokenizer",
        "estimated",
        "unavailable",
    ] = "unavailable"


class ModelProvider(ABC):
    """Abstract base for model providers."""

    @abstractmethod
    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse: ...

    @abstractmethod
    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]: ...

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[StreamEvent]:
        """Structured streaming events (text/thinking/tool/usage/done/error).

        Default implementation wraps ``chat_stream()`` so providers that only
        emit token text still feed the structured pipeline — each yielded
        chunk becomes one ``text_delta`` event, followed by a terminal
        ``done`` event. Concrete providers override this to expose richer
        deltas (thinking, tool-call partials, usage) without breaking the
        legacy ``chat_stream()`` contract that ``runner.py`` / ``router.py``
        already depend on.
        """
        from js.models.stream_events import StreamEvent

        try:
            async for token in self.chat_stream(
                messages=messages,
                model=model,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
            ):
                if token:
                    yield StreamEvent(kind="text_delta", text=token, model=model)
            yield StreamEvent(kind="done", finish_reason="stop", model=model)
        except Exception as exc:
            from js.models.capability import SafeProviderError, safe_provider_error

            config = getattr(self, "config", None)
            api_key = getattr(config, "api_key", None)
            query_param_name = getattr(config, "query_param_name", None)
            safe = (
                exc
                if isinstance(exc, SafeProviderError)
                else safe_provider_error(
                    exc,
                    api_key=api_key,
                    query_param_name=query_param_name,
                    retryable=is_retryable_provider_error(exc),
                )
            )
            # Even a pre-built SafeProviderError may be legacy/custom — re-scrub.
            if isinstance(safe, SafeProviderError) and (api_key or query_param_name):
                from js.models.capability import sanitize_provider_error

                safe = SafeProviderError(
                    sanitize_provider_error(
                        str(safe),
                        api_key=api_key,
                        query_param_name=query_param_name,
                    ),
                    retryable=safe.retryable,
                )
            yield StreamEvent(
                kind="error",
                error=str(safe),
                model=model,
                meta={"retryable": is_retryable_provider_error(safe)},
            )

    @abstractmethod
    async def health_check(self) -> bool: ...

    @abstractmethod
    async def close(self) -> None: ...


class OpenAICompatibleProvider(ModelProvider):
    """Provider for any OpenAI-compatible API with circuit breaker and health checks.

    Optimizations:
    - Shared HTTP connection pool with keep-alive for lower latency
    - Separate timeout profiles for local vs cloud providers
    - Per-provider concurrency limit to prevent overload
    - API key redaction in all logs
    """

    # Concurrency semaphore per provider to prevent overwhelming the endpoint
    _SEMAPHORES: dict[str, asyncio.Semaphore] = {}
    _SEMA_LOCK = asyncio.Lock()

    def __init__(self, config: ModelProviderConfig) -> None:
        self.config = config
        self._is_local = _is_local_provider(config.base_url)

        # Local providers are more fragile — trip the breaker sooner
        cb_threshold = 3 if self._is_local else 5
        cb_recovery = 15.0 if self._is_local else 30.0
        self.circuit = CircuitBreaker(
            name=config.name,
            failure_threshold=cb_threshold,
            recovery_timeout=cb_recovery,
        )

        # --- Optimised HTTP client ---
        # 1. Connection pool: enough for concurrent tool calls + chat
        # 2. HTTP/2: reduces latency for sequential requests
        # 3. Keep-alive: avoids TLS handshake overhead on every request
        # 4. trust_env=False: bypass system proxies for localhost
        _limits = httpx.Limits(
            max_connections=20,
            max_keepalive_connections=10,
            keepalive_expiry=30.0,
        )

        # Local models need longer timeouts — cold-start model loading into GPU
        # can take 2-3 minutes (especially for large models like qwen3.5).
        if self._is_local:
            try:
                cfg_timeout = float(config.timeout)
            except (TypeError, ValueError):
                cfg_timeout = 120.0
            _local_timeout = max(cfg_timeout, 300.0)
            _timeout = httpx.Timeout(
                _local_timeout,
                connect=3.0,
                read=_local_timeout,
                write=10.0,
                pool=3.0,
            )
            _http2 = False  # Many local servers don't support HTTP/2 well
        else:
            _timeout = httpx.Timeout(
                config.timeout,
                connect=8.0,
                read=config.timeout,
                write=15.0,
                pool=5.0,
            )
            _http2 = True

        self._http_timeout = _timeout
        self._http_limits = _limits
        self._http2 = _http2
        self._client: Any | None = None
        self._client_guard = threading.Lock()

        self._last_health_check = 0.0
        self._health_status = False
        self._health_lock = asyncio.Lock()
        self._last_stream_usage: dict[str, int] | None = None
        self._stream_options_supported = True

        # Transport layer (Hermes v0.14 architecture)
        self._transport: Any = None
        if _transport_available:
            ttype = getattr(config, "transport_type", "chat_completions")
            if ttype != "chat_completions":
                try:
                    self._transport = get_transport(
                        ttype,
                        api_key=config.api_key,
                    )
                    logger.info(
                        "Provider %s using transport=%s",
                        config.name,
                        ttype,
                    )
                except Exception as e:
                    logger.warning(
                        "Transport %s failed for %s, falling back to chat_completions: %s",
                        ttype,
                        config.name,
                        e,
                    )
                    self._transport = ChatCompletionsTransport()
            else:
                self._transport = ChatCompletionsTransport()

        logger.info(
            "Provider %s initialised (local=%s, key=%s, http2=%s)",
            config.name,
            self._is_local,
            _redact_key(config.api_key),
            _http2,
        )

    def _build_client(self) -> AsyncOpenAI:
        http_client = httpx.AsyncClient(
            trust_env=False,
            timeout=self._http_timeout,
            limits=self._http_limits,
            http2=self._http2,
        )
        client_kwargs: dict[str, Any] = {
            "base_url": self.config.base_url,
            "api_key": self.config.api_key or "not-needed",
            "http_client": http_client,
            "max_retries": 0,
        }
        if (
            self.config.auth_adapter == "query_param"
            and self.config.api_key
            and self.config.query_param_name
        ):
            client_kwargs["default_query"] = {self.config.query_param_name: self.config.api_key}
            client_kwargs["api_key"] = "not-needed"
        return AsyncOpenAI(**client_kwargs)

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        with self._client_guard:
            if self._client is None:
                self._client = self._build_client()
            return self._client

    @property
    def client(self) -> Any:
        return self._ensure_client()

    @client.setter
    def client(self, value: Any) -> None:
        self._client = value

    def _convert_messages(self, messages: list[ChatMessage]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for m in messages:
            msg: dict[str, Any] = {"role": m.role}
            if isinstance(m.content, list):
                msg["content"] = m.content
            else:
                msg["content"] = m.content
            if m.tool_calls:
                msg["tool_calls"] = m.tool_calls
            if m.tool_call_id:
                msg["tool_call_id"] = m.tool_call_id
            if m.reasoning_content:
                msg["reasoning_content"] = m.reasoning_content
            # Note: we intentionally do NOT serialize `m.name` here.
            # The `name` field is not part of the standard OpenAI `tool` message
            # format and can confuse strict local-model jinja templates.
            result.append(msg)
        return result

    async def _semaphore(self) -> asyncio.Semaphore:
        """Lazy-create a per-provider concurrency semaphore."""
        key = self.config.name
        if key not in self._SEMAPHORES:
            async with self._SEMA_LOCK:
                if key not in self._SEMAPHORES:
                    # Local providers: limit to 2 concurrent requests
                    # Cloud providers: limit to 5 concurrent requests
                    limit = 2 if self._is_local else 5
                    self._SEMAPHORES[key] = asyncio.Semaphore(limit)
        return self._SEMAPHORES[key]

    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        if not await self.circuit.can_execute():
            raise RuntimeError(f"Circuit breaker OPEN for {self.config.name}")

        async def _do_chat() -> ChatResponse:
            converted = self._convert_messages(messages)
            kwargs: dict[str, Any] = {
                "model": model,
                "messages": converted,
                "temperature": temperature,
            }
            from js.bots.persona import apply_bots_cache_hooks

            apply_bots_cache_hooks(
                converted,
                kwargs,
                transport_type=str(getattr(self.config, "transport_type", "") or ""),
            )
            if tools:
                kwargs["tools"] = tools
                kwargs["tool_choice"] = "auto"
            if max_tokens:
                kwargs["max_tokens"] = max_tokens

            # Enforce a hard ceiling on request size (safety / DoS prevention)
            total_chars = sum(
                len(m.content) if isinstance(m.content, str) else len(str(m.content))
                for m in messages
            )
            if total_chars > 500_000:
                raise ValueError(
                    f"Request too large ({total_chars} chars, max 500k). "
                    "Please shorten the message or use file tools."
                )

            with start_span("model.chat", {"model": model, "provider": self.config.name}):
                start = time.perf_counter()
                try:
                    try:
                        get_metrics().model_requests_total.labels(
                            model=model, provider=self.config.name
                        ).inc()
                    except Exception:
                        logger.warning("Suppressed error", exc_info=True)

                    # Concurrency gate: prevent overwhelming the endpoint
                    sem = await self._semaphore()
                    async with sem:
                        response = await self.client.chat.completions.create(**kwargs)

                    choice = response.choices[0]
                    message = choice.message

                    tool_calls: list[dict[str, Any]] = []
                    if message.tool_calls:
                        for tc in message.tool_calls:
                            tool_calls.append(
                                {
                                    "id": tc.id,
                                    "type": tc.type,
                                    "function": {
                                        "name": tc.function.name,
                                        "arguments": tc.function.arguments,
                                    },
                                }
                            )

                    from js.models.usage import map_openai_usage

                    buckets = map_openai_usage(
                        response.usage,
                        source="provider_actual" if response.usage else "unavailable",
                    )
                    usage = buckets.to_usage_dict()

                    latency = time.perf_counter() - start
                    try:
                        get_metrics().model_latency_seconds.labels(
                            model=model, provider=self.config.name
                        ).observe(latency)
                    except Exception:
                        logger.warning("Suppressed error", exc_info=True)
                    return ChatResponse(
                        content=message.content or "",
                        tool_calls=tool_calls,
                        model=response.model,
                        usage=usage,
                        finish_reason=choice.finish_reason or "stop",
                        reasoning_content=getattr(message, "reasoning_content", "") or "",
                        usage_source=buckets.usage_source,
                    )
                except Exception as e:
                    # Convert at the boundary before metrics/logging so a metrics
                    # secondary failure cannot attach the raw provider exception
                    # as ``__context__`` into logs / exc_info consumers.
                    from js.models.capability import (
                        reraise_safe_provider_error,
                        safe_provider_error,
                    )

                    mapped: BaseException = e
                    if isinstance(e, RuntimeError) and (
                        "generator didn't stop after throw()" in str(e)
                        or "generator didn't stop after athrow()" in str(e)
                    ):
                        mapped = RuntimeError(
                            f"Connection to {self.config.name} was interrupted. "
                            "The remote server may have closed the connection unexpectedly."
                        )
                    safe_error = safe_provider_error(
                        mapped,
                        api_key=self.config.api_key,
                        query_param_name=getattr(self.config, "query_param_name", None),
                        retryable=is_retryable_provider_error(mapped),
                    )
                    latency = time.perf_counter() - start
                    try:
                        get_metrics().model_latency_seconds.labels(
                            model=model, provider=self.config.name
                        ).observe(latency)
                        get_metrics().model_errors_total.labels(
                            model=model, provider=self.config.name
                        ).inc()
                    except Exception:
                        logger.warning(
                            "Suppressed metrics error after provider failure",
                            exc_info=False,
                        )
                    reraise_safe_provider_error(safe_error)

        try:
            return await self.circuit.execute(_do_chat())  # type: ignore[no-any-return]
        except Exception as exc:
            from js.models.capability import SafeProviderError

            if isinstance(exc, SafeProviderError):
                raise
            _raise_as_safe_provider_error(
                exc,
                api_key=self.config.api_key,
                query_param_name=getattr(self.config, "query_param_name", None),
            )

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        if not await self.circuit.can_execute():
            raise RuntimeError(f"Circuit breaker OPEN for {self.config.name}")

        converted = self._convert_messages(messages)
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": converted,
            "temperature": temperature,
            "stream": True,
        }
        from js.bots.persona import apply_bots_cache_hooks

        apply_bots_cache_hooks(
            converted,
            kwargs,
            transport_type=str(getattr(self.config, "transport_type", "") or ""),
        )
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if max_tokens:
            kwargs["max_tokens"] = max_tokens

        # Try to request usage in the final stream chunk (OpenAI-compatible).
        # Some providers don't support stream_options; we fallback gracefully.
        stream_options_supported = bool(getattr(self, "_stream_options_supported", True))
        if stream_options_supported:
            kwargs["stream_options"] = {"include_usage": True}

        self._last_stream_usage = None

        try:
            # Use ``async with`` so the stream is closed cleanly even if the
            # async-for loop is cancelled or interrupted.
            sem = await self._semaphore()
            async with sem:
                stream = await self.client.chat.completions.create(**kwargs)
            async with stream as stream_ctx:
                async for chunk in stream_ctx:
                    if getattr(chunk, "usage", None):
                        from js.models.usage import map_openai_usage

                        self._last_stream_usage = map_openai_usage(chunk.usage).to_usage_dict()
                    if chunk.choices and chunk.choices[0].delta.content:
                        yield chunk.choices[0].delta.content
            await self.circuit.record_success()
            return
        except Exception as exc:
            if stream_options_supported and "stream_options" in str(exc):
                self._stream_options_supported = False
            if isinstance(exc, RuntimeError) and (
                "generator didn't stop after throw()" in str(exc)
                or "generator didn't stop after athrow()" in str(exc)
            ):
                exc = RuntimeError(
                    f"Connection to {self.config.name} was interrupted. "
                    "The remote server may have closed the connection unexpectedly."
                )
            await self.circuit.record_failure()
            _raise_as_safe_provider_error(
                exc,
                api_key=self.config.api_key,
                query_param_name=getattr(self.config, "query_param_name", None),
            )

    async def chat_stream_events(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[StreamEvent]:
        """OpenAI-compatible structured event stream.

        Unlike the legacy ``chat_stream()`` (which only yields text fragments),
        this exposes every protocol-level event the OpenAI streaming format
        carries: text, reasoning content (DeepSeek-R1/QwQ/Kimi-K2-Thinking),
        partial tool calls, the final usage summary, and a terminal
        done / error marker. Each event is tagged with the provider name
        and model id at the boundary so downstream consumers can attribute
        them without bookkeeping.
        """
        from js.models.stream_events import StreamEvent, parse_openai_chunk

        if not await self.circuit.can_execute():
            yield StreamEvent(
                kind="error",
                error=f"Circuit breaker OPEN for {self.config.name}",
                provider=self.config.name,
                model=model,
            )
            return

        converted = self._convert_messages(messages)
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": converted,
            "temperature": temperature,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        from js.bots.persona import apply_bots_cache_hooks

        apply_bots_cache_hooks(
            converted,
            kwargs,
            transport_type=str(getattr(self.config, "transport_type", "") or ""),
        )
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if max_tokens:
            kwargs["max_tokens"] = max_tokens

        stream_options_supported = bool(getattr(self, "_stream_options_supported", True))
        if not stream_options_supported:
            kwargs.pop("stream_options", None)
        done_emitted = False
        try:
            sem = await self._semaphore()
            async with sem:
                stream = await self.client.chat.completions.create(**kwargs)
            async with stream as stream_ctx:
                async for chunk in stream_ctx:
                    for ev in parse_openai_chunk(chunk):
                        ev.provider = self.config.name
                        if not ev.model:
                            ev.model = model
                        if ev.kind == "done":
                            done_emitted = True
                        yield ev
            await self.circuit.record_success()
            if not done_emitted:
                yield StreamEvent(
                    kind="done",
                    finish_reason="stop",
                    provider=self.config.name,
                    model=model,
                )
            return
        except Exception as exc:
            from js.models.capability import safe_provider_error

            compatibility_retry = stream_options_supported and "stream_options" in str(exc)
            if compatibility_retry:
                self._stream_options_supported = False
            if isinstance(exc, RuntimeError) and (
                "generator didn't stop after throw()" in str(exc)
                or "generator didn't stop after athrow()" in str(exc)
            ):
                exc = RuntimeError(
                    f"Connection to {self.config.name} was interrupted. "
                    "The remote server may have closed the connection unexpectedly."
                )
            await self.circuit.record_failure()
            # First exit: convert to SafeProviderError so stream consumers only
            # see scrubbed text (not a raw credential-bearing SDK exception).
            safe = safe_provider_error(
                exc,
                api_key=self.config.api_key,
                query_param_name=getattr(self.config, "query_param_name", None),
                retryable=compatibility_retry or is_retryable_provider_error(exc),
            )
            yield StreamEvent(
                kind="error",
                error=str(safe),
                provider=self.config.name,
                model=model,
                meta={
                    "retryable": safe.retryable,
                },
            )

    async def health_check(self) -> bool:
        # Fast path: return cached result without lock
        now = time.time()
        # Local providers change state frequently (model loading/unloading) -
        # cache for shorter. Cloud providers are stable - cache longer.
        cache_ttl = 3.0 if self._is_local else 10.0
        if now - self._last_health_check < cache_ttl:
            return self._health_status

        # Use lock to prevent concurrent health checks from racing
        async with self._health_lock:
            # Double-check after acquiring lock
            now = time.time()
            if now - self._last_health_check < cache_ttl:
                return self._health_status

            try:
                # Use a short timeout for health checks to avoid hanging.
                # The OpenAI client models.list() does not accept a timeout
                # kwarg in all versions, so we use asyncio.wait_for instead.
                # Local providers should respond very fast.
                hc_timeout = 4.0 if self._is_local else 8.0
                await asyncio.wait_for(self.client.models.list(), timeout=hc_timeout)
                self._health_status = True
                # Do NOT record health-check success to circuit — only real calls should
                # affect the breaker. Otherwise routine health checks can keep the
                # circuit closed even when actual requests are failing.
            except Exception:
                self._health_status = False
                # Similarly, do not record health-check failures to the circuit breaker.
                # A transient health-check failure should not trip the breaker.
                pass

            self._last_health_check = time.time()
            return self._health_status

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception(is_retryable_provider_error),
    )
    async def embed(
        self,
        texts: list[str],
        model: str | None = None,
    ) -> list[list[float]]:
        """Generate embeddings for a batch of texts."""
        if not await self.circuit.can_execute():
            raise RuntimeError(f"Circuit breaker OPEN for {self.config.name}")

        if not texts:
            return []

        # Size gate: reject unreasonably large embedding requests
        total_chars = sum(len(t) for t in texts)
        if total_chars > 500_000:
            raise ValueError(
                f"Embedding request too large ({total_chars} chars, max 500k). "
                "Please split into smaller batches."
            )

        resolved_model = model or (
            self.config.models[0].id if self.config.models else "text-embedding-3-small"
        )

        async def _do_embed() -> list[list[float]]:
            sem = await self._semaphore()
            async with sem:
                response = await self.client.embeddings.create(
                    model=resolved_model,
                    input=texts,
                )
            return [item.embedding for item in response.data]

        return await self.circuit.execute(_do_embed())  # type: ignore[no-any-return]

    async def close(self) -> None:
        client = self._client
        if client is not None:
            await client.close()
