"""Model provider adapters with retry, fallback, circuit breaker, and error handling."""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

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
    """Redact an API key for safe logging."""
    if not key:
        return "<not-set>"
    if len(key) <= 8:
        return "***"
    return key[:4] + "****" + key[-4:]


def _is_local_provider(base_url: str) -> bool:
    """Detect local model servers (LM Studio, Ollama, etc.) by URL."""
    if not base_url:
        return False
    return any(h in base_url for h in ("127.0.0.1", "localhost", "0.0.0.0", "::1"))


def _is_retryable_exception(exc: BaseException) -> bool:
    """Retry on network errors, protocol errors, timeouts, 5xx, and 429 rate limits."""
    if isinstance(exc, (httpx.NetworkError, httpx.TimeoutException, asyncio.TimeoutError,
                        httpx.RemoteProtocolError, httpx.ConnectError)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500 or exc.response.status_code == 429
    return False

logger = get_logger("js.models")


@dataclass
@dataclass
class ChatMessage:
    role: str
    content: str | list[dict[str, Any]]
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = None
    name: str | None = None
    reasoning_content: str | None = None


@dataclass
class ChatResponse:
    content: str
    tool_calls: list[dict[str, Any]]
    model: str
    usage: dict[str, int]
    finish_reason: str
    reasoning_content: str = ""


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
    ) -> ChatResponse:
        ...

    @abstractmethod
    def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...


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

        _http_client = httpx.AsyncClient(
            trust_env=False,
            timeout=_timeout,
            limits=_limits,
            http2=_http2,
        )

        self.client = AsyncOpenAI(
            base_url=config.base_url,
            api_key=config.api_key or "not-needed",
            http_client=_http_client,
            max_retries=0,  # We handle retries ourselves
        )

        self._last_health_check = 0.0
        self._health_status = False
        self._health_lock = asyncio.Lock()
        self._last_stream_usage: dict[str, int] | None = None

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

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=20),
        retry=retry_if_exception(_is_retryable_exception),
    )
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
            kwargs: dict[str, Any] = {
                "model": model,
                "messages": self._convert_messages(messages),
                "temperature": temperature,
            }
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
                            tool_calls.append({
                                "id": tc.id,
                                "type": tc.type,
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments,
                                },
                            })

                    usage: dict[str, int] = {
                        "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                        "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                        "total_tokens": response.usage.total_tokens if response.usage else 0,
                        "cached_tokens": 0,
                    }
                    # Extract cached token count when available (OpenAI, Anthropic, etc.)
                    if response.usage:
                        details = getattr(response.usage, "prompt_tokens_details", None)
                        if details:
                            usage["cached_tokens"] = getattr(details, "cached_tokens", 0) or 0

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
                    )
                except Exception as e:
                    latency = time.perf_counter() - start
                    try:
                        get_metrics().model_latency_seconds.labels(
                            model=model, provider=self.config.name
                        ).observe(latency)
                        get_metrics().model_errors_total.labels(
                            model=model, provider=self.config.name
                        ).inc()
                    except Exception:
                        logger.warning("Suppressed error", exc_info=True)
                    # Map cryptic async-generator protocol errors to something
                    # users can understand. These usually come from httpx/openai
                    # internals when a connection is cancelled or closed
                    # unexpectedly.
                    if isinstance(e, RuntimeError) and (
                        "generator didn't stop after throw()" in str(e)
                        or "generator didn't stop after athrow()" in str(e)
                    ):
                        raise RuntimeError(
                            f"Connection to {self.config.name} was interrupted. "
                            "The remote server may have closed the connection unexpectedly."
                        ) from e
                    raise

        try:
            return await self.circuit.execute(_do_chat())  # type: ignore[no-any-return]
        except Exception:
            raise

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

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": self._convert_messages(messages),
            "temperature": temperature,
            "stream": True,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if max_tokens:
            kwargs["max_tokens"] = max_tokens

        # Try to request usage in the final stream chunk (OpenAI-compatible).
        # Some providers don't support stream_options; we fallback gracefully.
        stream_options_supported = True
        kwargs["stream_options"] = {"include_usage": True}

        self._last_stream_usage = None

        # Retry wrapper for stream initialization
        last_error: BaseException | None = None
        max_retries = getattr(self.config, 'max_retries', 3)
        for attempt in range(max_retries):
            try:
                # Use ``async with`` so the stream is closed cleanly even if
                # the async-for loop is cancelled or interrupted. This helps
                # avoid "generator didn't stop after throw()" errors from
                # httpx/openai internals.
                sem = await self._semaphore()
                async with sem:
                    stream = await self.client.chat.completions.create(**kwargs)
                async with stream as stream_ctx:
                    async for chunk in stream_ctx:
                        # Capture usage from the final chunk when available
                        if getattr(chunk, "usage", None):
                            self._last_stream_usage = {
                                "prompt_tokens": chunk.usage.prompt_tokens or 0,
                                "completion_tokens": chunk.usage.completion_tokens or 0,
                                "total_tokens": chunk.usage.total_tokens or 0,
                                "cached_tokens": 0,
                            }
                            # Some providers include cached token details in stream usage
                            details = getattr(chunk.usage, "prompt_tokens_details", None)
                            if details:
                                self._last_stream_usage["cached_tokens"] = getattr(details, "cached_tokens", 0) or 0
                        if chunk.choices and chunk.choices[0].delta.content:
                            yield chunk.choices[0].delta.content
                await self.circuit.record_success()
                return
            except Exception as e:
                # If the provider rejected stream_options, retry without it once
                if stream_options_supported and attempt == 0 and "stream_options" in str(e):
                    stream_options_supported = False
                    kwargs.pop("stream_options", None)
                    self._last_stream_usage = None
                    continue
                # Map cryptic async-generator protocol errors
                if isinstance(e, RuntimeError) and (
                    "generator didn't stop after throw()" in str(e)
                    or "generator didn't stop after athrow()" in str(e)
                ):
                    last_error = RuntimeError(
                        f"Connection to {self.config.name} was interrupted. "
                        "The remote server may have closed the connection unexpectedly."
                    )
                    break
                last_error = e
                if not _is_retryable_exception(e):
                    break
                if attempt < max_retries - 1:
                    wait = min(2 ** attempt, 30)
                    logger.warning(f"Stream retry {attempt + 1} for {self.config.name} after {wait}s: {e}")
                    await asyncio.sleep(wait)
        await self.circuit.record_failure()
        raise last_error or RuntimeError(f"Stream failed for {self.config.name}")

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
        retry=retry_if_exception(_is_retryable_exception),
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
        await self.client.close()
