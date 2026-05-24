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


def _is_retryable_exception(exc: BaseException) -> bool:
    """Retry on network errors, timeouts, 5xx, and 429 rate limits."""
    if isinstance(exc, (httpx.NetworkError, httpx.TimeoutException, asyncio.TimeoutError)):
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


@dataclass
class ChatResponse:
    content: str
    tool_calls: list[dict[str, Any]]
    model: str
    usage: dict[str, int]
    finish_reason: str


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
    """Provider for any OpenAI-compatible API with circuit breaker and health checks."""

    def __init__(self, config: ModelProviderConfig) -> None:
        self.config = config
        self.circuit = CircuitBreaker(name=config.name, failure_threshold=5, recovery_timeout=30.0)
        self.client = AsyncOpenAI(
            base_url=config.base_url,
            api_key=config.api_key or "not-needed",
            timeout=httpx.Timeout(config.timeout, connect=5.0, read=config.timeout),
            max_retries=0,  # We handle retries ourselves
        )
        self._last_health_check = 0.0
        self._health_status = False
        self._health_lock = asyncio.Lock()

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
            if m.name:
                msg["name"] = m.name
            result.append(msg)
        return result

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
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

            with start_span("model.chat", {"model": model, "provider": self.config.name}):
                start = time.perf_counter()
                try:
                    try:
                        get_metrics().model_requests_total.labels(
                            model=model, provider=self.config.name
                        ).inc()
                    except Exception:
                        logger.warning("Suppressed error", exc_info=True)
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

                    usage = {
                        "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                        "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                        "total_tokens": response.usage.total_tokens if response.usage else 0,
                    }

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
                    )
                except Exception:
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

        # Retry wrapper for stream initialization
        last_error = None
        max_retries = getattr(self.config, 'max_retries', 3)
        for attempt in range(max_retries):
            try:
                stream = await self.client.chat.completions.create(**kwargs)
                async for chunk in stream:
                    if chunk.choices and chunk.choices[0].delta.content:
                        yield chunk.choices[0].delta.content
                await self.circuit.record_success()
                return
            except Exception as e:
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
        if now - self._last_health_check < 5.0:
            return self._health_status

        # Use lock to prevent concurrent health checks from racing
        async with self._health_lock:
            # Double-check after acquiring lock
            now = time.time()
            if now - self._last_health_check < 5.0:
                return self._health_status

            try:
                # Use a short timeout for health checks to avoid hanging
                await self.client.models.list(timeout=8.0)
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

        async def _do_embed() -> list[list[float]]:
            response = await self.client.embeddings.create(
                model=model or self.config.models[0].id if self.config.models else "text-embedding-3-small",
                input=texts,
            )
            return [item.embedding for item in response.data]

        return await self.circuit.execute(_do_embed())  # type: ignore[no-any-return]

    async def close(self) -> None:
        await self.client.close()
