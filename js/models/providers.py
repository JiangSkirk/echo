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
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from js.config import ModelProviderConfig
from js.models.circuit_breaker import CircuitBreaker
from js.utils.log import get_logger
from js.utils.metrics import get_metrics, start_span

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
            api_key=config.api_key or "dummy",
            timeout=httpx.Timeout(config.timeout),
            max_retries=0,  # We handle retries ourselves
        )
        self._last_health_check = 0.0
        self._health_status = False

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
        retry=retry_if_exception_type((httpx.NetworkError, httpx.TimeoutException, asyncio.TimeoutError)),
    )
    async def chat(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        if not self.circuit.can_execute():
            raise RuntimeError(f"Circuit breaker OPEN for {self.config.name}")

        try:
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
                        logger.debug("Suppressed error", exc_info=True)
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

                    self.circuit.record_success()
                    latency = time.perf_counter() - start
                    try:
                        get_metrics().model_latency_seconds.labels(
                            model=model, provider=self.config.name
                        ).observe(latency)
                    except Exception:
                        logger.debug("Suppressed error", exc_info=True)
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
                        logger.debug("Suppressed error", exc_info=True)
                    raise
        except Exception:
            self.circuit.record_failure()
            raise

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        if not self.circuit.can_execute():
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

        try:
            stream = await self.client.chat.completions.create(**kwargs)
            async for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
            self.circuit.record_success()
        except Exception:
            self.circuit.record_failure()
            raise

    async def health_check(self) -> bool:
        import time
        # Cache health check for 5 seconds
        if time.time() - self._last_health_check < 5.0:
            return self._health_status

        try:
            await self.client.models.list()
            self._health_status = True
            self.circuit.record_success()
        except Exception:
            self._health_status = False
            self.circuit.record_failure()

        self._last_health_check = time.time()
        return self._health_status

    async def embed(
        self,
        texts: list[str],
        model: str | None = None,
    ) -> list[list[float]]:
        """Generate embeddings for a batch of texts."""
        if not self.circuit.can_execute():
            raise RuntimeError(f"Circuit breaker OPEN for {self.config.name}")
        try:
            response = await self.client.embeddings.create(
                model=model or self.config.models[0].id if self.config.models else "text-embedding-3-small",
                input=texts,
            )
            return [item.embedding for item in response.data]
        except Exception:
            self.circuit.record_failure()
            raise

    async def close(self) -> None:
        await self.client.close()

    def get_circuit_stats(self) -> dict[str, Any]:
        return self.circuit.get_stats()
