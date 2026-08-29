"""Opt-in model transport that keeps provider tokens out of Echo.

Default off. Echo holds only a destination + SecretHandle. The Services Cell
(or a test double) injects the token. Failure does not fall back to ambient
hydration.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from js.models.providers import ChatMessage, ChatResponse
from js.orin.process_split import mark_provider_tokens_out_of_echo

_BLOCKED_SCHEMES = frozenset({"file", "ftp", "gopher", "javascript"})


@dataclass(frozen=True, slots=True)
class ModelConnectorRequest:
    destination: str
    secret_handle: str
    messages: tuple[ChatMessage, ...]
    model: str
    temperature: float = 0.7
    max_tokens: int | None = None


def destination_is_allowed(url: str, *, allowlist: Sequence[str]) -> bool:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    if parsed.scheme.lower() in _BLOCKED_SCHEMES:
        return False
    if parsed.username or parsed.password:
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return False
    allowed = {item.lower().rstrip(".") for item in allowlist if item}
    return not allowed or host in allowed


class CellBackedChatProvider:
    """Provider adapter with no api_key. Tokens stay in the Cell."""

    api_key = None

    def __init__(
        self,
        *,
        destination: str,
        secret_handle: str,
        relay: Any,
        allowlist: Sequence[str] = (),
        name: str = "cell-model",
    ) -> None:
        if not destination_is_allowed(destination, allowlist=allowlist):
            raise ValueError("model connector destination is not allowed")
        if not secret_handle:
            raise ValueError("model connector requires a SecretHandle")
        self.destination = destination
        self.secret_handle = secret_handle
        self._relay = relay
        self.name = name
        mark_provider_tokens_out_of_echo(True)

    async def chat(
        self,
        messages: list[ChatMessage],
        *,
        model: str,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> ChatResponse:
        del tools
        request = ModelConnectorRequest(
            destination=self.destination,
            secret_handle=self.secret_handle,
            messages=tuple(messages),
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        result = await self._relay(request)
        if not isinstance(result, ChatResponse):
            raise TypeError("model connector relay returned an invalid response")
        return result


def cell_model_transport_enabled(settings: Any) -> bool:
    orin = getattr(settings, "orin", None)
    return getattr(orin, "cell_model_transport", False) is True


__all__ = [
    "CellBackedChatProvider",
    "ModelConnectorRequest",
    "cell_model_transport_enabled",
    "destination_is_allowed",
]
