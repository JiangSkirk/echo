"""Model capability registry & provider/API key probing.

Adds a small, dependency-light layer on top of the existing OpenAI-compatible
provider plumbing to:

1. Verify an API key is actually usable against its base URL (not just that the
   endpoint is reachable).
2. Pull or identify the list of models that key can access.
3. Identify each model's capabilities (context window, max output tokens,
   tools / vision / thinking / streaming support).
4. Never leak API keys into logs, error messages, or response bodies.

Used by:
- ``js/web/model_refresh.py`` (background refresh of cloud + local /models).
- ``js/models/provider_manager.py`` (model discovery on add-provider).
- Future fleet / dashboard endpoints that need a "is this key still good?"
  check before assigning roles to a provider.

The OpenAI-compatible path covers most providers (OpenAI, DeepSeek, Kimi,
DashScope, SiliconFlow, Volcano Ark, LM Studio, Ollama, vLLM, etc.).  Anthropic
has its own ``/v1/models`` shape (``data: [{id, display_name, type,
created_at}]``) requiring ``x-api-key`` + ``anthropic-version`` headers
instead of ``Authorization: Bearer``.

This file ONLY does discovery / probing — it does not register transports or
construct providers. Callers compose ``probe_provider()`` with their own
``ModelRouter`` / ``OpenAICompatibleProvider`` wiring.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, NoReturn
from urllib.parse import quote, urlparse

from js.config import ModelConfig
from js.utils.log import get_logger

logger = get_logger("js.models.capability")


# ---------------------------------------------------------------------------
# Key redaction
# ---------------------------------------------------------------------------


class SafeProviderError(RuntimeError):
    """Provider-boundary error whose message is safe to log, store, or return.

    Constructed only after scrubbing credentials from the original exception
    text. Never chains ``__cause__`` / ``__context__`` to the raw provider
    exception, so ``exc_info`` / traceback consumers cannot recover secrets
    via cause links. Downstream layers (router, Echo, ledger, HTTP/WS/UI)
    must consume this type (or its message) instead of raw SDK/httpx errors.
    """

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = bool(retryable)
        # Belt-and-suspenders: clear any accidental cause/context wiring.
        self.__cause__ = None
        self.__context__ = None
        self.__suppress_context__ = True


def safe_provider_error(
    exc: BaseException,
    *,
    api_key: str | None,
    query_param_name: str | None = None,
    retryable: bool = False,
) -> SafeProviderError:
    """Build a :class:`SafeProviderError` from *exc* without chaining causes.

    If *exc* is already a :class:`SafeProviderError`, returns it unchanged
    (preserving its retryable flag unless a caller-supplied ``retryable`` is
    True and the existing flag is False — callers should pass the computed
    retryability of the *original* exception before conversion).
    """
    if isinstance(exc, SafeProviderError):
        if retryable and not exc.retryable:
            return SafeProviderError(str(exc), retryable=True)
        return exc
    message = sanitize_provider_error(
        str(exc),
        api_key=api_key,
        query_param_name=query_param_name,
    )
    return SafeProviderError(message, retryable=retryable)


def reraise_safe_provider_error(err: SafeProviderError) -> NoReturn:
    """Re-raise *err* after detaching any secret-bearing cause/context links."""
    try:
        raise err from None
    finally:
        err.__cause__ = None
        err.__context__ = None
        err.__suppress_context__ = True


def raise_safe_provider_error(
    exc: BaseException,
    *,
    api_key: str | None,
    query_param_name: str | None = None,
    retryable: bool = False,
) -> NoReturn:
    """Raise a :class:`SafeProviderError` derived from *exc* with no cause chain.

    This is the canonical first-exit conversion at the provider adapter
    boundary. ``raise ... from None`` alone still attaches the original
    exception as ``__context__``; we clear cause/context in ``finally`` so
    introspecting the raised error cannot recover credentials.
    """
    reraise_safe_provider_error(
        safe_provider_error(
            exc,
            api_key=api_key,
            query_param_name=query_param_name,
            retryable=retryable,
        )
    )


def redact_api_key(key: str | None) -> str:
    """Return a safe-to-log representation of an API key.

    Examples:
        redact_api_key(None)        -> '<not-set>'
        redact_api_key('')          -> '<not-set>'
        redact_api_key('abc')       -> '***'
        redact_api_key('sk-abcdef') -> 'sk-a****cdef'

    The first/last 4 visible characters give enough surface area to tell two
    keys apart in a log without disclosing the secret. Keys ≤8 chars collapse
    to ``***``.
    """
    if not key:
        return "<not-set>"
    if len(key) <= 8:
        return "***"
    return f"{key[:4]}****{key[-4:]}"


def _percent_hex_pattern(encoded: str) -> str:
    """Turn ``%2F`` into a regex fragment with case-insensitive hex digits."""
    out: list[str] = []
    i = 0
    while i < len(encoded):
        if encoded[i] == "%" and i + 2 < len(encoded):
            h1, h2 = encoded[i + 1], encoded[i + 2]
            out.append(
                f"%[{re.escape(h1.upper())}{re.escape(h1.lower())}]"
                f"[{re.escape(h2.upper())}{re.escape(h2.lower())}]"
            )
            i += 3
        else:
            out.append(re.escape(encoded[i]))
            i += 1
    return "".join(out)


def _percent_insensitive_char_pattern(char: str) -> str:
    """Regex fragment matching *char* literally or percent-encoded (hex case-insensitive)."""
    literal = re.escape(char)
    alts = [literal]
    if char == " ":
        alts.append(r"\+")
    hex_form = f"%{ord(char):02X}"
    if hex_form.lower() != char.lower():
        alts.append(_percent_hex_pattern(hex_form))
    encoded = quote(char, safe="")
    if encoded not in {char, hex_form}:
        alts.append(_percent_hex_pattern(encoded))
    return f"(?:{'|'.join(dict.fromkeys(alts))})"


def _percent_insensitive_pattern(secret: str) -> re.Pattern[str]:
    """Build a regex where each ``%HH`` triplet matches hex case-insensitively."""
    return re.compile("".join(_percent_insensitive_char_pattern(ch) for ch in secret))


def _secret_encoding_forms(secret: str) -> list[str]:
    """Known transport encodings of *secret* (not exhaustive string enumeration)."""
    from urllib.parse import quote_plus

    forms = [secret, quote(secret, safe=""), quote_plus(secret)]
    expanded: list[str] = []
    seen: set[str] = set()
    for form in forms:
        for variant in (form, form.upper(), form.lower()):
            if variant not in seen:
                seen.add(variant)
                expanded.append(variant)
    return expanded


def _scrub_secret_regex(text: str, secret: str, replacement: str) -> str:
    if not secret or not text:
        return text
    cleaned = text
    for form in _secret_encoding_forms(secret):
        cleaned = _percent_insensitive_pattern(form).sub(replacement, cleaned)
    return cleaned


def _scrub_query_param_assignments(text: str, param: str, redacted: str) -> str:
    """Clear the entire configured query-param value (``=`` or ``%3D`` / ``%3d``)."""
    if not param or not text:
        return text
    # Callable replacement avoids ``\\1`` + digit-leading redactions being parsed
    # as high backreference groups (e.g. redaction ``1234****3456``).
    return re.sub(
        rf"({re.escape(param)}(?:=|%3[Dd]))([^&\s#]*)",
        lambda match: match.group(1) + redacted,
        text,
    )


def _scrub_key_from_text(text: str, key: str | None) -> str:
    """Defensive scrub: replace verbatim API key occurrences in arbitrary text.

    Used as a last-resort filter on error messages and stack traces that may
    have captured the bearer token via HTTP client internals.
    """
    if not key or not text:
        return text or ""
    return _scrub_secret_regex(text, key, redact_api_key(key))


def sanitize_provider_error(
    text: str,
    *,
    api_key: str | None,
    query_param_name: str | None = None,
) -> str:
    """Single provider-boundary sanitizer for secrets in exception / URL text.

    Scrubs the exact secret and percent-encoded forms (``%HH`` hex is matched
    case-insensitively; unencoded text stays case-sensitive), plus named
    query-param assignments such as ``key=<secret>`` without assuming an
    ``sk-`` prefix.
    """
    if not text:
        return ""
    cleaned = text
    redacted = redact_api_key(api_key) if api_key else "***"
    if api_key:
        cleaned = _scrub_secret_regex(cleaned, api_key, redacted)
        for prefix in ("Bearer ", "bearer "):
            bearer_pat = re.compile(
                rf"{re.escape(prefix)}{_percent_insensitive_pattern(api_key).pattern}"
            )
            cleaned = bearer_pat.sub(f"{prefix}{redacted}", cleaned)
    param = (query_param_name or "").strip()
    if param and api_key:
        cleaned = _scrub_query_param_assignments(cleaned, param, redacted)
    return cleaned


# ---------------------------------------------------------------------------
# Capability heuristics
# ---------------------------------------------------------------------------

# Model-id substrings that strongly imply each capability. Kept conservative —
# the registry layer is allowed to be over-cautious (defaults to False on
# unknown). Callers may override with provider-side hints.
_THINKING_HINTS = (
    "thinking",
    "reasoner",
    "reasoning",
    "-r1",
    "/r1",
    "r1-",
    "o1",
    "o3",
    "o4",
    "qwq",
    "deepseek-r",
)
_VISION_HINTS = (
    "vision",
    "-vl",
    "vl-",
    "multimodal",
    "llava",
    "claude-3",
    "claude-sonnet",
    "claude-haiku",
    "claude-opus",
    "gpt-4o",
    "gpt-4.1",
    "gpt-5",
    "gemini",
    "qwen-vl",
)
# Models known NOT to support tool-calling — narrow list of common exceptions.
_NO_TOOLS_HINTS = (
    "embed",
    "embedding",
    "rerank",
    "moderation",
    "whisper",
    "tts",
)


def infer_capabilities_from_id(model_id: str) -> dict[str, bool]:
    """Best-effort capability inference from a model identifier.

    Returns a partial dict of capability flags. Callers should treat any key
    not in the returned dict as "unknown — keep current value or default".
    """
    if not model_id:
        return {}
    mid = model_id.lower()
    out: dict[str, bool] = {}

    if any(h in mid for h in _THINKING_HINTS):
        out["supports_thinking"] = True
        # R1 / reasoner family historically does not expose tools.
        if any(h in mid for h in ("reasoner", "-r1", "/r1", "r1-", "qwq")):
            out["supports_tools"] = False

    if any(h in mid for h in _VISION_HINTS):
        out["supports_vision"] = True

    if any(h in mid for h in _NO_TOOLS_HINTS):
        out["supports_tools"] = False

    return out


# ---------------------------------------------------------------------------
# Probe result
# ---------------------------------------------------------------------------


@dataclass
class ProbeResult:
    """Outcome of a single provider/API-key probe.

    ``ok`` is True only when the endpoint accepted the key AND returned a
    non-empty model list. ``status`` is the HTTP status (0 on transport-level
    failures). ``error`` is a human-readable message with any verbatim key
    replaced by the redacted form.
    """

    ok: bool
    status: int
    latency_ms: float
    models: list[ModelConfig] = field(default_factory=list)
    error: str = ""
    transport: str = "openai"
    base_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "latency_ms": round(self.latency_ms, 2),
            "transport": self.transport,
            "base_url": self.base_url,
            "models": [m.model_dump(mode="json") for m in self.models],
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Probe entrypoint
# ---------------------------------------------------------------------------


def _detect_transport(base_url: str, explicit: str | None) -> str:
    """Pick an API protocol based on the base_url shape.

    Default is ``openai`` (covers /v1, /compatible-mode/v1, /api/v3 Ark, etc.).
    Anthropic native API lives under ``api.anthropic.com``; everything else
    that mentions ``anthropic`` in the host also routes to native.
    """
    if explicit and explicit in ("openai", "anthropic"):
        return explicit
    if not base_url:
        return "openai"
    host = (urlparse(base_url).hostname or "").lower()
    if "anthropic" in host:
        return "anthropic"
    return "openai"


async def probe_provider(
    base_url: str,
    api_key: str | None,
    *,
    transport: str | None = None,
    timeout: float = 15.0,
    allow_private: bool = False,
) -> ProbeResult:
    """Verify an API key against ``base_url`` and pull its model catalog.

    This is intentionally NOT a SDK call — it goes through ``httpx`` so we can
    apply ``js.security.net_guard`` SSRF policy and pin the resolved IP.

    OpenAI-compatible providers (default): GET ``{base_url}/models`` with
    ``Authorization: Bearer <key>``. Volcano Ark, DeepSeek, DashScope, etc.
    all match this shape.

    Anthropic native: GET ``{base_url}/models`` (or ``/v1/models``) with
    ``x-api-key`` + ``anthropic-version``. Response is
    ``{"data": [{"id": ..., "display_name": ..., "type": "model"}]}``.
    Anthropic's API does NOT expose context_window in /models — we fall back
    to preset / heuristic for those values.
    """
    import httpx

    from js.security.net_guard import OutboundURLError, PinnedTransport, resolve_and_validate

    start = time.perf_counter()
    transport_kind = _detect_transport(base_url, transport)

    if not base_url:
        return ProbeResult(
            ok=False,
            status=0,
            latency_ms=0.0,
            error="base_url is required",
            transport=transport_kind,
        )

    # SSRF / private-IP / metadata-IP guard (mirror provider_manager.discover_models).
    hostname = (urlparse(base_url).hostname or "").lower()
    is_local_literal = hostname in ("localhost", "127.0.0.1", "::1")
    try:
        validated_ips = resolve_and_validate(
            base_url,
            allow_loopback=is_local_literal,
            allow_private=allow_private,
        )
    except OutboundURLError as exc:
        return ProbeResult(
            ok=False,
            status=0,
            latency_ms=(time.perf_counter() - start) * 1000,
            error=f"address rejected by policy: {exc}",
            transport=transport_kind,
            base_url=base_url,
        )

    if transport_kind == "anthropic":
        headers = {
            "x-api-key": api_key or "",
            "anthropic-version": "2023-06-01",
        }
        # Anthropic root is https://api.anthropic.com/v1, but callers sometimes
        # pass the bare host. Normalise to .../v1/models.
        normalised = base_url.rstrip("/")
        if not normalised.endswith("/v1") and "/v1/" not in normalised + "/":
            normalised = f"{normalised}/v1"
        url = f"{normalised}/models"
    else:
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        url = f"{base_url.rstrip('/')}/models"

    try:
        async with httpx.AsyncClient(
            transport=PinnedTransport(validated_ips[0], verify=True),
            timeout=timeout,
            trust_env=False,
        ) as client:
            resp = await client.get(url, headers=headers)
            latency_ms = (time.perf_counter() - start) * 1000

            if resp.status_code == 401 or resp.status_code == 403:
                return ProbeResult(
                    ok=False,
                    status=resp.status_code,
                    latency_ms=latency_ms,
                    error="API key rejected by provider (authentication failed)",
                    transport=transport_kind,
                    base_url=base_url,
                )
            if resp.status_code >= 400:
                # Body may include the verbatim key in echoes; scrub.
                body = _scrub_key_from_text(resp.text[:500], api_key)
                return ProbeResult(
                    ok=False,
                    status=resp.status_code,
                    latency_ms=latency_ms,
                    error=f"HTTP {resp.status_code}: {body}",
                    transport=transport_kind,
                    base_url=base_url,
                )

            data = resp.json()
            models = _parse_models_response(data, transport_kind)
            now = time.time()
            for m in models:
                m.probed_at = now

            return ProbeResult(
                ok=bool(models),
                status=resp.status_code,
                latency_ms=latency_ms,
                models=models,
                error="" if models else "endpoint accepted key but returned no models",
                transport=transport_kind,
                base_url=base_url,
            )
    except httpx.ConnectError as exc:
        return ProbeResult(
            ok=False,
            status=0,
            latency_ms=(time.perf_counter() - start) * 1000,
            error=_scrub_key_from_text(f"connect failed: {exc}", api_key),
            transport=transport_kind,
            base_url=base_url,
        )
    except httpx.TimeoutException:
        return ProbeResult(
            ok=False,
            status=0,
            latency_ms=(time.perf_counter() - start) * 1000,
            error="probe timed out",
            transport=transport_kind,
            base_url=base_url,
        )
    except Exception as exc:
        return ProbeResult(
            ok=False,
            status=0,
            latency_ms=(time.perf_counter() - start) * 1000,
            error=_scrub_key_from_text(f"probe failed: {exc}", api_key),
            transport=transport_kind,
            base_url=base_url,
        )


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def _parse_models_response(data: Any, transport: str) -> list[ModelConfig]:
    """Build ModelConfig list from a provider's /models response payload."""
    if not isinstance(data, dict):
        return []

    raw_models = data.get("data") or data.get("models") or []
    if not isinstance(raw_models, list):
        return []

    out: list[ModelConfig] = []
    for raw in raw_models:
        if isinstance(raw, str):
            cfg = _build_config_from_id(raw, transport)
            if cfg is not None:
                out.append(cfg)
            continue
        if not isinstance(raw, dict):
            continue

        model_id = raw.get("id") or raw.get("model") or raw.get("name")
        if not isinstance(model_id, str) or not model_id:
            continue

        # Context window priority:
        #   1) API-provided field (api)
        #   2) caller-supplied preset (handled by callers, not here)
        #   3) heuristic from model id (fallback)
        api_ctx = (
            raw.get("context_length") or raw.get("max_context_length") or raw.get("context_window")
        )
        if api_ctx:
            try:
                ctx = int(api_ctx)
                ctx_source: str = "api"
            except (TypeError, ValueError):
                ctx = _infer_context_window(model_id)
                ctx_source = "heuristic"
        else:
            ctx = _infer_context_window(model_id)
            ctx_source = "heuristic"

        api_max_out = (
            raw.get("max_output_tokens") or raw.get("max_tokens") or raw.get("output_token_limit")
        )
        max_out: int | None
        if api_max_out:
            try:
                max_out = int(api_max_out)
            except (TypeError, ValueError):
                max_out = None
        else:
            max_out = None

        cfg = ModelConfig(
            id=model_id,
            name=str(raw.get("display_name") or raw.get("name") or model_id),
            context_window=ctx,
            max_tokens=min(max_out or (ctx // 4), 32768) if ctx > 0 else 4096,
            max_output_tokens=max_out,
            context_source=ctx_source,
            supports_tools=True,
            supports_streaming=True,
        )
        # Capability hints from id (vision / thinking / reasoner-no-tools).
        for k, v in infer_capabilities_from_id(model_id).items():
            setattr(cfg, k, v)
        out.append(cfg)

    return out


def _build_config_from_id(model_id: str, transport: str) -> ModelConfig | None:
    """Helper: build a default ModelConfig for a bare id (no metadata)."""
    if not model_id:
        return None
    ctx = _infer_context_window(model_id)
    cfg = ModelConfig(
        id=model_id,
        name=model_id,
        context_window=ctx,
        max_tokens=min(ctx // 4, 8192) if ctx > 0 else 4096,
        context_source="heuristic",
    )
    for k, v in infer_capabilities_from_id(model_id).items():
        setattr(cfg, k, v)
    return cfg


def _infer_context_window(model_id: str) -> int:
    """Thin re-export of ``LocalModelDiscovery._infer_context_window``.

    Imported lazily to avoid a circular import via ``js.models.__init__``.
    """
    from js.models.discovery import LocalModelDiscovery

    return LocalModelDiscovery._infer_context_window(model_id)


__all__ = [
    "ProbeResult",
    "SafeProviderError",
    "infer_capabilities_from_id",
    "probe_provider",
    "raise_safe_provider_error",
    "redact_api_key",
    "reraise_safe_provider_error",
    "safe_provider_error",
    "sanitize_provider_error",
]
