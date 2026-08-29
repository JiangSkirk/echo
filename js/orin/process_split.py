"""AppShell/Echo process-split observations.

The default product host still serves AppShell and Echo in one process.
These helpers exist so the §6.1 checker can name the missing bits instead of
pretending the split shipped. Provider tokens stay out of Echo only when
``orin.enforce`` is actually observed; that conjunction is still incomplete.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Final

_AUTHORITY_ENV_KEYS: Final[frozenset[str]] = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "DASHSCOPE_API_KEY",
        "DEEPSEEK_API_KEY",
        "GOOGLE_API_KEY",
        "MOONSHOT_API_KEY",
        "OPENAI_API_KEY",
        "ORIN_OWNER_PRIVATE_KEY",
        "ORIN_OWNER_WITNESS_KEY",
        "SILICONFLOW_API_KEY",
        "TELEGRAM_BOT_TOKEN",
        "VOLCANO_API_KEY",
    }
)
_AUTHORITY_ENV_FRAGMENTS: Final[tuple[str, ...]] = (
    "API_KEY",
    "OWNER_PRIVATE",
    "OWNER_WITNESS",
    "PROVIDER_TOKEN",
    "SECRET",
    "TOKEN",
)


_appshell_echo_separated = False
_provider_tokens_out_of_echo = False


def reset_process_split_observations() -> None:
    """Test helper. Default product observations stay false."""

    global _appshell_echo_separated, _provider_tokens_out_of_echo
    _appshell_echo_separated = False
    _provider_tokens_out_of_echo = False


def mark_appshell_echo_separated(value: bool) -> None:
    """Observe a live product split. Call only after a worker is actually spawned."""

    global _appshell_echo_separated
    _appshell_echo_separated = bool(value)


def mark_provider_tokens_out_of_echo(value: bool) -> None:
    """Observe Cell-backed model transport with no Echo-held tokens."""

    global _provider_tokens_out_of_echo
    _provider_tokens_out_of_echo = bool(value)


def production_appshell_echo_separated() -> bool:
    """True only when the product host no longer imports Echo in-process."""

    return bool(_appshell_echo_separated)


def provider_tokens_out_of_echo() -> bool:
    """True only when model credentials live in Secret/Net Cell, not Echo."""

    return bool(_provider_tokens_out_of_echo)


def strip_authority_from_env(env: Mapping[str, str]) -> dict[str, str]:
    """Drop owner keys and provider tokens from a worker environment."""

    cleaned: dict[str, str] = {}
    for key, value in env.items():
        upper = key.upper()
        if upper in _AUTHORITY_ENV_KEYS:
            continue
        if any(fragment in upper for fragment in _AUTHORITY_ENV_FRAGMENTS):
            continue
        cleaned[key] = value
    return cleaned


def current_process_holds_authority_env() -> bool:
    return bool(os.environ.keys() - strip_authority_from_env(os.environ).keys())


__all__ = [
    "current_process_holds_authority_env",
    "mark_appshell_echo_separated",
    "mark_provider_tokens_out_of_echo",
    "production_appshell_echo_separated",
    "provider_tokens_out_of_echo",
    "reset_process_split_observations",
    "strip_authority_from_env",
]
