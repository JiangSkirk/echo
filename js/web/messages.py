"""User-facing Chinese presentation strings.

Pure presentation layer. The agent *core* keeps its status/error wording in
English (tests assert on values like ``"Run cancelled by user request"`` and
``"All providers unhealthy"``, and those must stay stable). This module maps
that English into friendly Chinese shown to factory-floor employees.

Rules:
- Never import agent state or mutate anything here — input strings only.
- Match on robust keyword buckets, not exact phrases, so core wording can
  change without silently falling back to the generic message.
"""

from __future__ import annotations

_GENERIC_ERROR = (
    "处理你的请求时出错了，请稍后重试；如果反复出现，请联系管理员查看服务器日志。"
)


def humanize_error(error_message: str | None) -> str:
    """Translate a core (English) error_message into a friendly Chinese line.

    Empty / unknown input returns a safe generic Chinese message — we never
    surface a raw Python exception or English string to the employee.
    """
    if not error_message:
        return _GENERIC_ERROR
    low = error_message.lower()

    if "cancel" in low:
        return "已取消本次请求。"
    if any(k in low for k in ("empty response", "maximum retries", "max retries")):
        return "模型多次没有返回有效内容，可能是服务繁忙，请稍后重试。"
    if any(k in low for k in ("rate limit", "ratelimit", "quota", "429", "too many")):
        return "请求过于频繁或额度已用尽，请稍后再试。"
    if any(k in low for k in ("unauthor", "401", "403", "forbidden", "api key", "apikey", "invalid key")):
        return "模型服务认证失败，请到「设置」检查 API Key 是否正确。"
    if any(k in low for k in ("timeout", "timed out", "connection", "connect", "network", "unreachable", "refused", "dns")):
        return "连接模型服务失败，请检查网络连接后重试。"
    if any(k in low for k in ("unhealthy", "no provider", "no healthy", "no model")):
        return "当前没有可用的模型服务，请检查模型配置或网络。"
    return _GENERIC_ERROR


def health_summary(*, degraded: bool, providers_configured: bool) -> dict[str, str]:
    """Compute a factory-friendly overall health verdict for ``/api/status``.

    Presentation only — derived from the agent's ``degraded`` flag and whether
    any provider/model is configured. Deliberately does NOT read the English
    ``degraded_reason`` text, so the core wording can change freely.

    Returns a dict with ``overall_status`` (``ok`` | ``degraded`` |
    ``no_provider``), a Chinese ``overall_status_text``, and a Chinese
    ``suggestion`` (empty when healthy).
    """
    if not providers_configured:
        return {
            "overall_status": "no_provider",
            "overall_status_text": "尚未配置可用模型",
            "suggestion": "请在「设置」里添加模型服务商（如 DeepSeek）的 API Key 后重试。",
        }
    if degraded:
        return {
            "overall_status": "degraded",
            "overall_status_text": "模型服务暂时不可用，正在降级运行",
            "suggestion": "请检查网络连接或模型服务商状态，恢复后会自动可用。",
        }
    return {
        "overall_status": "ok",
        "overall_status_text": "运行正常",
        "suggestion": "",
    }
