"""Whitelist-only gateway push templates."""

from __future__ import annotations

import pytest

from js.cron.templates import get_template
from js.gateway.push import PushTemplateError, render_push_template


def test_allowlisted_templates_render() -> None:
    assert "daily brief" in render_push_template("daily_brief").lower()
    assert "health" in render_push_template("health_ok").lower()


def test_unknown_template_is_rejected() -> None:
    with pytest.raises(PushTemplateError, match="not allowlisted"):
        render_push_template("freeform-model-text")


def test_cron_template_is_gateway_push() -> None:
    template = get_template("gateway_daily_brief")
    assert template is not None
    assert template.task_type == "gateway_push"
    assert template.default_payload["template"] == "daily_brief"
