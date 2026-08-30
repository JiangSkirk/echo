"""SECURITY.md must exist and match live configuration defaults."""

from __future__ import annotations

from pathlib import Path

from js.config import GatewayConfig, JSSettings, OrinConfig, OrinPolicyProfile

ROOT = Path(__file__).resolve().parents[1]
SECURITY_ZH = ROOT / "SECURITY.md"
SECURITY_EN = ROOT / "SECURITY_en.md"

_REQUIRED_ZH = (
    "## 1. 报告漏洞",
    "## 2. 信任模型",
    "承重边界",
    "每工具 OS 沙箱",
    "整进程容器",
    "orin.enforce",
    "friends_enabled",
    "mobile_enabled",
    "gateway.enabled",
    "strict_isolation",
    "## 3. 范围",
    "## 2.5 供应链姿态",
    "uv.lock",
    "constraints.txt",
    "not_implemented",
    "compat",
    "计划控制流",
)

_REQUIRED_EN = (
    "## 1. Reporting a Vulnerability",
    "## 2. Trust Model",
    "load-bearing",
    "Per-tool OS sandbox",
    "Whole-process container",
    "orin.enforce",
    "friends_enabled",
    "mobile_enabled",
    "gateway.enabled",
    "strict_isolation",
    "## 3. Scope",
    "## 2.5 Supply Chain",
    "uv.lock",
    "constraints.txt",
    "not_implemented",
    "compat",
    "control flow",
)


def test_security_policy_files_exist() -> None:
    assert SECURITY_ZH.is_file()
    assert SECURITY_EN.is_file()


def test_security_policy_required_sections() -> None:
    zh = SECURITY_ZH.read_text(encoding="utf-8")
    en = SECURITY_EN.read_text(encoding="utf-8")
    missing_zh = [item for item in _REQUIRED_ZH if item not in zh]
    missing_en = [item for item in _REQUIRED_EN if item not in en]
    assert missing_zh == [], missing_zh
    assert missing_en == [], missing_en


def test_security_policy_matches_config_defaults() -> None:
    assert OrinConfig.model_fields["enabled"].default is False
    assert OrinConfig.model_fields["enforce"].default is False
    assert JSSettings.model_fields["friends_enabled"].default is False
    assert JSSettings.model_fields["mobile_enabled"].default is False
    assert JSSettings.model_fields["remote_collaboration_enabled"].default is False
    assert JSSettings.model_fields["gateway"].default_factory is GatewayConfig
    assert GatewayConfig.model_fields["enabled"].default is False
    assert OrinConfig.model_fields["policy_profile"].default is OrinPolicyProfile.CONSERVATIVE

    for path in (SECURITY_ZH, SECURITY_EN):
        text = path.read_text(encoding="utf-8")
        assert "orin.enabled" in text
        assert "orin.enforce" in text
        assert "false" in text.lower()
        assert "friends_enabled" in text
        assert "mobile_enabled" in text
        assert "gateway.enabled" in text
        assert "strict_isolation=True" in text
