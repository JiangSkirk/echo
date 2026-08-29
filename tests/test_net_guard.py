"""Regression tests for outbound URL safety, Host/Origin checks, the cancel
route de-duplication, and WebBridge token handling.

These prove the SSRF canaries (127.1, 2130706433, *.nip.io rebinding, cloud
metadata) cannot reach internal services and that the previously-shadowed
owner-checked cancel route is the only one registered.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import httpx
import pytest

from js.security.net_guard import OutboundURLError, resolve_and_validate


def _fixed_resolver(mapping: dict[str, list[str]]):
    """Build a deterministic resolver that ignores the real DNS."""

    def _resolve(host: str, port: int | None) -> list[str]:
        if host in mapping:
            return mapping[host]
        raise OutboundURLError(f"unmapped host {host!r}")

    return _resolve


# ---------------------------------------------------------------------------
# SSRF canaries
# ---------------------------------------------------------------------------


class TestSSRFCanaries:
    @pytest.mark.parametrize("url", ["http://127.1/", "http://2130706433/", "http://0x7f000001/"])
    def test_numeric_loopback_forms_blocked(self, url: str) -> None:
        """Numeric/short loopback forms resolve to 127.0.0.1 and are blocked."""
        with pytest.raises(OutboundURLError):
            resolve_and_validate(url, allow_loopback=False, allow_private=False)

    def test_nip_io_loopback_rebinding_blocked(self) -> None:
        resolver = _fixed_resolver({"127.0.0.1.nip.io": ["127.0.0.1"]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate("http://127.0.0.1.nip.io/", resolver=resolver)

    def test_nip_io_metadata_rebinding_blocked(self) -> None:
        resolver = _fixed_resolver({"169.254.169.254.nip.io": ["169.254.169.254"]})
        with pytest.raises(OutboundURLError):
            # Even with the most permissive policy, link-local/metadata is blocked.
            resolve_and_validate(
                "http://169.254.169.254.nip.io/",
                allow_loopback=True,
                allow_private=True,
                resolver=resolver,
            )

    def test_cloud_metadata_always_blocked(self) -> None:
        resolver = _fixed_resolver({"metadata.example": ["169.254.169.254"]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate(
                "http://metadata.example/latest/meta-data/",
                allow_loopback=True,
                allow_private=True,
                resolver=resolver,
            )

    def test_cgnat_shared_address_space_blocked(self) -> None:
        """CGNAT 100.64.0.0/10 is neither private nor reserved; the non-global
        check must reject it even with both policy flags opted in."""
        resolver = _fixed_resolver({"cgnat.example": ["100.64.0.1"]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate("http://cgnat.example/", resolver=resolver)
        with pytest.raises(OutboundURLError):
            resolve_and_validate(
                "http://cgnat.example/",
                allow_loopback=True,
                allow_private=True,
                resolver=resolver,
            )

    def test_metadata_hostname_blocked_by_name(self) -> None:
        with pytest.raises(OutboundURLError):
            resolve_and_validate("http://metadata.google.internal/")

    def test_non_http_scheme_blocked(self) -> None:
        with pytest.raises(OutboundURLError):
            resolve_and_validate("ftp://example.com/")
        with pytest.raises(OutboundURLError):
            resolve_and_validate("file:///etc/passwd")

    def test_dns_rebinding_mixed_answer_fails_closed(self) -> None:
        """If a host resolves to both a public and an internal IP, reject all."""
        resolver = _fixed_resolver({"evil.example": ["93.184.216.34", "10.0.0.5"]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate("http://evil.example/", resolver=resolver)

    def test_public_host_allowed(self) -> None:
        resolver = _fixed_resolver({"example.com": ["93.184.216.34"]})
        ips = resolve_and_validate("https://example.com/", resolver=resolver)
        assert ips == ["93.184.216.34"]


# ---------------------------------------------------------------------------
# discover_models policy
# ---------------------------------------------------------------------------


class TestDiscoverPolicy:
    def test_loopback_allowed_for_local_models(self) -> None:
        ips = resolve_and_validate(
            "http://127.0.0.1:1234/v1", allow_loopback=True, allow_private=False
        )
        assert ips == ["127.0.0.1"]

    def test_private_blocked_by_default(self) -> None:
        resolver = _fixed_resolver({"gpu.lan": ["192.168.1.50"]})
        with pytest.raises(OutboundURLError):
            resolve_and_validate(
                "http://gpu.lan:1234/v1",
                allow_loopback=True,
                allow_private=False,
                resolver=resolver,
            )

    def test_private_allowed_when_opted_in(self) -> None:
        resolver = _fixed_resolver({"gpu.lan": ["192.168.1.50"]})
        ips = resolve_and_validate(
            "http://gpu.lan:1234/v1", allow_loopback=True, allow_private=True, resolver=resolver
        )
        assert ips == ["192.168.1.50"]

    @pytest.mark.asyncio
    async def test_discover_models_rejects_metadata(self) -> None:
        from js.models.provider_manager import ProviderManager

        result = await ProviderManager.discover_models(
            "http://169.254.169.254/latest/", allow_private=True
        )
        assert "error" in result
        assert "拒绝" in result["error"]

    # --- Real canaries: default policy must reject DNS-rebinding to loopback ---
    # These call discover_models for real.  A blocked URL never reaches httpx, so
    # the error is always the policy message ("安全策略") — never a connection
    # error — whether the rebinding domain resolves (online) or not (offline).

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target_url",
        [
            "http://127.0.0.1.nip.io/v1",  # domain resolving to loopback
            "http://127.1/v1",  # short-form loopback
            "http://2130706433/v1",  # decimal-encoded loopback
            "http://169.254.169.254.nip.io/v1",  # domain resolving to metadata
        ],
    )
    async def test_discover_models_rejects_rebinding_canaries(self, target_url: str) -> None:
        from js.models.provider_manager import ProviderManager

        result = await ProviderManager.discover_models(target_url)
        assert "error" in result, f"{target_url} should be rejected"
        assert "models" not in result
        assert "安全策略" in result["error"], (
            f"{target_url} must be blocked by policy, not connection"
        )

    @pytest.mark.asyncio
    async def test_discover_models_allows_local_literal(self) -> None:
        """Literal 127.0.0.1 clears the guard (fails only at connection)."""
        from js.models.provider_manager import ProviderManager

        result = await ProviderManager.discover_models("http://127.0.0.1:1/v1")
        assert "error" in result  # nothing listening on port 1
        assert "安全策略" not in result["error"]  # but NOT a policy rejection


# ---------------------------------------------------------------------------
# Host / Origin checks
# ---------------------------------------------------------------------------


class _FakeHeaders:
    def __init__(self, data: dict[str, str]) -> None:
        self._data = {k.lower(): v for k, v in data.items()}

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._data.get(key.lower(), default)


class _FakeRequest:
    def __init__(self, headers: dict[str, str], method: str = "POST") -> None:
        self.headers = _FakeHeaders(headers)
        self.method = method


class TestOriginCheck:
    def setup_method(self) -> None:
        import js.web.auth as auth

        auth._ALLOWED_ORIGINS = None  # reset env cache
        os.environ.pop("JS_ALLOWED_ORIGINS", None)

    def test_same_origin_allowed_dynamic_port(self) -> None:
        from js.web.auth import check_origin

        req = _FakeRequest({"host": "localhost:9999", "origin": "http://localhost:9999"})
        check_origin(req)  # should not raise

    def test_cross_origin_rejected(self) -> None:
        from fastapi import HTTPException

        from js.web.auth import check_origin

        req = _FakeRequest({"host": "localhost:8000", "origin": "http://evil.com"})
        with pytest.raises(HTTPException) as exc:
            check_origin(req)
        assert exc.value.status_code == 403

    def test_unrecognized_host_rejected(self) -> None:
        from fastapi import HTTPException

        from js.web.auth import check_origin

        req = _FakeRequest({"host": "attacker.com", "origin": "http://attacker.com"})
        with pytest.raises(HTTPException):
            check_origin(req)

    def test_no_origin_requires_api_key(self) -> None:
        from fastapi import HTTPException

        from js.web.auth import check_origin

        with pytest.raises(HTTPException) as exc:
            check_origin(_FakeRequest({"host": "localhost:8000"}))
        assert exc.value.status_code == 403
        # A present but unverified key must not skip Origin (CSRF).
        with pytest.raises(HTTPException) as exc:
            check_origin(_FakeRequest({"host": "localhost:8000", "x-api-key": "k"}))
        assert exc.value.status_code == 403

    def test_referer_with_path_normalized(self) -> None:
        from js.web.auth import check_origin

        req = _FakeRequest(
            {"host": "127.0.0.1:8000", "referer": "http://127.0.0.1:8000/app/index.html"}
        )
        check_origin(req)  # should not raise

    @pytest.mark.asyncio
    async def test_require_admin_get_skips_origin(self) -> None:
        from js.web.auth import require_admin

        # GET with a cross-origin header must NOT be rejected (safe method).
        req = _FakeRequest({"host": "localhost", "origin": "http://evil.com"}, method="GET")
        ctx = await require_admin(req, {"role": "admin"})
        assert ctx["role"] == "admin"

    @pytest.mark.asyncio
    async def test_require_admin_post_enforces_origin(self) -> None:
        from fastapi import HTTPException

        from js.web.auth import require_admin

        req = _FakeRequest({"host": "localhost", "origin": "http://evil.com"}, method="POST")
        with pytest.raises(HTTPException):
            await require_admin(req, {"role": "admin"})


# ---------------------------------------------------------------------------
# Cancel route de-duplication
# ---------------------------------------------------------------------------


def test_cancel_route_not_in_system_router() -> None:
    """The owner-checked /api/cancel handler lives in server.py only.

    A duplicate in the system router would register first and silently shadow
    the owner_key_hash isolation, so it must not exist here.
    """
    from js.web.routers import system

    cancel_routes = [
        r for r in system.router.routes if getattr(r, "path", "") == "/api/cancel/{session_id}"
    ]
    assert cancel_routes == []


# ---------------------------------------------------------------------------
# WebBridge token
# ---------------------------------------------------------------------------


class TestWebBridgeToken:
    def setup_method(self) -> None:
        os.environ.pop("JS_WEBRIDGE_TOKEN", None)

    def test_token_generated_and_persisted_0600(self, tmp_path: Path) -> None:
        from js.tools.webbridge import WebBridgeTool

        tool = WebBridgeTool(state_dir=tmp_path)
        token_file = tmp_path / "webbridge_token"
        assert token_file.exists()
        assert tool._token == token_file.read_text().strip()
        assert len(tool._token) >= 20
        mode = stat.S_IMODE(token_file.stat().st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_token_never_falls_back_to_old_fixed_value(self, tmp_path: Path) -> None:
        from js.tools.webbridge import WebBridgeTool

        tool = WebBridgeTool(state_dir=tmp_path)
        assert tool._token != "js-agent-webbridge-v1"

    def test_token_stable_across_instances(self, tmp_path: Path) -> None:
        from js.tools.webbridge import WebBridgeTool

        t1 = WebBridgeTool(state_dir=tmp_path)
        t2 = WebBridgeTool(state_dir=tmp_path)
        assert t1._token == t2._token

    def test_env_override_takes_precedence(self, tmp_path: Path) -> None:
        from js.tools.webbridge import WebBridgeTool

        os.environ["JS_WEBRIDGE_TOKEN"] = "shared-explicit-token"
        try:
            tool = WebBridgeTool(state_dir=tmp_path)
            assert tool._token == "shared-explicit-token"
        finally:
            os.environ.pop("JS_WEBRIDGE_TOKEN", None)

    def test_auth_rejection_detection(self, tmp_path: Path) -> None:
        from js.tools.webbridge import WebBridgeTool

        tool = WebBridgeTool(state_dir=tmp_path)
        req = httpx.Request("POST", "http://127.0.0.1:10086/command")
        assert tool._is_auth_rejection(httpx.Response(401, request=req)) is True
        assert tool._is_auth_rejection(httpx.Response(403, request=req)) is True
        assert (
            tool._is_auth_rejection(
                httpx.Response(200, json={"ok": False, "error": "invalid token"}, request=req)
            )
            is True
        )
        assert tool._is_auth_rejection(httpx.Response(200, json={"ok": True}, request=req)) is False

    @pytest.mark.asyncio
    async def test_token_mismatch_disables_calls(self, tmp_path: Path) -> None:
        from js.tools.webbridge import WebBridgeTool

        tool = WebBridgeTool(state_dir=tmp_path)
        tool._token_mismatch = True
        with pytest.raises(RuntimeError):
            await tool._call("list_tabs", {})
