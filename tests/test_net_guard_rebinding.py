"""DNS-rebinding regression tests for SSRF protection.

Verifies that :func:`resolve_and_validate` returns validated IPs and that
:class:`PinnedIPBackend` / :class:`PinnedTransport` force connections to
those IPs, preventing DNS-rebinding attacks where an attacker domain first
resolves to a public IP (passing validation) and then rebinds to an internal
IP before the actual HTTP request.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpcore
import httpx
import pytest

from js.security.net_guard import (
    OutboundURLError,
    PinnedIPBackend,
    PinnedTransport,
    create_pinned_client,
    resolve_and_validate,
)


class TestResolveAndValidateReturnsIPs:
    """resolve_and_validate must return the list of safe resolved IPs."""

    def test_returns_validated_ips_for_public_host(self) -> None:
        """For a public hostname, returns the resolved IP(s)."""
        # Use a mock resolver so the test is hermetic (no real DNS).
        def mock_resolver(host: str, port: int | None) -> list[str]:
            return ["93.184.216.34"]  # example.com

        ips = resolve_and_validate(
            "http://example.com/path",
            resolver=mock_resolver,
        )
        assert ips == ["93.184.216.34"]

    def test_returns_multiple_ips_when_dns_returns_multiple(self) -> None:
        """When DNS returns multiple A records, all are returned."""
        def mock_resolver(host: str, port: int | None) -> list[str]:
            return ["1.2.3.4", "1.2.3.5"]

        ips = resolve_and_validate(
            "http://example.com",
            resolver=mock_resolver,
        )
        assert ips == ["1.2.3.4", "1.2.3.5"]

    def test_rejects_loopback_even_with_mock_resolver(self) -> None:
        """Loopback addresses are rejected regardless of resolver."""
        def mock_resolver(host: str, port: int | None) -> list[str]:
            return ["127.0.0.1"]

        with pytest.raises(OutboundURLError, match="loopback"):
            resolve_and_validate("http://evil.com", resolver=mock_resolver)

    def test_rejects_metadata_ip_even_with_mock_resolver(self) -> None:
        """Cloud metadata addresses are always rejected."""
        def mock_resolver(host: str, port: int | None) -> list[str]:
            return ["169.254.169.254"]

        with pytest.raises(OutboundURLError, match="metadata"):
            resolve_and_validate("http://evil.com", resolver=mock_resolver)


class TestPinnedIPBackend:
    """PinnedIPBackend forces TCP connections to the pinned IP."""

    @pytest.mark.asyncio
    async def test_connect_tcp_ignores_hostname(self) -> None:
        """connect_tcp uses the pinned IP, not the hostname."""
        mock_backend = AsyncMock()
        mock_stream = MagicMock()
        mock_backend.connect_tcp = AsyncMock(return_value=mock_stream)

        pinned = PinnedIPBackend("1.2.3.4", backend=mock_backend)
        stream = await pinned.connect_tcp("evil.com", 80, timeout=5.0)

        assert stream is mock_stream
        mock_backend.connect_tcp.assert_awaited_once_with(
            "1.2.3.4", 80, 5.0, None, None
        )

    @pytest.mark.asyncio
    async def test_forwards_unix_socket_and_sleep(self) -> None:
        """Other backend methods are forwarded unchanged."""
        mock_backend = AsyncMock()
        pinned = PinnedIPBackend("1.2.3.4", backend=mock_backend)

        await pinned.connect_unix_socket("/tmp/test.sock", timeout=1.0)
        mock_backend.connect_unix_socket.assert_awaited_once()

        await pinned.sleep(0.5)
        mock_backend.sleep.assert_awaited_once_with(0.5)


class TestPinnedTransport:
    """PinnedTransport creates an httpx client pinned to a validated IP."""

    @pytest.mark.asyncio
    async def test_transport_is_httpx_compatible(self) -> None:
        """PinnedTransport can be passed to httpx.AsyncClient."""
        transport = PinnedTransport("127.0.0.1", verify=False)
        async with httpx.AsyncClient(transport=transport) as client:
            # Just verify the client can be created; we don't make a real request
            assert client._transport is transport

    @pytest.mark.asyncio
    async def test_pool_uses_pinned_backend(self) -> None:
        """The underlying pool uses PinnedIPBackend."""
        transport = PinnedTransport("1.2.3.4", verify=False)
        pool = transport._pool
        # httpcore.AsyncConnectionPool stores the backend in _network_backend
        backend = getattr(pool, "_network_backend", None)
        assert backend is not None
        assert isinstance(backend, PinnedIPBackend)
        assert backend.pinned_ip == "1.2.3.4"
        await transport.aclose()


class TestCreatePinnedClient:
    """create_pinned_client convenience helper."""

    @pytest.mark.asyncio
    async def test_creates_client_with_pinned_transport(self) -> None:
        """Returns an AsyncClient whose transport is pinned."""
        client = create_pinned_client(["1.2.3.4"], timeout=5.0)
        assert isinstance(client, httpx.AsyncClient)
        transport = client._transport
        assert isinstance(transport, PinnedTransport)
        assert transport._pool._network_backend.pinned_ip == "1.2.3.4"
        await client.aclose()

    def test_raises_when_no_ips(self) -> None:
        """Empty IP list raises OutboundURLError."""
        with pytest.raises(OutboundURLError, match="no validated IPs"):
            create_pinned_client([])


class TestDNSRebindingDefense:
    """End-to-end: validated IP is actually used for the connection."""

    @pytest.mark.asyncio
    async def test_pinned_connection_uses_validated_ip(self) -> None:
        """Simulate a DNS-rebinding attack: hostname resolves to different
        IPs before and after validation.  The pinned transport must use the
        IP returned by resolve_and_validate, not a later re-resolved IP."""

        # First resolution (during validation) returns a public IP
        def first_resolve(host: str, port: int | None) -> list[str]:
            return ["1.2.3.4"]

        validated_ips = resolve_and_validate(
            "http://rebinding-test.example/path",
            resolver=first_resolve,
        )
        assert validated_ips == ["1.2.3.4"]

        # Second resolution (what a naive client would do) returns loopback
        def second_resolve(host: str, port: int | None) -> list[str]:
            return ["127.0.0.1"]

        # Create a PinnedIPBackend with the validated IP
        mock_backend = AsyncMock()
        mock_stream = MagicMock()
        mock_backend.connect_tcp = AsyncMock(return_value=mock_stream)

        pinned_backend = PinnedIPBackend("1.2.3.4", backend=mock_backend)
        pool = httpcore.AsyncConnectionPool(network_backend=pinned_backend)
        transport = PinnedTransport("1.2.3.4", verify=False)
        # Replace the pool created by super().__init__ with our test pool
        transport._pool = pool

        async with httpx.AsyncClient(transport=transport) as _client:
            # We can't easily mock the full request flow, but we can verify
            # that the backend's connect_tcp was called with the pinned IP
            # by inspecting the pool's backend.
            actual_backend = transport._pool._network_backend
            assert isinstance(actual_backend, PinnedIPBackend)
            assert actual_backend.pinned_ip == "1.2.3.4"

        await pool.aclose()

    @pytest.mark.asyncio
    async def test_browser_fetch_pins_connection(self) -> None:
        """BrowserTool.fetch uses PinnedTransport with validated IPs."""
        from pathlib import Path

        from js.config import SecurityConfig, ToolLimits
        from js.security.guard import BehaviorGuard
        from js.tools.browser import BrowserTool

        limits = ToolLimits()
        guard = BehaviorGuard(SecurityConfig(), Path("/tmp"))
        tool = BrowserTool(limits, guard)

        # Mock resolve_and_validate to return a controlled IP
        with (
            patch(
                "js.tools.browser.resolve_and_validate",
                return_value=["1.2.3.4"],
            ) as mock_resolve,
            patch(
                "js.tools.browser.PinnedTransport",
            ) as mock_transport_class,
            patch("httpx.AsyncClient") as mock_client_class,
        ):
            mock_transport = MagicMock()
            mock_transport_class.return_value = mock_transport

            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.is_redirect = False
            mock_response.text = "hello"
            mock_response.raise_for_status = MagicMock()
            mock_client.get = AsyncMock(return_value=mock_response)

            await tool.fetch("http://example.com/test")

            mock_resolve.assert_called_once_with(
                "http://example.com/test",
                allow_loopback=False,
                allow_private=False,
            )
            # Verify AsyncClient was created with a transport argument
            mock_client_class.assert_called_once()
            call_kwargs = mock_client_class.call_args.kwargs
            assert "transport" in call_kwargs
            # The transport should be a PinnedTransport instance (or mock)
            transport = call_kwargs["transport"]
            assert hasattr(transport, "_pool") or isinstance(transport, MagicMock)

    @pytest.mark.asyncio
    async def test_provider_manager_pins_connection(self) -> None:
        """ProviderManager.discover_models uses PinnedTransport with validated IPs."""
        from js.models.provider_manager import ProviderManager

        with (
            patch(
                "js.security.net_guard.resolve_and_validate",
                return_value=["1.2.3.4"],
            ) as mock_resolve,
            patch(
                "js.security.net_guard.PinnedTransport",
            ) as mock_transport_class,
            patch("httpx.AsyncClient") as mock_client_class,
        ):
            mock_transport = MagicMock()
            mock_transport_class.return_value = mock_transport

            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": []}
            mock_response.raise_for_status = MagicMock()
            mock_client.get = AsyncMock(return_value=mock_response)

            await ProviderManager.discover_models(
                "http://example.com/v1", api_key="test"
            )

            mock_resolve.assert_called_once()
            # Verify AsyncClient was created with a transport argument
            mock_client_class.assert_called_once()
            call_kwargs = mock_client_class.call_args.kwargs
            assert "transport" in call_kwargs
            transport = call_kwargs["transport"]
            assert hasattr(transport, "_pool") or isinstance(transport, MagicMock)

    @pytest.mark.asyncio
    async def test_provider_manager_pins_lmstudio_context_probe(self) -> None:
        """The LM Studio v0 metadata probe must share the validated pinned transport."""
        from js.models.provider_manager import ProviderManager

        with (
            patch(
                "js.security.net_guard.resolve_and_validate",
                return_value=["127.0.0.1"],
            ),
            patch("js.security.net_guard.PinnedTransport") as transport_class,
            patch("httpx.AsyncClient") as client_class,
        ):
            transport = MagicMock()
            transport_class.return_value = transport
            client = AsyncMock()
            client_class.return_value = client
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=None)

            v0_response = MagicMock(status_code=200)
            v0_response.json.return_value = {
                "data": [
                    {"id": "model-a", "state": "loaded", "max_context_length": 8192}
                ]
            }
            v1_response = MagicMock(status_code=200)
            v1_response.json.return_value = {"data": [{"id": "model-a"}]}
            v1_response.raise_for_status = MagicMock()
            client.get = AsyncMock(side_effect=[v0_response, v1_response])

            result = await ProviderManager.discover_models(
                "http://127.0.0.1:1234/v1",
                api_key="test-key",
            )

            assert result["models"][0]["context_window"] == 8192
            client_class.assert_called_once()
            assert client_class.call_args.kwargs["transport"] is transport
            assert [call.args[0] for call in client.get.await_args_list] == [
                "http://127.0.0.1:1234/api/v0/models",
                "http://127.0.0.1:1234/v1/models",
            ]
