"""Frontend sanity tests: verify static assets, module integrity, and window mounts."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from js.web.server import create_app


@pytest.fixture
def client() -> TestClient:
    """Build a TestClient with a fully-mocked agent."""
    from unittest.mock import AsyncMock, MagicMock

    from js.web import server as web_server
    from js.web.deps import set_globals

    mock_agent = MagicMock()
    mock_agent.settings.workspace = Path("/tmp")
    mock_agent.settings.state_dir = Path("/tmp")
    mock_agent.settings.max_turns = 10
    mock_agent.settings.default_model = "test/model"
    mock_agent.settings.security.api_key_required = False
    mock_agent.registry.get_stats.return_value = {}
    mock_agent.secrets.get_stats.return_value = {"stored_secrets": 0, "detected_leaks": 0}
    mock_agent.metacognition = MagicMock()
    mock_agent.learner = MagicMock()
    mock_agent.optimizer = MagicMock()
    mock_agent._run_evolution_cycle = AsyncMock(return_value={"ok": True})
    mock_agent.skills = MagicMock()
    mock_agent.router = MagicMock()
    mock_agent.memory = MagicMock()
    mock_agent.memory.get_context_string.return_value = ""
    mock_agent.memory.get_episodes.return_value = []
    mock_agent.memory.get_dream_logs.return_value = []
    mock_agent.memory.get_all_semantic.return_value = []
    mock_agent.memory.get_all_working.return_value = []
    mock_agent.memory.list_memory_files.return_value = []
    mock_agent.memory.get_sessions.return_value = []
    mock_agent.memory.cleanup_empty_sessions.return_value = 0
    mock_agent.memory.embedder.health.return_value = MagicMock(
        provider="test", active=True, fallback_provider=None, failure_count=0
    )

    web_server._agent = mock_agent
    web_server._settings = mock_agent.settings
    set_globals(mock_agent, mock_agent.settings)
    app = create_app()
    return TestClient(app)


class TestStaticAssets:
    """Verify all static JS modules are accessible."""

    STATIC_FILES = [
        "app.js",
        "state/store.js",
        "utils/dom.js",
        "utils/markdown.js",
        "tabs/agents.js",
        "tabs/approvals.js",
        "tabs/audit.js",
        "tabs/cron.js",
        "tabs/dashboard.js",
        "tabs/evolution.js",
        "tabs/files.js",
        "tabs/memory.js",
        "tabs/models.js",
        "tabs/search.js",
        "tabs/skills.js",
        "tabs/stats.js",
        "tabs/status.js",
    ]

    @pytest.mark.parametrize("path", STATIC_FILES)
    def test_js_module_accessible(self, client: TestClient, path: str) -> None:
        res = client.get(f"/static/{path}")
        assert res.status_code == 200, f"Static file {path} not accessible"
        assert "javascript" in res.headers.get("content-type", "") or path.endswith(".js")

    def test_default_chat_stream_keeps_tools_enabled(self, client: TestClient) -> None:
        app_js = client.get("/static/app.js").text

        assert "enable_tools: true" in app_js

    @pytest.mark.parametrize(
        "path",
        [
            "vendor/tailwind.css",
            "vendor/fontawesome/css/all.min.css",
            "vendor/fontawesome/webfonts/fa-solid-900.woff2",
        ],
    )
    def test_local_ui_asset_is_packaged_and_served(
        self, client: TestClient, path: str
    ) -> None:
        response = client.get(f"/static/{path}")

        assert response.status_code == 200
        assert response.content

    def test_stream_errors_clear_transient_ui_state(self, client: TestClient) -> None:
        app_js = client.get("/static/app.js").text

        assert "function abortStream()" in app_js
        assert "data.type === 'stream_diagnostic'" in app_js
        assert "abortStream();\n      appendMessage('system', '流式通道错误:" not in app_js
        assert "data.type === 'error'" in app_js
        assert "abortStream();\n      appendMessage('system', '错误:" in app_js

    def test_echo_approval_ui_uses_safe_rendering_and_validates_decisions(
        self, client: TestClient
    ) -> None:
        approvals_js = client.get("/static/tabs/approvals.js").text

        assert "'/api/echo/approvals'" in approvals_js
        assert "/api/echo/approvals/${encodeURIComponent(requestId)}/decision" in approvals_js
        assert "JSON.parse" in approvals_js
        assert "edited_arguments must be a JSON object" in approvals_js
        assert "response must not be empty" in approvals_js
        assert "startApprovalsPolling" in approvals_js
        assert "stopApprovalsPolling" in approvals_js
        assert ".textContent" in approvals_js
        assert ".innerHTML" not in approvals_js


class TestHtmlIntegrity:
    """Verify HTML references valid functions and modules."""

    def test_index_html_references_valid_functions(self, client: TestClient) -> None:
        """All onclick handlers must have corresponding JS functions mounted to window."""
        res = client.get("/")
        assert res.status_code == 200
        html = res.text

        # Extract all onclick handlers
        handlers = set()
        for m in re.finditer(r'onclick=["\']([^"\']+)["\']', html):
            func_name = m.group(1).split("(")[0].strip()
            if func_name != "document.getElementById":  # inline JS, not a global func
                handlers.add(func_name)

        # Parse app.js for all functions mounted to window
        app_js = client.get("/static/app.js").text

        # Get all imported names
        declared = set()
        for m in re.finditer(r'import\s*\{([^}]+)\}\s*from', app_js):
            for part in m.group(1).split(","):
                part = part.strip()
                if not part:
                    continue
                if " as " in part:
                    name = part.split(" as ")[-1].strip()
                else:
                    name = part.strip()
                declared.add(name)
        for m in re.finditer(r'import\s+(\w+)\s+from', app_js):
            declared.add(m.group(1))
        for m in re.finditer(r'(?:async\s+)?function\s+(\w+)', app_js):
            declared.add(m.group(1))
        for m in re.finditer(r'(?:let|const|var)\s+(\w+)', app_js):
            declared.add(m.group(1))

        # Get _windowFuncs entries
        wf_match = re.search(r'const _windowFuncs = \{([^}]+)\};', app_js, re.DOTALL)
        assert wf_match, "_windowFuncs not found in app.js"
        window_funcs = set()
        for m in re.finditer(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', wf_match.group(1)):
            window_funcs.add(m.group())
        # Remove non-function keywords
        window_funcs -= {
            "state", "const", "let", "var", "function", "async", "await",
            "return", "if", "else", "for", "while", "true", "false", "null", "undefined",
        }

        # Every window func must be declared
        missing_in_app = window_funcs - declared
        assert not missing_in_app, f"Functions in _windowFuncs but not declared: {missing_in_app}"

        # Every HTML handler must be in window funcs
        missing_handlers = handlers - window_funcs
        assert not missing_handlers, f"HTML onclick handlers without window mount: {missing_handlers}"

    def test_no_duplicate_window_func_entries(self, client: TestClient) -> None:
        """_windowFuncs should not have duplicate keys."""
        app_js = client.get("/static/app.js").text
        wf_match = re.search(r'const _windowFuncs = \{([^}]+)\};', app_js, re.DOTALL)
        assert wf_match
        entries = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[,}]', wf_match.group(1))
        duplicates = {k for k in entries if entries.count(k) > 1}
        assert not duplicates, f"Duplicate entries in _windowFuncs: {duplicates}"


class TestModuleSyntax:
    """Verify JS module syntax with Node.js."""

    def test_app_js_syntax(self) -> None:
        import subprocess

        app_path = Path(__file__).parent.parent / "js" / "web" / "static" / "app.js"
        result = subprocess.run(
            ["node", "-c", str(app_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"app.js syntax error: {result.stderr}"

    @pytest.mark.parametrize(
        "module",
        [
            "tabs/memory.js",
            "tabs/agents.js",
            "tabs/approvals.js",
            "tabs/audit.js",
            "tabs/cron.js",
            "tabs/dashboard.js",
            "tabs/evolution.js",
            "tabs/files.js",
            "tabs/models.js",
            "tabs/search.js",
            "tabs/skills.js",
            "tabs/stats.js",
            "tabs/status.js",
            "utils/dom.js",
            "utils/markdown.js",
            "state/store.js",
        ],
    )
    def test_module_syntax(self, module: str) -> None:
        import subprocess

        mod_path = Path(__file__).parent.parent / "js" / "web" / "static" / module
        result = subprocess.run(
            ["node", "-c", str(mod_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"{module} syntax error: {result.stderr}"


class TestIndexHtml:
    """Basic checks on the index template."""

    def test_sidebar_toggle_present(self, client: TestClient) -> None:
        res = client.get("/")
        assert res.status_code == 200
        assert 'onclick="toggleSidebar()"' in res.text

    def test_app_js_loaded_as_module(self, client: TestClient) -> None:
        res = client.get("/")
        assert res.status_code == 200
        assert '<script type="module" src="/static/app.js?v=4"></script>' in res.text

    def test_browser_assets_are_local_and_csp_disallows_public_cdns(
        self, client: TestClient
    ) -> None:
        html = client.get("/").text

        assert 'href="/static/vendor/tailwind.css"' in html
        assert 'href="/static/vendor/fontawesome/css/all.min.css"' in html
        assert "cdn.tailwindcss.com" not in html
        assert "cdnjs.cloudflare.com" not in html
        assert "script-src 'self' 'unsafe-inline'" in html
        assert "font-src 'self'" in html

    def test_echo_approvals_navigation_and_container_are_present(
        self, client: TestClient
    ) -> None:
        html = client.get("/").text
        app_js = client.get("/static/app.js").text

        assert 'id="nav-approvals"' in html
        assert "switchTab('approvals')" in html
        assert 'id="approvals-pending-count"' in html
        assert 'id="tab-approvals"' in html
        assert 'id="approvals-list"' in html
        assert "from './tabs/approvals.js'" in app_js
        assert "if (tab === 'approvals') loadApprovals();" in app_js
