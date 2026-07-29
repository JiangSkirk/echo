"""Fleet routing must preserve the owning Work web runtime."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient


def _write_work_config(path: Path) -> Path:
    config = path / "config.yaml"
    config.write_text(
        """
security:
  api_key_required: false
providers:
  - name: mock
    base_url: http://127.0.0.1:1/v1
    default_model: mock-model
    models:
      - id: mock-model
        name: Mock
        provider: mock
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return config


def test_work_fleet_status_uses_the_request_runtime_cache(monkeypatch: Any, tmp_path: Path) -> None:
    from js_work.web import create_work_web_app

    created: list[CapturingFleet] = []

    class CapturingFleet:
        def __init__(self, settings: Any) -> None:
            self.settings = settings
            created.append(self)

        def get_status(self) -> dict[str, str]:
            return {
                "state_dir": str(self.settings.state_dir),
                "workspace": str(self.settings.workspace),
            }

    def create_capturing_fleet(
        *,
        settings: Any,
        profile: Any,
        allow_host_code_tools: bool,
    ) -> CapturingFleet:
        del profile
        assert allow_host_code_tools is False
        return CapturingFleet(settings)

    monkeypatch.setattr("js_work.web.create_work_fleet", create_capturing_fleet)

    home_a = tmp_path / "app-a"
    home_b = tmp_path / "app-b"
    home_a.mkdir()
    home_b.mkdir()
    app_a = create_work_web_app(config=str(_write_work_config(home_a)), home=home_a)
    app_b = create_work_web_app(config=str(_write_work_config(home_b)), home=home_b)

    expected_a = {
        "state_dir": str(home_a / ".js-work" / "state"),
        "workspace": str(home_a / ".js-work" / "workspace"),
    }
    expected_b = {
        "state_dir": str(home_b / ".js-work" / "state"),
        "workspace": str(home_b / ".js-work" / "workspace"),
    }

    with TestClient(app_a) as client_a:
        assert created == []
        assert client_a.get("/api/fleet/status").json() == expected_a
        with TestClient(app_b) as client_b:
            assert len(created) == 1
            assert client_b.get("/api/fleet/status").json() == expected_b
            assert client_b.get("/api/fleet/status").json() == expected_b
        assert client_a.get("/api/fleet/status").json() == expected_a

    assert len(created) == 2
    assert created[0].settings.state_dir == home_a / ".js-work" / "state"
    assert created[1].settings.state_dir == home_b / ".js-work" / "state"


def test_work_web_runtime_uses_the_work_limited_fleet(tmp_path: Path) -> None:
    from js_work.web import create_work_web_app

    home = tmp_path / "work-app"
    home.mkdir()
    app = create_work_web_app(config=str(_write_work_config(home)), home=home)

    with TestClient(app) as client:
        assert client.get("/api/fleet/status").status_code == 200
        fleet = app.state.web_runtime.fleet

        assert fleet is not None
        assert fleet._inherit_skills is False
        assert fleet._skills_source is None
        assert fleet._worker_configurer is not None


def test_work_web_shutdown_is_safe_before_first_fleet_request(
    monkeypatch: Any, tmp_path: Path
) -> None:
    from js_work.web import create_work_web_app

    created: list[object] = []

    class CapturingFleet:
        async def close_all(self) -> None:
            return None

    def create_capturing_fleet(**_: Any) -> CapturingFleet:
        fleet = CapturingFleet()
        created.append(fleet)
        return fleet

    monkeypatch.setattr("js_work.web.create_work_fleet", create_capturing_fleet)

    home = tmp_path / "work-app"
    home.mkdir()
    app = create_work_web_app(config=str(_write_work_config(home)), home=home)

    with TestClient(app):
        assert created == []

    assert created == []


def test_runtime_creates_one_fleet_under_concurrent_first_access() -> None:
    from js.web.runtime_context import WebRuntime

    factory_entered = threading.Event()
    second_factory_entered = threading.Event()
    release_factory = threading.Event()
    created: list[object] = []

    def fleet_factory() -> object:
        fleet = object()
        created.append(fleet)
        factory_entered.set()
        if len(created) > 1:
            second_factory_entered.set()
        assert release_factory.wait(timeout=2)
        return fleet

    runtime = WebRuntime(agent=object(), settings=object(), fleet_factory=fleet_factory)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(runtime.get_or_create_fleet)
        assert factory_entered.wait(timeout=2)
        second = executor.submit(runtime.get_or_create_fleet)
        second_factory_entered.wait(timeout=0.1)
        release_factory.set()
        first_fleet = first.result(timeout=2)
        second_fleet = second.result(timeout=2)

    assert second_factory_entered.is_set() is False
    assert created == [first_fleet]
    assert second_fleet is first_fleet
