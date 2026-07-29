from __future__ import annotations

from pathlib import Path

from scripts import echo_smoke


def test_echo_smoke_exercises_only_echo_on(monkeypatch, tmp_path, capsys) -> None:
    calls: list[tuple[str, str, Path]] = []

    def _record_api(mode: str, base: Path) -> None:
        calls.append(("api", mode, base))

    def _record_ws(mode: str, base: Path) -> None:
        calls.append(("ws", mode, base))

    monkeypatch.setattr(echo_smoke, "_check_api_chat", _record_api)
    monkeypatch.setattr(echo_smoke, "_check_ws_ping", _record_ws)

    echo_smoke.run_smoke()

    assert [(kind, mode) for kind, mode, _base in calls] == [
        ("api", "on"),
        ("ws", "on"),
    ]
    output = capsys.readouterr().out
    assert "off" not in output
    assert "shadow" not in output
