import json

import iniciar
from scripts.smoke import discover_base_url


def test_discover_base_url_prefers_active_instance_over_saved_port(tmp_path, monkeypatch):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"port": 8001}), encoding="utf-8")
    monkeypatch.setattr(iniciar, "find_current_server", lambda: 8003)

    assert discover_base_url(state) == "http://127.0.0.1:8003"


def test_discover_base_url_uses_saved_valid_port_when_server_is_down(tmp_path, monkeypatch):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"port": 8012}), encoding="utf-8")
    monkeypatch.setattr(iniciar, "find_current_server", lambda: None)

    assert discover_base_url(state) == "http://127.0.0.1:8012"


def test_discover_base_url_ignores_invalid_state_and_uses_default(tmp_path, monkeypatch):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"port": True}), encoding="utf-8")
    monkeypatch.setattr(iniciar, "find_current_server", lambda: None)

    assert discover_base_url(state) == "http://127.0.0.1:8000"
