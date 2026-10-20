import json

import iniciar
from scripts.smoke import discover_base_url, select_ai_smoke_finding


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


def test_ai_smoke_selects_native_finding_ahead_of_optional_scanner_alerts():
    bandit = {"rule_id": "BANDIT-B307"}
    native = {"rule_id": "PY-R001"}

    assert select_ai_smoke_finding({"findings": [bandit, native]}) is native


def test_ai_smoke_falls_back_to_available_finding_when_native_rule_is_absent():
    finding = {"rule_id": "BANDIT-B307"}

    assert select_ai_smoke_finding({"findings": [finding]}) is finding
    assert select_ai_smoke_finding({"findings": []}) is None
