import json
import os
from pathlib import Path
import socket
import time
from unittest.mock import MagicMock, patch

import pytest

import manter_sast as launcher


def supervisor(tmp_path, **options):
    return launcher.Supervisor(18991, tmp_path / "history", runtime=tmp_path / "runtime", **options)


def test_health_rejects_wrong_service_and_gateway_error():
    response = MagicMock()
    response.__enter__.return_value.read.return_value = b'{"service":"another","status":"healthy"}'
    with patch.object(launcher.urllib.request, "urlopen", return_value=response):
        assert not launcher.healthy("http://127.0.0.1:18991")
    with patch.object(launcher.urllib.request, "urlopen", side_effect=OSError("HTTP 502")):
        assert not launcher.healthy("http://127.0.0.1:18991")


def test_gateway_failure_does_not_restart_healthy_api(tmp_path):
    service = supervisor(tmp_path, cloudflare=True, public_url="https://test-link.trycloudflare.com")
    with (patch.object(launcher, "healthy", side_effect=lambda url: url == service.address),
          patch.object(launcher, "ollama_ready", return_value=True), patch.object(service, "spawn") as spawn):
        service.tick()
    spawn.assert_not_called()
    assert service.api_status == "healthy"
    assert service.tunnel_status == "reconnecting"
    assert service.public_failures == 1


def test_healthy_existing_services_are_adopted_without_spawn(tmp_path):
    service = supervisor(tmp_path)
    with (patch.object(launcher, "healthy", return_value=True),
          patch.object(launcher, "ollama_ready", return_value=True), patch.object(service, "spawn") as spawn):
        service.tick()
    spawn.assert_not_called()
    assert service.children == {}
    state = launcher.read_state(service.runtime)
    assert state["api"] == "healthy"
    assert state["data_dir"] == str(service.data_dir)


def test_an_unresponsive_unowned_listener_is_never_killed(tmp_path):
    service = supervisor(tmp_path)
    with (patch.object(launcher, "healthy", return_value=False), patch.object(launcher, "port_free", return_value=False),
          patch.object(service, "spawn") as spawn, patch.object(service, "stop_child") as stop):
        for _ in range(10):
            service.ensure_api()
    spawn.assert_not_called()
    stop.assert_not_called()
    assert service.api_status == "unresponsive"


def test_missing_api_starts_on_same_port_with_same_database(tmp_path):
    service = supervisor(tmp_path)
    with (patch.object(launcher, "healthy", return_value=False), patch.object(launcher, "port_free", return_value=True),
          patch.object(service, "spawn", return_value=True) as spawn):
        service.ensure_api()
    args, kwargs = spawn.call_args
    assert args[0] == "api"
    assert args[1][-2:] == ["--port", "18991"]
    assert kwargs["env"]["SAST_DATA_DIR"] == str(service.data_dir)


def test_exit_of_owned_api_is_recovered(tmp_path):
    service = supervisor(tmp_path)
    child = MagicMock()
    child.poll.return_value = 1
    service.children["api"] = child
    with (patch.object(launcher, "healthy", return_value=False), patch.object(launcher, "port_free", return_value=True),
          patch.object(service, "spawn", return_value=True) as spawn):
        service.ensure_api()
    spawn.assert_called_once()
    child.terminate.assert_not_called()


def test_shutdown_terminates_only_owned_children(tmp_path):
    service = supervisor(tmp_path)
    child = MagicMock()
    child.poll.return_value = None
    service.children["api"] = child
    service.close()
    child.terminate.assert_called_once()


def test_lock_prevents_duplicate_supervisors_and_releases(tmp_path):
    first = launcher.InstanceLock(tmp_path)
    assert first.acquire()
    second = launcher.InstanceLock(tmp_path)
    assert not second.acquire()
    first.close()
    third = launcher.InstanceLock(tmp_path)
    assert third.acquire()
    third.close()


def test_url_parsing_never_uses_arbitrary_log_urls():
    assert launcher.PUBLIC_URL.findall("http://evil.test https://a-b.trycloudflare.com/dashboard") == ["https://a-b.trycloudflare.com"]
    assert not launcher.PUBLIC_URL.fullmatch("https://test.trycloudflare.com.evil.test")


def test_new_tunnel_url_is_saved(tmp_path):
    service = supervisor(tmp_path, cloudflare=True)
    child = MagicMock()
    child.poll.return_value = None
    service.children["tunnel"] = child
    service.tunnel_log.write_text("Your tunnel: https://fresh-link.trycloudflare.com", encoding="utf-8")
    service.api_status = "healthy"
    with patch.object(launcher, "healthy", return_value=True):
        service.ensure_tunnel()
    assert service.public_url == "https://fresh-link.trycloudflare.com"
    assert service.tunnel_status == "healthy"


def test_repeated_gateway_failure_replaces_tunnel_without_touching_api(tmp_path):
    service = supervisor(tmp_path, cloudflare=True, public_url="https://old-link.trycloudflare.com")
    service.api_status = "healthy"
    with (patch.object(launcher, "healthy", return_value=False), patch.object(service, "stop_child") as stop,
          patch.object(service, "start_tunnel") as start):
        for _ in range(6):
            service.next_public_check = 0
            service.ensure_tunnel()
    stop.assert_called_once_with("tunnel")
    start.assert_called_once()


def test_atomic_state_contains_operational_details_only(tmp_path):
    launcher.write_state(tmp_path, {"port": 8001, "public_url": "https://fresh-link.trycloudflare.com"})
    assert json.loads((tmp_path / "state.json").read_text()) == launcher.read_state(tmp_path)
    assert not (tmp_path / "state.tmp").exists()


@pytest.mark.skipif(os.getenv("SAST_TEST_SUPERVISOR") != "1", reason="opt-in real process recovery")
def test_real_api_process_recovers_on_same_port_and_data_directory(tmp_path, monkeypatch):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    monkeypatch.setenv("SAST_ENGINES", "native")
    service = launcher.Supervisor(port, tmp_path / "history", runtime=tmp_path / "runtime")

    def wait_healthy():
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            if launcher.healthy(service.address):
                return
            time.sleep(0.4)
        pytest.fail("API de teste não respondeu; veja " + str(service.runtime / "api.log"))

    try:
        service.ensure_api()
        original = service.children["api"]
        wait_healthy()
        payload = json.dumps({"code": "const value = 1;", "filename": "recovery.js", "project_name": "Recovery regression"}).encode()
        request = launcher.urllib.request.Request(service.address + "/api/v1/scan/code", data=payload, headers={"Content-Type": "application/json"})
        with launcher.urllib.request.urlopen(request, timeout=10) as response:
            saved_scan = json.load(response)
        original.terminate()
        original.wait(timeout=10)
        service.next_start["api"] = 0
        service.ensure_api()
        replacement = service.children["api"]
        assert replacement.pid != original.pid
        wait_healthy()
        service.ensure_api()
        assert service.api_status == "healthy"
        assert service.data_dir == (tmp_path / "history").resolve()
        assert (service.data_dir / "scans.sqlite3").exists()
        with launcher.urllib.request.urlopen(service.address + "/api/v1/scans/" + saved_scan["scan_id"], timeout=5) as response:
            assert json.load(response)["scan_id"] == saved_scan["scan_id"]
    finally:
        service.close()
