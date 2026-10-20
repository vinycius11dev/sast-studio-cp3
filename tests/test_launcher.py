import urllib.error
from unittest.mock import MagicMock, patch

import iniciar


class FakeResponse:
    def __init__(self, body=b"", status=200):
        self.body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, *_args):
        return self.body


def test_launcher_accepts_current_server_with_presentation_page():
    responses = [
        FakeResponse(b'{"service":"sast-engine-api"}'),
        FakeResponse(status=200),
        FakeResponse(b'{"items":[{"engine":"native","version":"3.1.0"}]}'),
    ]
    with patch("iniciar.urllib.request.urlopen", side_effect=responses):
        assert iniciar.existing_server_status("http://127.0.0.1:8000") == "ready"


def test_launcher_does_not_reuse_pre_expansion_engine():
    responses = [FakeResponse(b'{"service":"sast-engine-api"}'), FakeResponse(status=200),
                 FakeResponse(b'{"items":[{"engine":"native","version":"3.0.0"}]}')]
    with patch("iniciar.urllib.request.urlopen", side_effect=responses):
        assert iniciar.existing_server_status("http://127.0.0.1:8000") == "stale"


def test_launcher_detects_old_sast_server_without_presentation_page():
    responses = [
        FakeResponse(b'{"service":"sast-engine-api"}'),
        urllib.error.HTTPError(
            "http://127.0.0.1:8000/apresentacao", 404, "Not Found", {}, None
        ),
    ]
    with patch("iniciar.urllib.request.urlopen", side_effect=responses):
        assert iniciar.existing_server_status("http://127.0.0.1:8000") == "stale"


def test_launcher_does_not_claim_an_unrelated_service_is_sast():
    with patch(
        "iniciar.urllib.request.urlopen",
        return_value=FakeResponse(b'{"service":"another-api"}'),
    ):
        assert iniciar.existing_server_status("http://127.0.0.1:8000") == "other"


def test_launcher_finds_current_server_on_fallback_port():
    connection = MagicMock()
    connection.connect_ex.side_effect = lambda address: 0 if address[1] == 8004 else 1
    socket_context = MagicMock()
    socket_context.__enter__.return_value = connection
    with (
        patch("iniciar.socket.socket", return_value=socket_context),
        patch(
            "iniciar.existing_server_status",
            side_effect=lambda address: "ready" if address.endswith(":8004") else "stale",
        ),
    ):
        assert iniciar.find_current_server(8001, 8005) == 8004


def test_launcher_uses_next_available_port_when_default_is_busy():
    connection = MagicMock()

    def bind(address):
        if address[1] == 8000:
            raise OSError("porta ocupada")

    connection.bind.side_effect = bind
    socket_context = MagicMock()
    socket_context.__enter__.return_value = connection
    with patch("iniciar.socket.socket", return_value=socket_context):
        assert iniciar.find_free_port(8000, 8002) == 8001
