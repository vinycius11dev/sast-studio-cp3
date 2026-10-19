import urllib.error
from unittest.mock import patch

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
    ]
    with patch("iniciar.urllib.request.urlopen", side_effect=responses):
        assert iniciar.existing_server_status("http://127.0.0.1:8000") == "ready"


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
