from pathlib import Path
from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient

from api import main
from api.store import ScanStore


@pytest.mark.parametrize(
    "variant,folder,total,gate",
    [("vulneravel", "01-vulneravel", 9, "blocked"), ("corrigido", "02-corrigido", 0, "passed")],
)
def test_ready_demo_projects_can_be_loaded_and_scanned(tmp_path, monkeypatch, variant, folder, total, gate):
    monkeypatch.setattr(main, "scan_store", ScanStore(tmp_path / "demo.sqlite3"))
    with TestClient(main.app) as client:
        response = client.get("/api/v1/samples", params={"variant": variant})
        assert response.status_code == 200
        data = response.json()
        assert len(data["files"]) == 3
        assert {file["language"] for file in data["files"]} == {"python", "javascript", "java"}
        assert all(file["path"].startswith(folder + "/") for file in data["files"])
        files = [("files", (file["path"], file["content"].encode("utf-8"), "text/plain")) for file in data["files"]]
        response = client.post("/api/v1/scan/project", files=files, data={"project_name": data["project_name"], "gate_threshold": "HIGH"})
        assert response.status_code == 200
        scan = response.json()
        assert scan["scanned_files_count"] == 3
        assert scan["total_findings"] == total
        assert scan["security_gate"]["status"] == gate
        assert scan["errors"] == []


def test_demo_variant_rejects_unknown_directory():
    with TestClient(main.app) as client:
        assert client.get("/api/v1/samples", params={"variant": "../data"}).status_code == 422


def test_file_pickers_are_native_inputs_inside_labels():
    class PickerParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.label = None
            self.inputs = {}

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "label":
                self.label = attrs.get("id")
            elif tag == "input" and attrs.get("type") == "file":
                self.inputs[attrs["id"]] = (self.label, attrs)

        def handle_endtag(self, tag):
            if tag == "label":
                self.label = None

    source = Path(__file__).resolve().parents[1] / "static" / "index.html"
    page = PickerParser()
    page.feed(source.read_text(encoding="utf-8"))
    for kind in ("file", "folder"):
        label, picker = page.inputs[f"{kind}-upload"]
        assert label == f"choose-{kind}"
        assert "hidden" not in picker
    assert "webkitdirectory" in page.inputs["folder-upload"][1]
