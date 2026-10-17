import json
from argparse import Namespace
from fastapi.testclient import TestClient

from api.main import app
from api.store import ScanStore
from cli import cmd_scan
from engine.engine import SASTEngine

client = TestClient(app)


def scan(code='eval(user_input)', filename="src/service.py", **options):
    response = client.post("/api/v1/scan/code", json={"code": code, "filename": filename, **options})
    assert response.status_code == 200
    return response.json()


def test_saved_scan_can_be_reopened_with_source(tmp_path, monkeypatch):
    store = ScanStore(tmp_path / "persistent.sqlite3")
    monkeypatch.setattr("api.main.scan_store", store)
    result = scan(project_name="Projeto persistente")
    # Recriar o repositório de dados simula a reabertura do servidor.
    monkeypatch.setattr("api.main.scan_store", ScanStore(store.path))
    saved = client.get(f"/api/v1/scans/{result['scan_id']}").json()
    assert saved == result
    source = client.get(f"/api/v1/scans/{result['scan_id']}/source", params={"path": "src/service.py"})
    assert source.json()["content"] == "eval(user_input)"
    history = client.get("/api/v1/scans").json()["items"]
    assert history[0]["project_name"] == "Projeto persistente"
    assert history[0]["findings"] == []  # resumo, sem transferir todos os achados
    assert history[0]["files"][0]["path"] == "src/service.py"


def test_reports_are_bound_to_selected_scan():
    vulnerable = scan()
    safe = scan("answer = 42", "safe.py")
    first = client.get(f"/api/v1/scans/{vulnerable['scan_id']}/report?format=sarif").json()
    second = client.get(f"/api/v1/scans/{safe['scan_id']}/report?format=sarif").json()
    assert len(first["runs"][0]["results"]) == 1
    assert first["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/service.py"
    assert second["runs"][0]["results"] == []
    assert client.get("/api/v1/report/sarif").json()["runs"][0]["results"] == []
    markdown = client.get(f"/api/v1/scans/{vulnerable['scan_id']}/report?format=markdown")
    assert vulnerable["scan_id"] in markdown.text
    assert "attachment;" in markdown.headers["content-disposition"]


def test_parser_error_prevents_gate_approval():
    result = scan("def invalid(:", "invalid.py")
    assert result["scanned_files_count"] == 0
    assert result["total_findings"] == 0
    assert result["security_gate"]["status"] == "error"
    assert result["files"][0]["status"] == "error"
    report = client.get(f"/api/v1/scans/{result['scan_id']}/report?format=sarif").json()
    assert report["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_gate_uses_selected_threshold():
    critical_only = scan('password = "hardcoded-secret-value"', gate_threshold="CRITICAL")
    high_or_more = scan('password = "hardcoded-secret-value"', gate_threshold="HIGH")
    assert critical_only["security_gate"]["status"] == "passed"
    assert high_or_more["security_gate"]["status"] == "blocked"


def test_project_backend_ignores_dependencies_and_preserves_nested_paths():
    files = [
        ("files", ("project/node_modules/lib/test.js", b"eval(userInput)", "text/plain")),
        ("files", ("project/README.md", b"# Example", "text/plain")),
        ("files", ("project/src/main.py", b"answer = 42", "text/plain")),
    ]
    response = client.post("/api/v1/scan/project", files=files, data={"project_name": "Projeto limpo"})
    assert response.status_code == 200
    result = response.json()
    assert result["scanned_files_count"] == 1
    assert result["ignored_files_count"] == 2
    assert result["files"][0]["path"] == "project/src/main.py"
    assert result["security_gate"]["status"] == "passed"


def test_invalid_upload_does_not_create_history():
    assert client.post("/api/v1/scan/file", files={"file": ("empty.py", b"", "text/plain")}).status_code == 400
    assert client.post("/api/v1/scan/file", files={"file": ("binary.py", b"\x00\x01", "text/plain")}).status_code == 400
    duplicate = [("files", ("a.py", b"answer=1", "text/plain")), ("files", ("a.py", b"answer=2", "text/plain"))]
    assert client.post("/api/v1/scan/project", files=duplicate).status_code == 400
    assert client.get("/api/v1/scans").json()["items"] == []


def test_history_source_cannot_read_arbitrary_disk_file():
    result = scan()
    assert client.get(f"/api/v1/scans/{result['scan_id']}/source", params={"path": "../../README.md"}).status_code == 404
    assert client.get("/api/v1/scans/unknown").status_code == 404
    assert client.get("/api/v1/report/sarif?scan_id=unknown").status_code == 404


def test_cli_errors_return_two_and_json_with_ai_stays_valid(tmp_path, monkeypatch):
    source = tmp_path / "broken.py"
    output = tmp_path / "report.json"
    source.write_text("def broken(:", encoding="utf-8")
    args = Namespace(path=str(source), no_recursive=False, format="json", no_color=True, output=str(output), ai=False, fail_on="HIGH")
    assert cmd_scan(args) == 2
    source.write_text("eval(user_input)", encoding="utf-8")
    monkeypatch.setattr("engine.ai_remediation.AIRemediationEngine.is_ollama_available", lambda self: False)
    args.ai = True
    assert cmd_scan(args) == 1
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["ai_remediations"][0]["provider"] == "heuristic"
    assert document["security_gate"]["status"] == "blocked"


def test_ai_status_and_capabilities_are_exposed(monkeypatch):
    status = {"service_available": True, "model_available": False, "model_loaded": False, "model": "missing", "status": "model_missing"}
    monkeypatch.setattr("api.main.ai_engine.get_status", lambda: status)
    assert client.get("/api/v1/ai/status").json() == status
    capability = client.get("/api/v1/capabilities").json()
    assert capability["limits"]["project_files"] == 200
    assert ".tsx" in capability["extensions"]


def test_directory_without_sources_is_incomplete(tmp_path):
    result = SASTEngine().scan_directory(str(tmp_path))
    assert result.has_errors is True
    assert result.scanned_files_count == 0


def test_ollama_service_without_configured_model_is_not_ready(monkeypatch):
    from engine.ai_remediation import AIRemediationEngine

    class FakeResponse:
        status_code = 200
        def json(self):
            return {"models": [{"name": "another-model:latest"}]}

    class FakeClient:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def get(self, url): return FakeResponse()

    monkeypatch.setattr("engine.ai_remediation.httpx.Client", FakeClient)
    status = AIRemediationEngine().get_status()
    assert status["service_available"] is True
    assert status["model_available"] is False
    assert status["status"] == "model_missing"


def test_remediation_diff_uses_original_file_context(monkeypatch):
    monkeypatch.setattr("api.main.ai_engine.is_ollama_available", lambda: False)
    result = scan("def process(user_input):\n    eval(user_input)\n", "src/process.py")
    finding = result["findings"][0]
    response = client.post("/api/v1/remediate", json={**finding, "scan_id": result["scan_id"]})
    assert response.status_code == 200
    remediation = response.json()
    assert remediation["provider"] == "heuristic"
    assert "--- a/src/process.py" in remediation["diff"]
    assert "-    eval(user_input)" in remediation["diff"]
    assert "+    import ast" in remediation["diff"]
    assert "+    ast.literal_eval(user_input)" in remediation["diff"]
    assert remediation["diff"].endswith("\n")
    foreign = {**finding, "line_number": 999, "scan_id": result["scan_id"]}
    assert client.post("/api/v1/remediate", json=foreign).status_code == 400
