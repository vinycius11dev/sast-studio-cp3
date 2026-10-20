from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["active_rules"] >= 14


def test_presentation_inlines_screenshots_for_access_protected_tunnels():
    response = client.get("/apresentacao")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.text.count("src=\"data:image/png;base64,") == 5
    assert "/presentation-assets/" not in response.text


def test_list_rules_endpoint():
    response = client.get("/api/v1/rules")
    assert response.status_code == 200
    rules = response.json()
    assert len(rules) >= 14
    rule_ids = {r["rule_id"] for r in rules}
    assert "PY-R001" in rule_ids
    assert "JS-R001" in rule_ids
    assert "JAVA-R001" in rule_ids


def test_scan_code_endpoint_with_vulnerabilities():
    code = 'eval("1 + 1")\npassword = "test12345"\n'
    response = client.post(
        "/api/v1/scan/code",
        json={"code": code, "filename": "vulnerable.py"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_findings"] == 2
    assert data["summary_by_severity"]["CRITICAL"] == 1
    assert data["summary_by_severity"]["HIGH"] == 1


def test_scan_file_upload_endpoint():
    file_content = b'import os\nos.system("ping 127.0.0.1")\n'
    files = {"file": ("script.py", file_content, "text/x-python")}
    response = client.post("/api/v1/scan/file", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["total_findings"] == 1
    assert data["findings"][0]["rule_id"] == "PY-R003"


def test_scan_file_upload_rejects_non_py_extension():
    files = {"file": ("malicious.exe", b"test", "application/octet-stream")}
    response = client.post("/api/v1/scan/file", files=files)
    assert response.status_code == 400
    assert "não suportada" in response.json()["detail"]


def test_scan_project_upload_endpoint_preserves_relative_paths():
    files = [
        ("files", ("demo/src/vulnerable.py", b'eval("1 + 1")\n', "text/x-python")),
        (
            "files",
            (
                "demo/web/vulnerable.js",
                b'const apiKey = "AIzaSyD-FakeApiKeyForNodeJSTesting123"; eval(input);',
                "text/javascript",
            ),
        ),
    ]
    response = client.post("/api/v1/scan/project", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["scanned_files_count"] == 2
    assert data["total_findings"] >= 3
    paths = {finding["file_path"] for finding in data["findings"]}
    assert "demo/src/vulnerable.py" in paths
    assert "demo/web/vulnerable.js" in paths


def test_scan_project_upload_rejects_parent_path():
    files = [("files", ("../outside.py", b'eval("1 + 1")\n', "text/x-python"))]
    response = client.post("/api/v1/scan/project", files=files)
    assert response.status_code == 400
    assert "Caminho relativo" in response.json()["detail"]


def test_security_headers_present():
    response = client.get("/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
