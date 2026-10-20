import json
import os
import pytest
from fastapi.testclient import TestClient
from api.main import app
from engine.engine import SASTEngine
from engine.reporter import Reporter
from engine.models import Severity

client = TestClient(app)


@pytest.fixture
def engine():
    return SASTEngine()


def test_slide8_samples_exact_finding_counts(engine):
    """Verifica que as 3 amostras do Slide 8 produzem as contagens exatas esperadas."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    samples_dir = os.path.join(base_dir, "samples")

    # Expanded credential recognition also reports the previously missed admin_token.
    auth_file = os.path.join(samples_dir, "auth_controller.py")
    assert os.path.exists(auth_file)
    auth_result = engine.scan_file(auth_file)
    assert auth_result.total_findings == 13
    assert any(f.rule_id == "PY-R002" and f.line_number == 14 for f in auth_result.findings)
    assert auth_result.summary_by_severity["CRITICAL"] >= 4

    # 2. db_config.js -> 8 Falhas (Slide 8)
    db_file = os.path.join(samples_dir, "db_config.js")
    assert os.path.exists(db_file)
    db_result = engine.scan_file(db_file)
    assert db_result.total_findings == 8

    # 3. user_service.java -> 5 Falhas (Slide 8)
    user_file = os.path.join(samples_dir, "user_service.java")
    assert os.path.exists(user_file)
    user_result = engine.scan_file(user_file)
    assert user_result.total_findings == 5


def test_sarif_export_schema_and_validity(engine):
    """Verifica que o exportador SARIF 2.1.0 produz JSON válido com regras e localizações."""
    code = 'import os\nos.system("ping 127.0.0.1")\neval("1+1")\n'
    result = engine.scan_code(code, "test_sarif.py")
    assert result.total_findings >= 2

    sarif_str = Reporter.to_sarif(result)
    assert isinstance(sarif_str, str)

    sarif = json.loads(sarif_str)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "FIAP-SAST-Platform"
    assert len(run["results"]) == result.total_findings
    assert all("ruleId" in r and "level" in r for r in run["results"])


def test_ssrf_detection_python_and_multilang(engine):
    """Verifica a regra de detecção de Server-Side Request Forgery (SSRF - CWE-918)."""
    py_code = """
import requests
def forward_webhook(user_url):
    return requests.get(user_url)
"""
    result = engine.scan_code(py_code, "webhook.py")
    ssrf_findings = [f for f in result.findings if f.cwe == "CWE-918"]
    assert len(ssrf_findings) >= 1
    assert ssrf_findings[0].severity == Severity.HIGH

    taint_code = """
def fetch_user_url(request):
    target = request.args.get('target')
    return requests.get(target)
"""
    taint_result = engine.scan_code(taint_code, "tainted_webhook.py")
    assert any(f.rule_id == "PY-T003" and f.cwe == "CWE-918" for f in taint_result.findings)
    assert "PY-T003" in {rule.rule_id for rule in engine.list_rules()}

    # JavaScript SSRF
    js_code = 'const axios = require("axios"); axios.get("http://" + userInput);'
    js_res = engine.scan_code(js_code, "api.js")
    assert any(f.cwe == "CWE-918" for f in js_res.findings)

    # Java SSRF
    java_code = 'public void call(String url) throws Exception { new URL("http://" + url).openConnection(); }'
    java_res = engine.scan_code(java_code, "Call.java")
    assert any(f.cwe == "CWE-918" for f in java_res.findings)


def test_api_scan_samples_and_sarif_endpoints():
    """Verifica os endpoints de scan em lote da pasta samples e download de SARIF."""
    # 1. Scan de samples
    resp = client.get("/api/v1/scan/samples")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scanned_files_count"] >= 5
    assert data["total_findings"] >= 25

    # 2. Export SARIF
    sarif_resp = client.get("/api/v1/report/sarif")
    assert sarif_resp.status_code == 200
    sarif_data = sarif_resp.json()
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) >= 25
