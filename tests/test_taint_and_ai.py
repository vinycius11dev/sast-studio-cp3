import json
import pytest
from fastapi.testclient import TestClient
from engine.engine import SASTEngine
from engine.ai_remediation import AIRemediationEngine
from engine.models import Finding, Severity
from api.main import app

client = TestClient(app)


@pytest.fixture
def engine():
    return SASTEngine()


def test_taint_sql_injection_detected(engine):
    code = """
def search_user(request, db):
    user_name = request.args.get('username')
    query = "SELECT * FROM users WHERE name = '" + user_name + "'"
    db.execute(query)
"""
    result = engine.scan_code(code, "taint_test.py")
    assert result.total_findings >= 1
    sql_findings = [f for f in result.findings if f.cwe == "CWE-89"]
    assert len(sql_findings) == 1
    assert sql_findings[0].severity == Severity.CRITICAL


def test_taint_path_traversal_detected(engine):
    code = """
def load_doc(request):
    doc_path = request.form.get('path')
    with open(doc_path, 'r') as f:
        return f.read()
"""
    result = engine.scan_code(code, "path_test.py")
    assert result.total_findings >= 1
    path_findings = [f for f in result.findings if f.cwe == "CWE-22"]
    assert len(path_findings) == 1
    assert path_findings[0].severity == Severity.HIGH
    assert path_findings[0].rule_id == "PY-T002"
    assert "PY-T002" in {rule.rule_id for rule in engine.list_rules()}


def test_taint_sanitized_input_is_safe(engine):
    code = """
def safe_search(request, db):
    safe_id = int(request.args.get('id', 0))
    # Sanitizado com int()
    query = f"SELECT * FROM items WHERE id = {safe_id}"
    db.execute(query)
"""
    result = engine.scan_code(code, "safe_taint.py")
    # Sanitizado com int(), não deve ser apontado como falha de taint
    assert result.total_findings == 0


def test_ai_remediation_engine(monkeypatch):
    finding = Finding(
        rule_id="PY-T001",
        rule_name="SQL Injection",
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        message="SQL injection detectado via taint",
        file_path="app.py",
        line_number=10,
        column_number=4,
        code_snippet='db.execute("SELECT * FROM u WHERE id=" + uid)',
        remediation_advice="Use queries parametrizadas",
    )
    ai_engine = AIRemediationEngine()
    monkeypatch.setattr(ai_engine, "is_ollama_available", lambda: False)
    remediation = ai_engine.remediate_finding(finding)

    assert remediation.rule_id == "PY-T001"
    assert remediation.cwe == "CWE-89"
    assert "Prepared Statement" in remediation.suggested_patch or "SELECT" in remediation.suggested_patch
    assert "--- a/app.py" in remediation.diff
    assert len(remediation.risk_analysis) > 10


def test_ssrf_remediation_matches_source_language():
    cases = [
        ("JS-R006", "client.js", "fetch(targetUrl)", "allowedHosts"),
        ("JAVA-R006", "Client.java", "new URL(targetUrl)", "allowedHosts"),
    ]
    ai_engine = AIRemediationEngine()
    ai_engine.is_ollama_available = lambda: False

    for rule_id, file_path, code_snippet, expected_text in cases:
        finding = Finding(
            rule_id=rule_id,
            rule_name="Server-Side Request Forgery",
            severity=Severity.HIGH,
            cwe="CWE-918",
            message="SSRF detectado",
            file_path=file_path,
            line_number=1,
            column_number=0,
            code_snippet=code_snippet,
            remediation_advice="Valide o destino.",
        )

        remediation = ai_engine.remediate_finding(finding)

        assert expected_text in remediation.suggested_patch
        assert "SELECT" not in remediation.suggested_patch


def test_ollama_structured_remediation(monkeypatch):
    payloads = []

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {
                "response": json.dumps(
                    {
                        "risk_analysis": "URL controlada por usuário pode alcançar serviços internos.",
                        "suggested_patch": "const target = new URL(targetUrl);",
                        "remediation_steps": "Valide HTTPS e hostname contra uma allow-list.",
                    }
                )
            }

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json):
            payloads.append(json)
            return FakeResponse()

    monkeypatch.setattr("engine.ai_remediation.httpx.Client", FakeClient)
    finding = Finding(
        rule_id="JS-R006",
        rule_name="SSRF",
        severity=Severity.HIGH,
        cwe="CWE-918",
        message="SSRF detectado",
        file_path="client.js",
        line_number=1,
        column_number=0,
        code_snippet="fetch(targetUrl)",
        remediation_advice="Valide o destino.",
    )
    ai_engine = AIRemediationEngine()
    monkeypatch.setattr(ai_engine, "is_ollama_available", lambda: True)

    remediation = ai_engine.remediate_finding(finding)

    assert remediation.model_used.startswith("Ollama (")
    assert remediation.suggested_patch == "const target = new URL(targetUrl);"
    assert "a/client.js" in remediation.diff
    assert "\n\n" not in remediation.diff
    assert "JavaScript" in payloads[0]["prompt"]
    assert payloads[0]["format"]["required"] == ["risk_analysis", "suggested_patch", "remediation_steps"]


def test_ollama_unsafe_eval_patch_uses_safe_fallback(monkeypatch):
    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {
                "response": json.dumps(
                    {
                        "risk_analysis": "eval pode executar código arbitrário.",
                        "suggested_patch": "eval(ast.literal_eval(user_input))",
                        "remediation_steps": "Remova a execução dinâmica.",
                    }
                )
            }

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json):
            return FakeResponse()

    monkeypatch.setattr("engine.ai_remediation.httpx.Client", FakeClient)
    ai_engine = AIRemediationEngine()
    monkeypatch.setattr(ai_engine, "is_ollama_available", lambda: True)
    finding = Finding(
        rule_id="PY-R001",
        rule_name="Uso de eval",
        severity=Severity.CRITICAL,
        cwe="CWE-95",
        message="eval perigoso",
        file_path="calc.py",
        line_number=5,
        column_number=2,
        code_snippet="eval(user_input)",
        remediation_advice="Use ast.literal_eval()",
    )

    remediation = ai_engine.remediate_finding(finding)

    assert "Fallback" in remediation.model_used
    assert remediation.suggested_patch == "import ast\nast.literal_eval(user_input)"


def test_ollama_unparameterized_sql_patch_uses_safe_fallback(monkeypatch):
    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {
                "response": json.dumps(
                    {
                        "risk_analysis": "A consulta concatena entrada não confiável.",
                        "suggested_patch": (
                            "from sqlalchemy import text\n"
                            "db_cursor.execute(text(query))"
                        ),
                        "remediation_steps": "Use parâmetros vinculados na consulta SQL.",
                    }
                )
            }

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json):
            return FakeResponse()

    monkeypatch.setattr("engine.ai_remediation.httpx.Client", FakeClient)
    ai_engine = AIRemediationEngine()
    monkeypatch.setattr(ai_engine, "is_ollama_available", lambda: True)
    finding = Finding(
        rule_id="PY-T001",
        rule_name="SQL Injection via taint",
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        message="query contaminada alcança db_cursor.execute()",
        file_path="app.py",
        line_number=8,
        column_number=4,
        code_snippet="db_cursor.execute(query)",
        remediation_advice="Use queries parametrizadas",
    )

    remediation = ai_engine.remediate_finding(finding)

    assert "Fallback" in remediation.model_used
    assert "%s" in remediation.suggested_patch
    assert "execute(query," in remediation.suggested_patch


def test_ollama_hardcoded_secret_patch_uses_environment_fallback(monkeypatch):
    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {
                "response": json.dumps(
                    {
                        "risk_analysis": "O segredo está exposto no código.",
                        "suggested_patch": 'api_key = "AIzaSyD-GoogleApiKeyExample998877"',
                        "remediation_steps": "Remova o segredo do código-fonte.",
                    }
                )
            }

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json):
            return FakeResponse()

    monkeypatch.setattr("engine.ai_remediation.httpx.Client", FakeClient)
    ai_engine = AIRemediationEngine()
    monkeypatch.setattr(ai_engine, "is_ollama_available", lambda: True)
    finding = Finding(
        rule_id="PY-R002",
        rule_name="Credencial hardcoded",
        severity=Severity.HIGH,
        cwe="CWE-798",
        message="api_key contém um segredo estático",
        file_path="settings.py",
        line_number=1,
        column_number=0,
        code_snippet='api_key = "AIzaSyD-GoogleApiKeyExample998877"',
        remediation_advice="Carregue a credencial de uma variável de ambiente.",
    )

    remediation = ai_engine.remediate_finding(finding)

    assert "Fallback" in remediation.model_used
    assert "os.getenv" in remediation.suggested_patch
    assert "AIzaSyD-GoogleApiKeyExample998877" not in remediation.suggested_patch


def test_ollama_secret_patch_rejects_hardcoded_default(monkeypatch):
    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {
                "response": json.dumps(
                    {
                        "risk_analysis": "A credencial não pode ficar no código.",
                        "suggested_patch": "const apiKey = process.env.API_KEY || 'defaultApiKey';",
                        "remediation_steps": "Defina a credencial no ambiente.",
                    }
                )
            }

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json):
            return FakeResponse()

    monkeypatch.setattr("engine.ai_remediation.httpx.Client", FakeClient)
    ai_engine = AIRemediationEngine()
    monkeypatch.setattr(ai_engine, "is_ollama_available", lambda: True)
    finding = Finding(
        rule_id="JS-R002",
        rule_name="Credencial hardcoded",
        severity=Severity.HIGH,
        cwe="CWE-798",
        message="apiKey contém um segredo estático",
        file_path="settings.js",
        line_number=1,
        column_number=0,
        code_snippet='const apiKey = "real-secret-token";',
        remediation_advice="Carregue a credencial de uma variável de ambiente.",
    )

    remediation = ai_engine.remediate_finding(finding)

    assert "Fallback" in remediation.model_used
    assert 'process.env.API_KEY || ""' in remediation.suggested_patch
    assert "defaultApiKey" not in remediation.suggested_patch


def test_ollama_xss_patch_rejects_inner_html():
    from engine.models import Finding, Severity

    ai_engine = AIRemediationEngine()
    finding = Finding(
        rule_id="JS-R004",
        rule_name="Cross-Site Scripting via innerHTML",
        severity=Severity.HIGH,
        cwe="CWE-79",
        message="Untrusted content is assigned to innerHTML",
        file_path="app.js",
        line_number=8,
        column_number=0,
        code_snippet='element.innerHTML = "<div>" + userInput + "</div>";',
        remediation_advice="Use textContent for untrusted text.",
    )

    assert not ai_engine._is_safe_model_patch(
        finding,
        'element?.innerHTML = `<div>${userInput}</div>`;',
    )
    assert ai_engine._is_safe_model_patch(
        finding,
        "element.textContent = userInput;",
    )


def test_ollama_unsafe_xss_patch_uses_safe_fallback(monkeypatch):
    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {
                "response": json.dumps(
                    {
                        "risk_analysis": "A resposta permite XSS.",
                        "suggested_patch": 'element.innerHTML = `<div>${userInput}</div>`;',
                        "remediation_steps": "Use textContent para exibir texto não confiável.",
                    }
                )
            }

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json):
            return FakeResponse()

    monkeypatch.setattr("engine.ai_remediation.httpx.Client", FakeClient)
    ai_engine = AIRemediationEngine()
    monkeypatch.setattr(ai_engine, "is_ollama_available", lambda: True)
    finding = Finding(
        rule_id="JS-R004",
        rule_name="Cross-Site Scripting via innerHTML",
        severity=Severity.HIGH,
        cwe="CWE-79",
        message="Untrusted content is assigned to innerHTML",
        file_path="app.js",
        line_number=8,
        column_number=0,
        code_snippet='element.innerHTML = "<div>" + userInput + "</div>";',
        remediation_advice="Use textContent for untrusted text.",
    )

    remediation = ai_engine.remediate_finding(finding)

    assert "Fallback" in remediation.model_used
    assert "textContent" in remediation.suggested_patch
    assert "innerHTML" not in remediation.suggested_patch


def test_command_injection_patch_requires_shell_free_argument_list():
    ai_engine = AIRemediationEngine()
    finding = Finding(
        rule_id="PY-R003",
        rule_name="Command Injection",
        severity=Severity.HIGH,
        cwe="CWE-78",
        message="Entrada do usuário chega em uma chamada de shell",
        file_path="app.py",
        line_number=3,
        column_number=0,
        code_snippet='os.system("ping " + host)',
        remediation_advice="Use subprocess com shell desativado e argumentos separados.",
    )

    assert ai_engine._is_safe_model_patch(
        finding,
        "import subprocess\nsubprocess.run(['ping', '-c', '1', host])",
    )
    assert not ai_engine._is_safe_model_patch(
        finding,
        'import subprocess\nsubprocess.run("ping " + host, shell=True)',
    )


def test_api_remediate_endpoint(monkeypatch):
    from api.main import ai_engine

    monkeypatch.setattr(ai_engine, "is_ollama_available", lambda: False)
    payload = {
        "rule_id": "PY-R001",
        "rule_name": "Uso de eval",
        "severity": "CRITICAL",
        "cwe": "CWE-95",
        "message": "eval perigoso",
        "file_path": "calc.py",
        "line_number": 5,
        "column_number": 2,
        "code_snippet": "eval(formula)",
        "remediation_advice": "Use ast.literal_eval()",
    }
    response = client.post("/api/v1/remediate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "literal_eval" in data["suggested_patch"]
    assert data["cwe"] == "CWE-95"
    assert "diff" in data
