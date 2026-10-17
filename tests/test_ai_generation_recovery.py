import json
from pathlib import Path

from engine.ai_remediation import AIRemediationEngine
from engine.engine import SASTEngine


def mock_generation(monkeypatch, responses):
    calls = []

    class FakeClient:
        def __init__(self, **kwargs):
            self.timeout = kwargs["timeout"]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json):
            index = len(calls)
            calls.append({"payload": json, "timeout": self.timeout})

            class Response:
                status_code = 200

                def json(self):
                    return responses[min(index, len(responses) - 1)]

            return Response()

    monkeypatch.setattr("engine.ai_remediation.httpx.Client", FakeClient)
    return calls


def eval_finding():
    return SASTEngine().scan_code("eval(user_input)", "calc.py").findings[0]


def valid_eval_response():
    return {"done": True, "done_reason": "stop", "response": json.dumps({
        "risk_analysis": "Execução de código arbitrário.",
        "suggested_patch": "import ast\nast.literal_eval(user_input)",
        "remediation_steps": "Substitua eval por ast.literal_eval.",
    })}


def test_truncated_json_is_regenerated_with_larger_budget(monkeypatch):
    calls = mock_generation(monkeypatch, [
        {"done": True, "done_reason": "length", "response": '{"suggested_patch":"incompleto'},
        valid_eval_response(),
    ])
    engine = AIRemediationEngine()
    monkeypatch.setattr(engine, "is_ollama_available", lambda: True)
    result = engine.remediate_finding(eval_finding())
    assert result.provider == "ollama"
    assert result.fallback_reason is None
    assert len(calls) == 2
    assert calls[0]["payload"]["options"]["num_predict"] == 1024
    assert calls[1]["payload"]["options"]["num_predict"] == 1536
    assert 0 < calls[1]["timeout"] <= calls[0]["timeout"] <= engine.request_timeout
    assert "Gere novamente" in calls[1]["payload"]["prompt"]


def test_malformed_json_is_regenerated(monkeypatch):
    calls = mock_generation(monkeypatch, [{"response": "not JSON"}, valid_eval_response()])
    engine = AIRemediationEngine()
    result = engine._query_ollama(eval_finding(), None)
    assert result.provider == "ollama"
    assert len(calls) == 2


def test_invalid_fields_after_retry_still_use_honest_fallback(monkeypatch):
    calls = mock_generation(monkeypatch, [{"response": json.dumps({
        "risk_analysis": "Risco", "suggested_patch": None, "remediation_steps": [],
    })}])
    engine = AIRemediationEngine()
    monkeypatch.setattr(engine, "is_ollama_available", lambda: True)
    result = engine.remediate_finding(eval_finding())
    assert result.provider == "heuristic"
    assert "segunda tentativa" in result.fallback_reason
    assert len(calls) == 2


def test_java_sql_uses_full_source_and_generates_full_file_diff(monkeypatch):
    root = Path(__file__).resolve().parents[1] / "demonstracao"
    source = (root / "01-vulneravel/java/UsuarioRepository.java").read_text(encoding="utf-8")
    corrected = (root / "02-corrigido/java/UsuarioRepository.java").read_text(encoding="utf-8")
    finding = next(item for item in SASTEngine().scan_code(source, "java/UsuarioRepository.java").findings if item.rule_id == "JAVA-R001")
    calls = mock_generation(monkeypatch, [{"response": json.dumps({
        "risk_analysis": "SQL concatenado permite injeção.", "suggested_patch": corrected,
        "remediation_steps": "Vincule o valor com PreparedStatement.",
    })}])
    result = AIRemediationEngine()._query_ollama(finding, source)
    assert result.provider == "ollama" and result.patch_scope == "file"
    assert source in calls[0]["payload"]["prompt"]
    assert "ARQUIVO JAVA COMPLETO" in calls[0]["payload"]["prompt"]
    assert "--- a/java/UsuarioRepository.java" in result.diff
    assert "+import java.sql.PreparedStatement;" in result.diff
    assert "-             ResultSet rows = statement.executeQuery" in result.diff
    assert "+                return rows.next();" in result.diff


def test_model_cannot_replace_java_class_with_generic_example(monkeypatch):
    root = Path(__file__).resolve().parents[1] / "demonstracao"
    source = (root / "01-vulneravel/java/UsuarioRepository.java").read_text(encoding="utf-8")
    finding = next(item for item in SASTEngine().scan_code(source, "UsuarioRepository.java").findings if item.rule_id == "JAVA-R001")
    mock_generation(monkeypatch, [{"response": json.dumps({
        "risk_analysis": "SQL concatenado.",
        "suggested_patch": 'class OutraClasse { void buscar() { var stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); stmt.setString(1, id); } }',
        "remediation_steps": "Use parâmetros.",
    })}])
    engine = AIRemediationEngine()
    monkeypatch.setattr(engine, "is_ollama_available", lambda: True)
    result = engine.remediate_finding(finding, source)
    assert result.provider == "heuristic"
    assert "classe Java original" in result.fallback_reason


def test_java_imports_and_package_are_preserved():
    engine = AIRemediationEngine()
    original = "package demo;\nimport java.io.IOException;\nclass Repo {}"
    patch = "import java.sql.PreparedStatement;\nclass Repo {}"
    result = engine._preserve_java_imports(original, patch)
    assert result.startswith("package demo;")
    assert result.count("import java.io.IOException;") == 1
    assert result.count("import java.sql.PreparedStatement;") == 1


def test_rejected_patch_gets_one_new_generation_with_validation_feedback(monkeypatch):
    invalid = valid_eval_response()
    invalid["response"] = json.dumps({"risk_analysis": "Risco", "suggested_patch": "eval(user_input)", "remediation_steps": "Corrija."})
    calls = mock_generation(monkeypatch, [invalid, valid_eval_response()])
    result = AIRemediationEngine()._query_ollama(eval_finding(), None)
    assert result.provider == "ollama"
    assert len(calls) == 2
    assert "não passou na validação" in calls[1]["payload"]["prompt"]


def test_retry_does_not_start_after_total_time_budget(monkeypatch):
    calls = mock_generation(monkeypatch, [{"response": "invalid JSON"}])
    clock_values = iter([0, 0, 100])
    monkeypatch.setattr("engine.ai_remediation.time.monotonic", lambda: next(clock_values))
    engine = AIRemediationEngine()
    monkeypatch.setattr(engine, "is_ollama_available", lambda: True)
    result = engine.remediate_finding(eval_finding())
    assert result.provider == "heuristic"
    assert "limite total" in result.fallback_reason
    assert len(calls) == 1
