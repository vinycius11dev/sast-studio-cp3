import json
from pathlib import Path

from fastapi.testclient import TestClient
import jsonschema

from api.main import app
from engine.ai_remediation import AIRemediationEngine
from engine.engine import SASTEngine
from engine.models import Finding
from engine.reporter import Reporter
from engine.semantic_review import AISemanticReviewEngine


def test_sarif_provenance_and_real_dataflow_validate_against_oasis_schema():
    schema = json.loads((Path(__file__).parent / "fixtures/sarif-2.1.0.schema.json").read_text(encoding="utf-8"))
    result = SASTEngine(engines=["native"]).scan_code(
        'name = input()\nquery = "SELECT * FROM users WHERE name=" + name\ncursor.execute(query)', "app.py")
    document = json.loads(Reporter.to_sarif(result))
    jsonschema.validate(document, schema)
    records = document["runs"][0]["results"]
    assert any(record.get("codeFlows") for record in records)
    assert all(record["properties"]["engines"] == ["native"] for record in records)
    assert all(record.get("partialFingerprints") for record in records)


def test_sarif_without_findings_or_with_processing_error_is_schema_valid():
    schema = json.loads((Path(__file__).parent / "fixtures/sarif-2.1.0.schema.json").read_text(encoding="utf-8"))
    for source in ["x = 1", "def syntax_error(:"]:
        report = Reporter.to_sarif(SASTEngine(engines=["native"]).scan_code(source, "app.py"))
        jsonschema.validate(json.loads(report), schema)


def test_quality_endpoint_labels_stale_measurement(monkeypatch, tmp_path):
    from engine import quality
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/benchmark-results.json").write_text(json.dumps({"detection_fingerprint": "old", "case_count": 20}))
    monkeypatch.setattr(quality, "ROOT", tmp_path)
    with TestClient(app) as client:
        result = client.get("/api/v1/quality")
    assert result.status_code == 200 and result.json()["status"] == "stale"
    assert "LLM" not in (result.json().get("engine") or "")


def test_unvalidated_new_rule_never_offers_generated_diff(monkeypatch):
    finding = Finding(rule_id="JS-R007", rule_name="Path Traversal", severity="HIGH", cwe="CWE-22",
        message="Potential file access", file_path="app.js", line_number=1, column_number=0,
        code_snippet="fs.readFileSync(req.query.path)", remediation_advice="Resolve and constrain the path.")
    model = AIRemediationEngine()
    monkeypatch.setattr(model, "_query_ollama", lambda *_: (_ for _ in ()).throw(AssertionError("No unverified patches")))
    result = model.remediate_finding(finding, finding.code_snippet)
    assert result.patch_scope == "manual_review" and not result.diff and not result.suggested_patch


def test_semantic_reasoning_rejects_explicit_nonexistent_calls_and_variables():
    method = AISemanticReviewEngine._unsupported_api_reference
    assert method("A função sanitizeQuery() protege a consulta.", "db.query(sql)") == "sanitizeQuery()"
    assert method("A variável `safeHost` foi validada.", "const host = req.query.host;") == "safeHost"
    assert method("A função query() recebe a consulta `sql`.", "db.query(sql)") is None


def test_proven_sql_flow_preserves_original_model_verdict_when_reconciled(monkeypatch):
    source = '''app.get("/user", (req, res) => {
  const id = req.query.id;
  const sql = "SELECT * FROM users WHERE id=" + id;
  db.query(sql, (err, rows) => res.json(rows));
});'''
    finding = SASTEngine(engines=["native"]).scan_code(source, "app.js").findings[0]
    model = AIRemediationEngine()
    monkeypatch.setattr(model, "is_ollama_available", lambda: True)
    raw = {"classification": "needs_review", "suggested_severity": "CRITICAL", "confidence": "low",
           "reasoning": "A origem da consulta não foi identificada pelo modelo.", "evidence_lines": [4]}
    monkeypatch.setattr(model, "_generate_structured_response", lambda *args, **kwargs: raw)
    review = AISemanticReviewEngine(model).review_finding(finding, source, "a" * 32)
    assert review.classification == "confirmed"
    assert review.model_decision["classification"] == "needs_review"
    assert review.validation_adjustments
    assert review.evidence_lines == [2, 3, 4]
