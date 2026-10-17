import json

import pytest
from fastapi.testclient import TestClient

from api import main
from engine.ai_remediation import AIRemediationEngine
from engine.models import SemanticReview
from engine.semantic_review import AISemanticReviewEngine, finding_key


def mock_model(monkeypatch, decision):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json):
            class Response:
                status_code = 200

                def json(self):
                    return {"response": __import__("json").dumps(decision), "done_reason": "stop"}

            return Response()

    monkeypatch.setattr("engine.ai_remediation.httpx.Client", Client)
    monkeypatch.setattr(main.ai_engine, "is_ollama_available", lambda: True)


def create_scan(client):
    response = client.post("/api/v1/scan/code", json={"code": 'eval("2 + 2")\n', "filename": "constant.py"})
    assert response.status_code == 200
    return response.json()


def decision(**changes):
    return {"classification": "likely_false_positive", "suggested_severity": "LOW", "confidence": "high",
            "reasoning": "O argumento é uma constante fixa sem entrada externa neste contexto.",
            "evidence_lines": [1], **changes}


def test_semantic_review_uses_llm_and_preserves_scan_and_gate(monkeypatch):
    mock_model(monkeypatch, decision())
    with TestClient(main.app) as client:
        scan = create_scan(client)
        response = client.post("/api/v1/triage", json={**scan["findings"][0], "scan_id": scan["scan_id"]})
        assert response.status_code == 200
        review = response.json()
        assert review["provider"] == "ollama"
        assert review["classification"] == "likely_false_positive"
        assert review["original_severity"] == "CRITICAL"
        assert review["suggested_severity"] == "LOW"
        assert review["review_id"] and review["created_at"]
        reopened = client.get("/api/v1/scans/" + scan["scan_id"]).json()
        assert reopened["findings"] == scan["findings"]
        assert reopened["security_gate"] == scan["security_gate"]
        assert reopened["semantic_reviews"][0] == review
        report = client.get(f'/api/v1/scans/{scan["scan_id"]}/report?format=json').json()
        assert report["semantic_reviews"][0]["review_id"] == review["review_id"]
        sarif = client.get(f'/api/v1/scans/{scan["scan_id"]}/report?format=sarif').json()
        assert sarif["runs"][0]["properties"]["semanticReviews"][0]["classification"] == "likely_false_positive"
        markdown = client.get(f'/api/v1/scans/{scan["scan_id"]}/report?format=markdown').text
        assert "Revisões semânticas" in markdown and "likely_false_positive" in markdown


def test_semantic_review_rejects_forged_finding():
    with TestClient(main.app) as client:
        scan = create_scan(client)
        finding = {**scan["findings"][0], "line_number": 500, "scan_id": scan["scan_id"]}
        assert client.post("/api/v1/triage", json=finding).status_code == 400


@pytest.mark.parametrize("changes", [{"evidence_lines": [999]}, {"classification": "safe"}, {"suggested_severity": "NONE"}, {"reasoning": "ok"}])
def test_invalid_model_triage_is_explicitly_unavailable(monkeypatch, changes):
    mock_model(monkeypatch, decision(**changes))
    with TestClient(main.app) as client:
        scan = create_scan(client)
        review = client.post("/api/v1/triage", json={**scan["findings"][0], "scan_id": scan["scan_id"]}).json()
        assert review["provider"] == "unavailable"
        assert review["classification"] == "needs_review"
        assert review["suggested_severity"] == scan["findings"][0]["severity"]
        assert review["fallback_reason"]


def test_model_unavailable_does_not_claim_ai_classification(monkeypatch):
    monkeypatch.setattr(main.ai_engine, "is_ollama_available", lambda: False)
    with TestClient(main.app) as client:
        scan = create_scan(client)
        review = client.post("/api/v1/triage", json={**scan["findings"][0], "scan_id": scan["scan_id"]}).json()
        assert review["provider"] == "unavailable"
        assert review["evidence_lines"] == []


def test_client_cannot_change_original_severity(monkeypatch):
    mock_model(monkeypatch, decision())
    with TestClient(main.app) as client:
        scan = create_scan(client)
        review = client.post("/api/v1/triage", json={**scan["findings"][0], "severity": "INFO", "scan_id": scan["scan_id"]}).json()
        assert review["original_severity"] == "CRITICAL"


def test_external_input_cannot_be_downgraded_to_false_positive(monkeypatch):
    mock_model(monkeypatch, decision(evidence_lines=[2]))
    with TestClient(main.app) as client:
        scan = client.post("/api/v1/scan/code", json={"code": "value = input()\neval(value)", "filename": "external.py"}).json()
        review = client.post("/api/v1/triage", json={**scan["findings"][0], "scan_id": scan["scan_id"]}).json()
        assert review["provider"] == "unavailable"
        assert "input() reaches eval()" in review["fallback_reason"]
        assert review["suggested_severity"] == "CRITICAL"
