"""GS CitizenTech: indicador Risco Cidadão, tradução por IA e API."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api import main
from engine.citizen_alert import CitizenAlertEngine, deterministic_alert
from engine.citizen_risk import compute_citizen_risk
from engine.engine import SASTEngine
from engine.ai_remediation import RemediationUnavailable
from engine.reporter import Reporter

DEMO = Path(__file__).resolve().parents[1] / "demonstracao"


def demo_sources(folder):
    return {f"{folder}/{path.relative_to(DEMO / folder).as_posix()}": path.read_text(encoding="utf-8")
            for path in sorted((DEMO / folder).rglob("*.py"))}


def scan_folder(folder):
    engine = SASTEngine()
    findings = []
    for path, source in demo_sources(folder).items():
        findings.extend(engine.scan_code(source, path).findings)
    return findings


def test_vulnerable_demo_has_confirmed_leaks_and_high_score():
    risk = compute_citizen_risk(scan_folder("04-pii-vulneravel"))
    assert risk.level == "critical" and risk.score >= 90
    assert risk.pii_findings == 9 and risk.confirmed_leaks == 6
    assert {driver.category for driver in risk.drivers} == {"documento", "saude", "senha"}
    assert risk.drivers[0].points >= risk.drivers[-1].points  # ordenado por impacto


def test_corrected_demo_has_no_exposure():
    findings = scan_folder("05-pii-corrigido")
    risk = compute_citizen_risk(findings)
    assert findings == [] and risk.score == 0 and risk.level == "none"
    assert "não prova" in risk.summary


def test_score_is_monotonic_and_leaks_weigh_more_than_literals():
    engine = SASTEngine()
    literal = engine.scan_code('CPF = "529.982.247-25"\n', "a.py").findings
    leak = engine.scan_code("def f(cpf):\n    print(cpf)\n", "b.py").findings
    assert compute_citizen_risk(leak).score > compute_citizen_risk(literal).score > 0
    assert compute_citizen_risk(literal + leak).score > compute_citizen_risk(leak).score


def test_non_pii_findings_count_less_and_incomplete_scan_is_flagged():
    injection = SASTEngine().scan_code("def f(x):\n    return eval(x)\n", "c.py").findings
    risk = compute_citizen_risk(injection, complete=False)
    assert risk.pii_findings == 0 and 0 < risk.score < 30 and not risk.complete
    assert "incompleta" in risk.summary


def test_scan_result_always_carries_the_indicator():
    result = SASTEngine().scan_code("def f(cpf):\n    print(cpf)\n", "d.py")
    assert result.citizen_risk and result.citizen_risk.confirmed_leaks == 1
    reloaded = type(result).model_validate_json(result.model_dump_json())
    assert reloaded.citizen_risk == result.citizen_risk


def test_reports_include_risk_and_trace():
    engine = SASTEngine()
    result = engine.scan_code("def f(cpf):\n    print(cpf)\n", "e.py")
    assert "Risco Cidadão" in Reporter.to_markdown(result) and "Caminho do dado" in Reporter.to_markdown(result)
    assert "Risco Cidadão" in Reporter.to_text(result, use_colors=False)
    sarif = json.loads(Reporter.to_sarif(result))
    run = sarif["runs"][0]
    assert run["properties"]["citizenRisk"]["score"] == result.citizen_risk.score
    assert run["results"][0]["properties"]["dataCategories"] == ["documento"]
    assert run["results"][0]["properties"]["taintTrace"][-1].endswith("← saída insegura")


class FakeModel:
    model_name = "fake"

    def __init__(self, available=True, response=None, error=None):
        self.available, self.response, self.error, self.prompts = available, response, error, []

    def is_ollama_available(self):
        return self.available

    def _generate_structured_response(self, prompt, schema, validator=None, string_values_only=True):
        self.prompts.append(prompt)
        if self.error:
            raise RemediationUnavailable(self.error)
        validator(self.response)
        return self.response


def first_leak():
    source = demo_sources("04-pii-vulneravel")["04-pii-vulneravel/atendimento/cadastro_ubs.py"]
    result = SASTEngine().scan_code(source, "cadastro_ubs.py")
    return next(item for item in result.findings if item.rule_id == "PY-T004"), source


GOOD = {
    "headline": "O CPF dos pacientes fica visível nos registros internos",
    "what_happened": "Cada atendimento escreve o CPF completo no registro interno do sistema, sem proteção.",
    "risk_for_citizen": "Quem acessar esses registros pode usar o CPF para aplicar golpes em nome do paciente.",
    "who_is_affected": "Todos os pacientes atendidos pela unidade.",
    "what_to_do": "Registrar o CPF mascarado e apagar os registros antigos que guardam o número completo.",
}


def test_alert_uses_llm_text_but_level_comes_from_severity():
    finding, source = first_leak()
    model = FakeModel(response={**GOOD})
    alert = CitizenAlertEngine(model).translate(finding, source, "s" * 32)
    assert alert.provider == "ollama" and alert.model_used == "Ollama (fake)"
    assert alert.headline == GOOD["headline"] and alert.risk_level == "critico"  # saúde+CPF em log: CRITICAL
    assert "LGPD" in alert.lgpd_reference
    assert "Linha 17" in model.prompts[0] and "SEM jargão" in model.prompts[0]


@pytest.mark.parametrize("bad_field,value", [("what_happened", "O taint chega ao sink do log sem sanitização."), ("what_to_do", "Use ```mask(cpf)```")])
def test_alert_rejects_jargon_and_code_and_falls_back(bad_field, value):
    finding, source = first_leak()
    model = FakeModel(response={**GOOD, bad_field: value + " " * 0 + " mais texto para passar do tamanho mínimo exigido"})
    alert = CitizenAlertEngine(model).translate(finding, source, "s" * 32)
    assert alert.provider == "deterministic" and alert.model_used == "Motor determinístico (Fallback)"
    assert alert.fallback_reason


def finding_by_rule(rule_id):
    source = demo_sources("04-pii-vulneravel")["04-pii-vulneravel/atendimento/cadastro_ubs.py"]
    result = SASTEngine().scan_code(source, "cadastro_ubs.py")
    return next(item for item in result.findings if item.rule_id == rule_id), source


@pytest.mark.parametrize("bad_field,value,reason", [
    ("what_happened", "Os dados ficam abertos ao público e qualquer um consegue ler.", "pública"),
    ("what_happened", "Um alerta de PII foi detectado nos registros internos do sistema.", "jargão"),
    ("who_is_affected", "Todos os pacientes, incluindo você, são afetados pela falha.", "pública"),
    ("what_to_do", "Guardar a senha com SHA-256 e revisar os registros internos do sistema.", "SHA"),
    ("what_to_do", "Guardar tudo com bcrypt ou Argon2 e revisar os registros internos do sistema.", "senha"),
])
def test_alert_rejects_overclaims_weak_hashes_and_off_topic_password_advice(bad_field, value, reason):
    finding, source = first_leak()  # log de CPF e saúde: não envolve senha
    alert = CitizenAlertEngine(FakeModel(response={**GOOD, bad_field: value})).translate(finding, source, "s" * 32)
    assert alert.provider == "deterministic" and alert.fallback_reason, reason


def test_password_alert_may_recommend_bcrypt_but_not_fast_hashes():
    finding, source = finding_by_rule("PY-P003")
    ok = {**GOOD, "what_to_do": "Guardar as senhas com bcrypt ou Argon2 e pedir que os usuários troquem a senha atual."}
    model = FakeModel(response=ok)
    assert CitizenAlertEngine(model).translate(finding, source, "s" * 32).provider == "ollama"
    assert "bcrypt ou Argon2" in model.prompts[0] and "este alerta não envolve senha" not in model.prompts[0]
    weak = {**ok, "what_to_do": "Trocar o MD5 pelo SHA-256 e pedir que os usuários troquem a senha atual."}
    assert CitizenAlertEngine(FakeModel(response=weak)).translate(finding, source, "s" * 32).provider == "deterministic"


def test_alert_falls_back_when_ollama_unavailable():
    finding, source = first_leak()
    alert = CitizenAlertEngine(FakeModel(available=False)).translate(finding, source, "s" * 32)
    assert alert.provider == "deterministic" and "indisponível" in alert.fallback_reason
    assert "registro interno" in alert.what_happened


def test_every_pii_rule_has_a_plain_language_fallback():
    engine = SASTEngine()
    findings = scan_folder("04-pii-vulneravel") + engine.scan_code("def f(x):\n    return eval(x)\n", "g.py").findings
    assert {item.rule_id for item in findings} >= {"PY-P001", "PY-P002", "PY-P003", "PY-T004", "PY-T005", "PY-T006", "PY-T007", "PY-R001"}
    for finding in findings:
        alert = deterministic_alert(finding, "s" * 32)
        text = " ".join([alert.headline, alert.what_happened, alert.risk_for_citizen, alert.who_is_affected, alert.what_to_do])
        assert len(alert.headline) > 10 and "taint" not in text.lower() and "CWE" not in text


def test_api_citizen_risk_and_alert_flow(monkeypatch):
    monkeypatch.setattr(main.citizen_engine, "model", FakeModel(available=False))
    with TestClient(main.app) as client:
        sources = demo_sources("04-pii-vulneravel")
        files = [("files", (path, source.encode("utf-8"), "text/plain")) for path, source in sources.items()]
        scan = client.post("/api/v1/scan/project", files=files, data={"project_name": "UBS", "gate_threshold": "HIGH"}).json()
        assert scan["citizen_risk"]["level"] == "critical" and scan["security_gate"]["status"] == "blocked"

        risk = client.get(f"/api/v1/scans/{scan['scan_id']}/citizen-risk").json()
        assert risk["citizen_risk"]["pii_findings"] == 9 and len(risk["exposures"]) == 9
        assert risk["exposures"][0]["severity"] == "CRITICAL" and risk["alerts"] == []

        leak = next(item for item in risk["exposures"] if item["rule_id"] == "PY-T005")
        assert leak["taint_trace"][-1].endswith("← saída insegura")
        alert = client.post("/api/v1/citizen-alert", json={**leak, "scan_id": scan["scan_id"]})
        assert alert.status_code == 200 and alert.json()["provider"] == "deterministic"
        assert client.get(f"/api/v1/scans/{scan['scan_id']}").json()["citizen_alerts"][0]["rule_id"] == "PY-T005"

        forged = {**leak, "scan_id": scan["scan_id"], "line_number": 999}
        assert client.post("/api/v1/citizen-alert", json=forged).status_code == 400
        assert client.get("/api/v1/scans/" + "0" * 32 + "/citizen-risk").status_code == 404


@pytest.mark.parametrize("variant,folder,pii,gate", [("pii-vulneravel", "04-pii-vulneravel", 9, "blocked"), ("pii-corrigido", "05-pii-corrigido", 0, "passed")])
def test_pii_demo_variants_load_and_scan(variant, folder, pii, gate):
    with TestClient(main.app) as client:
        data = client.get("/api/v1/samples", params={"variant": variant}).json()
        assert len(data["files"]) == 2 and all(file["path"].startswith(folder + "/") for file in data["files"])
        files = [("files", (file["path"], file["content"].encode("utf-8"), "text/plain")) for file in data["files"]]
        scan = client.post("/api/v1/scan/project", files=files, data={"project_name": data["project_name"], "gate_threshold": "HIGH"}).json()
        assert scan["errors"] == [] and scan["citizen_risk"]["pii_findings"] == pii
        assert scan["security_gate"]["status"] == gate
