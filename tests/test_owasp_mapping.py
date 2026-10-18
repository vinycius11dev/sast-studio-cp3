import json

from engine.engine import SASTEngine
from engine.models import Finding, RuleMetadata
from engine.owasp import owasp_category_for_cwe
from engine.reporter import Reporter


def finding_payload(cwe="CWE-89"):
    return {
        "rule_id": "TEST-R001",
        "rule_name": "Regra de teste",
        "severity": "HIGH",
        "cwe": cwe,
        "message": "Entrada não confiável usada em operação sensível.",
        "file_path": "src/service.py",
        "line_number": 12,
        "column_number": 4,
        "code_snippet": "execute(user_input)",
        "remediation_advice": "Valide a entrada e use uma API segura.",
    }


def test_owasp_2025_mapping_is_versioned_and_does_not_guess_unknown_cwes():
    expected = {
        "CWE-22": "A01:2025",
        "CWE-78": "A05:2025",
        "CWE-79": "A05:2025",
        "CWE-89": "A05:2025",
        "CWE-95": "A05:2025",
        "CWE-502": "A08:2025",
        "CWE-798": "A07:2025",
        "CWE-918": "A01:2025",
    }
    for cwe, category_id in expected.items():
        category = owasp_category_for_cwe(cwe)
        assert category is not None
        assert category.id == category_id
        assert category.version == "2025"
        assert category.url.startswith("https://top10.owasp.org/2025/")
    assert owasp_category_for_cwe("CWE-99999") is None


def test_legacy_finding_and_rule_payloads_are_mapped_when_rehydrated():
    finding_json = json.dumps(finding_payload())
    finding = Finding.model_validate_json(finding_json)
    assert finding.owasp.id == "A05:2025"

    rule = RuleMetadata.model_validate({
        "rule_id": "TEST-R001",
        "name": "Regra de teste",
        "severity": "HIGH",
        "cwe": "CWE-89",
        "description": "Descrição da regra.",
        "remediation": "Orientação segura.",
    })
    assert rule.owasp.id == "A05:2025"

    unmapped = Finding.model_validate(finding_payload("CWE-99999"))
    assert unmapped.owasp is None


def test_json_markdown_and_sarif_reports_include_owasp_category():
    result = SASTEngine().scan_code("eval(user_input)", "src/service.py")
    assert result.findings
    finding = result.findings[0]
    assert finding.owasp and finding.owasp.id == "A05:2025"

    as_json = json.loads(Reporter.to_json(result))
    assert as_json["findings"][0]["owasp"]["id"] == "A05:2025"

    markdown = Reporter.to_markdown(result)
    assert "OWASP Top 10:2025" in markdown
    assert "A05:2025" in markdown
    assert "OWASP A05:2025 - Injeção" in Reporter.to_text(result, use_colors=False)

    sarif = json.loads(Reporter.to_sarif(result))
    run = sarif["runs"][0]
    sarif_finding = run["results"][0]
    assert sarif_finding["properties"]["owaspTop10"]["id"] == "A05:2025"
    rule = run["tool"]["driver"]["rules"][0]
    assert "owasp-top10:a05:2025" in rule["properties"]["tags"]
    assert rule["properties"]["owaspTop10"]["version"] == "2025"
