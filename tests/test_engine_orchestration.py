import json
import os
from pathlib import Path
import sys

import pytest

from engine.engine import SASTEngine
from engine.models import Finding
from engine.orchestration import ExternalScanners, normalize_findings
from engine.policy import evaluate_gate
from scripts.benchmark import evaluate


def signal(engine="native", column=0, code="eval(value)"):
    return Finding(rule_id="PY-R001" if engine == "native" else "BANDIT-B307", rule_name="eval", severity="HIGH",
        cwe="CWE-95", message="Dynamic execution", file_path="app.py", line_number=1,
        column_number=column, code_snippet=code, remediation_advice="Remove dynamic execution", engines=[engine])


def test_dedup_merges_same_operation_and_preserves_evidence():
    result = normalize_findings([signal(), signal("bandit", 5)], {"app.py": "eval(value)"})
    assert len(result) == 1
    assert result[0].engines == ["bandit", "native"]
    assert {item.rule_id for item in result[0].evidence} == {"PY-R001", "BANDIT-B307"}
    assert result[0].fingerprint


def test_dedup_preserves_distinct_same_cwe_sinks_on_same_line():
    code = "eval(a); eval(b)"
    result = normalize_findings([signal(column=0, code=code), signal(column=9, code=code),
        signal("bandit", column=0, code=code), signal("bandit", column=9, code=code)], {"app.py": code})
    assert len(result) == 2
    assert len({item.fingerprint for item in result}) == 2
    assert all(len(item.evidence) == 2 for item in result)


@pytest.mark.parametrize("path", ["../../outside.py", "/absolute.py", "C:/outside.py", "nested/../outside.py"])
def test_temporary_workspace_rejects_path_traversal(path, tmp_path):
    with pytest.raises(ValueError):
        ExternalScanners._write_sources({path: "x=1"}, tmp_path)
    assert list(tmp_path.rglob("*.py")) == []


def test_requested_missing_engine_is_incomplete_without_hiding_native_findings(monkeypatch):
    adapters = ExternalScanners(engines=["native", "bandit"])
    monkeypatch.setattr(adapters, "version", lambda *_: None)
    result = SASTEngine(external_scanners=adapters).scan_code("eval(value)", "app.py")
    assert result.findings and result.has_errors
    assert result.engine_runs[-1].status == "unavailable"
    assert evaluate_gate(result).status == "error"


def test_timeout_preserves_native_result(monkeypatch):
    adapters = ExternalScanners(engines=["bandit"])
    monkeypatch.setattr(adapters, "version", lambda *_: "test")
    def timeout(*_):
        raise TimeoutError("test timeout")
    monkeypatch.setattr(adapters, "_run", timeout)
    result = SASTEngine(external_scanners=adapters).scan_code("eval(value)", "app.py")
    assert result.total_findings == 1 and result.has_errors
    assert result.engine_runs[-1].status == "timeout"


def test_external_errors_keep_partial_results_and_fail_gate(monkeypatch):
    adapters = ExternalScanners(engines=["bandit"])
    monkeypatch.setattr(adapters, "version", lambda *_: "test")
    monkeypatch.setattr(adapters, "_run", lambda *_: (0, json.dumps({"results": [], "errors": [{"reason": "parse"}]}), ""))
    result = SASTEngine(external_scanners=adapters).scan_code("eval(value)", "app.py")
    assert result.total_findings == 1 and result.has_errors
    assert result.engine_runs[-1].status == "error"


def test_subprocess_timeout_is_enforced(tmp_path):
    adapters = ExternalScanners(python=sys.executable)
    with pytest.raises(TimeoutError):
        adapters._run([sys.executable, "-c", "import time; time.sleep(5)"], tmp_path, timeout=.2)


def test_process_environment_does_not_inherit_provider_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-do-not-inherit")
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "test-only-do-not-inherit")
    env = ExternalScanners()._environment(tmp_path)
    assert "OPENAI_API_KEY" not in env and "SEMGREP_APP_TOKEN" not in env
    assert env["SEMGREP_SEND_METRICS"] == "off"


def test_output_budget_is_enforced(tmp_path):
    adapters = ExternalScanners(python=sys.executable)
    adapters.max_output = 64
    with pytest.raises(ValueError, match="Saída"):
        adapters._run([sys.executable, "-c", "print('x'*1000)"], tmp_path)


def test_occurrence_benchmark_catches_second_missed_sink_and_wrong_line():
    report = evaluate([{"id": "multiplicity", "filename": "app.py", "code": "eval(value)",
                        "expected_rules": ["PY-R001", "PY-R001"]}], repeats=1)
    assert report["true_positives"] == 1 and report["false_negatives"] == 1
    report = evaluate([{"id": "location", "filename": "app.py", "code": "eval(value)",
                        "expected_rules": ["PY-R001"],
                        "expected_locations": [{"rule_id": "PY-R001", "line_number": 2}]}], repeats=1)
    assert report["false_negatives"] == 1 and report["false_positives"] == 1


@pytest.mark.skipif(os.getenv("SAST_TEST_EXTERNAL") != "1", reason="Requires optional scanner runtime")
def test_installed_external_engines_run_real_three_language_analysis(tmp_path):
    adapters = ExternalScanners(engines=["native", "bandit", "semgrep"])
    sources = {
        "app.py": 'import os\nhost = input()\nos.system("ping " + host)',
        "app.js": 'const id = req.query.id; db.query("SELECT * FROM users WHERE id=" + id);',
        "A.java": 'class A { void run(Request req, Statement stmt) { String id = req.getParameter("id"); stmt.executeQuery("SELECT * FROM users WHERE id=" + id); } }',
    }
    result = SASTEngine(external_scanners=adapters).scan_sources(sources)
    assert not result.has_errors, result.errors
    assert {run.engine for run in result.engine_runs if run.status == "completed"} == {"native", "bandit", "semgrep"}
    assert len(result.findings) == 3
    assert all("semgrep" in finding.engines for finding in result.findings)
    assert "bandit" in next(f for f in result.findings if f.file_path == "app.py").engines


def test_scanning_sources_never_executes_them(tmp_path):
    marker = tmp_path / "must-not-exist"
    code = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')"
    result = SASTEngine(engines=["native"]).scan_code(code, "submitted.py")
    assert not result.has_errors and not marker.exists()
