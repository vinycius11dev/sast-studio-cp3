"""Native Python coverage: inert programs, exact locations and safe controls.

These fixtures are a regression corpus, not an independent industry benchmark.
No submitted program or vulnerable sample is executed by these tests.
"""
from collections import Counter
import json
from pathlib import Path

import pytest

from engine.languages.python_scanner import PythonScanner


CORPUS_PATH = Path(__file__).resolve().parents[1] / "benchmarks" / "coverage_python.json"
CASES = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_python_regression_corpus(case):
    findings, errors = PythonScanner().scan_source(case["code"], case["filename"])
    assert not errors
    assert Counter(f.rule_id for f in findings) == Counter(case["expected_rules"])
    if "expected_locations" in case:
        assert Counter((f.rule_id, f.line_number) for f in findings) == Counter((loc["rule_id"], loc["line_number"]) for loc in case["expected_locations"])


def test_new_python_rules_have_metadata_and_positive_negative_controls():
    metadata = PythonScanner().list_rules()
    ids = [rule.rule_id for rule in metadata]
    assert len(ids) == len(set(ids))
    assert {f"PY-R{number:03d}" for number in range(1, 16)} <= set(ids)
    assert {f"PY-T{number:03d}" for number in range(1, 4)} <= set(ids)
    assert all(rule.cwe.startswith("CWE-") and rule.description and rule.remediation for rule in metadata)
    expected = {rule for case in CASES for rule in case["expected_rules"]}
    assert {f"PY-R{number:03d}" for number in range(5, 16)} <= expected
    assert sum(not case["expected_rules"] for case in CASES) >= 20


def test_real_source_propagation_sink_trace_has_original_locations():
    code = "name = request.args['name']\nquery = 'SELECT * FROM people WHERE name = ' + name\ncursor.execute(query)\n"
    findings, errors = PythonScanner().scan_source(code, "trace.py")
    assert not errors and len(findings) == 1
    finding = findings[0]
    assert finding.analysis_scope == "local_dataflow"
    assert [(step.role, step.line_number) for step in finding.data_flow] == [("source", 1), ("propagation", 1), ("propagation", 2), ("sink", 3)]
    assert all(step.code_snippet == code.splitlines()[step.line_number - 1] for step in finding.data_flow)


def test_dynamic_sql_without_known_external_source_does_not_invent_flow():
    code = "def search(name, cursor):\n    cursor.execute(f'SELECT * FROM users WHERE name = {name}')\n"
    findings, errors = PythonScanner().scan_source(code, "potential.py")
    assert not errors and len(findings) == 1
    assert findings[0].analysis_scope == "pattern"
    assert findings[0].data_flow == []
    assert "não comprovada" in findings[0].message
    assert findings[0].limitations


def test_http_aliases_and_request_method_url_position():
    code = "import requests as http\ntarget = request.args['url']\nhttp.request('GET', url=target)\n"
    findings, errors = PythonScanner().scan_source(code, "http.py")
    assert not errors
    flow = next(f for f in findings if f.rule_id == "PY-T003")
    assert flow.analysis_scope == "local_dataflow"
    assert flow.data_flow[-1].line_number == 3


def test_branch_join_keeps_unsafe_branch_without_fabricating_single_trace():
    code = "if condition:\n    name = request.args['name']\nelse:\n    name = 'public'\ncursor.execute('SELECT * FROM users WHERE name = ' + name)\n"
    findings, errors = PythonScanner().scan_source(code, "branch.py")
    assert not errors and len(findings) == 1
    assert findings[0].data_flow == []
    assert findings[0].limitations


def test_source_state_does_not_leak_between_functions():
    code = "def first(request):\n    name = request.args['name']\n\ndef second(name):\n    return open(name)\n"
    findings, errors = PythonScanner().scan_source(code, "scope.py")
    assert not errors and findings == []


def test_generic_validation_does_not_sanitize_a_path():
    code = "name = validate(request.args['filename'])\nopen(name)\n"
    findings, errors = PythonScanner().scan_source(code, "path.py")
    assert not errors
    assert [finding.rule_id for finding in findings] == ["PY-T002"]


def test_invalid_python_reports_parse_error_instead_of_silent_success():
    findings, errors = PythonScanner().scan_source("def broken(\n", "broken.py")
    assert findings == []
    assert errors
