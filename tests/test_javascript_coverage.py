"""Positive/negative coverage and adversarial lexical-flow regressions.

The curated corpus measures these cases only; it is not a claim that arbitrary
JavaScript programs are completely analyzed. Target code is never executed.
"""
from collections import Counter
import json
from pathlib import Path

import pytest

from engine.languages.javascript_scanner import JavaScriptScanner


CORPUS = json.loads((Path(__file__).resolve().parents[1] / "benchmarks" / "coverage_javascript.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CORPUS, ids=lambda case: case["id"])
def test_javascript_curated_coverage(case):
    findings, errors = JavaScriptScanner().scan_source(case["code"], case["filename"])
    assert errors == []
    assert Counter(finding.rule_id for finding in findings) == Counter(case["expected_rules"])
    for location in case.get("expected_locations", []):
        assert any(finding.rule_id == location["rule_id"] and finding.line_number == location["line_number"] for finding in findings)


@pytest.mark.parametrize("source,expected", [
    ('''function risky(input) { const sql="SELECT * FROM users WHERE id="+input; db.query(sql); }
function safe() { const sql="SELECT * FROM users"; db.query(sql); }''', ["JS-R005"]),
    ('''const sql="SELECT * FROM users";
function ignored() { sql="SELECT * FROM users WHERE id="+input; }
db.query(sql);''', []),
    ('''let sql="SELECT * FROM users WHERE id="+input;
if (condition) { sql="SELECT * FROM users"; }
db.query(sql);''', ["JS-R005"]),
    ('''let sql="SELECT * FROM users";
if (condition) { sql="SELECT * FROM users WHERE id="+input; }
db.query(sql);''', ["JS-R005"]),
    ('''const sql="SELECT * FROM users WHERE id="+input;
function safe() { { let sql="SELECT * FROM users"; db.query(sql); } }''', []),
    ('''const host = "127.0.0.1";
function ping(host) { const cp=require("child_process"); cp.exec("ping "+host); }''', ["JS-R003"]),
    ('''const fs=require("fs"); function handler(fs) { fs.readFile(req.query.name); }''', []),
    ('''const cp=require("child_process"); function handler(cp) { cp.exec(req.body.command); }''', []),
    ('''const {query:run}=db; { const run=()=>{}; run("SELECT * FROM users WHERE id="+id); }''', []),
    ('''const data=req.body.password; function show(data) { console.log(data); }''', []),
])
def test_lexical_scope_and_conservative_conditional_assignments(source, expected):
    findings, errors = JavaScriptScanner().scan_source(source, "flow.js")
    assert not errors
    assert Counter(finding.rule_id for finding in findings) == Counter(expected)


@pytest.mark.parametrize("filename,source", [
    ("broken.js", "function bad( {"),
    ("broken.ts", "const value: = ;"),
    ("broken.tsx", "const view = <div>"),
])
def test_parse_failure_is_reported_as_incomplete(filename, source):
    findings, errors = JavaScriptScanner().scan_source(source, filename)
    assert findings == []
    assert len(errors) == 1
    assert filename in errors[0]
    assert "incompleta" in errors[0]


def test_locations_preserve_unicode_columns_and_multiline_sink():
    source = 'const café="teste"; db.query(\n  "SELECT * FROM users WHERE id=" + input\n);'
    findings, errors = JavaScriptScanner().scan_source(source, "unicode.js")
    assert not errors
    finding = next(item for item in findings if item.rule_id == "JS-R005")
    assert finding.line_number == 1
    assert finding.column_number == source.splitlines()[0].index("db.query")
    assert "input" in finding.code_snippet


def test_each_rule_has_a_positive_case_and_unique_metadata():
    rules = JavaScriptScanner().list_rules()
    assert len({rule.rule_id for rule in rules}) == len(rules)
    expected = {rule for case in CORPUS for rule in case["expected_rules"]}
    assert expected == {rule.rule_id for rule in rules}
