import os
import pytest
from engine.engine import SASTEngine
from engine.languages.javascript_scanner import JavaScriptScanner
from engine.languages.java_scanner import JavaScanner
from engine.models import Severity


@pytest.fixture
def engine():
    return SASTEngine()


def test_javascript_scanner_detection():
    js_code = """
const apiKey = "AIzaSyD-FakeApiKeyForNodeJSTesting123";
const dbPassword = "SecretPassword123";

function test(input) {
    eval(input);
    document.getElementById("box").innerHTML = input;
    child_process.exec("ping " + input);
}
"""
    scanner = JavaScriptScanner()
    findings, errors = scanner.scan_source(js_code, "test.js")
    assert len(errors) == 0
    assert len(findings) == 5

    rule_ids = {f.rule_id for f in findings}
    assert "JS-R001" in rule_ids  # eval
    assert "JS-R002" in rule_ids  # secrets
    assert "JS-R003" in rule_ids  # command injection
    assert "JS-R004" in rule_ids  # XSS innerHTML


def test_java_scanner_detection():
    java_code = """
package com.fiap.test;

public class TestService {
    private static final String API_KEY = "sk-live-fake-java-key-123456";

    public void run(java.sql.Statement stmt, String id) throws Exception {
        stmt.executeQuery("SELECT * FROM u WHERE id = '" + id + "'");
        Runtime.getRuntime().exec("ping " + id);
    }
}
"""
    scanner = JavaScanner()
    findings, errors = scanner.scan_source(java_code, "TestService.java")
    assert len(errors) == 0
    assert len(findings) == 3

    rule_ids = {f.rule_id for f in findings}
    assert "JAVA-R001" in rule_ids  # SQLi
    assert "JAVA-R002" in rule_ids  # secrets
    assert "JAVA-R003" in rule_ids  # Runtime.exec


def test_sast_engine_multi_language_routing(engine):
    # Snippet JavaScript
    js_snippet = "const apiKey = 'AIzaSyD-testKey1234'; eval(input);"
    js_result = engine.scan_code(js_snippet, "app.js")
    assert js_result.total_findings == 2

    # Snippet Java
    java_snippet = "public class A { String password = 'SecretPass123'; }"
    java_result = engine.scan_code(java_snippet, "A.java")
    assert java_result.total_findings == 1
    assert java_result.findings[0].rule_id == "JAVA-R002"


def test_directory_scan_picks_all_languages(engine):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    samples_dir = os.path.join(base_dir, "samples")

    result = engine.scan_directory(samples_dir)
    assert result.scanned_files_count >= 5  # .py, .js, .java

    rule_ids = {f.rule_id for f in result.findings}
    # Verifica que achados de Python, JS e Java foram detectados na pasta
    has_py = any(rid.startswith("PY-") for rid in rule_ids)
    has_js = any(rid.startswith("JS-") for rid in rule_ids)
    has_java = any(rid.startswith("JAVA-") for rid in rule_ids)

    assert has_py is True
    assert has_js is True
    assert has_java is True
