from engine.ai_remediation import AIRemediationEngine
from engine.languages.javascript_scanner import JavaScriptScanner


COMMAND_SOURCE = '''
const express = require("express");
const { exec } = require("node:child_process");
const app = express();
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec("ping -c 1 " + host, (error, stdout) => {
    if (error) return res.status(500).send("Falha no ping");
    res.send(stdout);
  });
});
'''

SAFE_COMMAND_PATCH = '''
const express = require("express");
const { execFile } = require("node:child_process");
const { isIP } = require("node:net");
const app = express();
app.get("/ping", (req, res) => {
  const host = req.query.host;
  if (typeof host !== "string" || !isIP(host)) {
    return res.status(400).json({ error: "Host inválido" });
  }
  execFile("ping", ["-c", "1", host], { shell: false }, (error, stdout) => {
    if (error) return res.status(500).send("Falha no ping");
    res.send(stdout);
  });
});
'''


def _finding(source, rule_id, file_path="app.js"):
    findings, errors = JavaScriptScanner().scan_source(source, file_path)
    assert not errors
    return next(item for item in findings if item.rule_id == rule_id)


def test_command_patch_rejects_invented_identifier_and_requires_validation():
    engine = AIRemediationEngine()
    finding = _finding(COMMAND_SOURCE, "JS-R003")
    bad_patch = SAFE_COMMAND_PATCH.replace("host]", "hostIp]")
    missing_guard = SAFE_COMMAND_PATCH.replace(
        '  if (typeof host !== "string" || !isIP(host)) {\n'
        '    return res.status(400).json({ error: "Host inválido" });\n'
        '  }\n',
        "",
    )

    assert not engine._is_safe_model_patch(finding, bad_patch, COMMAND_SOURCE)
    assert not engine._is_safe_model_patch(finding, missing_guard, COMMAND_SOURCE)
    assert engine._is_safe_model_patch(finding, SAFE_COMMAND_PATCH, COMMAND_SOURCE)


def test_eval_remediation_requires_review_instead_of_assuming_json():
    source = "function evaluate(input) { return eval(input); }"
    finding = _finding(source, "JS-R001")
    result = AIRemediationEngine().remediate_finding(finding, source)

    assert result.patch_scope == "manual_review"
    assert result.suggested_patch == ""
    assert result.diff == ""
    assert "JSON.parse" in result.remediation_steps
    assert "JSON.parse(input)" not in result.suggested_patch


def test_hardcoded_secret_fallback_has_no_empty_default_and_fails_fast():
    source = 'const API_TOKEN = "demo-secret-value";'
    finding = _finding(source, "JS-R002", "server/config.js")
    engine = AIRemediationEngine()
    result = engine._generate_heuristic_remediation(finding, source)

    assert "process.env.API_TOKEN" in result.suggested_patch
    assert 'if (!API_TOKEN)' in result.suggested_patch
    assert "throw new Error" in result.suggested_patch
    assert '|| ""' not in result.suggested_patch
    assert "demo-secret-value" not in result.suggested_patch
    assert engine._is_environment_based_secret_patch(finding, result.suggested_patch, source)


def test_command_fallback_does_not_offer_unvalidated_or_invented_patch():
    finding = _finding(COMMAND_SOURCE, "JS-R003")
    result = AIRemediationEngine()._generate_heuristic_remediation(finding, COMMAND_SOURCE)

    assert result.patch_scope == "manual_review"
    assert result.suggested_patch == ""
    assert result.diff == ""
    assert "host" in result.remediation_steps
    assert "hostIp" not in result.remediation_steps
