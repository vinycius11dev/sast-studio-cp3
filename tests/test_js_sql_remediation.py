import json

import pytest

from engine.ai_remediation import AIRemediationEngine, RemediationUnavailable
from engine.languages.javascript_scanner import JavaScriptScanner


MYSQL_ROUTE = '''
const express = require("express");
const mysql = require("mysql2");
const app = express();
const db = mysql.createConnection({});

app.get("/usuario", (req, res) => {
  const id = req.query.id;
  const sql = "SELECT * FROM usuarios WHERE id = " + id;
  db.query(sql, (err, rows) => {
    if (err) {
      return res.status(500).json({ erro: "Erro interno do servidor" });
    }
    res.json(rows);
  });
});
'''

SAFE_MYSQL_ROUTE = '''
const express = require("express");
const mysql = require("mysql2");
const app = express();
const db = mysql.createConnection({});

app.get("/usuario", (req, res) => {
  const id = req.query.id;
  const sql = "SELECT * FROM usuarios WHERE id = ?";
  db.query(sql, [id], (err, rows) => {
    if (err) {
      return res.status(500).json({ erro: "Erro interno do servidor" });
    }
    res.json(rows);
  });
});
'''

SAFE_MYSQL_BLOCK = '''app.get("/usuario", (req, res) => {
  const id = req.query.id;
  const sql = "SELECT * FROM usuarios WHERE id = ?";
  db.query(sql, [id], (err, rows) => {
    if (err) return res.status(500).json({ erro: "Erro interno do servidor" });
    res.json(rows);
  });
});'''

UNSAFE_POSTGRES_PLACEHOLDER = SAFE_MYSQL_ROUTE.replace(
    "WHERE id = ?", "WHERE id = $1"
)


def _mysql_finding():
    findings, errors = JavaScriptScanner().scan_source(MYSQL_ROUTE, "routes/usuario.js")
    assert not errors
    return next(item for item in findings if item.rule_id == "JS-R005")


def _model_payload(patch):
    return json.dumps(
        {
            "risk_analysis": "A entrada era concatenada diretamente à consulta SQL.",
            "suggested_patch": patch,
            "remediation_steps": "Use o placeholder compatível com mysql2 e preserve o callback.",
        }
    )


def test_mysql2_sql_patch_retries_wrong_placeholder_and_preserves_route(monkeypatch):
    prompts = []
    responses = [UNSAFE_POSTGRES_PLACEHOLDER, SAFE_MYSQL_BLOCK]

    class FakeResponse:
        status_code = 200

        def __init__(self, patch):
            self.patch = patch

        def json(self):
            return {"response": _model_payload(self.patch)}

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json):
            prompts.append(json["prompt"])
            return FakeResponse(responses.pop(0))

    monkeypatch.setattr("engine.ai_remediation.httpx.Client", FakeClient)
    engine = AIRemediationEngine()
    monkeypatch.setattr(engine, "is_ollama_available", lambda: True)

    result = engine.remediate_finding(_mysql_finding(), original_code=MYSQL_ROUTE)

    assert result.provider == "ollama"
    assert result.patch_scope == "file"
    assert "WHERE id = ?" in result.suggested_patch
    assert "WHERE id = $1" not in result.suggested_patch
    assert "res.status(500).json" in result.suggested_patch
    assert "res.json(rows)" in result.suggested_patch
    assert "db.query(sql, [id], (err, rows) =>" in result.suggested_patch
    assert len(prompts) == 2
    assert "mysql/mysql2" in prompts[0]
    assert "Preserve exatamente a assinatura" in prompts[0]
    after, errors = JavaScriptScanner().scan_source(result.suggested_patch, "routes/usuario.js")
    assert not errors
    assert not any(item.rule_id == "JS-R005" for item in after)


def test_mysql2_sql_patch_rejects_removed_callback_and_http_response():
    engine = AIRemediationEngine()
    finding = _mysql_finding()
    broken_route = '''
const express = require("express");
const mysql = require("mysql2");
const app = express();
const db = mysql.createConnection({});

app.get("/usuario", (req, res) => {
  const id = req.query.id;
  const sql = "SELECT * FROM usuarios WHERE id = ?";
  return db.query(sql, [id]);
});
'''

    with pytest.raises(RemediationUnavailable, match="callback|resposta"):
        engine._validate_javascript_sql_file_patch(finding, MYSQL_ROUTE, broken_route)


def test_mysql2_and_postgres_fallbacks_use_their_own_placeholder():
    engine = AIRemediationEngine()
    engine.is_ollama_available = lambda: False
    finding = _mysql_finding()

    mysql_result = engine.remediate_finding(finding, original_code=MYSQL_ROUTE)
    assert "WHERE id = ?" in mysql_result.suggested_patch
    assert "WHERE id = $1" not in mysql_result.suggested_patch

    postgres_source = "const { Pool } = require('pg');\nconst db = new Pool();"
    postgres_finding = finding.model_copy(update={
        "file_path": "routes/usuario.js",
        "remediation_advice": "Use placeholders compatible with pg.",
    })
    postgres_result = engine.remediate_finding(postgres_finding, original_code=postgres_source)
    assert "WHERE id = $1" in postgres_result.suggested_patch\n