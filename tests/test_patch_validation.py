"""Independent patch gate regressions; target application code is never run."""
from pathlib import Path

import pytest

from engine.languages.java_scanner import JavaScanner
from engine.languages.javascript_scanner import JavaScriptScanner
from engine.languages.python_scanner import PythonScanner
from engine.patch_validation import validate_file_patch


MYSQL_SOURCE = '''const mysql = require("mysql2");
const db = mysql.createConnection({});
app.get("/usuario", (req, res) => {
  const id = req.query.id;
  const sql = "SELECT * FROM usuarios WHERE id = " + id;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({error: "Erro interno"});
    res.json(rows);
  });
});'''
MYSQL_PATCH = MYSQL_SOURCE.replace('"SELECT * FROM usuarios WHERE id = " + id', '"SELECT * FROM usuarios WHERE id = ?"').replace("db.query(sql, (err, rows)", "db.query(sql, [id], (err, rows)")

COMMAND_SOURCE = '''const {exec} = require("node:child_process");
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec("ping -c 1 " + host, (err, stdout) => {
    if (err) return res.status(500).send("Erro no ping");
    res.type("text/plain").send(stdout);
  });
});'''
COMMAND_PATCH = '''const {execFile} = require("node:child_process");
const {isIP} = require("node:net");
app.get("/ping", (req, res) => {
  const host = req.query.host;
  if (typeof host !== "string" || !isIP(host)) return res.status(400).send("Host inválido");
  execFile("ping", ["-c", "1", host], {shell:false}, (err, stdout) => {
    if (err) return res.status(500).send("Erro no ping");
    res.type("text/plain").send(stdout);
  });
});'''


def finding(source, rule, filename="route.js"):
    scanner = PythonScanner() if filename.endswith(".py") else JavaScanner() if filename.endswith(".java") else JavaScriptScanner()
    findings, errors = scanner.scan_source(source, filename)
    assert not errors
    return next(item for item in findings if item.rule_id == rule)


def check(result, name):
    return next(item for item in result["checks"] if item["name"] == name)


def test_accepts_mysql_patch_with_real_placeholders_and_callback_preserved():
    result = validate_file_patch(finding(MYSQL_SOURCE, "JS-R005"), MYSQL_SOURCE, MYSQL_PATCH)
    assert result["status"] == "passed", result
    assert check(result, "sql_driver_parameters")["status"] == "passed"
    assert check(result, "preserved_contracts")["status"] == "passed"


def test_rejects_postgres_placeholder_with_mysql_driver():
    result = validate_file_patch(finding(MYSQL_SOURCE, "JS-R005"), MYSQL_SOURCE, MYSQL_PATCH.replace("id = ?", "id = $1"))
    assert result["status"] == "rejected"
    assert check(result, "sql_driver_parameters")["status"] == "failed"
    assert "PostgreSQL" in check(result, "sql_driver_parameters")["detail"]


def test_rejects_question_placeholder_with_postgres_driver():
    original = MYSQL_SOURCE.replace('require("mysql2")', 'require("pg")')
    proposed = MYSQL_PATCH.replace('require("mysql2")', 'require("pg")')
    result = validate_file_patch(finding(original, "JS-R005"), original, proposed)
    assert result["status"] == "rejected"
    assert check(result, "sql_driver_parameters")["status"] == "failed"


def test_accepts_postgres_placeholder_with_driver_evidence():
    original = MYSQL_SOURCE.replace('require("mysql2")', 'require("pg")')
    proposed = MYSQL_PATCH.replace('require("mysql2")', 'require("pg")').replace("id = ?", "id = $1")
    result = validate_file_patch(finding(original, "JS-R005"), original, proposed)
    assert result["status"] == "passed", result


@pytest.mark.parametrize("sql,values", [("id = '?'", "[id]"), ("id = ? AND name = ?", "[id]"), ("id = ?", "null")])
def test_rejects_quoted_placeholder_missing_values_and_arity_mismatch(sql, values):
    proposed = MYSQL_PATCH.replace("id = ?", sql).replace("[id]", values)
    result = validate_file_patch(finding(MYSQL_SOURCE, "JS-R005"), MYSQL_SOURCE, proposed)
    assert result["status"] == "rejected"
    assert check(result, "sql_driver_parameters")["status"] == "failed"


def test_rejects_removed_mysql_callback_and_http_response():
    proposed = MYSQL_PATCH[:MYSQL_PATCH.index("  db.query")] + "  db.query(sql, [id]);\n});"
    result = validate_file_patch(finding(MYSQL_SOURCE, "JS-R005"), MYSQL_SOURCE, proposed)
    assert result["status"] == "rejected"
    assert check(result, "preserved_contracts")["status"] == "failed"
    assert "Callback sql" in check(result, "preserved_contracts")["detail"]


def test_rejects_removed_error_branch_even_when_callback_remains():
    proposed = MYSQL_PATCH.replace('    if (err) return res.status(500).json({error: "Erro interno"});\n', "")
    result = validate_file_patch(finding(MYSQL_SOURCE, "JS-R005"), MYSQL_SOURCE, proposed)
    assert result["status"] == "rejected"
    assert check(result, "preserved_contracts")["status"] == "failed"


def test_accepts_command_patch_and_rejects_invented_hostip_reference():
    target = finding(COMMAND_SOURCE, "JS-R003")
    valid = validate_file_patch(target, COMMAND_SOURCE, COMMAND_PATCH)
    assert valid["status"] == "passed", valid
    bad = COMMAND_PATCH.replace('["-c", "1", host]', '["-c", "1", hostIp]')
    result = validate_file_patch(target, COMMAND_SOURCE, bad)
    assert result["status"] == "rejected"
    assert check(result, "new_references")["status"] == "failed"
    assert "hostIp" in check(result, "new_references")["detail"]


def test_new_identifier_in_an_unrelated_scope_does_not_validate_hostip():
    proposed = COMMAND_PATCH.replace('["-c", "1", host]', '["-c", "1", hostIp]') + '\nfunction unrelated(){ const hostIp="127.0.0.1"; return hostIp; }'
    result = validate_file_patch(finding(COMMAND_SOURCE, "JS-R003"), COMMAND_SOURCE, proposed)
    assert result["status"] == "rejected"
    assert "hostIp" in check(result, "new_references")["detail"]


def test_reference_property_name_is_not_a_value_declaration():
    original = COMMAND_SOURCE + '\nconst documentation={hostIp: "example"};'
    proposed = COMMAND_PATCH.replace('["-c", "1", host]', '["-c", "1", hostIp]') + '\nconst documentation={hostIp: "example"};'
    result = validate_file_patch(finding(original, "JS-R003"), original, proposed)
    assert result["status"] == "rejected"
    assert "hostIp" in check(result, "new_references")["detail"]


def test_rejects_new_vulnerability_despite_removal_of_target():
    proposed = MYSQL_PATCH + '\neval(req.body.code);'
    result = validate_file_patch(finding(MYSQL_SOURCE, "JS-R005"), MYSQL_SOURCE, proposed)
    assert check(result, "target_occurrence")["status"] == "passed"
    assert result["status"] == "rejected"
    assert check(result, "no_new_findings")["status"] == "failed"


def test_line_shifts_do_not_turn_existing_findings_into_new_findings():
    original = MYSQL_SOURCE + '\neval(existingInput);'
    proposed = '\n// Preserved existing unrelated issue\n\n' + MYSQL_PATCH + '\n\neval(existingInput);'
    result = validate_file_patch(finding(original, "JS-R005"), original, proposed)
    assert result["status"] == "passed", result
    assert check(result, "no_new_findings")["status"] == "passed"


def test_rejects_removing_different_occurrence_while_selected_one_remains():
    original = 'eval(first);\neval(second);'
    proposed = 'eval(first);\nJSON.parse(second);'
    target = finding(original, "JS-R001")
    result = validate_file_patch(target, original, proposed)
    assert result["status"] == "rejected"
    assert check(result, "target_occurrence")["status"] == "failed"


def test_rejects_target_not_present_in_original_file():
    target = finding(MYSQL_SOURCE, "JS-R005").model_copy(update={"line_number": 999})
    result = validate_file_patch(target, MYSQL_SOURCE, MYSQL_PATCH)
    assert result["status"] == "rejected"
    assert check(result, "target_occurrence")["status"] == "failed"


def test_rejects_route_path_change():
    result = validate_file_patch(finding(MYSQL_SOURCE, "JS-R005"), MYSQL_SOURCE, MYSQL_PATCH.replace('"/usuario"', '"/other"'))
    assert result["status"] == "rejected"
    assert "rota" in check(result, "preserved_contracts")["detail"]


def test_rejects_removed_named_function_return():
    original = 'function parseInput(raw) { return eval(raw); }'
    proposed = 'function parseInput(raw) { JSON.parse(raw); }'
    result = validate_file_patch(finding(original, "JS-R001"), original, proposed)
    assert result["status"] == "rejected"
    assert "retorno" in check(result, "preserved_contracts")["detail"]


def test_rejects_removing_implicit_arrow_return():
    original = 'const parseInput = raw => eval(raw);'
    proposed = 'const parseInput = raw => { JSON.parse(raw); };'
    result = validate_file_patch(finding(original, "JS-R001"), original, proposed)
    assert result["status"] == "rejected"
    assert "retorno" in check(result, "preserved_contracts")["detail"]


def test_changed_existing_finding_counts_as_new_even_if_total_is_unchanged():
    original = MYSQL_SOURCE + '\neval(firstInput);'
    proposed = MYSQL_PATCH + '\neval(otherInput);'
    result = validate_file_patch(finding(original, "JS-R005"), original, proposed)
    assert result["status"] == "rejected"
    assert check(result, "no_new_findings")["status"] == "failed"


def test_unknown_sql_driver_still_requires_parameterization_evidence():
    original = 'const sql="SELECT * FROM users WHERE id="+id; db.query(sql);'
    proposed = 'const sql="SELECT * FROM users WHERE id=1"; db.query(sql);'
    result = validate_file_patch(finding(original, "JS-R005"), original, proposed)
    assert result["status"] == "rejected"
    assert check(result, "sql_driver_parameters")["status"] == "failed"


def test_unknown_sql_driver_reports_dialect_not_run_when_parameters_are_present():
    original = 'const sql="SELECT * FROM users WHERE id="+id; db.query(sql);'
    proposed = 'const sql="SELECT * FROM users WHERE id=?"; db.query(sql,[id]);'
    result = validate_file_patch(finding(original, "JS-R005"), original, proposed)
    assert result["status"] == "passed", result
    assert check(result, "sql_driver_parameters")["status"] == "not_run"


def test_new_declared_javascript_class_is_not_an_invented_reference():
    original = 'const SECRET_KEY="demo-secret-key";'
    proposed = 'class Vault { static load(name) { return process.env[name]; } } const SECRET_KEY=Vault.load("SECRET_KEY");'
    result = validate_file_patch(finding(original, "JS-R002"), original, proposed)
    assert result["status"] == "passed", result


def test_python_ast_symtable_accepts_import_and_rejects_invented_reference():
    original = 'def parse_input(raw):\n    return eval(raw)\n'
    proposed = 'import ast\ndef parse_input(raw):\n    return ast.literal_eval(raw)\n'
    target = finding(original, "PY-R001", "parser.py")
    valid = validate_file_patch(target, original, proposed)
    assert valid["status"] == "passed", valid
    invalid = validate_file_patch(target, original, proposed.replace("ast.literal_eval(raw)", "ast.literal_eval(payload)"))
    assert invalid["status"] == "rejected"
    assert "payload" in check(invalid, "new_references")["detail"]


def test_python_missing_import_is_rejected():
    original = 'def parse_input(raw):\n    return eval(raw)\n'
    proposed = 'def parse_input(raw):\n    return ast.literal_eval(raw)\n'
    result = validate_file_patch(finding(original, "PY-R001", "parser.py"), original, proposed)
    assert result["status"] == "rejected"
    assert "ast" in check(result, "new_references")["detail"]


def test_python_read_before_new_local_definition_is_rejected():
    original = 'def parse_input(raw):\n    return eval(raw)\n'
    proposed = 'import ast\ndef parse_input(raw):\n    result=payload\n    payload=ast.literal_eval(raw)\n    return result\n'
    result = validate_file_patch(finding(original, "PY-R001", "parser.py"), original, proposed)
    assert result["status"] == "rejected"
    assert "payload (antes da definição local)" in check(result, "new_references")["detail"]


def test_python_route_and_function_contract_are_preserved():
    original = '@app.get("/parse")\ndef parse_input(raw):\n    return eval(raw)\n'
    proposed = 'import ast\n@app.get("/other")\ndef parse_input(raw):\n    return ast.literal_eval(raw)\n'
    result = validate_file_patch(finding(original, "PY-R001", "parser.py"), original, proposed)
    assert result["status"] == "rejected"
    assert "rota" in check(result, "preserved_contracts")["detail"]


def test_java_declares_reference_resolution_and_compilation_not_run():
    original = 'class Demo { static final String PASSWORD="demo-password-1234"; }'
    proposed = 'class Demo { static final String PASSWORD=System.getenv("PASSWORD"); }'
    result = validate_file_patch(finding(original, "JAVA-R002", "Demo.java"), original, proposed)
    assert result["status"] == "passed", result
    assert check(result, "new_references")["status"] == "not_run"
    assert check(result, "typecheck")["status"] == "not_run"


def test_java_return_contract_is_checked_even_without_compilation():
    original = 'class Demo { static final String PASSWORD="demo-password-1234"; static String get(){return PASSWORD;} }'
    proposed = 'class Demo { static final String PASSWORD=System.getenv("PASSWORD"); static String get(){System.getenv("PASSWORD");} }'
    result = validate_file_patch(finding(original, "JAVA-R002", "Demo.java"), original, proposed)
    assert result["status"] == "rejected"
    assert "retorno" in check(result, "preserved_contracts")["detail"]


def test_malformed_patch_is_rejected_and_dependent_checks_not_run():
    result = validate_file_patch(finding(MYSQL_SOURCE, "JS-R005"), MYSQL_SOURCE, 'function broken( {')
    assert result["status"] == "rejected"
    assert check(result, "proposed_syntax")["status"] == "failed"
    assert check(result, "target_occurrence")["status"] == "not_run"


def test_static_check_never_executes_target_code(tmp_path):
    marker = tmp_path / "TARGET_CODE_WAS_EXECUTED"
    side_effect = 'from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("EXECUTED")\n'
    original = side_effect + 'def parse_input(raw):\n    return eval(raw)\n'
    proposed = 'import ast\n' + side_effect + 'def parse_input(raw):\n    return ast.literal_eval(raw)\n'
    result = validate_file_patch(finding(original, "PY-R001", "parser.py"), original, proposed)
    assert result["status"] == "passed", result
    assert not marker.exists()
    assert check(result, "application_tests")["status"] == "not_run"
    assert check(result, "os_sandbox")["status"] == "not_run"
    assert check(result, "behavioral_equivalence")["status"] == "not_run"


def test_temporary_workspace_is_cleaned_and_limitations_are_explicit(monkeypatch, tmp_path):
    import engine.patch_validation as validation
    real_directory = validation.tempfile.TemporaryDirectory
    created = []
    def directory(**kwargs):
        instance = real_directory(dir=tmp_path, **kwargs)
        created.append(Path(instance.name))
        return instance
    monkeypatch.setattr(validation.tempfile, "TemporaryDirectory", directory)
    result = validate_file_patch(finding(MYSQL_SOURCE, "JS-R005"), MYSQL_SOURCE, MYSQL_PATCH)
    assert result["status"] == "passed", result
    assert created and all(not item.exists() for item in created)
    assert all(item["status"] in {"passed", "failed", "not_run"} for item in result["checks"])
    assert any("equivalência" in limitation for limitation in result["limitations"])


@pytest.mark.parametrize("proposal", ["", "   ", None])
def test_empty_or_missing_file_is_rejected(proposal):
    result = validate_file_patch(finding(MYSQL_SOURCE, "JS-R005"), MYSQL_SOURCE, proposal)
    assert result["status"] == "rejected"
    assert result["errors"]
