import pytest
from engine.engine import SASTEngine


@pytest.mark.parametrize("filename,source", [
    ("safe.js", 'const example = "eval(input) and node.innerHTML = value"; /* eval(input); */'),
    ("Safe.java", 'class Safe { String example = "Runtime.getRuntime().exec(input)"; /* in.readObject(); */ }'),
    ("safe.ts", 'const example: string = "eval(input)"; const id: number = 1;'),
    ("safe.tsx", 'const Button = () => <button>eval(input)</button>;'),
])
def test_ast_ignores_code_examples_in_strings_and_comments(filename, source):
    result = SASTEngine().scan_code(source, filename)
    assert result.errors == []
    assert result.findings == []


@pytest.mark.parametrize("filename,source,rule,line", [
    ("multiline.js", 'db.query(\n  "SELECT * FROM users WHERE id = " + userId\n);', "JS-R005", 1),
    ("Multi.java", 'class Multi { void run(String userId) {\n stmt.executeQuery(\n "SELECT * FROM users WHERE id = " + userId\n );\n} }', "JAVA-R001", 2),
    ("settings.ts", 'const apiKey: string = "DEMO_NOT_REAL_1234";', "JS-R002", 1),
    ("Example.tsx", 'const Box = () => { eval(input); return <div />; };', "JS-R001", 1),
])
def test_ast_detects_structural_multiline_and_typed_code(filename, source, rule, line):
    result = SASTEngine().scan_code(source, filename)
    assert result.errors == []
    assert any(f.rule_id == rule and f.line_number == line for f in result.findings)


@pytest.mark.parametrize("filename,source", [("broken.js", "function broken( {"), ("Broken.java", "class Broken { void run( {"), ("broken.ts", "const value: = ;")])
def test_syntax_errors_are_reported_instead_of_a_false_clean_scan(filename, source):
    result = SASTEngine().scan_code(source, filename)
    assert result.has_errors
    assert result.scanned_files_count == 0


def test_sql_variable_propagation_is_scoped_to_function():
    source = '''
function vulnerable(userId) {
  const sql = "SELECT * FROM users WHERE id=" + userId;
  db.query(sql);
}
function safe() {
  const sql = "SELECT * FROM users WHERE id=?";
  db.query(sql, [1]);
}
'''
    result = SASTEngine().scan_code(source, "repo.js")
    sql = [f for f in result.findings if f.rule_id == "JS-R005"]
    assert len(sql) == 1
    assert sql[0].line_number == 4


def test_static_sql_concatenation_is_not_treated_as_external_input():
    source = 'db.query("SELECT * FROM users WHERE id=" + "1");'
    assert SASTEngine().scan_code(source, "constant.js").findings == []
