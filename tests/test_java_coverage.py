"""Reference cases for Java's supported APIs, including safe counterparts.

These curated cases measure regressions in documented patterns. Passing them is
not a claim about recall on arbitrary Java projects or third-party benchmarks.
"""
from collections import Counter
import json
from pathlib import Path

import pytest

from engine.languages.java_scanner import JavaScanner


REFERENCE = Path(__file__).resolve().parents[1] / "benchmarks" / "coverage_java.json"
CASES = json.loads(REFERENCE.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_java_reference_case(case):
    findings, errors = JavaScanner().scan_source(case["code"], case["filename"])
    assert errors == []
    assert Counter(finding.rule_id for finding in findings) == Counter(case["expected_rules"])
    for expected in case.get("expected_locations", []):
        assert any(finding.rule_id == expected["rule_id"] and finding.line_number == expected["line_number"] for finding in findings)


def test_class_fields_are_not_shared_between_classes():
    source = '''
class Vulnerable {
  String sql = "SELECT * FROM users WHERE name=" + input;
  void run() { stmt.executeQuery(sql); }
}
class Safe {
  String sql = "SELECT 1";
  void run() { stmt.executeQuery(sql); }
}
'''
    findings, errors = JavaScanner().scan_source(source, "Services.java")
    assert not errors
    assert [(finding.rule_id, finding.line_number) for finding in findings] == [("JAVA-R001", 4)]


def test_lexical_shadow_does_not_hide_vulnerable_field_from_this():
    source = '''
class Repository {
  String sql = "SELECT * FROM users WHERE id=" + input;
  void run() {
    String sql = "SELECT 1";
    stmt.executeQuery(sql);
    stmt.executeQuery(this.sql);
  }
}
'''
    findings, errors = JavaScanner().scan_source(source, "Repository.java")
    assert not errors
    assert [(finding.rule_id, finding.line_number) for finding in findings] == [("JAVA-R001", 7)]


def test_sibling_block_assignment_cannot_mark_a_different_local_variable_safe():
    source = '''
class Repository {
  void run(String input) {
    String sql = "SELECT * FROM users WHERE id=" + input;
    if (input.isEmpty()) { sql = "SELECT 1"; }
    stmt.executeQuery(sql);
  }
}
'''
    findings, errors = JavaScanner().scan_source(source, "Repository.java")
    assert not errors
    assert [finding.rule_id for finding in findings] == ["JAVA-R001"]


def test_xxe_flags_in_another_method_do_not_suppress_the_parser():
    source = '''
class XmlParser {
  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
  void configureOtherMethod() {
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  }
  void run(InputStream source) {
    DocumentBuilder builder = factory.newDocumentBuilder();
    builder.parse(source);
  }
}
'''
    findings, errors = JavaScanner().scan_source(source, "XmlParser.java")
    assert not errors
    assert [finding.rule_id for finding in findings] == ["JAVA-R008"]


@pytest.mark.parametrize("statement", [
    'if (enabled) { sql = input; }',
    'if (enabled) sql = input;',
    'while (enabled) { sql = input; }',
])
def test_conditional_unsafe_assignments_taint_the_join(statement):
    source = 'class Repository {void run(String input, boolean enabled) {String sql="SELECT 1"; ' + statement + ' stmt.executeQuery(sql);}}'
    findings, errors = JavaScanner().scan_source(source, "Repository.java")
    assert not errors
    assert [finding.rule_id for finding in findings] == ["JAVA-R001"]


def test_unconditional_overwrite_kills_previous_conditional_value():
    source = 'class Repository {void run(String input, boolean enabled) {String sql="SELECT 1"; if(enabled) {sql=input;} sql="SELECT 2"; stmt.executeQuery(sql);}}'
    findings, errors = JavaScanner().scan_source(source, "Repository.java")
    assert not errors
    assert findings == []


def test_chained_stringbuilder_append_preserves_dynamic_arguments():
    source = 'class Repository {void run(String input) {StringBuilder sql=new StringBuilder(); sql.append("SELECT ").append(input); stmt.executeQuery(sql.toString());}}'
    findings, errors = JavaScanner().scan_source(source, "Repository.java")
    assert not errors
    assert [finding.rule_id for finding in findings] == ["JAVA-R001"]


def test_conditional_xml_protection_is_insufficient():
    source = '''class Parser {
      void run(InputStream source, boolean enabled) {
        DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();
        if(enabled) f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder b=f.newDocumentBuilder(); b.parse(source);
      }
    }'''
    findings, errors = JavaScanner().scan_source(source, "Parser.java")
    assert not errors
    assert [finding.rule_id for finding in findings] == ["JAVA-R008"]


def test_conditional_path_guard_cannot_hide_traversal():
    source = '''class Reader {
      void run(String input, boolean enabled) {
        Path base=Path.of("/srv/uploads").toAbsolutePath().normalize();
        Path path=base.resolve(input).normalize();
        if (!path.startsWith(base) && enabled) {throw new IllegalArgumentException();}
        Files.readString(path);
      }
    }'''
    findings, errors = JavaScanner().scan_source(source, "Reader.java")
    assert not errors
    assert [finding.rule_id for finding in findings] == ["JAVA-R005"]


@pytest.mark.parametrize("sink", [
    'stmt.executeQuery("SELECT * FROM users WHERE name=" + alias);',
    'response.getWriter().write(alias);',
])
def test_alias_preserves_conditional_array_input(sink):
    source = '''class Repository {
      void run(String[] values) {
        String value="";
        if(values != null) value=values[0];
        String alias=value;
    ''' + sink + '''
      }
    }'''
    findings, errors = JavaScanner().scan_source(source, "Repository.java")
    assert not errors
    assert len(findings) == 1
    assert findings[0].rule_id == ("JAVA-R001" if "executeQuery" in sink else "JAVA-R007")


@pytest.mark.parametrize("definition", [
    'if(values != null) value="safe";',
    'if(values != null) value=values[0]; value="safe";',
])
def test_alias_with_only_constant_or_overwritten_branch_values_is_safe(definition):
    source = 'class Repository {void run(String[] values) {String value=""; ' + definition + ' String alias=value; stmt.executeQuery("SELECT "+alias);}}'
    findings, errors = JavaScanner().scan_source(source, "Repository.java")
    assert not errors
    assert findings == []


@pytest.mark.parametrize("setup,command", [
    ('', 'pb.command("sh", "-c", input);'),
    ('String[] command={"sh", "-c", input};', 'pb.command(command);'),
    ('List<String> command=new ArrayList<String>(); command.add("sh"); command.add("-c"); command.add(input);', 'pb.command(command);'),
    ('List<String> command=new ArrayList<String>(); if(windows) {command.add("cmd.exe");command.add("/c");} else {command.add("sh");command.add("-c");} command.add("echo "+input);', 'pb.command(command);'),
    ('List<String> original=new ArrayList<String>(); original.add("sh"); original.add("-c"); original.add(input); List<String> command=original;', 'pb.command(command);'),
])
def test_empty_processbuilder_receives_dynamic_shell_command(setup, command):
    source = 'class Runner {void run(String input, boolean windows) { ' + setup + ' ProcessBuilder pb=new ProcessBuilder(); ' + command + ' pb.start();}}'
    findings, errors = JavaScanner().scan_source(source, "Runner.java")
    assert not errors
    assert [finding.rule_id for finding in findings] == ["JAVA-R003"]


@pytest.mark.parametrize("setup,command", [
    ('', 'pb.command("/usr/bin/ping", "-c", "1", input);'),
    ('String[] command={"/usr/bin/ping", "-c", "1", input};', 'pb.command(command);'),
    ('List<String> command=new ArrayList<String>(); command.add("/usr/bin/ping"); command.add("-c"); command.add("1"); command.add(input);', 'pb.command(command);'),
    ('', 'pb.command(List.of("/usr/bin/ping", input));'),
    ('', 'pb.command(Arrays.asList("/usr/bin/ping", input));'),
    ('', 'pb.command("sh", "-c", "echo fixed");'),
])
def test_fixed_processbuilder_executable_preserves_argument_boundary(setup, command):
    source = 'class Runner {void run(String input) { ' + setup + ' ProcessBuilder pb=new ProcessBuilder(); ' + command + ' pb.start();}}'
    findings, errors = JavaScanner().scan_source(source, "Runner.java")
    assert not errors
    assert findings == []


def test_fixed_processbuilder_array_constructor_does_not_become_shell_injection():
    source = 'class Runner {void run(String input) {new ProcessBuilder(new String[]{"/usr/bin/ping", "-c", "1", input}).start();}}'
    findings, errors = JavaScanner().scan_source(source, "Runner.java")
    assert not errors
    assert findings == []


@pytest.mark.parametrize("mutation", [
    'command[0]=input;',
    'if(enabled) command[0]=input;',
])
def test_mutated_array_executable_is_not_mistaken_for_fixed_command(mutation):
    source = 'class Runner {void run(String input, boolean enabled) {String[] command={"/usr/bin/id"}; ' + mutation + ' new ProcessBuilder(command).start();}}'
    findings, errors = JavaScanner().scan_source(source, "Runner.java")
    assert not errors
    assert [finding.rule_id for finding in findings] == ["JAVA-R003"]


def test_unknown_list_mutation_does_not_prove_a_safe_executable():
    source = 'class Runner {void run(String input) {List<String> command=Arrays.asList("/usr/bin/id"); command.set(0,input); ProcessBuilder pb=new ProcessBuilder(); pb.command(command); pb.start();}}'
    findings, errors = JavaScanner().scan_source(source, "Runner.java")
    assert not errors
    assert [finding.rule_id for finding in findings] == ["JAVA-R003"]


def test_conditional_constant_shell_executables_remain_shells():
    source = '''class Runner {void run(String input, boolean windows) {
      String executable="";
      if(windows) executable="cmd.exe"; else executable="sh";
      String[] command={executable,"-c",input};
      new ProcessBuilder(command).start();
    }}'''
    findings, errors = JavaScanner().scan_source(source, "Runner.java")
    assert not errors
    assert [finding.rule_id for finding in findings] == ["JAVA-R003"]


def test_conditional_fixed_non_shell_executables_preserve_argument_boundary():
    source = '''class Runner {void run(String input, boolean enabled) {
      String executable="/usr/bin/ping";
      if(enabled) executable="/usr/local/bin/ping";
      String[] command={executable,"-c","1",input};
      new ProcessBuilder(command).start();
    }}'''
    findings, errors = JavaScanner().scan_source(source, "Runner.java")
    assert not errors
    assert findings == []


def test_parse_failure_is_explicit_and_does_not_return_a_clean_success():
    findings, errors = JavaScanner().scan_source("class Broken { void run( {", "Broken.java")
    assert findings == []
    assert errors and "Análise incompleta" in errors[0]


def test_original_java_rule_identifiers_remain_stable():
    rules = {rule.rule_id: rule.cwe for rule in JavaScanner().list_rules()}
    assert {key: rules[key] for key in (f"JAVA-R00{number}" for number in range(1, 7))} == {
        "JAVA-R001": "CWE-89", "JAVA-R002": "CWE-798", "JAVA-R003": "CWE-78",
        "JAVA-R004": "CWE-502", "JAVA-R005": "CWE-22", "JAVA-R006": "CWE-918",
    }
