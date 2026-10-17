import os
import pytest
from engine.engine import SASTEngine
from engine.models import Severity


@pytest.fixture
def engine():
    return SASTEngine()


def test_eval_exec_detection(engine):
    code = """
def calculate(data):
    return eval(data)

def execute_block(stmt):
    exec(stmt)
"""
    result = engine.scan_code(code, "test_eval.py")
    assert result.total_findings == 2
    rule_ids = [f.rule_id for f in result.findings]
    assert rule_ids == ["PY-R001", "PY-R001"]
    assert result.summary_by_severity["CRITICAL"] == 2


def test_hardcoded_secrets_detection(engine):
    code = """
db_password = "SecretPassword123"
api_key: str = "AKIAIOSFODNN7EXAMPLE"
config = {
    "jwt_secret": "my-ultra-secret-key-1234"
}
"""
    result = engine.scan_code(code, "test_secrets.py")
    assert result.total_findings == 3
    for f in result.findings:
        assert f.rule_id == "PY-R002"
        assert f.severity == Severity.HIGH


def test_command_injection_detection(engine):
    code = """
import os
import subprocess

def run_ip(ip):
    os.system("ping " + ip)
    subprocess.Popen("ls " + ip, shell=True)
    subprocess.run("dir", shell=True)
"""
    result = engine.scan_code(code, "test_cmd_injection.py")
    assert result.total_findings == 3
    for f in result.findings:
        assert f.rule_id == "PY-R003"
        assert f.severity == Severity.CRITICAL


def test_secure_code_has_zero_findings(engine):
    code = """
import os
import json
import subprocess

db_password = os.getenv("DB_PASSWORD", "")
api_key = os.environ.get("API_KEY")

def safe_calc(val):
    return json.loads(val)

def safe_exec():
    subprocess.run(["ping", "127.0.0.1"], shell=False)
"""
    result = engine.scan_code(code, "test_secure.py")
    assert result.total_findings == 0
    assert result.summary_by_severity["CRITICAL"] == 0
    assert result.summary_by_severity["HIGH"] == 0


def test_syntax_error_handled_gracefully(engine):
    broken_code = """
def invalid_func(
    print("broken syntax without closing parenthesis"
"""
    result = engine.scan_code(broken_code, "broken.py")
    assert result.has_errors is True
    assert len(result.errors) == 1
    assert "Erro de sintaxe" in result.errors[0]
    assert result.total_findings == 0


def test_samples_files_exist_and_validate(engine):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    vuln_path = os.path.join(base_dir, "samples", "vulnerable_sample.py")
    sec_path = os.path.join(base_dir, "samples", "secure_sample.py")

    assert os.path.exists(vuln_path)
    assert os.path.exists(sec_path)

    vuln_res = engine.scan_file(vuln_path)
    assert vuln_res.total_findings > 0
    assert vuln_res.summary_by_severity["CRITICAL"] >= 2
    assert vuln_res.summary_by_severity["HIGH"] >= 2

    sec_res = engine.scan_file(sec_path)
    assert sec_res.total_findings == 0
