"""GS CitizenTech: Taint Analysis de PII, da origem sensível até a saída insegura."""
import pytest

from engine.engine import SASTEngine
from engine.models import Severity


@pytest.fixture
def engine():
    return SASTEngine()


def leaks(engine, code):
    result = engine.scan_code(code, "servico.py")
    return [finding for finding in result.findings if finding.rule_id.startswith("PY-T00") and finding.rule_id >= "PY-T004"]


def test_cpf_to_log_through_fstring_keeps_trace(engine):
    code = (
        "import logging\n"
        "logger = logging.getLogger('x')\n"
        "def atender(paciente):\n"
        "    cpf = paciente['cpf']\n"
        "    mensagem = f'Atendimento de {cpf}'\n"
        "    logger.info(mensagem)\n"
    )
    [finding] = leaks(engine, code)
    assert finding.rule_id == "PY-T004" and finding.cwe == "CWE-532"
    assert finding.severity == Severity.HIGH and finding.data_categories == ["documento"]
    assert finding.line_number == 6
    assert finding.taint_trace[0].startswith("campo 'cpf' de paciente (linha 4)")
    assert [step.split(" (")[0] for step in finding.taint_trace[1:3]] == ["cpf", "mensagem"]
    assert finding.taint_trace[-1].endswith("← saída insegura")


def test_health_and_password_in_console_are_critical(engine):
    code = "def f(diagnostico, senha):\n    print(diagnostico)\n    print('x', senha)\n"
    found = leaks(engine, code)
    assert [item.severity for item in found] == [Severity.CRITICAL, Severity.CRITICAL]
    assert {tuple(item.data_categories) for item in found} == {("saude",), ("senha",)}


@pytest.mark.parametrize("code", [
    "def f(cpf):\n    print(mascarar_cpf(cpf))\n",
    "def f(cpf):\n    cpf = mask(cpf)\n    print(cpf)\n",
    "def f(cpf):\n    print('final', cpf[-2:])\n",
    "def f(senha):\n    print(hashlib.sha256(senha.encode()).hexdigest())\n",
    "def f(senha):\n    senha_hash = bcrypt.hashpw(senha, bcrypt.gensalt())\n    print(senha_hash)\n",
    "def f(cpf):\n    print(len(cpf), bool(cpf), is_valid_cpf(cpf))\n",
    "def f(nome, cidade):\n    print(nome, cidade)\n",
    "def f(cpf):\n    log = 'processando'\n    print(log)\n",
])
def test_sanitizers_and_clean_values_stop_the_taint(engine, code):
    assert leaks(engine, code) == []


def test_reassignment_with_clean_value_removes_taint(engine):
    code = "def f(request):\n    cpf = request.form['cpf']\n    cpf = '***'\n    print(cpf)\n"
    assert leaks(engine, code) == []


def test_branches_are_merged(engine):
    code = (
        "def f(cpf, cond):\n"
        "    if cond:\n"
        "        valor = cpf\n"
        "    else:\n"
        "        valor = 'x'\n"
        "    print(valor)\n"
    )
    assert len(leaks(engine, code)) == 1


def test_route_return_and_response_sink_are_reported_once(engine):
    code = (
        "from flask import Flask, jsonify\n"
        "app = Flask(__name__)\n"
        "@app.get('/p/<int:i>')\n"
        "def ver(i):\n"
        "    paciente = {'id': i, 'cpf': carregar(i)}\n"
        "    return jsonify(paciente)\n"
        "@app.get('/q')\n"
        "def ver2(cpf):\n"
        "    return {'documento': cpf}\n"
    )
    found = leaks(engine, code)
    assert [item.rule_id for item in found] == ["PY-T005", "PY-T005"]
    assert [item.line_number for item in found] == [6, 9]


def test_masked_response_is_safe(engine):
    code = (
        "@app.get('/p')\n"
        "def ver(cpf):\n"
        "    return jsonify({'cpf': mascarar_cpf(cpf), 'id': 1})\n"
    )
    assert leaks(engine, code) == []


def test_interprocedural_return_summary(engine):
    code = (
        "def obter(p):\n"
        "    return p.cpf\n"
        "def usar(p):\n"
        "    valor = obter(p)\n"
        "    print(valor)\n"
    )
    [finding] = leaks(engine, code)
    assert any("retorno de obter()" in step for step in finding.taint_trace)


def test_summary_works_when_callee_is_defined_later(engine):
    code = (
        "def usar(p):\n"
        "    print(obter(p))\n"
        "def obter(p):\n"
        "    return p.diagnostico\n"
    )
    assert len(leaks(engine, code)) == 1


def test_storage_and_database_rules(engine):
    code = (
        "def salvar(nome, senha, cpf, db):\n"
        "    with open('u.csv', 'a') as f:\n"
        "        f.write(f'{nome};{senha}')\n"
        "    db.execute('INSERT INTO u (senha) VALUES (%s)', (senha,))\n"
        "    db.execute('INSERT INTO u (cpf) VALUES (%s)', (cpf,))\n"
    )
    found = leaks(engine, code)
    assert [(item.rule_id, item.line_number) for item in found] == [("PY-T006", 3), ("PY-T006", 4)]
    assert all(item.severity == Severity.CRITICAL for item in found)  # CPF no banco é esperado: não acusa


def test_external_service_severity(engine):
    code = (
        "def enviar(cpf, senha):\n"
        "    requests.post('https://x.example', json={'cpf': cpf})\n"
        "    requests.post('https://x.example', data=senha)\n"
    )
    found = leaks(engine, code)
    assert [(item.rule_id, item.severity) for item in found] == [("PY-T007", Severity.MEDIUM), ("PY-T007", Severity.CRITICAL)]


def test_user_prompt_is_a_source(engine):
    code = "def f():\n    valor = input('Digite o CPF do paciente: ')\n    print(valor)\n"
    [finding] = leaks(engine, code)
    assert finding.data_categories == ["documento"] and "entrada do usuário" in finding.taint_trace[0]


def test_most_severe_category_decides_severity(engine):
    code = "def f(p):\n    print(p.cpf, p.diagnostico)\n"
    [finding] = leaks(engine, code)
    assert finding.severity == Severity.CRITICAL and finding.data_categories == ["documento", "saude"]


def test_existing_injection_taint_is_unaffected(engine):
    code = "def f(request, db):\n    nome = request.args.get('n')\n    db.execute(\"SELECT * FROM t WHERE n='\" + nome + \"'\")\n"
    ids = [item.rule_id for item in engine.scan_code(code, "x.py").findings]
    assert ids == ["PY-T001"]
