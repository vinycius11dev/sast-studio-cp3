"""GS CitizenTech: regras de mapeamento de PII (CPF, saúde, senhas) e catálogo."""
import pytest

from engine.engine import SASTEngine
from engine.models import Severity
from engine.pii import classify_identifier, find_cpfs, is_valid_cpf, mask_cpf

VALID_CPF = "529.982.247-25"  # fictício: válido só pelos dígitos verificadores


@pytest.fixture
def engine():
    return SASTEngine()


def rule_ids(result):
    return [finding.rule_id for finding in result.findings]


@pytest.mark.parametrize("value,expected", [
    ("529.982.247-25", True), ("52998224725", True), ("111.111.111-11", False),
    ("529.982.247-24", False), ("123", False), ("", False),
])
def test_cpf_checksum(value, expected):
    assert is_valid_cpf(value) is expected


def test_find_cpfs_requires_format_or_whole_value():
    assert find_cpfs(f"cpf: {VALID_CPF}") == [VALID_CPF]
    assert find_cpfs("52998224725") == ["52998224725"]
    assert find_cpfs("protocolo 52998224725 emitido") == []  # 11 dígitos soltos em texto: não acusa
    assert find_cpfs("123.456.789-00") == []                  # formato certo, dígitos inválidos
    assert mask_cpf(VALID_CPF) == "***.***.***-25"


@pytest.mark.parametrize("name,category", [
    ("cpf", "documento"), ("cpf_cidadao", "documento"), ("numeroCPF", "documento"), ("rg", "documento"),
    ("diagnostico", "saude"), ("Diagnóstico", "saude"), ("historico_prontuario", "saude"), ("medicamentos", "saude"),
    ("senha", "senha"), ("password", "senha"), ("userPassword", "senha"), ("nova_senha", "senha"),
    ("senha_hash", None), ("password_hashed", None), ("cpf_mascarado", None), ("is_valid_cpf", None),
    ("password_length", None), ("nome", None), ("cidade", None), (None, None),
])
def test_classify_identifier(name, category):
    assert classify_identifier(name) == category


def test_cpf_literal_is_reported_with_masked_message(engine):
    result = engine.scan_code(f'CPF_TESTE = "{VALID_CPF}"\n', "dados.py")
    assert rule_ids(result) == ["PY-P001"]
    finding = result.findings[0]
    assert finding.severity == Severity.HIGH and finding.cwe == "CWE-359"
    assert finding.data_categories == ["documento"]
    assert VALID_CPF not in finding.message and "***.***.***-25" in finding.message


def test_invalid_or_embedded_numbers_are_not_cpf(engine):
    code = 'a = "123.456.789-00"\nb = "pedido 52998224725"\nc = "111.111.111-11"\n'
    assert engine.scan_code(code, "ok.py").findings == []


def test_health_literal_in_assignment_dict_and_keyword(engine):
    code = (
        'diagnostico = "Hipertensão arterial"\n'
        'registro = {"prontuario": "Paciente com diabetes"}\n'
        'criar(laudo="Exame alterado")\n'
    )
    result = engine.scan_code(code, "saude.py")
    assert rule_ids(result) == ["PY-P002"] * 3
    assert all(item.data_categories == ["saude"] for item in result.findings)


def test_health_placeholders_and_non_health_names_are_ignored(engine):
    code = 'diagnostico = ""\nlaudo = "teste"\nnome = "Hipertensão arterial"\n'
    assert engine.scan_code(code, "ok.py").findings == []


@pytest.mark.parametrize("expression", [
    "hashlib.md5(senha.encode()).hexdigest()",
    "hashlib.sha1(password.encode())",
    "hashlib.new('md5', senha.encode())",
])
def test_weak_password_hash(engine, expression):
    result = engine.scan_code(f"import hashlib\nvalor = {expression}\n", "auth.py")
    assert "PY-P003" in rule_ids(result)
    finding = next(item for item in result.findings if item.rule_id == "PY-P003")
    assert finding.cwe == "CWE-328" and finding.data_categories == ["senha"]


def test_strong_or_unrelated_hashes_are_not_reported(engine):
    code = (
        "import hashlib\n"
        "a = hashlib.sha256(senha.encode()).hexdigest()\n"
        "b = hashlib.md5(conteudo_do_arquivo).hexdigest()\n"
        "c = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())\n"
    )
    assert "PY-P003" not in rule_ids(engine.scan_code(code, "ok.py"))


def test_new_rules_are_listed_in_catalog(engine):
    ids = {rule.rule_id for rule in engine.list_rules()}
    assert {"PY-P001", "PY-P002", "PY-P003", "PY-T004", "PY-T005", "PY-T006", "PY-T007"} <= ids


def test_javascript_cpf_and_health_literals(engine):
    code = (
        f'const cpfTeste = "{VALID_CPF}";\n'
        'const diagnostico = "Hipertensão arterial";\n'
        'const registro = { prontuario: "Paciente com diabetes", nome: "Maria" };\n'
        'const senhaMinima = "12345678";\n'
    )
    result = engine.scan_code(code, "cadastro.js")
    assert [(item.rule_id, item.line_number) for item in result.findings if item.rule_id.startswith("JS-P")] == [
        ("JS-P001", 1), ("JS-P002", 2), ("JS-P002", 3)]
    assert {tuple(item.data_categories) for item in result.findings if item.rule_id.startswith("JS-P")} == {("documento",), ("saude",)}


def test_java_cpf_and_health_literals(engine):
    code = (
        "class Paciente {\n"
        f'    String cpf = "{VALID_CPF}";\n'
        '    String diagnostico = "Hipertensão arterial";\n'
        '    String cidade = "São Paulo";\n'
        "}\n"
    )
    result = engine.scan_code(code, "Paciente.java")
    assert [(item.rule_id, item.line_number) for item in result.findings if item.rule_id.startswith("JAVA-P")] == [
        ("JAVA-P001", 2), ("JAVA-P002", 3)]


def test_javascript_and_java_clean_code_has_no_pii_findings(engine):
    js = 'const cpf = process.env.CPF_TESTE;\nconst diagnostico = "";\nconst n = "11111111111";\n'
    java = 'class A { String diagnostico = System.getenv("D"); String n = "123.456.789-00"; }\n'
    assert engine.scan_code(js, "a.js").findings == [] and engine.scan_code(java, "A.java").findings == []
