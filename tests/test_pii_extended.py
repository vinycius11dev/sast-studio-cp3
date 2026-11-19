"""GS CitizenTech: CNS, cartão de pagamento, e-mail e telefone (validação por valor e por nome)."""
import pytest

from engine.engine import SASTEngine
from engine.pii import (
    CONTATO, FINANCEIRO, classify_identifier, find_cards, find_cns, find_emails, find_phones, is_valid_card,
    is_valid_cns, mask_card, mask_cns, mask_email, mask_phone,
)


def definitive_cns(pis: str) -> str:
    """Gera um CNS definitivo válido a partir de 11 dígitos de PIS (algoritmo oficial do SUS)."""
    total = sum(int(pis[i]) * (15 - i) for i in range(11))
    check = 11 - total % 11
    if check == 11:
        check = 0
    if check == 10:
        total += 2
        return pis + "001" + str(11 - total % 11)
    return pis + "000" + str(check)


PROVISIONAL_CNS = "700000000000005"
DEFINITIVE_CNS = definitive_cns("12345678901")
CARD = "5500 0000 0000 0004"  # Mastercard fictício com Luhn válido


def scan(code, name="t.py"):
    return SASTEngine().scan_code(code, name).findings


def rules(code, name="t.py"):
    return [item.rule_id for item in scan(code, name)]


@pytest.mark.parametrize("value,expected", [
    (PROVISIONAL_CNS, True), (DEFINITIVE_CNS, True), (definitive_cns("20000000000"), True),
    (DEFINITIVE_CNS[:-1] + str((int(DEFINITIVE_CNS[-1]) + 1) % 10), False), ("700000000000006", False),
    ("300000000000005", False), ("111111111111111", False), ("12345", False),
])
def test_cns_checksum(value, expected):
    assert is_valid_cns(value) is expected


def test_find_cns_formatted_or_whole_value_only():
    formatted = f"{PROVISIONAL_CNS[:3]} {PROVISIONAL_CNS[3:7]} {PROVISIONAL_CNS[7:11]} {PROVISIONAL_CNS[11:]}"
    assert find_cns(f"cartão {formatted}") == [formatted]
    assert find_cns(PROVISIONAL_CNS) == [PROVISIONAL_CNS]
    assert find_cns(f"protocolo {PROVISIONAL_CNS} emitido") == []
    assert mask_cns(PROVISIONAL_CNS) == "*** **** **** 0005"


@pytest.mark.parametrize("value,expected", [
    ("5500 0000 0000 0004", True), ("4532015112830366", True), ("378282246310005", False),  # Amex de teste publicado
    ("4111 1111 1111 1111", False),  # número de teste do provedor
    ("1234 5678 9012 3456", False),  # Luhn inválido e sem bandeira
    ("4532015112830367", False),     # Luhn inválido
    ("0000 0000 0000 0000", False),
])
def test_card_luhn_and_published_test_numbers(value, expected):
    assert is_valid_card(value) is expected
    assert bool(find_cards(value)) is expected


def test_find_cards_ignores_digits_inside_text():
    assert find_cards("pedido 4532015112830366 enviado") == []
    assert mask_card(CARD) == "**** **** **** 0004"


def test_find_emails_ignores_examples_and_role_mailboxes():
    assert find_emails("fale com maria.silva@gmail.com") == ["maria.silva@gmail.com"]
    for ignored in ("teste@example.com", "fulano@exemplo.com.br", "contato@empresa.com", "suporte@orgao.gov.br",
                    "a@b.test", "no-reply@servico.com"):
        assert find_emails(ignored) == [], ignored
    assert mask_email("maria.silva@gmail.com") == "m***@gmail.com"


def test_find_phones_requires_format_and_real_ddd():
    assert find_phones("ligar (11) 91234-5678") == ["(11) 91234-5678"]
    assert find_phones("+55 21 98765-4321") == ["+55 21 98765-4321"]  # sem duplicar o trecho interno
    assert find_phones("11 98765-4321") == ["11 98765-4321"]
    for ignored in ("(00) 91234-5678", "(11) 99999-9999", "11987654321", "protocolo 91234-5678", "2024-11-16"):
        assert find_phones(ignored) == [], ignored
    assert mask_phone("(11) 91234-5678") == "(**) *****-5678"


@pytest.mark.parametrize("name,category", [
    ("email", CONTATO), ("email_paciente", CONTATO), ("e_mail", CONTATO), ("telefone", CONTATO), ("celularContato", CONTATO),
    ("numero_cartao", FINANCEIRO), ("cardNumber", FINANCEIRO), ("cvv", FINANCEIRO),
    ("mail_server", None), ("email_hash", None), ("telefone_mascarado", None), ("card_title", None), ("cartaosus", "documento"),
])
def test_identifier_categories_for_new_data_types(name, category):
    assert classify_identifier(name) == category


def test_python_literals_are_reported_with_masked_message():
    findings = {item.rule_id: item for item in scan(
        f'CNS = "{PROVISIONAL_CNS}"\nCARTAO = "{CARD}"\nEMAIL = "maria.silva@gmail.com"\nFONE = "(11) 91234-5678"\n')}
    assert set(findings) == {"PY-P004", "PY-P005", "PY-P006"}
    assert findings["PY-P004"].data_categories == ["documento"] and findings["PY-P004"].severity.value == "HIGH"
    assert findings["PY-P005"].data_categories == ["financeiro"] and findings["PY-P005"].severity.value == "HIGH"
    assert findings["PY-P006"].data_categories == ["contato"] and findings["PY-P006"].severity.value == "MEDIUM"
    assert PROVISIONAL_CNS not in findings["PY-P004"].message and CARD not in findings["PY-P005"].message
    assert "maria.silva" not in findings["PY-P006"].message


def test_contact_in_docstring_and_placeholders_are_not_reported():
    assert rules('"""Autor: dev.pessoa@gmail.com"""\nx = 1\n') == []
    assert rules('A = "teste@example.com"\nB = "contato@empresa.com"\nC = "(99) 99999-9999"\nD = "4111 1111 1111 1111"\n') == []


def test_card_and_contact_taint_severities():
    assert [(item.rule_id, item.severity.value) for item in scan("def f(cartao_credito):\n    print(cartao_credito)\n")] == [("PY-T004", "CRITICAL")]
    assert [(item.rule_id, item.severity.value) for item in scan("def f(email):\n    print(email)\n")] == [("PY-T004", "LOW")]
    assert rules("def f(cartao_credito, db):\n    db.execute('INSERT INTO p VALUES (%s)', (cartao_credito,))\n") == []  # banco: só senha é acusada


def test_contact_in_response_and_external_calls_is_normal_flow():
    assert rules("@app.get('/me')\ndef me(email):\n    return {'email': email}\n") == []
    assert rules("def f(email):\n    requests.post('https://api.example/cadastro', json={'email': email})\n") == []


@pytest.mark.parametrize("name,code,rule", [
    ("a.js", f'const cns = "{PROVISIONAL_CNS}";', "JS-P003"),
    ("a.js", f'const c = "{CARD}";', "JS-P004"),
    ("A.java", f'class A {{ String c = "{PROVISIONAL_CNS}"; }}', "JAVA-P003"),
    ("A.java", f'class A {{ String c = "{CARD}"; }}', "JAVA-P004"),
])
def test_javascript_and_java_literals(name, code, rule):
    assert rule in rules(code, name)


def test_javascript_and_java_ignore_test_cards():
    assert rules('const c = "4111 1111 1111 1111";', "a.js") == []
    assert rules('class A { String c = "4111 1111 1111 1111"; }', "A.java") == []
