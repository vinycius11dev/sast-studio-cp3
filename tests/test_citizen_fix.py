"""GS CitizenTech: "corrigir e provar" — correção automática de exposições de PII com reanálise."""
import ast
import types

import pytest
from fastapi.testclient import TestClient

from api import main
from engine.citizen_fix import fix_file, fix_project
from engine.engine import SASTEngine
from tests.test_pii_extended import CARD, PROVISIONAL_CNS
from tests.test_citizen_risk import demo_sources

CPF = "529.982.247-25"


def fixed_code(source, name="t.py"):
    result, before, after, code = fix_file(source, name)
    return result, code, before, after


def pii_rules(code, name="t.py"):
    return [item.rule_id for item in SASTEngine().scan_code(code, name).findings if item.data_categories]


def helpers_of(code):
    """Executa o código corrigido sem bcrypt instalado e devolve o namespace (funções auxiliares geradas)."""
    namespace = {"bcrypt": types.SimpleNamespace(hashpw=lambda senha, salt: b"$2b$fake$" + senha, gensalt=lambda: b"salt")}
    tree = ast.parse(code)
    keep = [node for node in tree.body if isinstance(node, (ast.Assign, ast.FunctionDef))
            and (isinstance(node, ast.FunctionDef) and node.name in {"mascarar_pii", "hash_senha"}
                 or isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "_CHAVES_SENSIVEIS" for t in node.targets))]
    exec(compile(ast.Module(keep, []), "<helpers>", "exec"), namespace)
    return namespace


def test_demo_project_is_fixed_and_proved():
    sources = demo_sources("04-pii-vulneravel")
    fix, fixed = fix_project("s" * 32, sources)
    assert fix.before.score == 99 and fix.after.score == 0 and fix.after.pii_findings == 0
    assert fix.verified and fix.applied_count == 10 and fix.remaining_count == 0
    assert {action.rule_id for item in fix.files for action in item.applied} == {"PY-P001", "PY-P002", "PY-P003", "PY-T004", "PY-T005", "PY-T006", "PY-T007"}
    engine = SASTEngine()
    for path, code in fixed.items():
        ast.parse(code)
        assert engine.scan_code(code, path).findings == []  # a reanálise independente confirma a prova
    assert all(item.diff.startswith("--- a/") for item in fix.files if item.changed)


def test_fixing_is_idempotent_and_leaves_clean_projects_alone():
    _, fixed = fix_project("s" * 32, demo_sources("04-pii-vulneravel"))
    again, again_fixed = fix_project("s" * 32, fixed)
    assert again.applied_count == 0 and not again.verified and again_fixed == fixed
    clean, _ = fix_project("s" * 32, demo_sources("05-pii-corrigido"))
    assert clean.applied_count == 0 and clean.before.score == 0 == clean.after.score


def test_literals_become_invalid_placeholders():
    source = (f'CPF = "{CPF}"\nCNS = "{PROVISIONAL_CNS}"\nCARTAO = "{CARD}"\nEMAIL = "maria.silva@gmail.com"\n'
              'FONE = "(11) 91234-5678"\nPRONTUARIO = {"nome": "Maria", "diagnostico": "Hipertensão arterial"}\n')
    result, code, before, after = fixed_code(source)
    assert sorted({item.rule_id for item in before if item.data_categories}) == ["PY-P001", "PY-P002", "PY-P004", "PY-P005", "PY-P006"]
    assert after == [] and pii_rules(code) == []
    for secret in (CPF, PROVISIONAL_CNS, CARD, "maria.silva", "91234-5678", "Hipertensão"):
        assert secret not in code
    assert '"diagnostico": None' in code and "000.000.000-00" in code and "usuario@example.com" in code


def test_weak_password_hash_becomes_bcrypt_with_one_import():
    source = "import hashlib\n\ndef guardar(senha):\n    return hashlib.md5(senha.encode()).hexdigest()\n"
    result, code, _, after = fixed_code(source)
    assert "return hash_senha(senha)" in code and code.count("import bcrypt") == 1 and after == []
    already = "import bcrypt\nimport hashlib\n\ndef guardar(senha):\n    return hashlib.sha1(senha.encode()).digest()\n"
    _, code2, _, _ = fixed_code(already)
    assert code2.count("import bcrypt") == 1 and "return hash_senha(senha)" in code2


def test_generated_helpers_really_mask_and_hash():
    source = ('def f(paciente, senha, db):\n    print(paciente["cpf"])\n    db.execute("INSERT INTO u (s) VALUES (%s)", (senha,))\n'
              '    return {"cpf": paciente["cpf"], "nome": "Maria"}\n')
    _, code, _, after = fixed_code(source)
    assert after == []
    helpers = helpers_of(code)
    mask, hashed = helpers["mascarar_pii"], helpers["hash_senha"]
    assert mask(CPF) == "***.***.***-25" and mask("52998224725") == "***.***.***-25" and mask("Hipertensão") == "***"
    assert mask({"cpf": CPF, "nome": "Maria", "senha": "abc", "id": 7}) == {"cpf": "***.***.***-25", "nome": "Maria", "senha": "***", "id": 7}
    assert mask([{"diagnostico": "x"}]) == [{"diagnostico": "***"}]
    assert hashed("segredo") != "segredo" and "segredo" not in hashed("segredo").replace("$2b$fake$segredo", "")


def test_existing_helper_is_reused_not_duplicated():
    source = 'def mascarar_pii(v):\n    return "***"\n\ndef f(cpf):\n    print(cpf)\n'
    _, code, _, after = fixed_code(source)
    assert code.count("def mascarar_pii") == 1 and "print(mascarar_pii(cpf))" in code and after == []


def test_flows_through_fstrings_dicts_and_concatenation():
    source = ('def f(cpf, email, diagnostico, db):\n    log = "Paciente " + cpf + " " + diagnostico\n    print(log)\n'
              '    logger.info(f"{cpf}-{diagnostico}")\n    requests.post("https://api.parceiro.com/x", json={"cpf": cpf, "nome": "Maria"})\n')
    _, code, before, after = fixed_code(source)
    assert len([item for item in before if item.data_categories]) == 3 and after == []
    assert 'json={"cpf": mascarar_pii(cpf), "nome": "Maria"}' in code
    assert "mascarar_pii(cpf)" in code and "mascarar_pii(diagnostico)" in code


def test_unsupported_and_invalid_files_are_reported_not_changed():
    js, _, _, _ = fix_file(f'const c = "{CARD}";', "a.js")
    assert not js.changed and "Python" in js.skipped_reason and js.remaining
    broken, _, _, code = fix_file("def f(:\n", "b.py")
    assert not broken.syntax_ok and not broken.changed and code == "def f(:\n"
    mixed, _ = fix_project("s" * 32, {"a.py": f'CPF = "{CPF}"\n', "b.js": f'const c = "{CARD}";'})
    assert mixed.applied_count == 1 and not mixed.verified and mixed.remaining_count == 1  # o JS segue pendente: sem falsa prova


def test_api_fix_saves_a_new_scan_and_keeps_the_original():
    with TestClient(main.app) as client:
        data = client.get("/api/v1/samples", params={"variant": "pii-vulneravel"}).json()
        files = [("files", (item["path"], item["content"].encode("utf-8"), "text/plain")) for item in data["files"]]
        scan = client.post("/api/v1/scan/project", files=files, data={"project_name": "UBS", "gate_threshold": "HIGH"}).json()
        fix = client.post(f"/api/v1/scans/{scan['scan_id']}/citizen-fix").json()
        assert fix["verified"] and fix["before"]["score"] == 99 and fix["after"]["score"] == 0 and fix["fixed_scan_id"] != scan["scan_id"]
        corrected = client.get(f"/api/v1/scans/{fix['fixed_scan_id']}").json()
        assert corrected["citizen_risk"]["score"] == 0 and corrected["security_gate"]["status"] == "passed"
        assert corrected["project_name"].endswith("· corrigido")
        original = client.get(f"/api/v1/scans/{scan['scan_id']}").json()
        assert original["citizen_risk"]["score"] == 99  # a análise original não é sobrescrita
        assert client.post("/api/v1/scans/" + "0" * 32 + "/citizen-fix").status_code == 404


def test_api_fix_on_clean_scan_creates_nothing():
    with TestClient(main.app) as client:
        data = client.get("/api/v1/samples", params={"variant": "pii-corrigido"}).json()
        files = [("files", (item["path"], item["content"].encode("utf-8"), "text/plain")) for item in data["files"]]
        scan = client.post("/api/v1/scan/project", files=files, data={"project_name": "UBS", "gate_threshold": "HIGH"}).json()
        fix = client.post(f"/api/v1/scans/{scan['scan_id']}/citizen-fix").json()
        assert fix["applied_count"] == 0 and fix["fixed_scan_id"] is None and not fix["verified"]


def test_payments_and_contact_demo_is_detected_and_fixed():
    sources = demo_sources("06-pii-cartao-e-contato")
    assert set(sources) == {"06-pii-cartao-e-contato/pagamentos/cobranca.py"}
    findings = [item for path, code in sources.items() for item in SASTEngine().scan_code(code, path).findings]
    assert sorted(item.rule_id for item in findings) == ["PY-P004", "PY-P005", "PY-P006", "PY-P006", "PY-T004", "PY-T004"]
    fix, fixed = fix_project("s" * 32, sources)
    assert fix.verified and fix.before.score == 84 and fix.after.score == 0 and fix.applied_count == 7
    assert "5500 0000 0000 0004" not in "".join(fixed.values()) and "maria.silva" not in "".join(fixed.values())
