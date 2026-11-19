"""Mapeamento de PII: dados pessoais expostos diretamente no código-fonte (GS CitizenTech)."""
import ast
from typing import List

from engine.models import RuleMetadata, Severity
from engine.pii import (
    CATEGORIES, CONTATO, DOCUMENTO, FINANCEIRO, SAUDE, SENHA, classify_identifier, find_cards, find_cns, find_cpfs,
    find_emails, find_phones, identifier_tokens, mask_card, mask_cns, mask_cpf, mask_email, mask_phone,
)
from .base_rule import BaseRule

_PLACEHOLDERS = {"", "none", "null", "n/a", "na", "changeme", "placeholder", "dummy", "test", "teste", "exemplo"}
_WEAK_HASHES = {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}


class PiiExposureRule(BaseRule):
    """PY-P001…P006: CPF, saúde, senha, CNS, cartão de pagamento e contato (e-mail/telefone) expostos no código."""

    rule_id: str = "PY-P001"
    name: str = "CPF em texto claro no código-fonte"
    severity: Severity = Severity.HIGH
    cwe: str = "CWE-359"
    description: str = (
        "Um CPF válido (com dígitos verificadores corretos) está escrito como literal no código. "
        "Dados pessoais reais em repositórios ficam copiados em históricos, forks e backups."
    )
    remediation: str = (
        "Remova o CPF do código. Use dados sintéticos claramente fictícios em testes, ou leia o valor "
        "de uma fonte controlada (banco, cofre). Se precisar exibi-lo, mascare: ***.***.***-NN."
    )

    def __init__(self):
        super().__init__()
        self._documentation = set()

    def scan(self, tree: ast.AST, file_path: str, source_code: str):
        self._documentation = set()  # ids de nós só valem dentro de um arquivo
        return super().scan(tree, file_path, source_code)

    def get_additional_metadata(self) -> List[RuleMetadata]:
        return [
            RuleMetadata(
                rule_id="PY-P002", name="Dado de saúde hardcoded no código-fonte", severity=Severity.HIGH,
                cwe="CWE-359",
                description=(
                    "Um valor literal está atribuído a uma variável, chave ou parâmetro de saúde "
                    "(diagnóstico, prontuário, exame, medicamento…). Dado de saúde é dado pessoal sensível (LGPD art. 5º, II)."
                ),
                remediation="Não grave dados de saúde no código. Use dados sintéticos em testes e armazene registros reais criptografados, com acesso restrito.",
            ),
            RuleMetadata(
                rule_id="PY-P003", name="Senha protegida com hash fraco (MD5/SHA-1)", severity=Severity.HIGH,
                cwe="CWE-328",
                description="Uma senha é processada com MD5 ou SHA-1, algoritmos rápidos e quebrados, sem salt nem custo adaptativo.",
                remediation="Use bcrypt, scrypt ou Argon2 (ex.: argon2-cffi, bcrypt.hashpw) com salt individual; nunca MD5 ou SHA-1 para senhas.",
            ),
            RuleMetadata(
                rule_id="PY-P004", name="CNS (Cartão Nacional de Saúde) em texto claro no código-fonte", severity=Severity.HIGH,
                cwe="CWE-359",
                description="Um CNS válido (dígito verificador do SUS correto) está escrito como literal no código. O CNS identifica o paciente em todo o SUS.",
                remediation="Remova o CNS do código; use números sintéticos inválidos em testes e mascare na exibição (*** **** **** NNNN).",
            ),
            RuleMetadata(
                rule_id="PY-P005", name="Cartão de pagamento em texto claro no código-fonte", severity=Severity.HIGH,
                cwe="CWE-359",
                description="Um número de cartão válido (bandeira conhecida e dígito de Luhn correto) está escrito como literal no código. Números de teste dos provedores são ignorados.",
                remediation="Remova o número do código; use os números de teste do provedor de pagamento e nunca guarde o cartão completo.",
            ),
            RuleMetadata(
                rule_id="PY-P006", name="E-mail ou telefone pessoal em texto claro no código-fonte", severity=Severity.MEDIUM,
                cwe="CWE-359",
                description="Um e-mail pessoal ou telefone com DDD válido está escrito como literal no código. Domínios de exemplo e caixas genéricas (contato@, suporte@) são ignorados.",
                remediation="Remova o contato do código; use endereços e números de exemplo (user@example.com, (00) 00000-0000) e mascare na exibição.",
            ),
        ]

    # ---- PY-P001: CPF literal · PY-P004…P006: CNS, cartão, contato ------------------------------
    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            self._documentation.add(id(node.value))  # docstring ou comentário-string: não conta como contato
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            cpfs = find_cpfs(node.value)
            if cpfs:
                self.add_finding(
                    node=node,
                    message=(
                        f"[PII · Documento] CPF válido ({mask_cpf(cpfs[0])}) escrito em texto claro no código-fonte. "
                        "Mesmo exemplos ficam registrados no histórico do repositório."
                    ),
                    data_categories=[DOCUMENTO],
                )
            cns = find_cns(node.value)
            if cns:
                self.add_finding(
                    node=node, rule_id="PY-P004", rule_name="CNS (Cartão Nacional de Saúde) em texto claro no código-fonte",
                    cwe="CWE-359", severity=Severity.HIGH,
                    message=f"[PII · Documento] CNS válido ({mask_cns(cns[0])}) escrito em texto claro no código-fonte. "
                            "O CNS identifica o paciente em todo o SUS.",
                    remediation="Remova o CNS do código; use números sintéticos inválidos em testes e mascare na exibição (*** **** **** NNNN).",
                    data_categories=[DOCUMENTO],
                )
            cards = find_cards(node.value)
            if cards:
                self.add_finding(
                    node=node, rule_id="PY-P005", rule_name="Cartão de pagamento em texto claro no código-fonte",
                    cwe="CWE-359", severity=Severity.HIGH,
                    message=f"[PII · Financeiro] Cartão de pagamento válido ({mask_card(cards[0])}) escrito em texto claro no código-fonte.",
                    remediation="Remova o número do código; use os números de teste do provedor de pagamento e nunca guarde o cartão completo.",
                    data_categories=[FINANCEIRO],
                )
            if id(node) not in self._documentation:
                contacts = [("e-mail", mask_email(item)) for item in find_emails(node.value)]
                contacts += [("telefone", mask_phone(item)) for item in find_phones(node.value)]
                if contacts:
                    kind, masked = contacts[0]
                    self.add_finding(
                        node=node, rule_id="PY-P006", rule_name="E-mail ou telefone pessoal em texto claro no código-fonte",
                        cwe="CWE-359", severity=Severity.MEDIUM,
                        message=f"[PII · Contato] {kind.capitalize()} pessoal ({masked}) escrito em texto claro no código-fonte.",
                        remediation="Remova o contato do código; use endereços e números de exemplo (user@example.com, (00) 00000-0000).",
                        data_categories=[CONTATO],
                    )
        self.generic_visit(node)

    # ---- PY-P002: dado de saúde literal --------------------------------------------------------
    @staticmethod
    def _meaningful_literal(node) -> bool:
        return (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and len(node.value.strip()) >= 3 and node.value.strip().lower() not in _PLACEHOLDERS)

    @staticmethod
    def _is_own_label(name, value) -> bool:
        """`SAUDE = "saude"` ou `{"diagnostico": "diagnostico"}`: o texto repete o nome, é rótulo e não dado."""
        return identifier_tokens(value.value) == identifier_tokens(name)

    def _check_health_literal(self, name, value, at) -> None:
        if (classify_identifier(name) == SAUDE and self._meaningful_literal(value)
                and not self._is_own_label(name, value)):
            self.add_finding(
                node=at, rule_id="PY-P002", rule_name="Dado de saúde hardcoded no código-fonte",
                cwe="CWE-359", severity=Severity.HIGH,
                message=f"[PII · Saúde] '{name}' recebe um valor de saúde escrito direto no código. "
                        f"{CATEGORIES[SAUDE].lgpd}.",
                remediation="Não grave dados de saúde no código. Use dados sintéticos em testes e armazene registros reais criptografados.",
                data_categories=[SAUDE],
            )

    @staticmethod
    def _target_name(target) -> str:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        return ""

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_health_literal(self._target_name(target), node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_health_literal(self._target_name(node.target), node.value, node)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                self._check_health_literal(key.value, value, key)
        self.generic_visit(node)

    # ---- PY-P002 (argumentos nomeados) e PY-P003 (hash fraco de senha) -------------------------
    def visit_Call(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            if keyword.arg:
                self._check_health_literal(keyword.arg, keyword.value, keyword.value)
        function = ast.unparse(node.func)
        hashed_arguments = []
        if function in _WEAK_HASHES:
            hashed_arguments = node.args
        elif (function == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant)
              and str(node.args[0].value).lower() in {"md5", "sha1"}):
            hashed_arguments = node.args[1:]
        if any(self._mentions_password(argument) for argument in hashed_arguments):
            self.add_finding(
                node=node, rule_id="PY-P003", rule_name="Senha protegida com hash fraco (MD5/SHA-1)",
                cwe="CWE-328", severity=Severity.HIGH,
                message=f"[PII · Senha] A senha é processada por '{function}()', algoritmo rápido e sem salt: "
                        "um vazamento do banco permite recuperar as senhas por força bruta em minutos.",
                remediation="Use bcrypt, scrypt ou Argon2 com salt individual (ex.: bcrypt.hashpw(senha, bcrypt.gensalt())).",
                data_categories=[SENHA],
            )
        self.generic_visit(node)

    @staticmethod
    def _mentions_password(node: ast.AST) -> bool:
        for child in ast.walk(node):
            name = child.id if isinstance(child, ast.Name) else child.attr if isinstance(child, ast.Attribute) else None
            if name and classify_identifier(name) == SENHA:
                return True
        return False
