import ast
import re
from engine.models import Severity
from .base_rule import BaseRule

# Padrões de nomes de variáveis suspeitas de conter credenciais
SECRET_NAME_PATTERN = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|(?:^|_)token(?:$|_)|(?:access|auth|api|admin)[_-]?token|jwt[_-]?secret|private[_-]?key|db[_-]?pass)",
    re.IGNORECASE,
)

# Valores ignorados (placeholders comuns)
SAFE_PLACEHOLDERS = {
    "",
    "none",
    "null",
    "true",
    "false",
    "changeme",
    "your_key_here",
    "placeholder",
    "dummy",
    "test",
}


class HardcodedSecretsRule(BaseRule):
    """Detecta credenciais, senhas e tokens de API hardcoded no código (CWE-798)."""

    rule_id: str = "PY-R002"
    name: str = "Credenciais ou Segredos Hardcoded"
    severity: Severity = Severity.HIGH
    cwe: str = "CWE-798"
    description: str = (
        "Identificada atribuição de senha, chave de API ou token em texto plano diretamente no código-fonte."
    )
    remediation: str = (
        "Substitua o valor estático por leitura de variáveis de ambiente usando `os.getenv('NOME_VAR')` "
        "ou utilize um cofre de segredos (como Vault ou AWS Secrets Manager). Nunca comite segredos no git."
    )

    def _is_suspicious_literal(self, value_node: ast.AST) -> bool:
        """Verifica se o nó é uma string literal não vazia e não seja um placeholder trivial."""
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
            val_clean = value_node.value.strip().lower()
            if len(val_clean) >= 3 and val_clean not in SAFE_PLACEHOLDERS:
                return True
        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        """Inspeciona atribuições normais: var = 'segredo'."""
        for target in node.targets:
            var_name = ""
            if isinstance(target, ast.Name):
                var_name = target.id
            elif isinstance(target, ast.Attribute):
                var_name = target.attr
            elif isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                var_name = target.slice.value

            if var_name and SECRET_NAME_PATTERN.search(var_name):
                if self._is_suspicious_literal(node.value):
                    self.add_finding(
                        node=node,
                        message=f"Atribuição de credencial hardcoded na variável '{var_name}'.",
                        remediation=self.remediation,
                    )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            if keyword.arg and SECRET_NAME_PATTERN.search(keyword.arg) and self._is_suspicious_literal(keyword.value):
                self.add_finding(node=node, message=f"Argumento sensível '{keyword.arg}' contém credencial hardcoded.")
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Inspeciona atribuições tipadas: var: str = 'segredo'."""
        var_name = ""
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
        elif isinstance(node.target, ast.Attribute):
            var_name = node.target.attr

        if var_name and SECRET_NAME_PATTERN.search(var_name):
            if node.value and self._is_suspicious_literal(node.value):
                self.add_finding(
                    node=node,
                    message=f"Atribuição de credencial hardcoded na variável tipada '{var_name}'.",
                    remediation=self.remediation,
                )

        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        """Inspeciona dicionários contendo chaves como {'password': '123'}."""
        for key_node, val_node in zip(node.keys, node.values):
            if key_node and isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                key_name = key_node.value
                if SECRET_NAME_PATTERN.search(key_name) and self._is_suspicious_literal(val_node):
                    self.add_finding(
                        node=key_node,
                        message=f"Dicionário contém chave sensível '{key_name}' com valor hardcoded.",
                        remediation=self.remediation,
                    )
        self.generic_visit(node)
