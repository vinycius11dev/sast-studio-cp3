import ast
from engine.models import Severity
from .base_rule import BaseRule


class DangerousEvalRule(BaseRule):
    """Detecta o uso de funções perigosas de execução dinâmica como eval() e exec()."""

    rule_id: str = "PY-R001"
    name: str = "Uso de Execução Dinâmica Perigosa (eval/exec)"
    severity: Severity = Severity.CRITICAL
    cwe: str = "CWE-95"
    description: str = (
        "A chamada direta a eval() ou exec() permite execução arbitrária de código, "
        "podendo levar ao comprometimento total da aplicação se dados externos forem processados."
    )
    remediation: str = (
        "Substitua eval() por alternativas seguras como ast.literal_eval() (para parsing de literais) "
        "ou json.loads() (para dados estruturados). Nunca execute código derivado de entrada de usuário."
    )

    def visit_Call(self, node: ast.Call) -> None:
        func_name = None

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in ("eval", "exec"):
            self.add_finding(
                node=node,
                message=f"Chamada detectada à função perigosa '{func_name}()'.",
                remediation=self.remediation,
            )

        # Continua a travessia na AST para nós filhos
        self.generic_visit(node)
