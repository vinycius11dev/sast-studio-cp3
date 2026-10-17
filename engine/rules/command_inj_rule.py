import ast
from engine.models import Severity
from .base_rule import BaseRule

DANGEROUS_SUBPROCESS_FUNCS = {
    "Popen",
    "run",
    "call",
    "check_call",
    "check_output",
}


class CommandInjectionRule(BaseRule):
    """Detecta execuções de comandos do sistema operacional suscetíveis a injeção (CWE-78)."""

    rule_id: str = "PY-R003"
    name: str = "Injeção de Comandos do Sistema Operacional (OS Command Injection)"
    severity: Severity = Severity.CRITICAL
    cwe: str = "CWE-78"
    description: str = (
        "Uso de métodos de execução do sistema (os.system, os.popen ou subprocess com shell=True) "
        "que podem permitir a um atacante executar comandos arbitrários no servidor."
    )
    remediation: str = (
        "Substitua `os.system()` ou `shell=True` por `subprocess.run(['comando', 'arg1'], shell=False)`. "
        "Nunca passe strings interpoladas com dados externos diretamente para o interpretador de comandos (shell)."
    )

    def visit_Call(self, node: ast.Call) -> None:
        # Caso 1: os.system(...) ou os.popen(...)
        if isinstance(node.func, ast.Attribute):
            obj = node.func.value
            attr = node.func.attr

            if isinstance(obj, ast.Name) and obj.id == "os" and attr in ("system", "popen"):
                self.add_finding(
                    node=node,
                    message=f"Uso inseguro de 'os.{attr}()' para execução de comandos do sistema.",
                    remediation=self.remediation,
                )

            # Caso 2: subprocess.run(..., shell=True)
            elif isinstance(obj, ast.Name) and obj.id == "subprocess" and attr in DANGEROUS_SUBPROCESS_FUNCS:
                for keyword in node.keywords:
                    if keyword.arg == "shell":
                        # Verifica se shell=True
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            self.add_finding(
                                node=node,
                                message=f"Chamada a 'subprocess.{attr}()' com 'shell=True' habilitado.",
                                remediation=self.remediation,
                            )

        # Caso 3: import direto, ex: from os import system -> system(...)
        elif isinstance(node.func, ast.Name):
            if node.func.id in ("system", "popen"):
                self.add_finding(
                    node=node,
                    message=f"Chamada direta à função '{node.func.id}()' para execução de comandos do SO.",
                    remediation=self.remediation,
                )

        self.generic_visit(node)
