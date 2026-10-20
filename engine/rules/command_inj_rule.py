import ast
from engine.models import Severity
from .python_context import PythonContextRule

DANGEROUS_SUBPROCESS_FUNCS = {
    "Popen",
    "run",
    "call",
    "check_call",
    "check_output",
}


class CommandInjectionRule(PythonContextRule):
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
        resolved = self.resolve(node.func)
        if resolved in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "asyncio.create_subprocess_shell"}:
            self.add_finding(node=node, message=f"Uso de '{resolved}()' com interpretador de comandos; valide a origem e prefira argumentos separados.")
        elif resolved.startswith("subprocess.") and resolved.split(".")[-1] in DANGEROUS_SUBPROCESS_FUNCS:
            for keyword in node.keywords:
                if keyword.arg == "shell" and self.literal(keyword.value) is True:
                    self.add_finding(node=node, message=f"Chamada a '{resolved}()' com shell=True habilitado.")
                    break
        self.generic_visit(node)
