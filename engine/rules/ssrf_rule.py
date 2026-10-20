import ast
import re
from engine.models import Severity
from .python_context import PythonContextRule


class ServerSideRequestForgeryRule(PythonContextRule):
    """Detecta vulnerabilidade de Server-Side Request Forgery (SSRF - CWE-918).

    Identifica chamadas HTTP via bibliotecas como `requests`, `urllib` ou `http.client`
    onde a URL de destino é construída com variáveis dinâmicas ou concatenação
    sem validação prévia de allow-list contra IPs internos ou serviços de metadados.
    """

    rule_id: str = "PY-R004"
    name: str = "Server-Side Request Forgery (SSRF)"
    severity: Severity = Severity.HIGH
    cwe: str = "CWE-918"
    description: str = (
        "Requisição HTTP para URL dinâmica construída sem validação contra allow-list "
        "de domínios permitidos (CWE-918 / CVE-2020-13379). Pode expor metadados de nuvem "
        "(ex: 169.254.169.254) ou serviços de rede interna protegidos."
    )
    remediation: str = (
        "Valide o domínio de destino contra uma lista restrita (allow-list) de URLs permitidas "
        "e bloqueie explicitamente o acesso a endereços privados (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16 "
        "e 169.254.169.254)."
    )

    def __init__(self):
        super().__init__()
        self.static_names = set()

    def _static(self, node):
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.static_names
        if isinstance(node, ast.BinOp):
            return self._static(node.left) and self._static(node.right)
        if isinstance(node, ast.JoinedStr):
            return all(self._static(value.value if isinstance(value, ast.FormattedValue) else value) for value in node.values)
        return False

    def visit_Assign(self, node):
        static = self._static(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if static:
                    self.static_names.add(target.id)
                else:
                    self.static_names.discard(target.id)
        super().visit_Assign(node)

    def visit_FunctionDef(self, node):
        outer = self.static_names
        parameters = {argument.arg for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
        self.static_names = outer - parameters
        try:
            super().visit_FunctionDef(node)
        finally:
            self.static_names = outer

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        func_expr = self.resolve(node.func)

        # Sinks de requisição HTTP em Python
        is_http_call = bool(
            re.fullmatch(r"requests\.(get|post|put|delete|head|patch|options|request)", func_expr)
            or re.fullmatch(r"urllib\.request\.(urlopen|Request)", func_expr)
            or re.fullmatch(r"httpx\.(get|post|put|delete|head|patch|options|request)", func_expr)
        )

        positional_index = 1 if func_expr.endswith(".request") else 0
        first_arg = node.args[positional_index] if len(node.args) > positional_index else next((keyword.value for keyword in node.keywords if keyword.arg == "url"), None)
        if is_http_call and first_arg is not None:
            # Se não for literal estático puro (ou seja, envolve concatenação, variável ou f-string)
            is_dynamic = not self._static(first_arg)

            if is_dynamic:
                arg_expr = ast.unparse(first_arg) if hasattr(ast, "unparse") else ""
                self.add_finding(
                    node=node,
                    message=(
                        f"Chamada HTTP via '{func_expr}()' com URL dinâmica '{arg_expr}' "
                        f"sem validação contra allow-list de domínios (CWE-918)."
                    ),
                    remediation=self.remediation,
                    severity=self.severity,
                    cwe=self.cwe,
                )

        self.generic_visit(node)
