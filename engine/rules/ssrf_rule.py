import ast
from engine.models import Severity
from .flow_rule import NameFlowRule, http_url


class ServerSideRequestForgeryRule(NameFlowRule):
    """Heurística de URL dinâmica; um alerta não comprova exploração de SSRF."""
    may_flow = False
    rule_id = "PY-R004"
    name = "Server-Side Request Forgery (SSRF)"
    severity = Severity.HIGH
    cwe = "CWE-918"
    description = "Requisição HTTP para URL dinâmica: revise a validação de esquema, domínio e endereços de destino."
    remediation = "Use uma allow-list estrita e bloqueie destinos privados, locais e de metadados, inclusive após redirects e resolução DNS."

    def _classification(self, node):
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.names
        if isinstance(node, ast.BinOp):
            return self._classification(node.left) and self._classification(node.right)
        if isinstance(node, (ast.Tuple, ast.List)):
            return all(self._classification(child) for child in node.elts)
        if isinstance(node, ast.JoinedStr):
            return all(self._classification(child.value if isinstance(child, ast.FormattedValue) else child) for child in node.values)
        return False

    def visit_Call(self, node):
        name = self.qualified_name(node.func)
        url = http_url(node, name)
        if url is not None and not self._classification(url):
            self.add_finding(node, message=(
                f"Chamada HTTP via '{name}()' com URL dinâmica '{ast.unparse(url)}'. "
                "Possível SSRF (CWE-918): confirme a validação de destinos; a análise local não comprova sua ausência."
            ))
        self.generic_visit(node)
