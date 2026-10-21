import ast
from engine.models import RuleMetadata, Severity
from .flow_rule import NameFlowRule, argument, http_url

SANITIZERS = {"int", "float", "bool"}
REQUEST_FIELDS = {"args", "form", "values", "json", "get_json", "GET", "POST", "data", "params", "headers"}


class TaintAnalysisRule(NameFlowRule):
    """Rastreia fontes externas até sinks no mesmo corpo de função/módulo."""
    rule_id = "PY-T001"
    name = "Taint Analysis: Fluxo de Dados Contaminado alcança Sink Crítico"
    severity = Severity.CRITICAL
    cwe = "CWE-89"
    description = "Entrada externa alcança uma operação SQL sem parametrização identificada no fluxo local."
    remediation = "Use queries parametrizadas; não concatene entradas à instrução SQL."

    def get_additional_metadata(self):
        return [
            RuleMetadata(rule_id="PY-T002", name="Path Traversal via Taint Analysis", severity=Severity.HIGH,
                         cwe="CWE-22", description="Entrada externa alcança uma operação de arquivo.",
                         remediation="Resolva o caminho e confirme que permanece dentro de uma base permitida; use uma allow-list."),
            RuleMetadata(rule_id="PY-T003", name="SSRF via Taint Analysis", severity=Severity.HIGH,
                         cwe="CWE-918", description="URL de entrada externa alcança uma chamada HTTP.",
                         remediation="Restrinja esquema e domínio; bloqueie IPs privados, locais e de metadados inclusive após redirects."),
        ]

    def _contamination(self, node):
        if node is None or isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.Call):
            name = self.qualified_name(node.func)
            if name in SANITIZERS and name not in self.shadowed:
                return None
            if name == "input" and "input" not in self.shadowed:
                return "input()"
        if isinstance(node, ast.Name) and node.id in self.names:
            return node.id
        if isinstance(node, ast.Attribute):
            name = self.qualified_name(node)
            if name in {"sys.argv", "os.environ"} or any(
                name == f"{owner}.{field}" for owner in ("request", "flask.request") for field in REQUEST_FIELDS
            ):
                return name
        for child in ast.iter_child_nodes(node):
            contaminated = self._contamination(child)
            if contaminated:
                return contaminated
        return None

    def _classification(self, node):
        return bool(self._contamination(node))

    def visit_Call(self, node):
        name = self.qualified_name(node.func)
        owner, _, method = name.rpartition(".")
        short_owner = owner.rsplit(".", 1)[-1]
        sql_owner = short_owner in {"cursor", "db", "connection", "conn", "session"} or short_owner.endswith("_cursor")
        sql = sql_owner and method in {"execute", "executemany", "raw"}
        path = name in {"open", "io.open", "os.open"}
        url = http_url(node, name)
        value = argument(node, 0, ("sql", "query", "statement")) if sql else (
            argument(node, 0, ("file", "path")) if path else url
        )
        source = self._contamination(value)
        if source:
            rule_id, title, cwe, severity, remediation = (
                ("PY-T001", "SQL Injection", "CWE-89", Severity.CRITICAL, self.remediation) if sql else
                ("PY-T002", "Path Traversal via Taint Analysis", "CWE-22", Severity.HIGH,
                 "Resolva o caminho e verifique contenção em um diretório permitido; aplique uma allow-list.") if path else
                ("PY-T003", "SSRF via Taint Analysis", "CWE-918", Severity.HIGH,
                 "Valide esquema, hostname e IP de destino; bloqueie redes privadas e revalide redirects.")
            )
            self.add_finding(node, rule_id=rule_id, rule_name=title, cwe=cwe, severity=severity,
                             message=f"[Taint Analysis] Possível {title} ({cwe}): entrada '{source}' alcança '{name}()' no fluxo local. Revise as validações e o contexto.",
                             remediation=remediation)
        self.generic_visit(node)
