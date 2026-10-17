import ast
import re
from typing import Set, Dict, List, Optional
from engine.models import Finding, RuleMetadata, Severity
from .base_rule import BaseRule

# Padrões que indicam fontes de dados não confiáveis (Sources)
SOURCE_PATTERNS = [
    r"request\.(args|form|values|json|get_json|GET|POST|data|params)",
    r"sys\.argv",
    r"input\(",
    r"os\.environ\.get",
    r"request\.headers",
]

# Funções que neutralizam o fluxo de dados (Sanitizers)
SANITIZERS = {
    "int",
    "float",
    "bool",
}


class TaintAnalysisRule(BaseRule):
    """Módulo de Taint Analysis (CP 2): rastreia o fluxo de dados não confiáveis de Sources até Sinks."""

    rule_id: str = "PY-T001"
    name: str = "Taint Analysis: Fluxo de Dados Contaminado alcança Sink Crítico"
    severity: Severity = Severity.CRITICAL
    cwe: str = "CWE-89"
    description: str = (
        "Uma entrada de usuário externa (Source) flui sem sanitização adequada até uma função sensível (Sink), "
        "gerando vulnerabilidade de injeção (SQL Injection, Path Traversal ou Command Injection)."
    )
    remediation: str = (
        "Sanitize as entradas antes de repassá-las a operações de banco de dados (use prepared statements), "
        "manipulação de arquivos (use basename e allow-lists) ou comandos do sistema operacional."
    )

    def get_additional_metadata(self) -> List[RuleMetadata]:
        return [
            RuleMetadata(
                rule_id="PY-T002",
                name="Path Traversal via Taint Analysis",
                severity=Severity.HIGH,
                cwe="CWE-22",
                description="Rastreia entradas não confiáveis até operações de leitura ou gravação de arquivos.",
                remediation=(
                    "Normalize o caminho e confirme que ele permanece dentro de um diretório base permitido; "
                    "aplique uma allow-list aos nomes de arquivo."
                ),
            ),
            RuleMetadata(
                rule_id="PY-T003",
                name="SSRF via Taint Analysis",
                severity=Severity.HIGH,
                cwe="CWE-918",
                description="Rastreia URLs derivadas de entradas não confiáveis até chamadas HTTP de saída.",
                remediation=(
                    "Valide esquema e hostname contra uma allow-list e bloqueie destinos locais, privados "
                    "e de metadados de nuvem."
                ),
            ),
        ]

    def __init__(self):
        super().__init__()
        self.tainted_vars: Set[str] = set()

    def _is_source_expression(self, node: ast.AST) -> bool:
        """Verifica se o nó AST representa uma entrada não confiável (Source) e não sanitizada."""
        if isinstance(node, ast.Call):
            func_name = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
            if func_name in SANITIZERS:
                return False

        node_str = ast.unparse(node) if hasattr(ast, "unparse") else ""
        for pattern in SOURCE_PATTERNS:
            if re.search(pattern, node_str):
                return True
        return False

    def _contains_tainted_var(self, node: ast.AST) -> Optional[str]:
        """Verifica se a expressão contém alguma variável contaminada e não sanitizada."""
        # Se for chamada a um sanitizador conhecido (ex: int(user_input)), neutraliza
        if isinstance(node, ast.Call):
            func_name = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
            if func_name in SANITIZERS:
                return None

        if isinstance(node, ast.Name) and node.id in self.tainted_vars:
            return node.id
        for child in ast.iter_child_nodes(node):
            contaminated = self._contains_tainted_var(child)
            if contaminated:
                return contaminated
        return None

    def visit_FunctionDef(self, node):
        outer = self.tainted_vars
        parameters = {argument.arg for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
        if node.args.vararg:
            parameters.add(node.args.vararg.arg)
        if node.args.kwarg:
            parameters.add(node.args.kwarg.arg)
        self.tainted_vars = outer - parameters
        try:
            self.generic_visit(node)
        finally:
            self.tainted_vars = outer

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        """Rastreia propagação de taint: se o valor for contaminado, a variável destino é contaminada."""
        is_tainted = False
        source_name = None

        # Caso A: Atribuição direta de uma fonte (x = request.args.get('id'))
        if self._is_source_expression(node.value):
            is_tainted = True
        else:
            # Caso B: Propagação de uma variável já contaminada (query = "SELECT... " + x)
            tainted_child = self._contains_tainted_var(node.value)
            if tainted_child:
                is_tainted = True
                source_name = tainted_child

        # Registra as variáveis do lado esquerdo
        for target in node.targets:
            if isinstance(target, ast.Name):
                if is_tainted:
                    self.tainted_vars.add(target.id)
                else:
                    # Se foi reatribuída com valor seguro, remove o taint
                    self.tainted_vars.discard(target.id)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Inspeciona se a chamada é um Sink sensível recebendo dados contaminados."""
        func_expr = ast.unparse(node.func) if hasattr(ast, "unparse") else ""

        # --- SINK 1: Execução SQL (cursor.execute / db.execute) ---
        if re.search(r"(cursor|db|connection|conn|session)\.(execute|raw)", func_expr):
            if node.args:
                sql_arg = node.args[0]
                tainted_var = self._contains_tainted_var(sql_arg) or (
                    "source" if self._is_source_expression(sql_arg) else None
                )

                if tainted_var:
                    self.add_finding(
                        node=node,
                        message=(
                            f"[Taint Analysis] Vulnerabilidade de SQL Injection (CWE-89): "
                            f"A variável de entrada '{tainted_var}' alcança o sink '{func_expr}()' "
                            f"sem prepared statements parametrizados."
                        ),
                        remediation=(
                            "Utilize queries parametrizadas: cursor.execute('SELECT * FROM tbl WHERE id = %s', (val,)) "
                            "em vez de concatenar entradas na string SQL."
                        ),
                        severity=Severity.CRITICAL,
                        cwe="CWE-89",
                    )

        # --- SINK 2: Manipulação de Arquivos (open com caminho contaminado) ---
        elif func_expr in ("open", "io.open", "os.open"):
            if node.args:
                path_arg = node.args[0]
                tainted_var = self._contains_tainted_var(path_arg)
                if tainted_var:
                    self.add_finding(
                        node=node,
                        rule_id="PY-T002",
                        rule_name="Path Traversal via Taint Analysis",
                        message=(
                            f"[Taint Analysis] Vulnerabilidade de Path Traversal (CWE-22): "
                            f"A variável contaminada '{tainted_var}' alcança a função 'open()' "
                            f"sem sanitização de caminho."
                        ),
                        remediation=(
                            "Valide o caminho contra uma lista permitida (allow-list) ou use "
                            "os.path.basename() para impedir sequências '../' de directory traversal."
                        ),
                        severity=Severity.HIGH,
                        cwe="CWE-22",
                    )

        # --- SINK 3: Requisições HTTP Externas / SSRF (CWE-918 / CVE-2020-13379) ---
        elif re.search(r"requests\.(get|post|put|delete|head|request)|urllib\.request\.urlopen", func_expr):
            if node.args:
                url_arg = node.args[0]
                tainted_var = self._contains_tainted_var(url_arg) or (
                    "source" if self._is_source_expression(url_arg) else None
                )
                if tainted_var:
                    self.add_finding(
                        node=node,
                        rule_id="PY-T003",
                        rule_name="SSRF via Taint Analysis",
                        message=(
                            f"[Taint Analysis] Vulnerabilidade de SSRF (CWE-918): "
                            f"A URL de entrada externa '{tainted_var}' flui até a requisição '{func_expr}()' "
                            f"sem validação contra allow-list de domínios permitidos."
                        ),
                        remediation=(
                            "Valide a URL contra uma allow-list estrita de domínios seguros "
                            "e bloqueie resoluções para endereços privados/locais ou metadados de nuvem."
                        ),
                        severity=Severity.HIGH,
                        cwe="CWE-918",
                    )

        # Continua a inspeção
        self.generic_visit(node)
