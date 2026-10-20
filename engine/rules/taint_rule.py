import ast
import re
from typing import Set, Dict, List, Optional
from engine.models import DataFlowStep, RuleMetadata, Severity
from .python_context import PythonContextRule, UNKNOWN

# Padrões que indicam fontes de dados não confiáveis (Sources)
SOURCE_PATTERNS = [
    r"request\.(args|form|values|json|get_json|GET|POST|data|params)",
    r"sys\.argv",
    r"input\(",
    r"os\.environ\.get",
    r"request\.headers",
    r"(?:request|req)\.(?:cookies|files|body|query_params|path_params)",
    r"(?:request|req)\.(?:args|form|values|json|get_json|GET|POST|data|params|headers)",
]

# Funções que neutralizam o fluxo de dados (Sanitizers)
SANITIZERS = {
    "int",
    "float",
    "bool",
}


class TaintAnalysisRule(PythonContextRule):
    """Módulo de Taint Analysis (CP 2): rastreia o fluxo de dados não confiáveis de Sources até Sinks."""

    rule_id: str = "PY-T001"
    name: str = "SQL Injection por fluxo local ou consulta dinâmica"
    severity: Severity = Severity.CRITICAL
    cwe: str = "CWE-89"
    description: str = (
        "Entrada externa ou construção dinâmica de SQL alcança uma operação de banco sem parametrização. "
        "A evidência distingue fluxo conhecido de padrão potencial com origem não comprovada."
    )
    remediation: str = (
        "Use parâmetros separados da string SQL; selecione nomes de tabelas e colunas por uma allow-list explícita."
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
        self.sql_tainted_vars: Set[str] = set()
        self.numeric_vars: Set[str] = set()
        self.path_vars: Set[str] = set()
        self.dynamic_sql: Set[str] = set()
        self.origins = {}

    def _is_source_expression(self, node: ast.AST) -> bool:
        """Verifica se o nó AST representa uma entrada não confiável (Source) e não sanitizada."""
        for part in ast.walk(node):
            if isinstance(part, ast.Call) and self.resolve(part.func) in {"input", "builtins.input", "sys.stdin.read", "sys.stdin.readline"}:
                return True
            if isinstance(part, (ast.Attribute, ast.Subscript)):
                target = part.value if isinstance(part, ast.Subscript) else part
                for text in (self.resolve(target), ast.unparse(target)):
                    if re.match(r"^(sys\.argv|os\.environ)(?:\.|$)", text):
                        return True
                    if re.search(r"(?:^|\.)(?:request|req)\.(?:args|form|values|json|get_json|GET|POST|data|params|headers|cookies|files|body|query_params|path_params)(?:\.|$)", text):
                        return True
        return False

    def _numeric(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.numeric_vars
        if isinstance(node, ast.Call):
            name = self.resolve(node.func)
            return name in SANITIZERS or (name == "str" and bool(node.args) and self._numeric(node.args[0]))
        return isinstance(node, ast.Constant) and isinstance(node.value, (int, float, bool))

    def _sql_tainted(self, node):
        if self._numeric(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.sql_tainted_vars
        if isinstance(node, (ast.Subscript, ast.Attribute)) and self._is_source_expression(node):
            return True
        if isinstance(node, ast.Call) and self.resolve(node.func) in {"input", "builtins.input", "sys.stdin.read", "sys.stdin.readline"}:
            return True
        return any(self._sql_tainted(child) for child in ast.iter_child_nodes(node))

    def _dynamic_sql(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.dynamic_sql
        if self.literal(node) is not UNKNOWN:
            return False
        sql_text = any(isinstance(part, ast.Constant) and isinstance(part.value, str) and re.search(r"\b(SELECT|UPDATE|DELETE|INSERT|DROP|ALTER|CREATE)\b", part.value, re.I) for part in ast.walk(node))
        if isinstance(node, ast.JoinedStr):
            return sql_text and any(isinstance(part, ast.FormattedValue) and not self._numeric(part.value) and self.literal(part.value) is UNKNOWN for part in node.values)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                return self._dynamic_sql(node.left) or self._dynamic_sql(node.right) or (sql_text and not self._numeric(node.right) and self.literal(node.right) is UNKNOWN)
            if isinstance(node.op, ast.Mod):
                values = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
                return sql_text and any(not self._numeric(value) and self.literal(value) is UNKNOWN for value in values)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return sql_text and any(not self._numeric(value) and self.literal(value) is UNKNOWN for value in [*node.args, *[kw.value for kw in node.keywords]])
        return False

    def _contains_tainted_var(self, node: ast.AST) -> Optional[str]:
        """Verifica se a expressão contém alguma variável contaminada e não sanitizada."""
        if isinstance(node, ast.Name) and node.id in self.tainted_vars:
            return node.id
        for child in ast.iter_child_nodes(node):
            contaminated = self._contains_tainted_var(child)
            if contaminated:
                return contaminated
        return None

    def visit_FunctionDef(self, node):
        outer = self.tainted_vars
        outer_sql_taint = self.sql_tainted_vars
        outer_numeric, outer_paths, outer_sql, outer_origins = self.numeric_vars, self.path_vars, self.dynamic_sql, self.origins
        parameters = {argument.arg for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
        if node.args.vararg:
            parameters.add(node.args.vararg.arg)
        if node.args.kwarg:
            parameters.add(node.args.kwarg.arg)
        self.tainted_vars = outer - parameters
        self.sql_tainted_vars = outer_sql_taint - parameters
        self.numeric_vars = outer_numeric - parameters
        self.path_vars = outer_paths - parameters
        self.dynamic_sql = outer_sql - parameters
        self.origins = {name: list(steps) for name, steps in outer_origins.items() if name not in parameters}
        try:
            super().visit_FunctionDef(node)
        finally:
            self.tainted_vars = outer
            self.sql_tainted_vars = outer_sql_taint
            self.numeric_vars, self.path_vars, self.dynamic_sql, self.origins = outer_numeric, outer_paths, outer_sql, outer_origins

    visit_AsyncFunctionDef = visit_FunctionDef

    def _is_path_value(self, node):
        return any(
            (isinstance(part, ast.Name) and part.id in self.path_vars)
            or (isinstance(part, ast.Call) and self.resolve(part.func) in {"Path", "pathlib.Path", "pathlib.PurePath"})
            for part in ast.walk(node)
        )

    def _record_assignment(self, target, value, statement):
        if isinstance(target, (ast.Tuple, ast.List)):
            for index, item in enumerate(target.elts):
                component = value.elts[index] if isinstance(value, (ast.Tuple, ast.List)) and index < len(value.elts) else value
                self._record_assignment(item, component, statement)
            return
        is_tainted = False
        if self._is_source_expression(value):
            is_tainted = True
        else:
            tainted_child = self._contains_tainted_var(value)
            if tainted_child:
                is_tainted = True
        if isinstance(target, ast.Name):
            numeric = self._numeric(value)
            sql_tainted = self._sql_tainted(value)
            dynamic_sql = self._dynamic_sql(value)
            path_value = self._is_path_value(value)
            origin = self._origin_steps(value)
            for state, present in ((self.tainted_vars, is_tainted), (self.numeric_vars, numeric), (self.sql_tainted_vars, sql_tainted), (self.dynamic_sql, dynamic_sql), (self.path_vars, path_value)):
                (state.add if present else state.discard)(target.id)
            if is_tainted and origin:
                self.origins[target.id] = [*origin, self._flow_step("propagation", statement)]
            else:
                self.origins.pop(target.id, None)
        self._bind(target, value)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Propagate only facts derived from this assignment, including tuples."""
        self.visit(node.value)
        for target in node.targets:
            self._record_assignment(target, node.value, node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            # Preserve real source locations while sharing assignment semantics.
            assignment = ast.Assign(targets=[node.target], value=node.value)
            ast.copy_location(assignment, node)
            self.visit_Assign(assignment)

    def visit_AugAssign(self, node):
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            if self._sql_tainted(node.value):
                self.sql_tainted_vars.add(node.target.id)
            if self._contains_tainted_var(node.value) or self._is_source_expression(node.value):
                self.tainted_vars.add(node.target.id)
                steps = [*self.origins.get(node.target.id, []), *self._origin_steps(node.value)]
                self.origins[node.target.id] = [*steps, self._flow_step("propagation", node)]
            self.numeric_vars.discard(node.target.id)
            self.values.pop(node.target.id, None)

    def visit_If(self, node):
        self.visit(node.test)
        names = ("tainted_vars", "sql_tainted_vars", "numeric_vars", "path_vars", "dynamic_sql")
        before = {name: set(getattr(self, name)) for name in names}
        before_aliases, before_values, before_origins = dict(self.aliases), dict(self.values), dict(self.origins)
        for statement in node.body:
            self.visit(statement)
        body = {name: set(getattr(self, name)) for name in names}
        body_aliases, body_values, body_origins = dict(self.aliases), dict(self.values), dict(self.origins)
        for name, value in before.items():
            setattr(self, name, set(value))
        self.aliases, self.values, self.origins = before_aliases, before_values, before_origins
        for statement in node.orelse:
            self.visit(statement)
        for name in names:
            other = getattr(self, name)
            setattr(self, name, body[name] & other if name == "numeric_vars" else body[name] | other)
        self.aliases = {key: value for key, value in body_aliases.items() if self.aliases.get(key, UNKNOWN) == value}
        self.values = {key: value for key, value in body_values.items() if self.values.get(key, UNKNOWN) == value}
        # A trace from one branch cannot represent a merged control-flow path.
        self.origins = {key: steps for key, steps in body_origins.items() if self.origins.get(key) == steps}

    def _flow_step(self, role, node):
        line = getattr(node, "lineno", 1)
        return {"role": role, "file_path": self.current_file_path, "line_number": line, "column_number": getattr(node, "col_offset", 0), "code_snippet": self.source_lines[line - 1].strip() if line <= len(self.source_lines) else ""}

    def _origin_steps(self, node):
        for part in ast.walk(node):
            if isinstance(part, ast.Name) and part.id in self.origins:
                return list(self.origins[part.id])
        for part in ast.walk(node):
            text = ""
            if isinstance(part, ast.Call):
                text = self.resolve(part.func) or ast.unparse(part.func)
                if text in {"input", "builtins.input", "sys.stdin.read", "sys.stdin.readline"}:
                    return [self._flow_step("source", part)]
            elif isinstance(part, (ast.Subscript, ast.Attribute)):
                target = part.value if isinstance(part, ast.Subscript) else part
                text = self.resolve(target) or ast.unparse(target)
            if re.search(r"(?:^|\.)(?:request|req)\.(?:args|form|values|json|get_json|GET|POST|data|params|headers|cookies|files|body|query_params|path_params)(?:\.|$)|^(?:sys\.argv|os\.environ)(?:\.|$)", text):
                return [self._flow_step("source", part)]
        return []

    def _attach_trace(self, node, argument):
        finding = self.findings[-1]
        if "analysis_scope" not in type(finding).model_fields:
            return
        steps = self._origin_steps(argument)
        if steps:
            finding.analysis_scope = "local_dataflow"
            finding.data_flow = [DataFlowStep(**step) for step in [*steps, self._flow_step("sink", node)]]
            finding.limitations = ["Fluxo intraprocedural; não comprova alcançabilidade em execução nem segue outros arquivos."]
        else:
            finding.limitations = ["Origem externa e fluxo completo não comprovados por esta análise local."]

    def visit_Call(self, node: ast.Call) -> None:
        """Inspeciona se a chamada é um Sink sensível recebendo dados contaminados."""
        func_expr = self.resolve(node.func) or ast.unparse(node.func)
        raw_func = ast.unparse(node.func)

        # --- SINK 1: Execução SQL (cursor.execute / db.execute) ---
        if re.search(r"(?:^|\.)(?:\w*_)?(?:cursor|cur|db|connection|conn|session)(?:_\w+)?\.(execute|executemany|executescript|raw)$", raw_func):
            sql_arg = self.argument(node, 0, "query", "sql", "operation")
            if sql_arg is not None:
                tainted_var = (self._contains_tainted_var(sql_arg) or "entrada externa") if self._sql_tainted(sql_arg) else None
                dynamic_sql = self._dynamic_sql(sql_arg)

                if tainted_var or dynamic_sql:
                    self.add_finding(
                        node=node,
                        message=(
                            f"[Taint Analysis] Vulnerabilidade de SQL Injection (CWE-89): "
                            f"{'A entrada externa ' + repr(tainted_var) if tainted_var else 'Consulta dinâmica (origem externa não comprovada)'} alcança o sink '{func_expr}()' "
                            f"sem prepared statements parametrizados."
                        ),
                        remediation=(
                            "Utilize queries parametrizadas: cursor.execute('SELECT * FROM tbl WHERE id = %s', (val,)) "
                            "em vez de concatenar entradas na string SQL."
                        ),
                        severity=Severity.CRITICAL,
                        cwe="CWE-89",
                    )
                    self._attach_trace(node, sql_arg)

        # --- SINK 2: Manipulação de Arquivos (open com caminho contaminado) ---
        elif func_expr in ("open", "builtins.open", "io.open", "os.open", "flask.send_file", "send_file") or (isinstance(node.func, ast.Attribute) and node.func.attr in {"open", "read_text", "read_bytes", "write_text", "write_bytes", "unlink"} and ((isinstance(node.func.value, ast.Name) and node.func.value.id in self.path_vars) or (isinstance(node.func.value, ast.Call) and self.resolve(node.func.value.func) in {"Path", "pathlib.Path"}))):
            pathlib_sink = isinstance(node.func, ast.Attribute) and node.func.attr in {"open", "read_text", "read_bytes", "write_text", "write_bytes", "unlink"} and self._is_path_value(node.func.value)
            path_arg = node.func.value if pathlib_sink else self.argument(node, 0, "file", "path", "path_or_file")
            if path_arg is not None:
                tainted_var = self._contains_tainted_var(path_arg) or ("entrada externa" if self._is_source_expression(path_arg) else None)
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
                            "Resolva o caminho completo e confirme que permanece no diretório permitido; "
                            "use uma allow-list de recursos acessíveis."
                        ),
                        severity=Severity.HIGH,
                        cwe="CWE-22",
                    )
                    self._attach_trace(node, path_arg)

        # --- SINK 3: Requisições HTTP Externas / SSRF (CWE-918 / CVE-2020-13379) ---
        elif re.fullmatch(r"(?:requests|httpx)\.(get|post|put|delete|patch|head|options|request)|urllib\.request\.(urlopen|Request)", func_expr):
            url_arg = self.argument(node, 1 if func_expr.endswith(".request") else 0, "url", "fullurl")
            if url_arg is not None:
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
                    self._attach_trace(node, url_arg)

        # Continua a inspeção
        self.generic_visit(node)
