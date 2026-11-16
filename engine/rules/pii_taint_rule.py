"""Taint Analysis de dados pessoais (GS CitizenTech): da origem sensível até a saída insegura.

Fontes (sources): variáveis, parâmetros, atributos, chaves de dicionário e prompts cujo nome indica
CPF/documento, dado de saúde ou senha. O dado se propaga por atribuições, f-strings, concatenação,
chamadas e retornos de funções do mesmo arquivo. Sanitizadores (máscara, hash, criptografia,
fatias curtas) interrompem o rastreio. Sinks: console/log, resposta HTTP, armazenamento em texto
claro e envio a serviços externos. Cada achado guarda o caminho percorrido em ``taint_trace``.

Limites: análise intra-arquivo, sem resolução de tipos; ramos ``if/else`` são unidos e laços são
percorridos uma vez. O resultado indica risco de vazamento, não prova exploração.
"""
import ast
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from engine.models import RuleMetadata, Severity
from engine.pii import CATEGORIES, CONTATO, DOCUMENTO, FINANCEIRO, SAUDE, SENHA, classify_identifier, most_severe
from .base_rule import BaseRule

MAX_TRACE = 8

SANITIZER_NAME = re.compile(
    r"(mask|masc|redact|anonim|anonym|pseudonym|hash|digest|crypt|tokeniz|sanitiz|obfusc|ofusc|scrub|"
    r"argon|pbkdf|scrypt|hmac|censor)", re.IGNORECASE)
BOOLEAN_NAME = re.compile(r"^(is_|has_|valid|check|verif)", re.IGNORECASE)
NEUTRAL_BUILTINS = {"len", "bool", "isinstance", "type", "id"}

CONSOLE_SINK = re.compile(
    r"^(print|sys\.(stdout|stderr)\.write|(?:[\w\.]*\.)?(?:logger|log|logging|_logger|LOGGER|LOG)"
    r"\.(?:debug|info|warning|warn|error|exception|critical|fatal|log))$")
RESPONSE_SINK = {
    "jsonify", "JSONResponse", "ORJSONResponse", "Response", "HTMLResponse", "PlainTextResponse",
    "make_response", "render_template", "render_template_string", "HttpResponse", "JsonResponse",
    "HTTPException", "abort", "StreamingResponse",
}
STORAGE_ATTRIBUTES = {"write", "writelines", "write_text", "write_bytes", "writerow", "writerows"}
STORAGE_FUNCTIONS = {"json.dump", "pickle.dump", "yaml.dump", "yaml.safe_dump"}
DATABASE_ATTRIBUTES = {"execute", "executemany"}
EXTERNAL_SINK = re.compile(
    r"^(requests\.(get|post|put|patch|delete|head|request)|httpx\.(get|post|put|patch|delete|head|request)|"
    r"urllib\.request\.urlopen|urlopen|session\.(post|put|patch|request)|aiohttp\.\w+)$")
EXTERNAL_ATTRIBUTES = {"sendmail", "send_mail", "send_email"}
ROUTE_DECORATOR = re.compile(r"\.(get|post|put|patch|delete|route|api_route)\b|^route$", re.IGNORECASE)

SINKS = {
    "console": ("PY-T004", "PII em log ou console", "CWE-532", "o console ou arquivo de log"),
    "response": ("PY-T005", "PII em resposta HTTP sem mascaramento", "CWE-201", "a resposta enviada ao cliente"),
    "storage": ("PY-T006", "PII gravada em texto claro", "CWE-312", "um arquivo ou banco de dados"),
    "external": ("PY-T007", "PII enviada a serviço externo", "CWE-359", "um serviço fora do sistema"),
}
# Contato (e-mail, telefone) só é acusado em log: devolver o e-mail ao próprio usuário ou enviá-lo num cadastro é fluxo normal.
SEVERITY = {
    "console": {SENHA: Severity.CRITICAL, SAUDE: Severity.CRITICAL, FINANCEIRO: Severity.CRITICAL, DOCUMENTO: Severity.HIGH, CONTATO: Severity.LOW},
    "response": {SENHA: Severity.CRITICAL, FINANCEIRO: Severity.CRITICAL, SAUDE: Severity.HIGH, DOCUMENTO: Severity.HIGH},
    "storage": {SENHA: Severity.CRITICAL, FINANCEIRO: Severity.CRITICAL, SAUDE: Severity.HIGH, DOCUMENTO: Severity.HIGH},
    "external": {SENHA: Severity.CRITICAL, FINANCEIRO: Severity.HIGH, SAUDE: Severity.HIGH, DOCUMENTO: Severity.MEDIUM},
}
REMEDIATION = {
    "console": "Registre apenas identificadores internos ou valores mascarados (ex.: ***.***.***-25). Nunca registre senhas nem dados de saúde.",
    "response": "Devolva apenas os campos necessários e mascare o CPF. Senha e hash nunca devem sair da API; dados de saúde só com autorização.",
    "storage": "Armazene senhas somente como hash com salt (bcrypt/Argon2) e proteja CPF e dados de saúde com criptografia (ex.: Fernet/AES) e permissão restrita.",
    "external": "Envie o mínimo necessário, mascarado ou pseudonimizado, e só a operadores com base legal e contrato (LGPD arts. 7º e 46).",
}

_UNSET = object()


@dataclass(frozen=True)
class FixSite:
    """Expressão que leva o dado sensível até uma saída insegura: o ponto onde o corretor aplica a proteção."""
    rule_id: str
    line: int          # linha da saída insegura (sink)
    leaf: ast.expr     # expressão a proteger
    helper: str        # "mask" (mascarar) ou "hash" (senha em armazenamento)
    categories: frozenset


class _Taint:
    """Dado sensível rastreado: categorias de PII e o caminho já percorrido."""
    __slots__ = ("categories", "trace")

    def __init__(self, categories, trace):
        self.categories = frozenset(categories)
        self.trace = tuple(trace)

    def extend(self, step: str) -> "_Taint":
        trace = self.trace if self.trace and self.trace[-1] == step else self.trace + (step,)
        return _Taint(self.categories, trace[-MAX_TRACE:])


def _merge(*items) -> Optional[_Taint]:
    items = [item for item in items if isinstance(item, _Taint)]
    if not items:
        return None
    if len(items) == 1:
        return items[0]
    longest = max(items, key=lambda item: len(item.trace))
    return _Taint(frozenset().union(*(item.categories for item in items)), longest.trace)


class PiiTaintRule(BaseRule):
    """PY-T004…T007: rastreia PII (documentos, saúde, senha, cartão, contato) até saídas inseguras."""

    rule_id: str = "PY-T004"
    name: str = SINKS["console"][1]
    severity: Severity = Severity.HIGH
    cwe: str = "CWE-532"
    description: str = (
        "Dado pessoal sensível (CPF, saúde, senha, cartão) flui até um log ou console sem mascaramento. "
        "Logs são copiados, indexados e lidos por muita gente, e o vazamento expõe o cidadão."
    )
    remediation: str = REMEDIATION["console"]

    def get_additional_metadata(self) -> List[RuleMetadata]:
        descriptions = {
            "response": "Dado pessoal sensível chega a uma resposta HTTP sem mascaramento; qualquer cliente que chame a rota recebe o valor completo.",
            "storage": "Dado pessoal sensível é gravado em arquivo ou banco em texto claro, sem hash nem criptografia.",
            "external": "Dado pessoal sensível é enviado a um serviço externo (HTTP ou e-mail) sem minimização.",
        }
        return [
            RuleMetadata(rule_id=SINKS[kind][0], name=SINKS[kind][1], severity=Severity.HIGH, cwe=SINKS[kind][2],
                         description=text, remediation=REMEDIATION[kind])
            for kind, text in descriptions.items()
        ]

    def __init__(self):
        super().__init__()
        self.env: Dict[str, Optional[_Taint]] = {}
        self.summaries: Dict[str, _Taint] = {}
        self.report = True
        self._returns: List[_Taint] = []
        self._collected: Dict[str, _Taint] = {}
        self._in_route = False
        self.fix_sites: List[FixSite] = []

    # ---- entrada -------------------------------------------------------------------------------
    def scan(self, tree: ast.AST, file_path: str, source_code: str):
        self.current_file_path, self.source_lines, self.findings, self.fix_sites = file_path, source_code.splitlines(), [], []
        for _ in range(2):  # duas passadas propagam retornos de funções declaradas fora de ordem
            probe = PiiTaintRule()
            probe.report, probe.summaries = False, dict(self.summaries)
            probe.current_file_path, probe.source_lines = file_path, self.source_lines
            probe.visit(tree)
            self.summaries = probe._collected
        self.env, self._returns, self._in_route = {}, [], False
        self.visit(tree)
        return self.findings

    # ---- expressões ----------------------------------------------------------------------------
    @staticmethod
    def _const_str(node) -> Optional[str]:
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    @staticmethod
    def _is_partial_slice(node: ast.Slice) -> bool:
        def value(part):
            if isinstance(part, ast.UnaryOp) and isinstance(part.op, ast.USub):  # -2 é UnaryOp(USub, 2) no AST
                inner = value(part.operand)
                return -inner if inner is not None else None
            return part.value if isinstance(part, ast.Constant) and isinstance(part.value, int) else None
        lower, upper = value(node.lower) if node.lower else 0, value(node.upper) if node.upper else None
        if lower is None or (node.upper and upper is None):
            return False
        if upper is None:
            return lower < 0 and -lower <= 5
        return lower >= 0 and 0 < upper - lower <= 5

    def _is_sanitizer(self, full: str) -> bool:
        last = full.split(".")[-1]
        return bool(SANITIZER_NAME.search(full) or BOOLEAN_NAME.match(last) or full in NEUTRAL_BUILTINS)

    def _explicitly_clean(self, node) -> bool:
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Call) and self._is_sanitizer(ast.unparse(node.func)):
            return True
        return isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice) and self._is_partial_slice(node.slice)

    def _source(self, category: str, description: str, node) -> _Taint:
        return _Taint({category}, (f"{description} (linha {getattr(node, 'lineno', '?')})",))

    def taint_of(self, node) -> Optional[_Taint]:
        if node is None or isinstance(node, (ast.Constant, ast.Lambda, ast.Compare)):
            return None
        if isinstance(node, ast.Name):
            if node.id in self.env:
                return self.env[node.id]
            category = classify_identifier(node.id)
            return self._source(category, f"'{node.id}'", node) if category else None
        if isinstance(node, ast.Attribute):
            category = classify_identifier(node.attr)
            if category:
                return self._source(category, f"atributo '{ast.unparse(node)}'", node)
            return self.taint_of(node.value)
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Slice):
                return None if self._is_partial_slice(node.slice) else self.taint_of(node.value)
            key = self._const_str(node.slice)
            category = classify_identifier(key)
            if category:
                return self._source(category, f"campo '{key}' de {ast.unparse(node.value)}", node)
            return self.taint_of(node.value)
        if isinstance(node, ast.Call):
            return self._call_taint(node)
        if isinstance(node, ast.Dict):
            parts = []
            for key, value in zip(node.keys, node.values):
                category = classify_identifier(self._const_str(key))
                if category and not self._explicitly_clean(value):
                    parts.append(self._source(category, f"chave '{self._const_str(key)}'", key))
                else:
                    parts.append(self.taint_of(value))
            return _merge(*parts)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return None
        return _merge(*[self.taint_of(child) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)])

    def _call_taint(self, node: ast.Call) -> Optional[_Taint]:
        full = ast.unparse(node.func)
        if self._is_sanitizer(full):
            return None
        if full in {"input", "getpass", "getpass.getpass"} and node.args:
            category = classify_identifier(self._const_str(node.args[0]))
            if category:
                return self._source(category, f"entrada do usuário ({self._const_str(node.args[0]).strip()[:30]})", node)
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "pop", "getlist", "getfirst"} and node.args:
            key = self._const_str(node.args[0])
            category = classify_identifier(key)
            if category:
                return self._source(category, f"campo '{key}' de {ast.unparse(node.func.value)}", node)
        if full == "getattr" and len(node.args) >= 2:
            category = classify_identifier(self._const_str(node.args[1]))
            if category:
                return self._source(category, f"atributo '{self._const_str(node.args[1])}'", node)
        local = full.split(".")[-1]
        if local in self.summaries:
            summary = self.summaries[local]
            return _Taint(summary.categories, summary.trace + (f"retorno de {local}() (linha {node.lineno})",))
        parts = [self.taint_of(node.func.value)] if isinstance(node.func, ast.Attribute) else []
        parts += [self.taint_of(argument) for argument in node.args]
        parts += [self.taint_of(keyword.value) for keyword in node.keywords]
        return _merge(*parts)

    # ---- instruções ----------------------------------------------------------------------------
    def _bind(self, target, taint: Optional[_Taint], value, lineno: int) -> None:
        if isinstance(target, ast.Name):
            if taint is not None:
                self.env[target.id] = taint.extend(f"{target.id} (linha {lineno})")
            elif self._explicitly_clean(value):
                self.env[target.id] = None
            else:
                self.env.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind(element.value if isinstance(element, ast.Starred) else element, taint, value, lineno)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        for target in node.targets:
            if isinstance(target, (ast.Tuple, ast.List)) and isinstance(node.value, (ast.Tuple, ast.List)) \
                    and len(target.elts) == len(node.value.elts):
                for element, value in zip(target.elts, node.value.elts):
                    self._bind(element, self.taint_of(value), value, node.lineno)
            else:
                self._bind(target, self.taint_of(node.value), node.value, node.lineno)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        if node.value is not None:
            self._bind(node.target, self.taint_of(node.value), node.value, node.lineno)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.generic_visit(node)
        taint = _merge(self.taint_of(node.target), self.taint_of(node.value))
        if taint is not None:
            self._bind(node.target, taint, node.value, node.lineno)

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._bind(node.target, self.taint_of(node.iter), node.iter, node.lineno)
        for statement in node.body + node.orelse:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        before = dict(self.env)
        for statement in node.body:
            self.visit(statement)
        after_body, self.env = self.env, dict(before)
        for statement in node.orelse:
            self.visit(statement)
        merged = {}
        for name in set(after_body) | set(self.env):
            a, b = after_body.get(name, _UNSET), self.env.get(name, _UNSET)
            if isinstance(a, _Taint) or isinstance(b, _Taint):
                merged[name] = _merge(a, b)
            elif a is not _UNSET and b is not _UNSET:
                merged[name] = None
        self.env = merged

    def visit_FunctionDef(self, node) -> None:
        saved = (self.env, self._returns, self._in_route)
        self.env, self._returns = {}, []
        self._in_route = any(ROUTE_DECORATOR.search(ast.unparse(decorator)) for decorator in node.decorator_list)
        arguments = node.args
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs, arguments.vararg, arguments.kwarg):
            category = classify_identifier(argument.arg) if argument else None
            if category:
                self.env[argument.arg] = self._source(category, f"parâmetro '{argument.arg}'", argument)
        for statement in node.body:
            self.visit(statement)
        if self._returns:
            self._collected[node.name] = _merge(*self._returns)
        self.env, self._returns, self._in_route = saved

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Return(self, node: ast.Return) -> None:
        self.generic_visit(node)
        taint = self.taint_of(node.value)
        if taint is None:
            return
        self._returns.append(taint)
        if self.report and self._in_route:
            self._report("response", taint, node, "return da rota HTTP")

    # ---- sinks ---------------------------------------------------------------------------------
    def _sink_kind(self, node: ast.Call) -> Optional[str]:
        full = ast.unparse(node.func)
        last = full.split(".")[-1]
        if CONSOLE_SINK.match(full):
            return "console"
        if last in RESPONSE_SINK:
            return "response"
        if EXTERNAL_SINK.match(full) or (isinstance(node.func, ast.Attribute) and node.func.attr in EXTERNAL_ATTRIBUTES):
            return "external"
        if full in STORAGE_FUNCTIONS or (isinstance(node.func, ast.Attribute) and node.func.attr in STORAGE_ATTRIBUTES):
            return "storage"
        if isinstance(node.func, ast.Attribute) and node.func.attr in DATABASE_ATTRIBUTES:
            return "database"
        return None

    def _argument_taint(self, node: ast.Call) -> Optional[_Taint]:
        parts = [self.taint_of(argument.value if isinstance(argument, ast.Starred) else argument) for argument in node.args]
        for keyword in node.keywords:
            category = classify_identifier(keyword.arg)
            if category and not self._explicitly_clean(keyword.value):
                parts.append(self._source(category, f"argumento nomeado '{keyword.arg}'", keyword.value))
            else:
                parts.append(self.taint_of(keyword.value))
        return _merge(*parts)

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        kind = self._sink_kind(node) if self.report else None
        if not kind:
            return
        taint = self._argument_taint(node)
        if taint is None:
            return
        if kind == "database":  # PII em banco é esperado; só a senha em texto claro é falha.
            if SENHA not in taint.categories:
                return
            taint, kind = _Taint({SENHA}, taint.trace), "storage"
        self._report(kind, taint, node, f"{ast.unparse(node.func)}()")

    def _report(self, kind: str, taint: _Taint, node, sink: str) -> None:
        rule_id, name, cwe, destination = SINKS[kind]
        if any(item.rule_id == rule_id and item.line_number == node.lineno for item in self.findings):
            return  # `return jsonify(...)` é um único vazamento, não dois
        reportable = [item for item in taint.categories if item in SEVERITY[kind]]
        if not reportable:
            return
        category = most_severe(reportable)
        self._collect_fix_sites(rule_id, kind, node, set(reportable))
        trace = list(taint.trace) + [f"{sink} (linha {node.lineno}) ← saída insegura"]
        origin = taint.trace[0] if taint.trace else "origem sensível"
        labels = " + ".join(CATEGORIES[item].label for item in sorted(taint.categories, key=lambda item: -CATEGORIES[item].rank))
        self.add_finding(
            node=node, rule_id=rule_id, rule_name=name, cwe=cwe, severity=SEVERITY[kind][category],
            message=(
                f"[Taint Analysis · PII] {labels} flui de {origin} até {sink}, que leva para "
                f"{destination}, sem máscara, hash ou criptografia. {CATEGORIES[category].lgpd}."
            ),
            remediation=REMEDIATION[kind],
            data_categories=sorted(taint.categories), taint_trace=trace,
        )

    # ---- pontos de correção (usados por engine.citizen_fix) ------------------------------------
    def _leaves(self, node) -> List[ast.expr]:
        """Subexpressões contaminadas de um argumento, descendo em f-strings, concatenações, listas e dicionários."""
        if node is None or isinstance(node, ast.Constant) or self._explicitly_clean(node):
            return []
        if isinstance(node, ast.Starred):
            return self._leaves(node.value)
        if isinstance(node, ast.JoinedStr):
            return [leaf for part in node.values if isinstance(part, ast.FormattedValue) for leaf in self._leaves(part.value)]
        if isinstance(node, ast.BinOp):
            return self._leaves(node.left) + self._leaves(node.right)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return [leaf for element in node.elts for leaf in self._leaves(element)]
        if isinstance(node, ast.IfExp):
            return self._leaves(node.body) + self._leaves(node.orelse)
        if isinstance(node, ast.Dict):
            leaves = []
            for key, value in zip(node.keys, node.values):
                if value is None or self._explicitly_clean(value):
                    continue
                if classify_identifier(self._const_str(key)):
                    leaves.append(value)  # chave sensível: protege o valor inteiro
                else:
                    leaves.extend(self._leaves(value))
            return leaves
        return [node] if self.taint_of(node) is not None else []

    def _collect_fix_sites(self, rule_id: str, kind: str, node, reportable: set) -> None:
        if isinstance(node, ast.Call):
            candidates = [argument.value if isinstance(argument, ast.Starred) else argument for argument in node.args]
            for keyword in node.keywords:
                candidates.append(keyword.value)
        else:
            candidates = [getattr(node, "value", None)]
        for candidate in candidates:
            for leaf in self._leaves(candidate):
                taint = self.taint_of(leaf)
                categories = set(taint.categories) if taint else set()
                if isinstance(candidate, ast.Dict) or not categories:
                    categories |= {item for item in (classify_identifier(self._const_str(key)) for key in getattr(candidate, "keys", []) if key is not None) if item}
                categories &= reportable
                if not categories:
                    continue
                helper = "hash" if kind == "storage" and SENHA in categories else "mask"
                self.fix_sites.append(FixSite(rule_id, node.lineno, leaf, helper, frozenset(categories)))
