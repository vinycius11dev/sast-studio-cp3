"""Small, bounded AST context shared by Python pattern rules.

Resolves import aliases and literal assignments without importing or running the
analyzed program. Values are local to a function; this is not whole-program
symbol resolution or a proof of reachability.
"""
import ast

from .base_rule import BaseRule


UNKNOWN = object()


class PythonContextRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.aliases = {}
        self.values = {}
        self.parents = []

    def visit(self, node):
        self.parents.append(node)
        try:
            return super().visit(node)
        finally:
            self.parents.pop()

    def resolve(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            prefix = self.resolve(node.value)
            return f"{prefix}.{node.attr}" if prefix else ""
        return ""

    def literal(self, node, seen=None):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return self.values.get(node.id, UNKNOWN)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.literal(node.operand)
            return not value if value is not UNKNOWN else UNKNOWN
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.literal(node.left), self.literal(node.right)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
        return UNKNOWN

    @staticmethod
    def argument(node, index, *names):
        if len(node.args) > index:
            return node.args[index]
        return next((kw.value for kw in node.keywords if kw.arg in names), None)

    def visit_Import(self, node):
        for entry in node.names:
            self.aliases[entry.asname or entry.name.split(".")[0]] = entry.name if entry.asname else entry.name.split(".")[0]

    def visit_ImportFrom(self, node):
        for entry in node.names:
            if entry.name != "*":
                self.aliases[entry.asname or entry.name] = f"{node.module}.{entry.name}" if node.module else entry.name

    def _bind(self, target, value):
        if isinstance(target, ast.Name):
            resolved = self.resolve(value)
            factory = self.resolve(value.func) if isinstance(value, ast.Call) else ""
            self.aliases[target.id] = resolved if resolved and isinstance(value, (ast.Name, ast.Attribute)) else ""
            if isinstance(value, ast.Call):
                instances = {"logging.getLogger": "logging", "random.Random": "random", "requests.Session": "requests", "httpx.Client": "httpx", "httpx.AsyncClient": "httpx"}
                if factory in instances:
                    self.aliases[target.id] = instances[factory]
            literal = self.literal(value)
            if literal is UNKNOWN:
                self.values.pop(target.id, None)
            else:
                self.values[target.id] = literal
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._bind(item, ast.Constant(None))

    def visit_Assign(self, node):
        self.visit(node.value)
        for target in node.targets:
            self._bind(target, node.value)
            self.visit(target)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
            self._bind(node.target, node.value)
        self.visit(node.target)

    def visit_AugAssign(self, node):
        self.generic_visit(node)
        if isinstance(node.target, ast.Name):
            self.values.pop(node.target.id, None)
            self.aliases[node.target.id] = ""

    def visit_FunctionDef(self, node):
        for value in (*node.decorator_list, *node.args.defaults, *[v for v in node.args.kw_defaults if v is not None]):
            self.visit(value)
        self.aliases[node.name] = ""
        outer_aliases, outer_values = self.aliases, self.values
        self.aliases, self.values = dict(outer_aliases), dict(outer_values)
        arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        for arg in (*arguments, *([node.args.vararg] if node.args.vararg else []), *([node.args.kwarg] if node.args.kwarg else [])):
            self.aliases[arg.arg] = ""
            self.values.pop(arg.arg, None)
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.aliases, self.values = outer_aliases, outer_values

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node):
        self.visit(node.test)
        before_aliases, before_values = dict(self.aliases), dict(self.values)
        for statement in node.body:
            self.visit(statement)
        body_aliases, body_values = self.aliases, self.values
        self.aliases, self.values = dict(before_aliases), dict(before_values)
        for statement in node.orelse:
            self.visit(statement)
        self.aliases = {key: value for key, value in body_aliases.items() if self.aliases.get(key, UNKNOWN) == value}
        self.values = {key: value for key, value in body_values.items() if self.values.get(key, UNKNOWN) == value}
