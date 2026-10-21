"""Fluxo intraprocedural: une caminhos e calcula ponto fixo limitado em laços.

Não executa código, não modela chamadas entre funções nem prova alcançabilidade.
"""
import ast
from .base_rule import BaseRule


def argument(node, position=0, keywords=()):
    if len(node.args) > position:
        return node.args[position]
    return next((item.value for item in node.keywords if item.arg in keywords), None)


def http_url(node, name):
    owner, _, method = name.rpartition(".")
    if owner in {"requests", "httpx"} and method in {
        "get", "post", "put", "delete", "head", "patch", "options", "request"
    }:
        return argument(node, 1 if method == "request" else 0, ("url",))
    if name in {"urllib.request.urlopen", "urllib.request.Request"}:
        return argument(node, 0, ("url", "fullurl"))
    return None


class NameFlowRule(BaseRule):
    may_flow = True

    def scan(self, tree, file_path, source_code):
        self.names, self.aliases, self.shadowed, self._reported = set(), {}, set(), set()
        return super().scan(tree, file_path, source_code)

    def add_finding(self, node, **kwargs):
        key = (kwargs.get("rule_id", self.rule_id), node.lineno, node.col_offset)
        if key not in self._reported:
            self._reported.add(key)
            super().add_finding(node, **kwargs)

    def qualified_name(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{self.qualified_name(node.value)}.{node.attr}"
        return ""

    def visit_Import(self, node):
        for item in node.names:
            self.aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]

    def visit_ImportFrom(self, node):
        if node.level == 0 and node.module:
            for item in node.names:
                if item.name != "*":
                    self.aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    def _snapshot(self):
        return self.names.copy(), self.aliases.copy(), self.shadowed.copy()

    def _restore(self, state):
        self.names, self.aliases, self.shadowed = (part.copy() for part in state)

    def _merge(self, *states):
        names = set.union(*(state[0] for state in states)) if self.may_flow else set.intersection(*(state[0] for state in states))
        aliases = {key: value for key, value in states[0][1].items()
                   if all(state[1].get(key) == value for state in states[1:])}
        return names, aliases, set.union(*(state[2] for state in states))

    def _block(self, statements, state):
        self._restore(state)
        for statement in statements:
            self.visit(statement)
        return self._snapshot()

    def _classification(self, node):
        raise NotImplementedError

    def _bindings(self, target, value):
        if isinstance(target, ast.Name):
            return [(target.id, self._classification(value))]
        if isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
                return [binding for left, right in zip(target.elts, value.elts) for binding in self._bindings(left, right)]
            return [binding for child in target.elts for binding in self._bindings(child, value)]
        if isinstance(target, ast.Starred):
            return self._bindings(target.value, value)
        return []

    def _apply_bindings(self, bindings):
        for name, classified in bindings:
            self.names.add(name) if classified else self.names.discard(name)
            self.aliases.pop(name, None)
            self.shadowed.add(name)

    def visit_Assign(self, node):
        self.visit(node.value)
        bindings = [binding for target in node.targets for binding in self._bindings(target, node.value)]
        self._apply_bindings(bindings)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
            self._apply_bindings(self._bindings(node.target, node.value))

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self._apply_bindings(self._bindings(node.target, node.value))

    def visit_AugAssign(self, node):
        self.visit(node.value)
        old, new = self._classification(node.target), self._classification(node.value)
        classified = (old or new) if self.may_flow else (old and new)
        if isinstance(node.target, ast.Name):
            self._apply_bindings([(node.target.id, classified)])

    def visit_If(self, node):
        self.visit(node.test)
        entry = self._snapshot()
        self._restore(self._merge(self._block(node.body, entry), self._block(node.orelse, entry)))

    def _loop(self, node):
        self.visit(node.iter if isinstance(node, (ast.For, ast.AsyncFor)) else node.test)
        entry = head = self._snapshot()
        for _ in range(32):
            self._restore(head)
            if isinstance(node, (ast.For, ast.AsyncFor)):
                self._apply_bindings(self._bindings(node.target, node.iter))
            else:
                self.visit(node.test)
            body = self._block(node.body, self._snapshot())
            joined = self._merge(entry, body)
            if joined == head:
                break
            head = joined
        else:
            self._restore(head)
            written = {child.id for child in ast.walk(node) if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)}
            self.names = self.names | written if self.may_flow else self.names - written
            head = self._snapshot()
            self._block(node.body, head)
        # break pode pular o else; preserve também o caminho sem ele.
        self._restore(self._merge(head, self._block(node.orelse, head)))

    visit_For = _loop
    visit_AsyncFor = _loop
    visit_While = _loop

    def visit_Try(self, node):
        possible = [self._snapshot()]
        for statement in node.body:
            self.visit(statement)
            possible.append(self._snapshot())
        outcomes = [self._block(node.orelse, possible[-1])]
        handler_entry = self._merge(*possible)
        for handler in node.handlers:
            outcomes.append(self._block(handler.body, handler_entry))
        if node.finalbody:
            # finally também executa quando uma exceção interrompe o corpo.
            # Inspecione esses caminhos sem tratá-los como saída normal do try.
            self._block(node.finalbody, self._merge(*possible, *outcomes))
        self._block(node.finalbody, self._merge(*outcomes))

    visit_TryStar = visit_Try

    def visit_FunctionDef(self, node):
        for expression in [*node.decorator_list, *node.args.defaults, *filter(None, node.args.kw_defaults)]:
            self.visit(expression)
        outer = self._snapshot()
        parameters = {arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
        parameters.update(arg.arg for arg in (node.args.vararg, node.args.kwarg) if arg)
        local = set(parameters)
        stack = list(node.body)
        while stack:
            child = stack.pop()
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                if hasattr(child, "name"):
                    local.add(child.name)
                continue
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                local.add(child.id)
            stack.extend(ast.iter_child_nodes(child))
        self.names -= local
        self.aliases = {key: value for key, value in self.aliases.items() if key not in local}
        self.shadowed |= local
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self._restore(outer)

    visit_AsyncFunctionDef = visit_FunctionDef
