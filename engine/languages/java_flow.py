"""Bounded lexical expression analysis for Java, without executing source code.

The analysis follows local assignments and class fields. It deliberately does not
claim interprocedural, cross-file, or path-sensitive data-flow coverage.
"""
from .syntax_tree import args, field, text, walk, LITERALS


LEXICAL_SCOPES = {
    "program", "class_body", "interface_body", "block", "constructor_body",
    "method_declaration", "constructor_declaration", "lambda_expression",
    "for_statement", "enhanced_for_statement", "catch_clause",
}
CONTROL_SCOPES = {"if_statement", "while_statement", "do_statement", "for_statement",
                  "enhanced_for_statement", "switch_expression", "switch_block_statement_group",
                  "catch_clause", "conditional_expression"}


def enclosing_scopes(node):
    current = node.parent
    while current is not None:
        if current.type in LEXICAL_SCOPES:
            yield current.id
        current = current.parent


def declaration_scope(node):
    return next(enclosing_scopes(node), 0)


class JavaFlow:
    """Resolve prior definitions using the lexical scope of each expression."""

    def __init__(self, root):
        self.root = root
        self.nodes = list(walk(root))
        self.bindings = {}
        self.types = {}
        self.mutations = {}
        # Collect declarations first so assignments can be attached to the right
        # symbol, including fields declared after a method in a Java class.
        for node in self.nodes:
            if node.type == "variable_declarator":
                name, value = field(node, "name"), field(node, "value")
                if name is None:
                    continue
                key = (declaration_scope(node), text(name))
                self.bindings.setdefault(key, []).append((node.start_byte, value, node))
                declared_type = text(field(node.parent, "type"))
                self.types[key] = declared_type
            elif node.type in {"formal_parameter", "spread_parameter", "catch_formal_parameter"}:
                name = field(node, "name")
                if name is not None:
                    key = (declaration_scope(node), text(name))
                    self.bindings.setdefault(key, []).append((node.start_byte, None, node))
                    self.types[key] = text(field(node, "type"))
        for node in self.nodes:
            if node.type == "assignment_expression":
                left, right = field(node, "left"), field(node, "right")
                key = self.symbol(left)
                if key and right is not None:
                    value = node if text(field(node, "operator")) != "=" else right
                    self.bindings.setdefault(key, []).append((node.start_byte, value, node))
            elif node.type == "method_invocation" and text(field(node, "name")) == "append":
                owner = field(node, "object")
                while owner is not None and owner.type == "method_invocation" and text(field(owner, "name")) == "append":
                    owner = field(owner, "object")
                key = self.symbol(owner)
                if key:
                    self.mutations.setdefault(key, []).append(node)
        for values in self.bindings.values():
            values.sort(key=lambda item: item[0])

    def symbol(self, node):
        if node is None:
            return None
        name = text(node)
        scopes = list(enclosing_scopes(node))
        if node.type == "field_access" and text(field(node, "object")) == "this":
            name = text(field(node, "field"))
            # this.x must not resolve to a local variable named x.
            scopes = [current.id for current in self.nodes
                      if current.id in scopes and current.type == "class_body"]
        elif node.type != "identifier":
            return None
        return next(((scope, name) for scope in scopes if (scope, name) in self.bindings), None)

    def resolve_once(self, node):
        """Return one definition, preserving intermediate symbols for joins."""
        if node is None:
            return None
        key = self.symbol(node)
        if not key:
            return node
        values = self.bindings.get(key, [])
        prior = [(position, value, declaration) for position, value, declaration in values
                 if position < node.start_byte and self._definite(declaration, node)]
        # Field initializers are in scope throughout their class, unlike locals.
        if not prior:
            prior = [(position, value, declaration) for position, value, declaration in values
                     if declaration.parent is not None and declaration.parent.type == "field_declaration"]
        if not prior or prior[-1][1] is None:
            return node
        return prior[-1][1]

    def resolve(self, node, seen=None):
        if node is None:
            return None
        key = self.symbol(node)
        seen = set() if seen is None else set(seen)
        if key is None or key in seen:
            return node
        seen.add(key)
        value = self.resolve_once(node)
        return self.resolve(value, seen) if value is not node else node

    @staticmethod
    def _visible(declaration, use):
        return declaration_scope(declaration) in set(enclosing_scopes(use))

    @classmethod
    def _definite(cls, declaration, use):
        if not cls._visible(declaration, use):
            return False
        ancestors = set()
        current = use.parent
        while current is not None:
            ancestors.add(current.id)
            current = current.parent
        current = declaration.parent
        while current is not None:
            if current.type in CONTROL_SCOPES and current.id not in ancestors:
                return False
            current = current.parent
        return True

    @staticmethod
    def _execution_context(node):
        current = node.parent
        while current is not None:
            if current.type in {"method_declaration", "constructor_declaration", "lambda_expression"}:
                return current.id
            current = current.parent
        return 0

    def type_of(self, node):
        key = self.symbol(node)
        declared = self.types.get(key, "")
        if declared and declared != "var":
            return declared
        resolved = self.resolve(node)
        if resolved is None:
            return ""
        if resolved.type == "object_creation_expression":
            return text(field(resolved, "type"))
        return ""

    def dynamic(self, node, depth=0, seen=None):
        if node is None or depth > 24:
            return True
        seen = set() if seen is None else set(seen)
        marker = (node.id, depth)
        if marker in seen:
            return True
        seen.add(marker)
        # Do not collapse an alias chain before visiting its intermediate
        # symbols: each symbol can have conditional definitions to merge.
        resolved = self.resolve_once(node)
        if resolved is not node:
            if self.dynamic(resolved, depth + 1, seen):
                return True
            key = self.symbol(node)
            prior = [(position, declaration) for position, _, declaration in self.bindings.get(key, [])
                     if position < node.start_byte and self._definite(declaration, node)]
            baseline = prior[-1][0] if prior else -1
            context = self._execution_context(node)
            # A conditional assignment may taint the symbol at the join. It
            # cannot erase an unsafe value unless an unconditional definition
            # supersedes it. Only definitions of the same lexical symbol count.
            for position, value, declaration in self.bindings.get(key, []):
                if baseline < position < node.start_byte and self._execution_context(declaration) == context and value is not None:
                    if self.dynamic(value, depth + 1, seen):
                        return True
            # StringBuilder.append mutates the value after construction,
            # including append chains and conditional appends on the same symbol.
            return any(self.dynamic(argument, depth + 1, seen)
                       for mutation in self.mutations.get(key, [])
                       if baseline < mutation.start_byte < node.start_byte and self._execution_context(mutation) == context
                       for argument in args(mutation))
        if node.type in LITERALS:
            return False
        if node.type in {"binary_expression", "parenthesized_expression", "cast_expression", "array_initializer"}:
            return any(self.dynamic(child, depth + 1, seen) for child in node.named_children
                       if child.type not in {"type_identifier", "integral_type", "floating_point_type"})
        if node.type == "assignment_expression":
            return self.dynamic(field(node, "left"), depth + 1, seen) or self.dynamic(field(node, "right"), depth + 1, seen)
        if node.type == "array_creation_expression":
            value = field(node, "value")
            return self.dynamic(value, depth + 1, seen) if value is not None else True
        if node.type == "object_creation_expression":
            kind = text(field(node, "type")).split(".")[-1]
            if kind in {"String", "StringBuilder", "StringBuffer", "File", "URI", "URL"}:
                return any(self.dynamic(argument, depth + 1, seen) for argument in args(node))
        if node.type == "method_invocation":
            name, owner = text(field(node, "name")), field(node, "object")
            arguments = args(node)
            if name in {"format", "formatted", "valueOf", "concat", "append", "toString", "trim", "strip", "normalize", "toAbsolutePath", "resolve", "getCanonicalPath", "getCanonicalFile", "getPath", "getFileName", "toPath", "create", "of", "get", "replace", "replaceAll"}:
                # Only model known value-building operations. Unknown methods
                # remain dynamic, regardless of names such as sanitize/validate.
                return ((owner is not None and text(owner) not in {"String", "Paths", "Path", "URI", "Integer", "Long"}
                         and self.dynamic(owner, depth + 1, seen))
                        or any(self.dynamic(argument, depth + 1, seen) for argument in arguments))
        return True

    def expanded_text(self, node, depth=0):
        if node is None or depth > 16:
            return ""
        resolved = self.resolve(node)
        if resolved is not node:
            return self.expanded_text(resolved, depth + 1)
        return text(node) + " " + " ".join(self.expanded_text(child, depth + 1) for child in node.named_children)

    def literal(self, node):
        node = self.resolve(node)
        if node is None:
            return None
        if node.type in {"string_literal", "character_literal"}:
            return text(node)[1:-1]
        if node.type in {"true", "false"}:
            return text(node) == "true"
        if node.type == "binary_expression" and text(field(node, "operator")) == "+":
            left, right = self.literal(field(node, "left")), self.literal(field(node, "right"))
            return left + right if isinstance(left, str) and isinstance(right, str) else None
        return None

    def possible_strings(self, node, depth=0):
        """Keep bounded constant alternatives instead of selecting one branch.

        None means that at least one value is unknown. This helper does not
        evaluate conditions or execute expressions from the analyzed program.
        """
        if node is None or depth > 20:
            return None
        key = self.symbol(node)
        value = self.resolve_once(node)
        if value is not node:
            alternatives = self.possible_strings(value, depth + 1)
            if alternatives is None:
                return None
            prior = [(position, declaration) for position, _, declaration in self.bindings.get(key, [])
                     if position < node.start_byte and self._definite(declaration, node)]
            baseline = prior[-1][0] if prior else -1
            context = self._execution_context(node)
            for position, branch, declaration in self.bindings.get(key, []):
                if baseline < position < node.start_byte and self._execution_context(declaration) == context and branch is not None:
                    branch_values = self.possible_strings(branch, depth + 1)
                    if branch_values is None:
                        return None
                    alternatives |= branch_values
                    if len(alternatives) > 32:
                        return None
            return alternatives
        if node.type in {"string_literal", "character_literal"}:
            return {text(node)[1:-1]}
        if node.type == "binary_expression" and text(field(node, "operator")) == "+":
            left = self.possible_strings(field(node, "left"), depth + 1)
            right = self.possible_strings(field(node, "right"), depth + 1)
            if left is not None and right is not None and len(left) * len(right) <= 32:
                return {a + b for a in left for b in right}
        if node.type in {"parenthesized_expression", "cast_expression"} and node.named_children:
            return self.possible_strings(node.named_children[-1], depth + 1)
        return None

    def calls_before(self, node, owner, names):
        key = self.symbol(owner)
        sink_ancestors = set()
        current = node.parent
        while current is not None:
            sink_ancestors.add(current.id)
            current = current.parent
        for candidate in self.nodes:
            if candidate.start_byte >= node.start_byte or candidate.type != "method_invocation":
                continue
            if text(field(candidate, "name")) not in names or not self._visible(candidate, node):
                continue
            current = candidate.parent
            conditional = False
            while current is not None:
                if current.type in CONTROL_SCOPES and current.id not in sink_ancestors:
                    conditional = True
                    break
                current = current.parent
            if conditional:
                continue
            other = field(candidate, "object")
            if key and self.symbol(other) == key:
                yield candidate
