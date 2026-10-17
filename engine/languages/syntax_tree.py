"""Parsing Tree-sitter e utilitários compartilhados pelos scanners estruturais."""
from functools import lru_cache
from tree_sitter import Language, Parser


@lru_cache(maxsize=4)
def language(name):
    if name == "java":
        import tree_sitter_java
        return Language(tree_sitter_java.language())
    if name in {"typescript", "tsx"}:
        import tree_sitter_typescript
        return Language(tree_sitter_typescript.language_tsx() if name == "tsx" else tree_sitter_typescript.language_typescript())
    import tree_sitter_javascript
    return Language(tree_sitter_javascript.language())


def parse(source, name):
    # Parser é criado por chamada: as instâncias não são compartilhadas entre threads.
    return Parser(language(name)).parse(source.encode("utf-8"))


def walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def text(node):
    return node.text.decode("utf-8") if node is not None else ""


def field(node, name):
    return node.child_by_field_name(name) if node is not None else None


def args(node):
    arguments = field(node, "arguments")
    return arguments.named_children if arguments is not None else []


LITERALS = {"string", "string_literal", "character_literal", "number", "decimal_integer_literal",
            "hex_integer_literal", "true", "false", "null_literal", "null"}
SCOPE_TYPES = {"function_declaration", "function_expression", "arrow_function", "method_definition",
               "method_declaration", "constructor_declaration", "lambda_expression"}


def scope(node):
    current = node.parent
    while current is not None:
        if current.type in SCOPE_TYPES:
            return current.id
        current = current.parent
    return 0


class Expressions:
    """Resolve atribuições anteriores no mesmo escopo; não interpreta o código."""
    def __init__(self, root):
        self.bindings = {}
        for node in walk(root):
            if node.type == "variable_declarator":
                name, value = field(node, "name"), field(node, "value")
            elif node.type in {"assignment_expression", "assignment"}:
                name, value = field(node, "left"), field(node, "right")
            else:
                continue
            if name is not None and value is not None and name.type == "identifier":
                self.bindings.setdefault((scope(node), text(name)), []).append((node.start_byte, value))

    def resolve(self, node, seen=None):
        if node is None or node.type != "identifier":
            return node
        seen = set() if seen is None else seen
        key = (scope(node), text(node))
        if key in seen:
            return node
        seen.add(key)
        candidates = self.bindings.get(key, [])
        if not candidates and key[0]:
            candidates = self.bindings.get((0, key[1]), [])
        previous = [value for position, value in candidates if position < node.start_byte]
        return self.resolve(previous[-1], seen) if previous else node

    def dynamic(self, node, depth=0):
        if node is None or depth > 20:
            return True
        resolved = self.resolve(node)
        if resolved is not node:
            return self.dynamic(resolved, depth + 1)
        if node.type in LITERALS:
            return False
        if node.type == "template_string":
            return any(self.dynamic(child.named_children[0], depth + 1)
                       for child in node.named_children if child.type == "template_substitution" and child.named_children)
        if node.type in {"binary_expression", "parenthesized_expression", "cast_expression"}:
            return any(self.dynamic(child, depth + 1) for child in node.named_children
                       if child.type not in {"type_identifier", "integral_type"})
        return True


def syntax_error(root, name, path):
    invalid = next((node for node in walk(root) if node.type == "ERROR" or node.is_missing), root)
    return f"Erro de sintaxe {name} em {path}:{invalid.start_point.row + 1}. Análise incompleta."


def finding_location(node, source):
    lines = source.splitlines()
    row, byte_column = node.start_point
    column = len(lines[row].encode("utf-8")[:byte_column].decode("utf-8", errors="replace")) if row < len(lines) else 0
    snippet = "\n".join(lines[row:node.end_point.row + 1])
    return row + 1, column, snippet
