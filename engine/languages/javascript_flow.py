"""Local lexical propagation for JS/TS. No code execution or inter-file inference.

Bindings retain source positions, so assignments after a sink and declarations in
unrelated blocks/functions cannot make a safe expression appear tainted (or vice
versa). Branches and function calls are not a complete control-flow analysis.
"""
from dataclasses import dataclass
import re

from .syntax_tree import args, field, text, walk, LITERALS


FUNCTIONS = {"function_declaration", "function_expression", "generator_function",
             "generator_function_declaration", "arrow_function", "method_definition"}
FRAMES = FUNCTIONS | {"program", "statement_block", "catch_clause", "for_statement",
                      "for_in_statement", "switch_body"}
WRAPPERS = {"parenthesized_expression", "as_expression", "type_assertion",
            "non_null_expression", "satisfies_expression", "await_expression"}


def property_name(node):
    if node is None:
        return ""
    if node.type == "member_expression":
        return text(field(node, "property"))
    if node.type == "subscript_expression":
        return text(field(node, "index")).strip("'\"")
    return ""


def string_value(node):
    return text(node).strip("'\"`") if node is not None else ""


@dataclass
class Binding:
    position: int
    parts: tuple = ()
    symbol: str = ""
    parameter: bool = False
    assignment_frame: int = 0


class JavaScriptFlow:
    def __init__(self, root):
        self.root = root
        self.bindings = {}
        self.parents = {}
        for node in walk(root):
            if node.type in FRAMES:
                self.parents[node.id] = self.frame(node.parent)
        # Register declarations first: a later lexical declaration still shadows
        # an outer name, even before initialization (the temporal dead zone).
        for node in walk(root):
            if node.type in FUNCTIONS:
                parameters = field(node, "parameters") or field(node, "parameter")
                if parameters is not None:
                    parameter_list = parameters.named_children if parameters.type == "formal_parameters" else [parameters]
                    call = node.parent.parent if node.parent is not None and node.parent.type == "arguments" else None
                    route = self.canonical(field(call, "function")) if call is not None and call.type == "call_expression" else ""
                    express_route = bool(re.match(r"^(?:app|router|express\(\)|express\.Router\(\))\.(?:get|post|put|patch|delete|all|use|head|options)$", route))
                    for index, parameter in enumerate(parameter_list):
                        symbol = ("request", "response")[index] if express_route and index < 2 else ""
                        self.declare(parameter, None, node.id, node.start_byte - 1, symbol=symbol, parameter=True)
                name = field(node, "name")
                if name is not None and node.type.endswith("declaration"):
                    self.declare(name, None, self.frame(node.parent), node.start_byte)
            elif node.type == "catch_clause":
                self.declare(field(node, "parameter"), None, node.id, node.start_byte - 1, parameter=True)
            elif node.type == "import_statement":
                self._import(node)
            elif node.type == "variable_declarator":
                parent = node.parent
                frame = self.frame(node.parent)
                if parent is not None and parent.type == "variable_declaration":
                    frame = self.function_frame(node)
                self.declare(field(node, "name"), field(node, "value"), frame, node.start_byte)
        for node in walk(root):
            if node.type not in {"assignment_expression", "augmented_assignment_expression"}:
                continue
            left, right = field(node, "left"), field(node, "right")
            if left is None or left.type != "identifier" or right is None:
                continue
            key, _ = self.lookup(left)
            key = key or (self.frame(node.parent), text(left))
            parts = (right,)
            ancestor = node.parent
            conditional = False
            while ancestor is not None and ancestor.type not in FUNCTIONS | {"program"}:
                conditional |= ancestor.type in {"if_statement", "switch_case", "switch_default", "for_statement", "for_in_statement", "while_statement", "do_statement", "catch_clause"}
                ancestor = ancestor.parent
            if node.type == "augmented_assignment_expression" or conditional:
                _, previous = self.lookup(left)
                parts = (previous.parts if previous else (left,)) + (right,)
            self.bindings.setdefault(key, []).append(Binding(node.start_byte, parts, assignment_frame=self.function_frame(node)))
        for events in self.bindings.values():
            events.sort(key=lambda event: event.position)

    def frame(self, node):
        while node is not None:
            if node.type in FRAMES:
                return node.id
            node = node.parent
        return 0

    def function_frame(self, node):
        while node is not None:
            if node.type in FUNCTIONS or node.type == "program":
                return node.id
            node = node.parent
        return 0

    def _import(self, node):
        module = string_value(field(node, "source")).removeprefix("node:")
        for child in node.named_children:
            if child.type != "import_clause":
                continue
            for item in child.named_children:
                if item.type == "identifier":
                    self.declare(item, None, self.root.id, -1, symbol=module)
                elif item.type == "namespace_import":
                    self.declare(item.named_children[-1], None, self.root.id, -1, symbol=module)
                elif item.type == "named_imports":
                    for specifier in item.named_children:
                        name = field(specifier, "name")
                        alias = field(specifier, "alias") or name
                        self.declare(alias, None, self.root.id, -1, symbol=module + "." + text(name))

    def declare(self, pattern, value, frame, position, *, symbol="", parameter=False):
        if pattern is None:
            return
        if pattern.type in {"identifier", "shorthand_property_identifier_pattern"}:
            self.bindings.setdefault((frame, text(pattern)), []).append(
                Binding(position, (value,) if value is not None else (), symbol, parameter))
        elif pattern.type in {"required_parameter", "optional_parameter", "rest_pattern"}:
            child = field(pattern, "pattern") or field(pattern, "name")
            if child is None:
                child = next((item for item in pattern.named_children if item.type not in {"type_annotation"}), None)
            self.declare(child, value, frame, position, symbol=symbol, parameter=parameter)
        elif pattern.type == "assignment_pattern":
            # Default values are not a guarantee that callers omit this argument.
            self.declare(field(pattern, "left"), None if parameter else field(pattern, "right"), frame, position, parameter=parameter)
        elif pattern.type == "object_pattern":
            base = symbol or self.canonical(value)
            for child in pattern.named_children:
                name = text(field(child, "key")) if child.type == "pair_pattern" else text(child)
                target = field(child, "value") if child.type == "pair_pattern" else child
                self.declare(target, value, frame, position, symbol=base + "." + name if base else "", parameter=parameter)
        elif pattern.type == "array_pattern":
            for child in pattern.named_children:
                self.declare(child, value, frame, position, parameter=parameter)

    def lookup(self, node):
        frame = self.frame(node.parent)
        current_function = self.function_frame(node)
        while frame:
            key = (frame, text(node))
            if key in self.bindings:
                previous = [event for event in self.bindings[key]
                            if event.position < node.start_byte and
                            (not event.assignment_frame or event.assignment_frame == current_function)]
                return key, max(previous, key=lambda event: event.position) if previous else None
            frame = self.parents.get(frame, 0)
        return None, None

    def resolve(self, node, seen=None):
        seen = set() if seen is None else seen
        while node is not None:
            if node.id in seen:
                return node
            seen.add(node.id)
            if node.type in WRAPPERS and node.named_children:
                node = node.named_children[0]
            elif node.type == "identifier":
                _, binding = self.lookup(node)
                if binding and not binding.symbol and len(binding.parts) == 1:
                    node = binding.parts[0]
                else:
                    return node
            else:
                return node
        return node

    def canonical(self, node, seen=None):
        if node is None:
            return ""
        seen = set() if seen is None else seen
        if node.id in seen or len(seen) > 64:
            return text(node)
        seen = seen | {node.id}
        if node.type == "identifier":
            _, binding = self.lookup(node)
            if binding:
                if binding.symbol:
                    return binding.symbol
                if len(binding.parts) == 1:
                    return self.canonical(binding.parts[0], seen)
                if text(node) in {"eval", "Function", "setTimeout", "setInterval", "exec", "execSync", "spawn", "spawnSync", "fetch", "crypto", "document", "Math", "child_process", "http", "https", "fs"}:
                    return "local:" + text(node)
            return text(node)
        if node.type in {"member_expression", "subscript_expression"}:
            return self.canonical(field(node, "object"), seen) + "." + property_name(node)
        if node.type in WRAPPERS and node.named_children:
            return self.canonical(node.named_children[0], seen)
        if node.type == "call_expression":
            function = field(node, "function")
            name = self.canonical(function, seen)
            arguments = args(node)
            if name == "require" and arguments and arguments[0].type == "string":
                return string_value(arguments[0]).removeprefix("node:")
            if name.endswith(".bind"):
                return name[:-5]
            return name + "()"
        return text(node)

    def children(self, node):
        if node.type == "identifier":
            _, binding = self.lookup(node)
            if binding and binding.parts:
                return list(binding.parts)
        return node.named_children

    def dynamic(self, node, seen=None):
        if node is None:
            return False
        seen = set() if seen is None else seen
        if node.id in seen or len(seen) > 64:
            return True
        seen = seen | {node.id}
        if node.type in LITERALS or node.type in {"string_fragment", "escape_sequence"}:
            return False
        if node.type == "identifier":
            _, binding = self.lookup(node)
            return any(self.dynamic(part, seen) for part in binding.parts) if binding and binding.parts else True
        if node.type in {"template_string", "template_substitution", "binary_expression", "ternary_expression", "unary_expression"} | WRAPPERS:
            return any(self.dynamic(child, seen) for child in node.named_children
                       if child.type not in {"type_identifier", "predefined_type", "type_annotation"})
        return True

    def expanded_text(self, node, seen=None):
        if node is None:
            return ""
        seen = set() if seen is None else seen
        if node.id in seen or len(seen) > 64:
            return ""
        seen = seen | {node.id}
        return (text(node)[:8192] + " " + " ".join(self.expanded_text(child, seen) for child in self.children(node)))[:16384]

    def contains(self, node, predicate, seen=None):
        if node is None:
            return False
        seen = set() if seen is None else seen
        if node.id in seen or len(seen) > 64:
            return False
        seen = seen | {node.id}
        return predicate(node) or any(self.contains(child, predicate, seen) for child in self.children(node))

    def external(self, node):
        return self.contains(node, lambda child: child.type in {"identifier", "member_expression", "subscript_expression"} and
            bool(re.match(r"(?:req|request)\.(?:body|query|params|headers|cookies)(?:\.|$)|(?:window\.)?location(?:\.|$)|document\.(?:cookie|URL)|process\.argv", self.canonical(child))))

    def sanitized(self, node, kind):
        node = self.resolve(node)
        if node is None or node.type != "call_expression":
            return False
        canonical = self.canonical(field(node, "function"))
        if kind == "html":
            return canonical in {"DOMPurify.sanitize", "dompurify.sanitize", "sanitize-html", "escape-html"}
        if kind == "path":
            return canonical in {"path.basename", "path.posix.basename", "path.win32.basename"}
        return False

    def path_risk(self, node, seen=None):
        if node is None or self.sanitized(node, "path"):
            return False
        seen = set() if seen is None else seen
        if node.id in seen or len(seen) > 64:
            return True
        seen = seen | {node.id}
        resolved = self.resolve(node)
        if resolved is not node:
            return self.path_risk(resolved, seen)
        if node.type == "identifier":
            _, binding = self.lookup(node)
            if binding and binding.parts:
                return any(self.path_risk(part, seen) for part in binding.parts)
            return binding.parameter if binding else True
        canonical = self.canonical(node)
        if canonical.startswith("process.env."):
            return False
        if self.external(node):
            # basename nested inside join removes path components, whereas
            # normalize/resolve alone do not confine input to a trusted root.
            if node.type == "call_expression":
                return any(self.path_risk(argument, seen) for argument in args(node))
            return True
        if node.type == "call_expression":
            return any(self.path_risk(argument, seen) for argument in args(node))
        if node.type in {"binary_expression", "template_string", "template_substitution"} | WRAPPERS:
            return any(self.path_risk(child, seen) for child in node.named_children)
        return self.dynamic(node) if node.type not in LITERALS | {"string_fragment", "escape_sequence"} else False
