"""Independent, static gate for complete-file remediation proposals.

This module never executes target code, imports target modules, invokes a shell,
or runs user tests. Temporary files provide working-directory separation only;
they are not an operating-system sandbox. Passing is evidence from the checks
below, never a claim of compilation or functional equivalence.
"""
from collections import Counter
from pathlib import Path
import ast
import builtins
import re
import symtable
import tempfile

from engine.languages.javascript_flow import JavaScriptFlow, Binding, FUNCTIONS, property_name, string_value
from engine.languages.syntax_tree import args, field, parse, text, walk


JS_GLOBALS = frozenset({
    "undefined", "NaN", "Infinity", "globalThis", "global", "window", "document", "navigator",
    "location", "localStorage", "sessionStorage", "console", "process", "require", "module", "exports",
    "__dirname", "__filename", "Buffer", "URL", "URLSearchParams", "TextEncoder", "TextDecoder",
    "AbortController", "AbortSignal", "fetch", "crypto", "performance", "structuredClone",
    "setTimeout", "setInterval", "clearTimeout", "clearInterval", "setImmediate", "clearImmediate",
    "queueMicrotask", "atob", "btoa", "eval", "parseInt", "parseFloat", "isNaN", "isFinite",
    "encodeURI", "encodeURIComponent", "decodeURI", "decodeURIComponent",
    "Object", "Function", "Boolean", "Symbol", "Number", "BigInt", "Math", "Date", "String",
    "RegExp", "Array", "Map", "Set", "WeakMap", "WeakSet", "WeakRef", "FinalizationRegistry",
    "ArrayBuffer", "SharedArrayBuffer", "DataView", "Atomics", "JSON", "Promise", "Reflect", "Proxy",
    "Intl", "WebAssembly", "Error", "EvalError", "RangeError", "ReferenceError", "SyntaxError",
    "TypeError", "URIError", "AggregateError", "Uint8Array", "Uint16Array", "Uint32Array",
    "Int8Array", "Int16Array", "Int32Array", "Float32Array", "Float64Array", "BigInt64Array",
    "BigUint64Array", "Event", "EventTarget", "CustomEvent", "FormData", "Headers", "Request",
    "Response", "ReadableStream", "WritableStream", "Blob", "File", "FileReader", "HTMLElement",
    "DOMParser", "XMLHttpRequest", "WebSocket", "Worker", "Notification", "alert", "confirm", "prompt",
})


def _get(value, name, default=None):
    return value.get(name, default) if isinstance(value, dict) else getattr(value, name, default)


def _normalized(code):
    return " ".join(code.split())


def _signature(finding):
    return (_get(finding, "rule_id"), _get(finding, "cwe"), _normalized(_get(finding, "code_snippet", "")))


def _language(file_path):
    suffix = Path(file_path).suffix.lower()
    return {".py": "python", ".java": "java", ".ts": "typescript", ".tsx": "tsx",
            ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript"}.get(suffix)


def _scanner(language):
    if language == "python":
        from engine.languages.python_scanner import PythonScanner
        return PythonScanner()
    if language == "java":
        from engine.languages.java_scanner import JavaScanner
        return JavaScanner()
    from engine.languages.javascript_scanner import JavaScriptScanner
    return JavaScriptScanner()


def _mark_pattern(node, identifiers):
    if node is None:
        return
    if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
        identifiers.add(node.id)
    elif node.type in {"pair_pattern", "assignment_pattern"}:
        _mark_pattern(field(node, "value") if node.type == "pair_pattern" else field(node, "left"), identifiers)
    elif node.type in {"required_parameter", "optional_parameter"}:
        _mark_pattern(field(node, "pattern") or field(node, "name"), identifiers)
    elif node.type in {"object_pattern", "array_pattern", "formal_parameters", "rest_pattern"}:
        for child in node.named_children:
            _mark_pattern(child, identifiers)


def _js_unresolved(source, language):
    root = parse(source, language).root_node
    flow = JavaScriptFlow(root)
    declaration_ids = set()
    for node in walk(root):
        if node.type == "import_statement":
            declaration_ids.update(child.id for child in walk(node) if child.type == "identifier")
        elif node.type == "variable_declarator":
            _mark_pattern(field(node, "name"), declaration_ids)
        elif node.type in FUNCTIONS:
            _mark_pattern(field(node, "name"), declaration_ids)
            _mark_pattern(field(node, "parameters") or field(node, "parameter"), declaration_ids)
            name = field(node, "name")
            if name is not None and node.type in {"function_expression", "generator_function"}:
                flow.bindings.setdefault((node.id, text(name)), []).append(Binding(node.start_byte - 1))
        elif node.type == "catch_clause":
            _mark_pattern(field(node, "parameter"), declaration_ids)
        elif node.type in {"class_declaration", "enum_declaration"}:
            name = field(node, "name")
            _mark_pattern(name, declaration_ids)
            if name is not None:
                flow.bindings.setdefault((flow.frame(node.parent), text(name)), []).append(Binding(node.start_byte - 1))
    unknown = set()
    for node in walk(root):
        if node.type not in {"identifier", "shorthand_property_identifier"} or node.id in declaration_ids:
            continue
        ancestor = node.parent
        type_only = False
        while ancestor is not None and ancestor.type not in FUNCTIONS | {"program", "expression_statement", "variable_declarator"}:
            if ancestor.type in {"type_annotation", "type_arguments", "type_parameters", "interface_declaration", "type_alias_declaration"}:
                type_only = True
                break
            ancestor = ancestor.parent
        if type_only or text(node) in JS_GLOBALS:
            continue
        _, binding = flow.lookup(node)
        if binding is None:
            unknown.add(text(node))
    return unknown


def _python_unresolved(source):
    table = symtable.symtable(source, "proposal.py", "exec")
    module_names = {symbol.get_name() for symbol in table.get_symbols()
                    if symbol.is_assigned() or symbol.is_imported() or symbol.is_namespace()}
    known = module_names | set(dir(builtins)) | {"__name__", "__file__", "__package__", "__doc__", "__annotations__", "__builtins__", "__spec__", "__loader__", "__cached__"}
    unknown = set()
    pending = [table]
    while pending:
        current = pending.pop()
        for symbol in current.get_symbols():
            if symbol.is_referenced() and symbol.is_global() and symbol.get_name() not in known:
                unknown.add(symbol.get_name())
        pending.extend(current.get_children())
    # symtable alone treats an assignment anywhere in a function as a local
    # declaration. Also reject obvious new reads before that local definition.
    tree = ast.parse(source)
    for owner in [tree] + [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]:
        available = {}
        if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for argument in owner.args.posonlyargs + owner.args.args + owner.args.kwonlyargs + ([owner.args.vararg] if owner.args.vararg else []) + ([owner.args.kwarg] if owner.args.kwarg else []):
                available[argument.arg] = (-1, -1)
        nodes, pending = [], list(owner.body)
        while pending:
            current = pending.pop()
            nodes.append(current)
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                continue
            pending.extend(ast.iter_child_nodes(current))
        global_names = {name for node in nodes if isinstance(node, (ast.Global, ast.Nonlocal)) for name in node.names}
        for node in nodes:
            assigned = []
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                assigned = [node.id]
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                assigned = [node.name]
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                assigned = [alias.asname or alias.name.split(".")[0] for alias in node.names if alias.name != "*"]
            elif isinstance(node, ast.ExceptHandler) and node.name:
                assigned = [node.name]
            for name in assigned:
                position = (node.lineno, node.col_offset)
                available[name] = min(available.get(name, position), position)
        for node in nodes:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in available and node.id not in global_names and (node.lineno, node.col_offset) < available[node.id]:
                unknown.add(node.id + " (antes da definição local)")
    return unknown


def _own_nodes(node, function_types):
    """Visit a function body without counting nested function implementations."""
    pending = list(reversed(node.named_children))
    while pending:
        current = pending.pop()
        if current.type in function_types:
            continue
        yield current
        pending.extend(reversed(current.named_children))


def _js_arity(function):
    parameters = field(function, "parameters") or field(function, "parameter")
    if parameters is None:
        return 0
    return len([child for child in parameters.named_children if child.type != "comment"]) if parameters.type == "formal_parameters" else 1


def _js_returns(function):
    body = field(function, "body")
    if function.type == "arrow_function" and body is not None and body.type != "statement_block":
        return 1
    return sum(child.type == "return_statement" for child in _own_nodes(function, FUNCTIONS))


def _js_contracts(source, language):
    root = parse(source, language).root_node
    flow = JavaScriptFlow(root)
    route_verbs = {"get", "post", "put", "patch", "delete", "all", "head", "options", "use"}
    response_methods = {"send", "json", "jsonp", "end", "write", "redirect", "render", "sendFile", "download"}
    result = {"functions": Counter(), "routes": Counter(), "responses": Counter(), "status_codes": Counter(), "returns": Counter(), "query_calls": 0, "callbacks": []}
    named_functions = {text(field(node, "name")): node for node in walk(root) if node.type in {"function_declaration", "generator_function_declaration"}}
    for node in walk(root):
        if node.type in {"function_declaration", "generator_function_declaration", "method_definition"}:
            name = text(field(node, "name"))
            if name:
                result["functions"][(name, _js_arity(node))] += 1
                result["returns"][(name, _js_arity(node))] += _js_returns(node)
        elif node.type == "variable_declarator":
            value = field(node, "value")
            if value is not None and value.type in FUNCTIONS:
                name = text(field(node, "name"))
                result["functions"][(name, _js_arity(value))] += 1
                result["returns"][(name, _js_arity(value))] += _js_returns(value)
        if node.type != "call_expression":
            continue
        function, arguments = field(node, "function"), args(node)
        canonical = flow.canonical(function)
        method = canonical.rsplit(".", 1)[-1]
        owner = canonical.rsplit(".", 1)[0] if "." in canonical else ""
        is_route = method in route_verbs and owner in {"app", "router", "express()", "express.Router()"}
        if is_route:
            path = text(flow.resolve(arguments[0])) if arguments and arguments[0].type not in FUNCTIONS else "<middleware>"
            result["routes"][(method, path)] += 1
        if method in response_methods and re.match(r"^(?:res|response)(?:\.|$)", canonical):
            result["responses"][method] += 1
        if method == "status" and owner in {"res", "response"} and arguments:
            result["status_codes"][text(flow.resolve(arguments[0]))] += 1
        family = "route" if is_route else "sql" if method in {"query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe"} else "command" if owner in {"child_process", ""} and method in {"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync"} else ""
        if family == "sql":
            result["query_calls"] += 1
        if not family or not arguments:
            continue
        final = flow.resolve(arguments[-1])
        if final is not None and final.type == "identifier":
            final = named_functions.get(text(final), final)
        if final is not None and final.type in FUNCTIONS:
            parameters = field(final, "parameters") or field(final, "parameter")
            first_parameter = parameters.named_children[0] if parameters is not None and parameters.type == "formal_parameters" and parameters.named_children else parameters
            error_name = text(first_parameter) if first_parameter is not None else ""
            own = list(_own_nodes(final, FUNCTIONS))
            guard = any(child.type == "if_statement" and error_name and re.search(r"\b" + re.escape(error_name) + r"\b", text(field(child, "condition"))) for child in own) if family != "route" else False
            result["callbacks"].append((family, _js_arity(final), bool(guard), _js_returns(final)))
        elif final is not None and final.type == "identifier" and re.fullmatch(r"(?:cb|callback|done|next|handler)", text(final), re.I):
            result["callbacks"].append((family, "named", False, 0))
    return result


def _python_contracts(source):
    root = ast.parse(source)
    result = {"functions": Counter(), "routes": Counter(), "returns": Counter()}
    def visit(node, prefix=""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, prefix + child.name + ".")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + child.name
                arguments = child.args
                signature = (name, isinstance(child, ast.AsyncFunctionDef), tuple(arg.arg for arg in arguments.posonlyargs), tuple(arg.arg for arg in arguments.args), tuple(arg.arg for arg in arguments.kwonlyargs), arguments.vararg.arg if arguments.vararg else "", arguments.kwarg.arg if arguments.kwarg else "", len(arguments.defaults), tuple(default is not None for default in arguments.kw_defaults))
                result["functions"][signature] += 1
                pending = list(child.body)
                while pending:
                    current = pending.pop()
                    if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                        continue
                    result["returns"][name] += isinstance(current, ast.Return)
                    pending.extend(ast.iter_child_nodes(current))
                for decorator in child.decorator_list:
                    if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.func.attr in {"get", "post", "put", "delete", "patch", "route", "websocket"}:
                        result["routes"][(ast.dump(decorator.func), tuple(ast.dump(argument) for argument in decorator.args), tuple((keyword.arg, ast.dump(keyword.value)) for keyword in decorator.keywords))] += 1
                visit(child, name + ".")
            else:
                visit(child, prefix)
    visit(root)
    return result


def _java_contracts(source):
    root = parse(source, "java").root_node
    result = {"functions": Counter(), "routes": Counter(), "returns": Counter()}
    methods = {"method_declaration", "constructor_declaration", "compact_constructor_declaration"}
    for node in walk(root):
        if node.type in methods:
            name = text(field(node, "name"))
            signature = (name, _normalized(text(field(node, "parameters"))), text(field(node, "type")))
            result["functions"][signature] += 1
            result["returns"][signature] += sum(child.type == "return_statement" for child in _own_nodes(node, methods | {"lambda_expression"}))
        elif node.type in {"annotation", "marker_annotation"} and text(field(node, "name")).split(".")[-1] in {"GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping", "Path", "GET", "POST", "PUT", "DELETE", "PATCH"}:
            result["routes"][_normalized(text(node))] += 1
    return result


def _contract_errors(before, after):
    errors = []
    for key, label in (("functions", "assinatura de função/método"), ("routes", "rota"), ("responses", "resposta HTTP"), ("status_codes", "status HTTP"), ("returns", "retorno")):
        missing = before.get(key, Counter()) - after.get(key, Counter())
        if missing:
            errors.append(f"A proposta remove ou altera {label} existente ({sum(missing.values())} ocorrência(s)).")
    if after.get("query_calls", 0) < before.get("query_calls", 0):
        errors.append("A proposta remove uma operação de consulta existente em vez de parametrizá-la.")
    candidates = list(after.get("callbacks", []))
    for family, arity, guard, returns in before.get("callbacks", []):
        match = next((index for index, callback in enumerate(candidates)
                      if callback[0] == family and callback[1] == arity and (not guard or callback[2]) and callback[3] >= returns), None)
        if match is None:
            errors.append(f"Callback {family} removido ou alterado: preserve seus parâmetros, retorno e tratamento de erro.")
        else:
            candidates.pop(match)
    return errors


def _js_sql_parameters(original, proposed, language):
    root = parse(original, language).root_node
    modules = set()
    for node in walk(root):
        module = None
        if node.type == "import_statement":
            module = string_value(field(node, "source"))
        elif node.type == "call_expression" and text(field(node, "function")) == "require" and args(node):
            module = string_value(args(node)[0])
        if module:
            modules.add(module)
    dialects = set()
    if modules & {"mysql", "mysql2", "mysql2/promise", "sqlite3", "better-sqlite3"}:
        dialects.add("question")
    if modules & {"pg", "pg-promise", "postgres"}:
        dialects.add("postgres")
    dialect = next(iter(dialects)) if len(dialects) == 1 else "unknown"
    root = parse(proposed, language).root_node
    flow = JavaScriptFlow(root)
    bound = 0
    def option(node, name):
        node = flow.resolve(node)
        if node is not None and node.type == "object":
            return next((field(pair, "value") for pair in node.named_children if pair.type == "pair" and string_value(field(pair, "key")) == name), None)
        return None
    for node in walk(root):
        if node.type != "call_expression" or flow.canonical(field(node, "function")).rsplit(".", 1)[-1] not in {"query", "execute", "raw"}:
            continue
        arguments = args(node)
        if not arguments:
            continue
        query = option(arguments[0], "text") or option(arguments[0], "sql") or flow.resolve(arguments[0])
        values = option(arguments[0], "values") or (arguments[1] if len(arguments) > 1 else None)
        if query is None or query.type not in {"string", "template_string"}:
            continue
        # SQL quoted literals/comments cannot supply bind placeholders.
        literal = text(query)
        sql = literal[1:-1] if len(literal) >= 2 and literal[0] == literal[-1] and literal[0] in "'\"`" else literal
        sql = re.sub(r"'(?:''|\\.|[^'])*'|\"(?:\"\"|\\.|[^\"])*\"|--[^\n]*|/\*.*?\*/", " ", sql, flags=re.S)
        numbered = re.findall(r"\$([1-9]\d*)", sql)
        questions = sql.count("?")
        if dialect == "question" and numbered:
            return "failed", "Driver MySQL/SQLite identificado, mas a consulta utiliza $1/$n de PostgreSQL."
        if dialect == "postgres" and questions:
            return "failed", "Driver PostgreSQL identificado, mas a consulta utiliza ? em vez de $1/$n."
        count = questions if dialect == "question" else max((int(number) for number in numbered), default=0) if dialect == "postgres" else max(questions, max((int(number) for number in numbered), default=0))
        if count:
            values = flow.resolve(values)
            if values is None or values.type not in {"array", "identifier"}:
                return "failed", "A consulta tem placeholder, mas não há valores vinculados em array ou variável separada."
            if values.type == "array" and len(values.named_children) < count:
                return "failed", "A quantidade de valores vinculados é menor que a quantidade de parâmetros SQL."
            bound += 1
    if not bound:
        return "failed", "A proposta não demonstra consulta parametrizada com valores vinculados no dialeto identificado."
    if dialect == "unknown":
        return "not_run", "Há placeholder e valores separados, mas o arquivo não demonstra um único driver SQL; compatibilidade do dialeto requer revisão."
    return "passed", "Placeholders e valores separados são compatíveis com o driver identificado no arquivo (verificação estática)."


def validate_file_patch(finding, original_code, proposed_code):
    """Return JSON-compatible validation evidence for a complete source file.

    Checks are deliberately conservative. `passed` means no implemented static
    check rejected this proposal. Missing typechecks/tests remain `not_run`.
    """
    result = {"status": "rejected", "checks": [], "limitations": [
        "Validação estática não prova equivalência funcional nem ausência de vulnerabilidades.",
        "Não foram executados código do usuário, aplicações, testes ou scripts de build.",
        "Não foram executados typecheck, compilação ou resolução completa de dependências.",
        "O diretório temporário não constitui sandbox do sistema operacional.",
        "Referências externas já existentes são toleradas; inferência de contratos, fluxo e bibliotecas é parcial e local ao arquivo.",
    ], "errors": []}
    def check(name, status, detail):
        result["checks"].append({"name": name, "status": status, "detail": detail})
        if status == "failed":
            result["errors"].append(detail)
    file_path = _get(finding, "file_path", "")
    language = _language(file_path)
    if not language:
        check("language", "failed", "Linguagem do arquivo não suportada pelo validador estático.")
    elif not isinstance(original_code, str) or not isinstance(proposed_code, str) or not proposed_code.strip():
        check("complete_file", "failed", "É necessário fornecer o arquivo original e uma proposta completa não vazia.")
    else:
        try:
            suffix = Path(file_path).suffix.lower()
            with tempfile.TemporaryDirectory(prefix="sast-patch-") as directory:
                workspace = Path(directory)
                before_path, after_path = workspace / ("original" + suffix), workspace / ("proposed" + suffix)
                before_path.write_text(original_code, encoding="utf-8")
                after_path.write_text(proposed_code, encoding="utf-8")
                check("temporary_workspace", "passed", "Origem e proposta analisadas em diretório temporário dedicado e removido ao final; nenhum arquivo do projeto foi executado.")
                scanner = _scanner(language)
                before, original_errors = scanner.scan_source(before_path.read_text(encoding="utf-8"), file_path)
                after, proposed_errors = scanner.scan_source(after_path.read_text(encoding="utf-8"), file_path)
                check("original_syntax", "failed" if original_errors else "passed", "; ".join(original_errors) if original_errors else "Arquivo original aceito pelo parser nativo.")
                check("proposed_syntax", "failed" if proposed_errors else "passed", "; ".join(proposed_errors) if proposed_errors else "Proposta aceita pelo parser nativo; parsing não equivale a compilação.")
                if original_errors or proposed_errors:
                    for name in ("target_occurrence", "no_new_findings", "new_references", "preserved_contracts", "sql_driver_parameters"):
                        check(name, "not_run", "Análise dependente de sintaxe válida; arquivo com erro de parsing.")
                else:
                    cwe, rule = _get(finding, "cwe"), _get(finding, "rule_id")
                    target = next((item for item in before if item.rule_id == rule and item.cwe == cwe and item.line_number == _get(finding, "line_number") and item.column_number == _get(finding, "column_number", 0)), None)
                    if target is None:
                        check("target_occurrence", "failed", "O achado alvo não corresponde a uma ocorrência no arquivo original informado.")
                    else:
                        old_cwe = sum(item.cwe == cwe for item in before)
                        new_cwe = sum(item.cwe == cwe for item in after)
                        old_signature = sum(_signature(item) == _signature(target) for item in before)
                        new_signature = sum(_signature(item) == _signature(target) for item in after)
                        removed = new_cwe < old_cwe and new_signature < old_signature
                        check("target_occurrence", "passed" if removed else "failed", f"Ocorrências de {cwe}: {old_cwe} → {new_cwe}; a assinatura do alvo {'foi reduzida' if new_signature < old_signature else 'permanece'}." + ("" if removed else " A remoção do alvo não foi demonstrada."))
                    introduced = Counter(_signature(item) for item in after) - Counter(_signature(item) for item in before)
                    check("no_new_findings", "failed" if introduced else "passed", f"{sum(introduced.values())} novo(s) achado(s) por assinatura de regra/CWE/trecho, ignorando deslocamento de linhas." if introduced else "Nenhum novo achado identificado pelos scanners nativos ao comparar regra, CWE e trecho sem posição de linha.")
                    if language == "java":
                        check("new_references", "not_run", "Resolução de referências Java exige classpath e compilador; não foi executada nem presumida.")
                    else:
                        old_unknown = _python_unresolved(original_code) if language == "python" else _js_unresolved(original_code, language)
                        new_unknown = _python_unresolved(proposed_code) if language == "python" else _js_unresolved(proposed_code, language)
                        added = new_unknown - old_unknown
                        check("new_references", "failed" if added else "passed", "Novas referências sem declaração reconhecida: " + ", ".join(sorted(added)) + "." if added else "Nenhuma nova referência sem declaração reconhecida em comparação ao arquivo original; resolução de dependências não executada.")
                    contracts = _python_contracts if language == "python" else _java_contracts if language == "java" else lambda code: _js_contracts(code, language)
                    contract_errors = _contract_errors(contracts(original_code), contracts(proposed_code))
                    check("preserved_contracts", "failed" if contract_errors else "passed", " ".join(contract_errors) if contract_errors else "Assinaturas, rotas, retornos e contratos de callbacks/respostas reconhecidos foram preservados pela comparação estrutural.")
                    if cwe == "CWE-89" and language in {"javascript", "typescript", "tsx"}:
                        status, detail = _js_sql_parameters(original_code, proposed_code, language)
                        check("sql_driver_parameters", status, detail)
                    else:
                        check("sql_driver_parameters", "not_run", "Validação específica de placeholder implementada para SQL JavaScript/TypeScript com driver identificável; não aplicável neste caso.")
        except Exception as error:
            check("static_analysis", "failed", f"Não foi possível concluir a validação estática ({type(error).__name__}).")
    check("typecheck", "not_run", "Typecheck/compilação não executados; não há confirmação de tipos, imports em runtime ou classpath Java.")
    check("application_tests", "not_run", "Testes da aplicação e execução do código proposto não foram realizados.")
    check("os_sandbox", "not_run", "Nenhum sandbox de sistema operacional foi criado ou utilizado.")
    check("behavioral_equivalence", "not_run", "Equivalência funcional não é demonstrada por essas verificações estáticas; requer revisão e testes da aplicação.")
    result["status"] = "rejected" if result["errors"] else "passed"
    return result
