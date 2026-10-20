import re
from typing import List, Tuple
from engine.models import Finding, RuleMetadata, Severity
from .base import LanguageScanner
from .syntax_tree import parse, walk, text, field, args, syntax_error, finding_location
from .java_flow import JavaFlow, enclosing_scopes, declaration_scope

PATTERNS_JAVA = [
    {
        "rule_id": "JAVA-R001",
        "name": "Injeção de SQL em JDBC / JPA (SQLi)",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-89",
        "message": "Consulta SQL/JPQL dinâmica chega a uma operação JDBC, JPA ou JdbcTemplate. Há risco de injeção se os valores forem controláveis externamente; confirme sua origem.",
        "remediation": "Utilize PreparedStatement com parâmetros: conn.prepareStatement(\"SELECT * FROM u WHERE id = ?\").",
    },
    {
        "rule_id": "JAVA-R002",
        "name": "Credenciais e Senhas Hardcoded em Java",
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
        "message": "Definição estática de credencial, senha ou chave de API diretamente no código-fonte Java.",
        "remediation": "Substitua por leitura de variáveis de ambiente com System.getenv(\"NOME_VAR\") ou AWS Secrets Manager.",
    },
    {
        "rule_id": "JAVA-R003",
        "name": "Injeção de Comandos do SO (Runtime.exec)",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-78",
        "message": "Comando dinâmico chega a Runtime.exec ou a um shell em ProcessBuilder. Verifique a origem e use executável fixo com argumentos validados.",
        "remediation": "Utilize ProcessBuilder passando argumentos como lista estrita de parâmetros sem shell intermediário.",
    },
    {
        "rule_id": "JAVA-R004",
        "name": "Deserialização Insegura de Objetos Java",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-502",
        "message": "Desserialização de objetos sem filtro restritivo reconhecido. Dados não confiáveis podem instanciar classes perigosas; confirme a origem e as classes permitidas.",
        "remediation": "Utilize serialização segura com JSON (Jackson com validação restrita) ou aplique filtros com JEP 290.",
    },
    {
        "rule_id": "JAVA-R005",
        "name": "Acesso Inseguro a Arquivos / Path Traversal",
        "severity": Severity.HIGH,
        "cwe": "CWE-22",
        "message": "Entrada dinâmica compõe um caminho de arquivo sem contenção de diretório reconhecida. Verifique a origem e impeça acesso fora da pasta permitida.",
        "remediation": "Valide se o caminho canônico do arquivo inicia com a pasta base segura usando file.getCanonicalPath().startsWith(baseDir).",
    },
    {
        "rule_id": "JAVA-R006",
        "name": "Server-Side Request Forgery (SSRF) em Java",
        "severity": Severity.HIGH,
        "cwe": "CWE-918",
        "message": "Destino HTTP dinâmico sem restrição de origem reconhecida. Há risco de SSRF se uma entrada externa controlar o destino.",
        "remediation": "Valide o esquema (apenas https) e restrinja os nomes de domínio permitidos via allow-list, bloqueando endereços IPv4 privados e portas internas.",
    },
    {
        "rule_id": "JAVA-R007", "name": "Saída HTML dinâmica sem codificação (XSS)",
        "severity": Severity.HIGH, "cwe": "CWE-79",
        "message": "Dados dinâmicos são escritos na resposta servlet sem codificação HTML reconhecida. Se incluírem entrada externa, podem executar script no navegador.",
        "remediation": "Codifique os dados conforme o contexto (por exemplo Encode.forHtml) e prefira templates com escape automático. Não interpole entrada externa diretamente em HTML.",
    },
    {
        "rule_id": "JAVA-R008", "name": "Parser XML com entidades externas habilitadas (XXE)",
        "severity": Severity.HIGH, "cwe": "CWE-611",
        "message": "XML dinâmico é processado sem configuração reconhecida que proíba DTD e entidades externas. Verifique as opções do parser antes de aceitar dados não confiáveis.",
        "remediation": "Em DocumentBuilderFactory, habilite disallow-doctype-decl ou desabilite entidades gerais, parametrizadas e DTD externa. Em StAX, desabilite SUPPORT_DTD e IS_SUPPORTING_EXTERNAL_ENTITIES.",
    },
    {
        "rule_id": "JAVA-R009", "name": "Algoritmo criptográfico ou hash fraco",
        "severity": Severity.MEDIUM, "cwe": "CWE-327",
        "message": "Algoritmo criptográfico legado ou modo ECB identificado. A adequação depende do uso; evite seu emprego na proteção de dados e credenciais.",
        "remediation": "Utilize AES/GCM com nonce único para cifragem e SHA-256 ou superior quando apropriado. Para senhas, utilize Argon2, scrypt, bcrypt ou PBKDF2 com parâmetros adequados.",
    },
    {
        "rule_id": "JAVA-R010", "name": "Gerador previsível em contexto de segurança",
        "severity": Severity.MEDIUM, "cwe": "CWE-338",
        "message": "Random, ThreadLocalRandom ou Math.random gera um valor em contexto de token, senha ou segredo. Esses geradores não oferecem imprevisibilidade criptográfica.",
        "remediation": "Utilize SecureRandom para tokens, chaves e outros valores que dependam de imprevisibilidade.",
    },
    {
        "rule_id": "JAVA-R011", "name": "Possível exposição de segredo em log",
        "severity": Severity.MEDIUM, "cwe": "CWE-532",
        "message": "Uma variável com nome de senha, token ou segredo é enviada ao log. Verifique se o valor contém dados sensíveis e remova-o ou aplique redação apropriada.",
        "remediation": "Não registre credenciais ou tokens. Registre identificadores de correlação e eventos sem o valor sensível.",
    },
    {
        "rule_id": "JAVA-R012", "name": "Execução dinâmica de script não confiável",
        "severity": Severity.CRITICAL, "cwe": "CWE-95",
        "message": "Um interpretador recebe código dinâmico. Caso uma entrada externa controle esse conteúdo, ela pode executar instruções com os privilégios da aplicação.",
        "remediation": "Não avalie código fornecido por usuários. Defina operações permitidas explicitamente e interprete dados em um formato restrito, preservando o contrato da aplicação.",
    },
]


class JavaScanner(LanguageScanner):
    """Analisador SAST estrutural especializado no ecossistema Java (Spring, JDBC, JPA, Enterprise)."""

    language_name: str = "Java"

    def list_rules(self) -> List[RuleMetadata]:
        rules_meta = []
        for p in PATTERNS_JAVA:
            rules_meta.append(
                RuleMetadata(
                    rule_id=p["rule_id"],
                    name=p["name"],
                    severity=p["severity"],
                    cwe=p["cwe"],
                    description=p["message"],
                    remediation=p["remediation"],
                )
            )
        return rules_meta

    def scan_source(self, source_code: str, file_path: str) -> Tuple[List[Finding], List[str]]:
        root = parse(source_code, "java").root_node
        if root.has_error:
            return [], [syntax_error(root, "Java", file_path)]
        expressions = JavaFlow(root)
        findings, seen = [], set()

        def add(number, node):
            rule = PATTERNS_JAVA[number - 1]
            line, column, snippet = finding_location(node, source_code)
            key = (rule["rule_id"], line, column)
            if key in seen:
                return
            seen.add(key)
            findings.append(self.create_finding(rule["rule_id"], rule["name"], rule["severity"], rule["cwe"], rule["message"], file_path, line, column, snippet, rule["remediation"]))

        def dynamic(argument):
            return expressions.dynamic(argument)

        def resolved(argument):
            return expressions.resolve(argument)

        def kind(argument):
            return expressions.type_of(argument).split(".")[-1]

        def value_call(node):
            value = resolved(node)
            return text(field(value, "name")) if value is not None and value.type == "method_invocation" else ""

        def command_sequences(argument, use, depth=0):
            """Bounded alternatives for command arrays and locally built lists."""
            if argument is None or depth > 12:
                return None
            reference = argument
            while reference is not None and reference.type in {"identifier", "field_access"}:
                value = expressions.resolve_once(reference)
                if value is reference or value is None:
                    break
                if value.type not in {"identifier", "field_access"}:
                    break
                reference = value
            value = resolved(argument)
            if value is None:
                return None
            key = expressions.symbol(reference)
            if value.type == "array_creation_expression":
                value = field(value, "value")
            if value is not None and value.type == "array_initializer":
                states = [list(value.named_children)]
                for mutation in expressions.nodes:
                    if key is None or mutation.type != "assignment_expression" or not value.start_byte < mutation.start_byte < use.start_byte:
                        continue
                    left = field(mutation, "left")
                    if left is None or left.type != "array_access" or expressions.symbol(field(left, "array")) != key:
                        continue
                    if expressions._execution_context(mutation) != expressions._execution_context(use):
                        continue
                    index = text(field(left, "index"))
                    if not index.isdigit() or any(int(index) >= len(state) for state in states):
                        return None
                    replacement = field(mutation, "right") if text(field(mutation, "operator")) == "=" else mutation
                    replaced = [state[:int(index)] + [replacement] + state[int(index) + 1:] for state in states]
                    states = replaced if expressions._definite(mutation, use) else states + replaced
                    if len(states) > 32:
                        return None
                return states
            if value is not None and value.type == "method_invocation":
                name, owner = text(field(value, "name")), text(field(value, "object"))
                if (name == "of" and owner.split(".")[-1] == "List") or (name == "asList" and owner.split(".")[-1] == "Arrays"):
                    for mutation in expressions.nodes:
                        if key is not None and mutation.type == "method_invocation" and value.start_byte < mutation.start_byte < use.start_byte and expressions.symbol(field(mutation, "object")) == key and text(field(mutation, "name")) in {"set", "add", "addAll", "remove", "removeAll", "clear", "replaceAll", "sort"}:
                            return None
                    return [list(args(value))]
            if value is None or value.type != "object_creation_expression":
                return None
            object_kind = text(field(value, "type")).split("<", 1)[0].split(".")[-1]
            if object_kind not in {"ArrayList", "LinkedList", "Vector"}:
                return None
            initialization = args(value)
            if initialization:
                states = command_sequences(initialization[0], use, depth + 1)
                if states is None:
                    return None
            else:
                states = [[]]
            if key is None:
                return states
            for mutation in expressions.nodes:
                if mutation.type != "method_invocation" or not value.start_byte < mutation.start_byte < use.start_byte:
                    continue
                if expressions.symbol(field(mutation, "object")) != key or expressions._execution_context(mutation) != expressions._execution_context(use):
                    continue
                mutation_name, mutation_args = text(field(mutation, "name")), args(mutation)
                if mutation_name == "add" and len(mutation_args) == 1:
                    appended = [state + [mutation_args[0]] for state in states]
                    states = appended if expressions._definite(mutation, use) else states + appended
                    if len(states) > 32:
                        return None
                elif mutation_name in {"set", "addAll", "remove", "removeAll", "clear", "replaceAll", "sort"} or mutation_name == "add":
                    return None
            return states

        def unsafe_command(arguments, use):
            if not arguments:
                return False
            if len(arguments) == 1:
                value = resolved(arguments[0])
                if value is not None and value.type in {"array_initializer", "array_creation_expression", "object_creation_expression", "method_invocation"}:
                    sequences = command_sequences(arguments[0], use)
                    if sequences is None:
                        known_container = value.type in {"array_initializer", "array_creation_expression", "object_creation_expression"} or (value.type == "method_invocation" and text(field(value, "object")).split(".")[-1] in {"List", "Arrays"})
                        return known_container or dynamic(arguments[0])
                else:
                    sequences = [arguments]
            else:
                sequences = [arguments]
            shells = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
            for sequence in sequences:
                if not sequence:
                    continue
                executables = expressions.possible_strings(sequence[0])
                shell = executables is not None and any(executable.replace("\\", "/").split("/")[-1].lower() in shells for executable in executables)
                if dynamic(sequence[0]) or (shell and any(dynamic(part) for part in sequence[1:])):
                    return True
            return False

        def html_encoded(node):
            value = resolved(node)
            if value is None:
                return False
            if value.type == "binary_expression":
                return all(not dynamic(child) or html_encoded(child) for child in value.named_children)
            if value.type != "method_invocation":
                return False
            name, owner = text(field(value, "name")), text(field(value, "object"))
            return (name in {"forHtml", "forHtmlContent", "forHtmlAttribute"} and owner.endswith("Encode")) or (name in {"escapeHtml", "escapeHtml4", "htmlEscape"} and owner.split(".")[-1] in {"StringEscapeUtils", "HtmlUtils"})

        def destination_dynamic(argument, depth=0):
            """Follow HttpRequest builders without mistaking a dynamic body for a URL."""
            if depth > 20:
                return True
            value = resolved(argument)
            if value is None:
                return True
            if value.type == "method_invocation":
                call_name, call_owner = text(field(value, "name")), field(value, "object")
                call_args = args(value)
                if call_name in {"newBuilder", "uri"} and call_args:
                    return dynamic(call_args[0])
                if call_name in {"build", "GET", "POST", "PUT", "DELETE", "method", "header", "headers", "timeout", "version", "expectContinue"}:
                    return destination_dynamic(call_owner, depth + 1)
            return dynamic(value)

        def secure_xml(node, parser_owner):
            parser_value = resolved(parser_owner)
            factory = field(parser_value, "object") if value_call(parser_owner) in {"newDocumentBuilder", "newSAXParser"} else parser_owner
            settings = {}
            for setting in expressions.calls_before(node, factory, {"setFeature", "setProperty"}):
                arguments = args(setting)
                if len(arguments) < 2:
                    continue
                key = expressions.literal(arguments[0])
                if key is None:
                    key = text(arguments[0]).split(".")[-1]
                settings[key] = expressions.literal(arguments[1])
            if settings.get("http://apache.org/xml/features/disallow-doctype-decl") is True:
                return True
            if all(settings.get(feature) is False for feature in (
                    "http://xml.org/sax/features/external-general-entities",
                    "http://xml.org/sax/features/external-parameter-entities",
                    "http://apache.org/xml/features/nonvalidating/load-external-dtd")):
                return True
            return ((settings.get("javax.xml.stream.supportDTD", settings.get("SUPPORT_DTD"))) is False
                    and settings.get("javax.xml.stream.isSupportingExternalEntities", settings.get("IS_SUPPORTING_EXTERNAL_ENTITIES")) is False)

        def filtered_stream(node, owner):
            for setting in expressions.calls_before(node, owner, {"setObjectInputFilter"}):
                if not args(setting):
                    continue
                filter_value = resolved(args(setting)[0])
                if value_call(args(setting)[0]) == "createFilter" and args(filter_value):
                    pattern = expressions.literal(args(filter_value)[0])
                    if isinstance(pattern, str):
                        entries = [entry.strip() for entry in pattern.split(";") if entry.strip()]
                        if entries and entries[-1] == "!*" and all("*" not in entry for entry in entries[:-1]):
                            return True
            return False

        def guarded_path(node, path):
            # Recognize an explicit normalized path containment guard with an
            # early throw/return. A mere normalize() or startsWith() call is not
            # proof of validation and must not suppress an alert.
            if value_call(path) not in {"normalize", "getCanonicalPath", "getCanonicalFile"}:
                return False
            path_key = expressions.symbol(path)
            for guard in expressions.nodes:
                if guard.type != "if_statement" or guard.start_byte >= node.start_byte:
                    continue
                if declaration_scope(guard) not in set(enclosing_scopes(node)):
                    continue
                condition, consequence = field(guard, "condition"), field(guard, "consequence")
                if condition is None or consequence is None:
                    continue
                while condition.type == "parenthesized_expression" and condition.named_children:
                    condition = condition.named_children[0]
                if condition.type != "unary_expression" or not text(condition).lstrip().startswith("!") or len(condition.named_children) != 1:
                    continue
                check = condition.named_children[0]
                if check.type != "method_invocation" or text(field(check, "name")) != "startsWith":
                    continue
                checks = [check]
                if not any(child.type in {"throw_statement", "return_statement"} for child in consequence.named_children + [consequence]):
                    continue
                for check in checks:
                    owner = field(check, "object")
                    if not path_key or expressions.symbol(owner) != path_key or not args(check):
                        continue
                    base = args(check)[0]
                    # Path.startsWith checks components. String.startsWith
                    # without separator can be bypassed by sibling prefixes.
                    if kind(path) in {"Path", "java.nio.file.Path"} and not dynamic(base):
                        return True
            return False

        sensitive_name = re.compile(r"password|passwd|pwd|api[_-]?key|secret|token|credential", re.I)
        security_context = re.compile(r"password|passwd|secret|token|nonce|otp|csrf|session", re.I)

        def sensitive_value(argument, depth=0):
            if argument is None or depth > 16:
                return False
            if argument.type in {"identifier", "field_access"} and sensitive_name.search(text(argument)):
                return True
            value = resolved(argument)
            if value is not argument:
                return sensitive_value(value, depth + 1)
            if value.type in {"string_literal", "character_literal"}:
                return False
            return any(sensitive_value(child, depth + 1) for child in value.named_children)

        for node in expressions.nodes:
            if node.type == "variable_declarator":
                name, value = field(node, "name"), field(node, "value")
                literal = expressions.literal(value)
                if sensitive_name.search(text(name)) and isinstance(literal, str) and len(literal) >= 4:
                    add(2, node)
            elif node.type == "assignment_expression":
                left, right = field(node, "left"), field(node, "right")
                literal = expressions.literal(right)
                if sensitive_name.search(text(left)) and isinstance(literal, str) and len(literal) >= 4:
                    add(2, node)
            elif node.type == "method_invocation":
                name, owner_node = text(field(node, "name")), field(node, "object")
                owner = text(owner_node)
                owner_kind = kind(owner_node)
                arguments = args(node)
                first = arguments[0] if arguments else None
                sql_sink = name in {"executeQuery", "executeUpdate", "executeLargeUpdate", "createQuery", "createNativeQuery", "prepareStatement", "prepareCall"}
                sql_sink |= name in {"query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet", "update", "batchUpdate", "execute"} and ("JdbcTemplate" in owner_kind or bool(re.search(r"jdbc|namedParameter", owner, re.I)))
                sql_sink |= name in {"addBatch", "execute"} and (owner_kind in {"Statement", "CallableStatement"} or bool(re.search(r"^(stmt|statement)$", owner)))
                if sql_sink and first is not None and dynamic(first):
                    add(1, node)
                runtime = re.sub(r"\s", "", owner) == "Runtime.getRuntime()" or owner_kind == "Runtime" or value_call(owner_node) == "getRuntime"
                if name == "exec" and runtime and first is not None and dynamic(first):
                    add(3, node)
                if name == "command" and owner_kind == "ProcessBuilder" and unsafe_command(arguments, node):
                    add(3, node)
                if name in {"readObject", "readUnshared"} and (owner_kind == "ObjectInputStream" or not owner_kind) and not filtered_stream(node, owner_node):
                    add(4, node)
                if name in {"readAllBytes", "readString", "readAllLines", "newInputStream", "newOutputStream", "newBufferedReader", "newBufferedWriter", "write", "writeString", "delete", "deleteIfExists", "copy", "move"} and owner.split(".")[-1] == "Files" and first is not None and dynamic(first) and not guarded_path(node, first):
                    add(5, node)
                if name in {"send", "sendAsync"} and ("HttpClient" in owner_kind or "HttpClient." in owner or value_call(owner_node) in {"newHttpClient", "build"} and "HttpClient" in expressions.expanded_text(owner_node)) and first is not None and destination_dynamic(first):
                    add(6, node)
                if name in {"getForObject", "getForEntity", "postForObject", "postForEntity", "put", "delete", "exchange", "execute"} and ("RestTemplate" in owner_kind or re.search(r"restTemplate", owner, re.I)) and first is not None and dynamic(first):
                    add(6, node)
                writer = "getWriter()" in re.sub(r"\s", "", owner) or (owner_kind in {"PrintWriter", "JspWriter"} and "getWriter" in expressions.expanded_text(owner_node))
                if name in {"write", "print", "println", "append", "format", "printf"} and writer and any(dynamic(argument) and not html_encoded(argument) for argument in arguments):
                    add(7, node)
                xml_parser = owner_kind in {"DocumentBuilder", "SAXParser", "XMLReader", "SAXBuilder"} or value_call(owner_node) in {"newDocumentBuilder", "newSAXParser"}
                if name in {"parse", "build"} and xml_parser and first is not None and dynamic(first) and not secure_xml(node, owner_node):
                    add(8, node)
                if name in {"createXMLStreamReader", "createXMLEventReader"} and ("XMLInputFactory" in owner_kind or value_call(owner_node) == "newFactory") and any(dynamic(argument) for argument in arguments) and not secure_xml(node, owner_node):
                    add(8, node)
                if name == "getInstance" and first is not None:
                    algorithm = expressions.literal(first)
                    if isinstance(algorithm, str):
                        normalized = algorithm.upper().replace("-", "")
                        weak_hash = owner.split(".")[-1] == "MessageDigest" and normalized in {"MD2", "MD4", "MD5", "SHA", "SHA1"}
                        weak_cipher = owner.split(".")[-1] == "Cipher" and (normalized.split("/")[0] in {"DES", "DESEDE", "RC2", "RC4", "ARCFOUR", "BLOWFISH"} or "/ECB/" in normalized or normalized == "AES")
                        if weak_hash or weak_cipher:
                            add(9, node)
                if name in {"md2Hex", "md5Hex", "sha1Hex", "md5Digest", "md5DigestAsHex", "sha1"} and owner.split(".")[-1] in {"DigestUtils", "Hashing"}:
                    add(9, node)
                weak_random = (name == "random" and owner == "Math") or (name.startswith("next") and (owner_kind in {"Random", "ThreadLocalRandom", "SplittableRandom"} or "ThreadLocalRandom.current()" in owner))
                if weak_random:
                    current = node.parent
                    while current is not None and current.type not in {"method_declaration", "constructor_declaration", "variable_declarator", "assignment_expression"}:
                        current = current.parent
                    target_name = text(field(current, "name")) if current is not None else ""
                    if current is not None and current.type == "assignment_expression":
                        target_name = text(field(current, "left"))
                    if security_context.search(target_name) or any(security_context.search(text(argument)) for argument in arguments if argument.type in {"identifier", "field_access"}):
                        add(10, node)
                logger = re.search(r"(^|\.)(log|logger|LOGGER|LOG)$", owner) or owner in {"System.out", "System.err"} or "Logger" in owner_kind
                if logger and name in {"trace", "debug", "info", "warn", "error", "fatal", "log", "print", "println", "printf"} and any(sensitive_value(argument) for argument in arguments):
                    add(11, node)
                script_engine = owner_kind in {"ScriptEngine", "GroovyShell", "JShell", "Interpreter"} or value_call(owner_node) == "getEngineByName"
                if name in {"eval", "evaluate"} and script_engine and first is not None and dynamic(first):
                    add(12, node)
            elif node.type == "object_creation_expression":
                object_kind = text(field(node, "type")).split(".")[-1]
                arguments = args(node)
                if object_kind == "ProcessBuilder" and arguments:
                    if unsafe_command(arguments, node):
                        add(3, node)
                elif object_kind == "XMLDecoder":
                    add(4, node)
                elif object_kind == "File" and arguments and dynamic(arguments[-1]) and not guarded_path(node, arguments[-1]):
                    add(5, node)
                elif object_kind in {"FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile"} and arguments and dynamic(arguments[0]) and not guarded_path(node, arguments[0]):
                    # A File construction already reports the same unsafe path.
                    if not (resolved(arguments[0]) is not None and resolved(arguments[0]).type == "object_creation_expression" and text(field(resolved(arguments[0]), "type")).split(".")[-1] == "File"):
                        add(5, node)
                elif object_kind == "URL" and arguments and dynamic(arguments[0]):
                    add(6, node)
        return sorted(findings, key=lambda item: (item.line_number, item.column_number, item.rule_id)), []
