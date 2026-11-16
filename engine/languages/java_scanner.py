import re
from typing import List, Tuple
from engine.models import Finding, RuleMetadata, Severity
from engine.pii import SAUDE, classify_identifier, find_cards, find_cns, find_cpfs
from .base import LanguageScanner
from .syntax_tree import parse, walk, text, field, args, Expressions, syntax_error, finding_location

PATTERNS_JAVA = [
    {
        "rule_id": "JAVA-R001",
        "name": "Injeção de SQL em JDBC / JPA (SQLi)",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-89",
        "message": "Construção de consulta SQL via concatenação de strings direta no Statement ou EntityManager.",
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
        "message": "Chamada insegura a Runtime.getRuntime().exec() ou ProcessBuilder com concatenação de comandos.",
        "remediation": "Utilize ProcessBuilder passando argumentos como lista estrita de parâmetros sem shell intermediário.",
    },
    {
        "rule_id": "JAVA-R004",
        "name": "Deserialização Insegura de Objetos Java",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-502",
        "message": "Uso de ObjectInputStream.readObject() ou XMLDecoder permite execução remota de código via gadgets.",
        "remediation": "Utilize serialização segura com JSON (Jackson com validação restrita) ou aplique filtros com JEP 290.",
    },
    {
        "rule_id": "JAVA-R005",
        "name": "Acesso Inseguro a Arquivos / Path Traversal",
        "severity": Severity.HIGH,
        "cwe": "CWE-22",
        "message": "Construção de caminho de arquivo usando entradas dinâmicas sem validação canônica.",
        "remediation": "Valide se o caminho canônico do arquivo inicia com a pasta base segura usando file.getCanonicalPath().startsWith(baseDir).",
    },
    {
        "rule_id": "JAVA-R006",
        "name": "Server-Side Request Forgery (SSRF) em Java",
        "severity": Severity.HIGH,
        "cwe": "CWE-918",
        "message": "Abertura de conexão HTTP com URL montada a partir de concatenação de parâmetros externos sem allow-list (CWE-918 / CVE-2020-13379).",
        "remediation": "Valide o esquema (apenas https) e restrinja os nomes de domínio permitidos via allow-list, bloqueando endereços IPv4 privados e portas internas.",
    },
    {
        "rule_id": "JAVA-P001",
        "name": "CPF em texto claro no código-fonte",
        "severity": Severity.HIGH,
        "cwe": "CWE-359",
        "message": "[PII · Documento] CPF válido escrito como literal no código Java.",
        "remediation": "Remova o CPF do código; use dados sintéticos em testes e mascare na exibição (***.***.***-NN).",
        "categories": ["documento"],
    },
    {
        "rule_id": "JAVA-P002",
        "name": "Dado de saúde hardcoded no código-fonte",
        "severity": Severity.HIGH,
        "cwe": "CWE-359",
        "message": "[PII · Saúde] Valor de saúde (diagnóstico, prontuário, exame…) escrito direto no código. Dado pessoal sensível (LGPD art. 5º, II).",
        "remediation": "Não grave dados de saúde no código; use dados sintéticos em testes e guarde registros reais criptografados.",
        "categories": ["saude"],
    },
    {
        "rule_id": "JAVA-P003",
        "name": "CNS (Cartão Nacional de Saúde) em texto claro no código-fonte",
        "severity": Severity.HIGH,
        "cwe": "CWE-359",
        "message": "[PII · Documento] CNS válido (dígito verificador do SUS correto) escrito como literal no código Java.",
        "remediation": "Remova o CNS do código; use números sintéticos inválidos em testes e mascare na exibição (*** **** **** NNNN).",
        "categories": ["documento"],
    },
    {
        "rule_id": "JAVA-P004",
        "name": "Cartão de pagamento em texto claro no código-fonte",
        "severity": Severity.HIGH,
        "cwe": "CWE-359",
        "message": "[PII · Financeiro] Número de cartão de pagamento válido (Luhn) escrito como literal no código Java.",
        "remediation": "Remova o número do código; use os números de teste do provedor de pagamento e nunca armazene o cartão completo.",
        "categories": ["financeiro"],
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
        expressions = Expressions(root)
        findings, seen = [], set()

        def add(number, node):
            rule = PATTERNS_JAVA[number - 1]
            line, column, snippet = finding_location(node, source_code)
            key = (rule["rule_id"], line, column)
            if key in seen:
                return
            seen.add(key)
            findings.append(self.create_finding(rule["rule_id"], rule["name"], rule["severity"], rule["cwe"], rule["message"], file_path, line, column, snippet, rule["remediation"], rule.get("categories")))

        for node in walk(root):
            if node.type == "string_literal" and find_cpfs(text(node).strip('"')):
                add(7, node)
            if node.type == "string_literal":
                literal = text(node).strip('"')
                if find_cns(literal):
                    add(9, node)
                if find_cards(literal):
                    add(10, node)
            if node.type == "variable_declarator":
                health_name, health_value = field(node, "name"), field(node, "value")
                if (health_value is not None and health_value.type == "string_literal" and len(text(health_value).strip('"')) >= 3
                        and classify_identifier(text(health_name)) == SAUDE):
                    add(8, node)
            if node.type == "variable_declarator":
                name, value = field(node, "name"), field(node, "value")
                if re.search(r"password|passwd|api[_-]?key|secret|token", text(name), re.I) and value is not None and value.type in {"string_literal", "character_literal"}:
                    if len(text(value).strip("'\"")) >= 4:
                        add(2, node)
            elif node.type == "method_invocation":
                name, owner = text(field(node, "name")), text(field(node, "object"))
                arguments = args(node)
                first = expressions.resolve(arguments[0]) if arguments else None
                if name in {"executeQuery", "executeUpdate", "createQuery", "createNativeQuery"} and first is not None and first.type == "binary_expression" and expressions.dynamic(first):
                    if re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", text(first), re.I):
                        add(1, node)
                if name == "exec" and re.sub(r"\s", "", owner) == "Runtime.getRuntime()":
                    add(3, node)
                if name == "readObject":
                    add(4, node)
                if name == "send" and re.sub(r"\s", "", owner) == "HttpClient.newHttpClient()":
                    add(6, node)
            elif node.type == "object_creation_expression":
                kind = text(field(node, "type")).split(".")[-1]
                arguments = args(node)
                if kind == "ProcessBuilder" and any(argument.type == "binary_expression" and expressions.dynamic(argument) for argument in arguments):
                    add(3, node)
                elif kind == "XMLDecoder":
                    add(4, node)
                elif kind == "File" and len(arguments) >= 2 and expressions.dynamic(arguments[1]):
                    add(5, node)
                elif kind == "FileInputStream" and arguments and expressions.dynamic(arguments[0]):
                    add(5, node)
                elif kind == "URL" and arguments and expressions.dynamic(arguments[0]):
                    add(6, node)
        return sorted(findings, key=lambda item: (item.line_number, item.column_number, item.rule_id)), []
