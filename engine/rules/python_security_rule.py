"""Security API patterns with import resolution and explicit safe alternatives."""
import ast
import re

from engine.models import RuleMetadata, Severity
from .python_context import PythonContextRule, UNKNOWN


# IDs are stable and deliberately separate: one CWE is not one finding.
RULES = {
    "PY-R005": ("Desserialização insegura", Severity.HIGH, "CWE-502", "Desserialização que pode reconstruir objetos executáveis a partir de dados não confiáveis.", "Prefira JSON com validação de esquema; use yaml.safe_load e nunca desserialize pickle/dill/marshal de origem não confiável."),
    "PY-R006": ("Hash criptográfico fraco", Severity.MEDIUM, "CWE-328", "MD5 e SHA-1 não oferecem resistência adequada a colisões em usos de segurança.", "Use SHA-256 ou superior para integridade; para senhas, use Argon2, scrypt ou bcrypt com salt."),
    "PY-R007": ("Algoritmo ou modo de cifra inseguro", Severity.HIGH, "CWE-327", "Cifra obsoleta ou modo ECB sem proteção adequada de confidencialidade e integridade.", "Use uma biblioteca mantida com criptografia autenticada, como AES-GCM ou ChaCha20-Poly1305, e nonce único."),
    "PY-R008": ("Token previsível gerado com random", Severity.HIGH, "CWE-338", "Gerador pseudoaleatório não criptográfico usado em valor com finalidade de autenticação ou segredo.", "Use secrets.token_urlsafe, secrets.token_hex ou secrets.choice para valores de segurança."),
    "PY-R009": ("Dados sensíveis expostos em logs", Severity.MEDIUM, "CWE-532", "Valor identificado como senha, segredo ou token enviado a uma operação de logging.", "Remova o dado sensível do log e registre somente identificadores operacionais ou dados explicitamente redigidos."),
    "PY-R010": ("Modo de depuração habilitado", Severity.HIGH, "CWE-489", "Configuração de depuração habilitada pode expor dados internos e funcionalidades administrativas.", "Desabilite DEBUG e debug=True na configuração de produção e use servidor WSGI/ASGI adequado."),
    "PY-R011": ("Nome previsível de arquivo temporário", Severity.MEDIUM, "CWE-377", "tempfile.mktemp cria um nome sem abrir o arquivo atomicamente, permitindo uma condição de corrida.", "Use tempfile.NamedTemporaryFile, TemporaryFile ou mkstemp e gerencie corretamente o descritor criado."),
    "PY-R012": ("Entidades XML externas habilitadas", Severity.HIGH, "CWE-611", "Parser XML habilita entidades ou DTDs externos, podendo acessar arquivos e rede.", "Use defusedxml ou desabilite entidades, DTDs e rede explicitamente: resolve_entities=False, load_dtd=False, no_network=True."),
    "PY-R013": ("Validação de certificado TLS desabilitada", Severity.HIGH, "CWE-295", "A chamada HTTPS desabilita a verificação da identidade do servidor.", "Mantenha verify=True e configure uma cadeia de certificados confiável quando necessário."),
    "PY-R014": ("HTML dinâmico marcado como seguro", Severity.HIGH, "CWE-79", "Dados dinâmicos escapam do mecanismo de autoescape de HTML, podendo permitir XSS.", "Use o autoescape do template ou escape HTML adequado ao contexto; não marque entrada externa como segura."),
    "PY-R015": ("Template construído com dados dinâmicos", Severity.HIGH, "CWE-1336", "Conteúdo dinâmico usado como código de um template pode permitir injeção de expressões no servidor.", "Mantenha templates estáticos e passe a entrada do usuário somente como variáveis do contexto."),
}

SENSITIVE = re.compile(r"(?:password|passwd|\bpwd\b|secret|(?:api|private)[_]?key|(?:access|auth|api|csrf|reset|session)[_]?token|(?:^|_)token(?:$|_)|credential|authorization)", re.I)
TOKEN_CONTEXT = re.compile(r"(?:token|secret|password|passwd|nonce|api_?key|session_?id|csrf|otp|verification_?code|reset_?code)", re.I)


class PythonSecurityRule(PythonContextRule):
    rule_id = "PY-R005"

    @staticmethod
    def metadata(rule_id):
        name, severity, cwe, description, remediation = RULES[rule_id]
        return RuleMetadata(rule_id=rule_id, name=name, severity=severity, cwe=cwe, description=description, remediation=remediation)

    def get_metadata(self):
        return self.metadata(self.rule_id)

    def get_additional_metadata(self):
        return [self.metadata(rule_id) for rule_id in RULES if rule_id != self.rule_id]

    def _emit(self, node, rule_id, detail):
        meta = self.metadata(rule_id)
        self.add_finding(node, rule_id=rule_id, rule_name=meta.name, severity=meta.severity, cwe=meta.cwe, message=detail, remediation=meta.remediation)

    def _keyword(self, node, name):
        return next((kw.value for kw in node.keywords if kw.arg == name), None)

    def _literal_keyword(self, node, name):
        value = self._keyword(node, name)
        return self.literal(value) if value is not None else UNKNOWN

    def _sensitive_argument(self, node):
        # String messages alone are not evidence of leaked credentials.
        return any(
            (isinstance(child, ast.Name) and SENSITIVE.search(child.id))
            or (isinstance(child, ast.Attribute) and SENSITIVE.search(child.attr))
            or (isinstance(child, ast.Subscript) and isinstance(child.slice, ast.Constant) and isinstance(child.slice.value, str) and SENSITIVE.search(child.slice.value))
            for child in ast.walk(node)
        )

    def _security_random_context(self):
        # The variable/function name is evidence of intended security use. A
        # random number for a game, sample or simulation is not automatically a
        # vulnerability. No generic "sanitize" name neutralizes this rule.
        for parent in reversed(self.parents[:-1]):
            if isinstance(parent, (ast.Assign, ast.AnnAssign)):
                targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
                if any(TOKEN_CONTEXT.search(ast.unparse(target)) for target in targets):
                    return True
            if isinstance(parent, ast.Dict):
                if any(
                    key is not None and isinstance(key, ast.Constant) and isinstance(key.value, str)
                    and TOKEN_CONTEXT.search(key.value)
                    and any(child is self.parents[-1] for child in ast.walk(value))
                    for key, value in zip(parent.keys, parent.values)
                ):
                    return True
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return bool(TOKEN_CONTEXT.search(parent.name))
        return False

    def visit_Assign(self, node):
        for target in node.targets:
            debug_target = (target.id if isinstance(target, ast.Name) else target.attr) if isinstance(target, (ast.Name, ast.Attribute)) else (target.slice.value if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) else None)
            if debug_target == "DEBUG" and self.literal(node.value) is True:
                self._emit(node, "PY-R010", "Configuração DEBUG=True presente no código; confirme que não é usada em produção.")
        super().visit_Assign(node)

    def visit_AnnAssign(self, node):
        if node.value is not None and isinstance(node.target, ast.Name) and node.target.id == "DEBUG" and self.literal(node.value) is True:
            self._emit(node, "PY-R010", "Configuração tipada DEBUG=True presente no código.")
        super().visit_AnnAssign(node)

    def visit_Call(self, node):
        name = self.resolve(node.func)
        if name in {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "dill.load", "dill.loads", "marshal.load", "marshal.loads", "shelve.open"}:
            self._emit(node, "PY-R005", f"'{name}()' reconstrói objetos; a origem confiável dos dados precisa ser garantida.")
        elif name in {"yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all"}:
            loader = self.argument(node, 1, "Loader")
            loader_name = self.resolve(loader) if loader is not None else ""
            if "unsafe" in name or loader is None or loader_name in {"yaml.Loader", "yaml.CLoader", "yaml.UnsafeLoader", "yaml.CUnsafeLoader"}:
                self._emit(node, "PY-R005", f"'{name}()' usa carregamento YAML sem SafeLoader explícito.")

        if name in {"hashlib.md5", "hashlib.sha1", "Crypto.Hash.MD5.new", "Crypto.Hash.SHA1.new", "Cryptodome.Hash.MD5.new", "Cryptodome.Hash.SHA1.new"}:
            if self._literal_keyword(node, "usedforsecurity") is not False:
                self._emit(node, "PY-R006", f"Hash fraco '{name}()' utilizado sem indicação de finalidade não criptográfica.")
        elif name == "hashlib.new":
            algorithm = self.argument(node, 0, "name")
            value = self.literal(algorithm)
            if isinstance(value, str) and value.lower().replace("-", "") in {"md5", "sha1"} and self._literal_keyword(node, "usedforsecurity") is not False:
                self._emit(node, "PY-R006", f"hashlib.new seleciona o algoritmo fraco '{value}'.")

        cipher_prefix = ("Crypto.Cipher.", "Cryptodome.Cipher.")
        if name.startswith(cipher_prefix) and name.endswith(".new"):
            algorithm = name.rsplit(".", 2)[-2]
            mode = self.argument(node, 1, "mode")
            mode_name = self.resolve(mode) if mode is not None else ""
            if algorithm in {"DES", "DES3", "ARC2", "ARC4", "Blowfish"} or mode_name.endswith(".MODE_ECB") or self.literal(mode) == 1:
                self._emit(node, "PY-R007", f"Cifra '{algorithm}' ou modo '{mode_name.rsplit('.', 1)[-1]}' inadequado para novas implementações de segurança.")
        elif name in {"cryptography.hazmat.primitives.ciphers.modes.ECB", "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES", "cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES", "cryptography.hazmat.decrepit.ciphers.algorithms.ARC4"}:
            self._emit(node, "PY-R007", f"Uso de '{name}()' com cifra obsoleta ou modo ECB.")

        if name.startswith("random.") and name.rsplit(".", 1)[-1] in {"random", "randint", "randrange", "choice", "choices", "getrandbits", "randbytes", "sample"} and self._security_random_context():
            self._emit(node, "PY-R008", f"'{name}()' usado em contexto de token/segredo; o gerador random é previsível.")

        is_log = name in {"print", "builtins.print"} or name.startswith("logging.") or (isinstance(node.func, ast.Attribute) and ast.unparse(node.func.value) in {"logger", "log", "self.logger", "self.log"})
        if is_log and name.rsplit(".", 1)[-1] in {"print", "debug", "info", "warning", "warn", "error", "exception", "critical", "log"} and any(self._sensitive_argument(arg) for arg in [*node.args, *[kw.value for kw in node.keywords]]):
            self._emit(node, "PY-R009", "Operação de logging recebe expressão que contém um identificador de credencial ou segredo.")

        if isinstance(node.func, ast.Attribute) and node.func.attr == "run" and self._literal_keyword(node, "debug") is True:
            self._emit(node, "PY-R010", "Servidor iniciado com debug=True; essa configuração é inadequada para produção.")
        if name == "tempfile.mktemp":
            self._emit(node, "PY-R011", "tempfile.mktemp não cria o arquivo atomicamente e permite corrida entre nomeação e abertura.")

        if name in {"lxml.etree.XMLParser", "lxml.etree.ETCompatXMLParser"}:
            if self._literal_keyword(node, "resolve_entities") is True or self._literal_keyword(node, "load_dtd") is True:
                self._emit(node, "PY-R012", "Parser lxml habilita resolução de entidades ou carregamento de DTD; pode acessar recursos externos.")
        elif name.endswith(".setFeature") and len(node.args) >= 2:
            feature = self.literal(node.args[0])
            if feature in {"http://xml.org/sax/features/external-general-entities", "http://xml.org/sax/features/external-parameter-entities"} and self.literal(node.args[1]) is True:
                self._emit(node, "PY-R012", "Parser SAX habilita entidades XML externas explicitamente.")

        if (name.startswith(("requests.", "httpx.")) and self._literal_keyword(node, "verify") is False) or name == "ssl._create_unverified_context":
            self._emit(node, "PY-R013", f"'{name}()' desabilita a validação de certificado TLS.")

        value = self.argument(node, 0, "s", "template", "source", "object")
        dynamic = value is not None and self.literal(value) is UNKNOWN
        if name in {"django.utils.safestring.mark_safe", "markupsafe.Markup"} and dynamic:
            self._emit(node, "PY-R014", f"'{name}()' marca conteúdo dinâmico como HTML seguro sem escape comprovado.")
        if name in {"flask.render_template_string", "jinja2.Template", "jinja2.Environment.from_string"} and dynamic:
            self._emit(node, "PY-R015", f"'{name}()' interpreta conteúdo dinâmico como código de template; passe valores como contexto de um template estático.")
        self.generic_visit(node)
