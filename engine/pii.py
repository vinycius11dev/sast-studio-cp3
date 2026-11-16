"""Catálogo de dados pessoais (PII) usado pelas regras de privacidade do motor SAST.

As categorias seguem a LGPD (Lei 13.709/2018): documento pessoal (art. 5º, I), dado
referente à saúde, que é dado pessoal sensível (art. 5º, II), e credenciais, protegidas
pelo dever de segurança do art. 46. A detecção é por nome de identificador e por valor
literal; ela indica *risco*, não prova que o dado seja real.
"""
import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional

DOCUMENTO = "documento"
SAUDE = "saude"
SENHA = "senha"
FINANCEIRO = "financeiro"
CONTATO = "contato"


@dataclass(frozen=True)
class PiiCategory:
    id: str
    label: str
    lgpd: str
    weight: float  # multiplicador usado pelo indicador Risco Cidadão
    rank: int      # desempate: categoria mais grave vence ao descrever um achado


CATEGORIES: Dict[str, PiiCategory] = {
    CONTATO: PiiCategory(CONTATO, "Contato (e-mail, telefone)", "LGPD art. 5º, I (dado pessoal)", 1.1, 0),
    DOCUMENTO: PiiCategory(DOCUMENTO, "Documento pessoal (CPF, RG, CNH, CNS)", "LGPD art. 5º, I (dado pessoal)", 1.25, 1),
    FINANCEIRO: PiiCategory(FINANCEIRO, "Dado financeiro (cartão de pagamento)", "LGPD art. 46 (medidas de segurança)", 1.4, 2),
    SAUDE: PiiCategory(SAUDE, "Dado de saúde", "LGPD art. 5º, II (dado pessoal sensível)", 1.5, 3),
    SENHA: PiiCategory(SENHA, "Senha ou credencial", "LGPD art. 46 (medidas de segurança)", 1.4, 4),
}

_DOCUMENT_TOKENS = {"cpf", "rg", "cnh", "cns", "ssn"}
_DOCUMENT_COMPACT = ("tituloeleitor", "cartaosus")
_FINANCIAL_TOKENS = {"cvv", "cvc"}
_FINANCIAL_COMPACT = ("numerocartao", "numerodocartao", "cartaocredito", "cartaodecredito", "creditcard", "cardnumber")
_CONTACT_TOKENS = {"email", "telefone", "celular", "phone", "whatsapp", "fone", "telephone"}
_HEALTH_TOKENS = {
    "diagnostico", "diagnosis", "prontuario", "laudo", "exame", "exames", "doenca", "patologia",
    "medicamento", "medicamentos", "medicacao", "sintoma", "sintomas", "hiv", "alergia", "alergias",
    "gestante", "deficiencia", "internacao", "prescricao", "saude", "health", "medical", "cid10",
}
_PASSWORD_TOKENS = {"senha", "password", "passwd", "pwd", "passphrase"}
# Formas já protegidas ou que descrevem o dado sem conter o valor (ex.: senha_hash, cpf_mascarado).
_SAFE_TOKENS = {
    "hash", "hashed", "digest", "salt", "encrypted", "masked", "mask", "mascarado", "mascarada",
    "ofuscado", "anonimizado", "anonimizada", "len", "length", "count", "qtd", "valid", "valido",
    "valida", "is", "has", "strength", "policy", "regex", "pattern", "min", "max", "field", "label",
    "placeholder", "type", "tipo", "format", "hint", "dica", "error", "erro", "msg", "message", "mensagem",
}


def identifier_tokens(identifier: str) -> List[str]:
    """Divide snake_case, camelCase e kebab-case em tokens minúsculos sem acento."""
    text = unicodedata.normalize("NFKD", str(identifier)).encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    return [token for token in re.split(r"[^A-Za-z0-9]+", text.lower()) if token]


def classify_identifier(identifier: Optional[str]) -> Optional[str]:
    """Retorna a categoria de PII sugerida por um nome de variável, atributo ou chave."""
    if not identifier:
        return None
    tokens = identifier_tokens(identifier)
    if not tokens or _SAFE_TOKENS.intersection(tokens):
        return None
    token_set, compact = set(tokens), "".join(tokens)
    if token_set & _PASSWORD_TOKENS:
        return SENHA
    if token_set & _HEALTH_TOKENS:
        return SAUDE
    if token_set & _DOCUMENT_TOKENS or any(part in compact for part in _DOCUMENT_COMPACT):
        return DOCUMENTO
    if token_set & _FINANCIAL_TOKENS or any(part in compact for part in _FINANCIAL_COMPACT):
        return FINANCEIRO
    if token_set & _CONTACT_TOKENS or compact in {"email", "emails"}:  # "e_mail" vira os tokens "e" e "mail"
        return CONTATO
    return None


def most_severe(categories) -> str:
    return max(categories, key=lambda category: CATEGORIES[category].rank)


# ---- CPF ---------------------------------------------------------------------------------------

_FORMATTED_CPF = re.compile(r"(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)")
_BARE_CPF = re.compile(r"\d{11}")


def is_valid_cpf(value: str) -> bool:
    """Valida os dois dígitos verificadores; sequências repetidas (111.111.111-11) são inválidas."""
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for size in (9, 10):
        total = sum(int(digits[i]) * (size + 1 - i) for i in range(size))
        if (total * 10 % 11) % 10 != int(digits[size]):
            return False
    return True


def find_cpfs(text: str) -> List[str]:
    """CPFs válidos em um literal: formatados em qualquer posição ou 11 dígitos como valor inteiro."""
    found = [match for match in _FORMATTED_CPF.findall(text) if is_valid_cpf(match)]
    stripped = text.strip()
    if _BARE_CPF.fullmatch(stripped) and is_valid_cpf(stripped):
        found.append(stripped)
    return found


def mask_cpf(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return f"***.***.***-{digits[-2:]}" if len(digits) == 11 else "***"


# ---- CNS (Cartão Nacional de Saúde) ---------------------------------------------------------------

_FORMATTED_CNS = re.compile(r"(?<!\d)\d{3}[ .]\d{4}[ .]\d{4}[ .]\d{4}(?!\d)")
_BARE_CNS = re.compile(r"\d{15}")


def is_valid_cns(value: str) -> bool:
    """Valida o CNS pelo algoritmo oficial do SUS: definitivo (1 ou 2) vem do PIS; provisório (7, 8 ou 9) soma múltipla de 11."""
    digits = re.sub(r"\D", "", value)
    if len(digits) != 15 or len(set(digits)) == 1:
        return False
    if digits[0] in "12":
        pis = digits[:11]
        total = sum(int(pis[i]) * (15 - i) for i in range(11))
        check = 11 - total % 11
        if check == 11:
            check = 0
        if check == 10:
            total += 2
            check = 11 - total % 11
            expected = pis + "001" + str(check)
        else:
            expected = pis + "000" + str(check)
        return digits == expected
    if digits[0] in "789":
        return sum(int(digits[i]) * (15 - i) for i in range(15)) % 11 == 0
    return False


def find_cns(text: str) -> List[str]:
    found = [match for match in _FORMATTED_CNS.findall(text) if is_valid_cns(match)]
    stripped = text.strip()
    if _BARE_CNS.fullmatch(stripped) and is_valid_cns(stripped):
        found.append(stripped)
    return found


def mask_cns(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return f"*** **** **** {digits[-4:]}" if len(digits) == 15 else "***"


# ---- Cartão de pagamento -------------------------------------------------------------------------

_FORMATTED_CARD = re.compile(r"(?<!\d)(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}|\d{4}[ -]\d{6}[ -]\d{5})(?!\d)")
_BARE_CARD = re.compile(r"\d{13,19}")
# Números de teste publicados pelos provedores de pagamento: não são cartões de pessoas.
KNOWN_TEST_CARDS = {
    "4111111111111111", "4242424242424242", "4012888888881881", "4000056655665556", "5555555555554444",
    "5105105105105100", "2223003122003222", "378282246310005", "371449635398431", "6011111111111117",
    "6011000990139424", "3056930009020004", "30569309025904", "3566002020360505", "6200000000000005",
}
_CARD_PREFIX = re.compile(r"^(4|5[1-5]|2(?:2[2-9]|[3-6]\d|7[01]|720)|3[47]|6011|65|35(?:2[89]|[3-8]\d)|36|38|30[0-5])")


def _luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        number = int(char)
        if index % 2:
            number *= 2
            number -= 9 if number > 9 else 0
        total += number
    return total % 10 == 0


def is_valid_card(value: str) -> bool:
    """Número de cartão plausível: 13 a 19 dígitos, bandeira conhecida, dígito de Luhn correto e fora da lista de testes."""
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1 or digits in KNOWN_TEST_CARDS:
        return False
    return bool(_CARD_PREFIX.match(digits)) and _luhn(digits)


def find_cards(text: str) -> List[str]:
    found = [match for match in _FORMATTED_CARD.findall(text) if is_valid_card(match)]
    stripped = text.strip()
    if _BARE_CARD.fullmatch(stripped) and is_valid_card(stripped):
        found.append(stripped)
    return found


def mask_card(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return f"**** **** **** {digits[-4:]}" if len(digits) >= 13 else "***"


# ---- Contato: e-mail e telefone ------------------------------------------------------------------

_EMAIL = re.compile(r"(?<![\w.%+-])[A-Za-z0-9][A-Za-z0-9._%+-]*@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?![\w-])")
_PLACEHOLDER_DOMAINS = {
    "example.com", "example.org", "example.net", "example.com.br", "exemplo.com", "exemplo.com.br", "teste.com",
    "teste.com.br", "test.com", "dominio.com", "dominio.com.br", "domain.com", "email.com", "seudominio.com",
    "seudominio.com.br", "mail.com", "localhost", "invalid", "test", "local",
}
_ROLE_MAILBOXES = {
    "user", "usuario", "test", "teste", "admin", "root", "noreply", "no-reply", "naoresponda", "contato", "contact",
    "info", "suporte", "support", "exemplo", "example", "fulano", "ciclano", "beltrano", "foo", "bar", "nome",
    "email", "seu", "seuemail", "webmaster", "sac", "atendimento", "ouvidoria", "dpo", "privacidade",
}
_PHONE_FORMATS = (
    re.compile(r"(?<!\d)\((\d{2})\)\s?(9\d{4}|[2-5]\d{3})-?(\d{4})(?!\d)"),
    re.compile(r"(?<![\d+])\+55[\s-]?\(?(\d{2})\)?[\s-]?(9\d{4}|[2-5]\d{3})[\s-]?(\d{4})(?!\d)"),
    re.compile(r"(?<![\d(+])(\d{2})\s(9\d{4})-(\d{4})(?!\d)"),
)
_VALID_DDD = {
    *range(11, 20), 21, 22, 24, 27, 28, 31, 32, 33, 34, 35, 37, 38, *range(41, 50), 51, 53, 54, 55,
    *range(61, 70), 71, 73, 74, 75, 77, 79, *range(81, 90), *range(91, 100),
}


def find_emails(text: str) -> List[str]:
    """E-mails com cara de pessoa real: ignora domínios de exemplo e caixas genéricas (contato@, suporte@)."""
    found = []
    for match in _EMAIL.finditer(text):
        local, domain = match.group(0).rsplit("@", 1)[0].lower(), match.group(1).lower()
        if domain in _PLACEHOLDER_DOMAINS or domain.endswith((".example", ".test", ".invalid", ".local", ".localhost")):
            continue
        if local in _ROLE_MAILBOXES:
            continue
        found.append(match.group(0))
    return found


def find_phones(text: str) -> List[str]:
    """Telefones brasileiros com formatação explícita e DDD existente; ignora números repetidos (99999-9999)."""
    found = []
    for pattern in _PHONE_FORMATS:
        for match in pattern.finditer(text):
            ddd, middle, tail = match.groups()
            if int(ddd) in _VALID_DDD and len(set(middle + tail)) > 2 and match.group(0) not in found:
                found.append(match.group(0))
    return [item for item in found if not any(item != other and item in other for other in found)]  # "+55 21 …" já contém "21 …"


def mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    return f"{local[:1]}***@{domain}"


def mask_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return f"(**) *****-{digits[-4:]}" if len(digits) >= 4 else "***"
