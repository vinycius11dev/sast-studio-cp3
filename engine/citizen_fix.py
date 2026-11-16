"""Corrigir e provar (GS CitizenTech): corrige exposições de PII em código Python e reanalisa o resultado.

Para cada exposição de dado pessoal o corretor aplica uma proteção determinística, sem depender de IA:

* CPF, CNS, cartão, e-mail ou telefone escritos no código viram valores fictícios inválidos;
* valor de saúde escrito no código é removido (``None``);
* senha com MD5/SHA-1 passa por ``hash_senha`` (bcrypt com salt);
* dado que chega a log, resposta, arquivo ou serviço externo passa por ``mascarar_pii``; senha que iria
  para o armazenamento passa por ``hash_senha``.

Depois da correção o código é analisado de novo pelo mesmo motor: a correção só é dada como **provada**
quando o arquivo continua sendo Python válido e nenhuma exposição de PII permanece. A prova é do motor de
regras: ela não executa o programa nem substitui revisão e testes de comportamento.
"""
import ast
import difflib
import sys
import textwrap
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from engine.citizen_risk import compute_citizen_risk
from engine.engine import SASTEngine
from engine.models import CitizenRisk, Finding
from engine import pii
from engine.rules.pii_rule import _WEAK_HASHES, PiiExposureRule
from engine.rules.pii_taint_rule import PiiTaintRule

MASK_HELPER, HASH_HELPER = "mascarar_pii", "hash_senha"
FICTITIOUS = {"cpf": ("000.000.000-00", "00000000000"), "cns": ("000 0000 0000 0000", "000000000000000"),
              "cartao": ("0000 0000 0000 0000", "0000000000000000")}
EMAIL_EXAMPLE, PHONE_EXAMPLE = "usuario@example.com", "(00) 00000-0000"
SENSITIVE_KEYS = sorted(pii._DOCUMENT_TOKENS | pii._HEALTH_TOKENS | pii._PASSWORD_TOKENS | pii._FINANCIAL_TOKENS | pii._CONTACT_TOKENS)


def _keys_literal() -> str:
    body = textwrap.fill(", ".join(f'"{key}"' for key in SENSITIVE_KEYS), width=96, initial_indent="    ", subsequent_indent="    ")
    return "_CHAVES_SENSIVEIS = (\n" + body + ",\n)"


HELPERS = {
    MASK_HELPER: '''def mascarar_pii(valor, chave=""):
    """Mascara dados pessoais antes de log, resposta ou envio a terceiros (gerado pelo SAST Studio)."""
    if isinstance(valor, dict):
        return {nome: mascarar_pii(item, str(nome)) for nome, item in valor.items()}
    if isinstance(valor, (list, tuple)):
        return [mascarar_pii(item, chave) for item in valor]
    partes = chave.lower().replace("-", "_").split("_")
    if chave and not any(parte in _CHAVES_SENSIVEIS for parte in partes):
        return valor  # campo comum dentro de um dicionário: mantém
    digitos = "".join(caractere for caractere in str(valor) if caractere.isdigit())
    return "***.***.***-" + digitos[-2:] if len(digitos) == 11 else "***"
''',
    HASH_HELPER: '''def hash_senha(valor):
    """Guarda a senha só como hash com salt (bcrypt), nunca em texto claro (gerado pelo SAST Studio)."""
    return bcrypt.hashpw(str(valor).encode(), bcrypt.gensalt()).decode()
''',
}


class FixAction(BaseModel):
    rule_id: str
    line: int
    action: str
    before: str
    after: str


class RemainingFinding(BaseModel):
    rule_id: str
    line: int
    message: str


class FileFix(BaseModel):
    file_path: str
    changed: bool = False
    syntax_ok: bool = True
    applied: List[FixAction] = Field(default_factory=list)
    remaining: List[RemainingFinding] = Field(default_factory=list)
    skipped_reason: Optional[str] = None
    diff: str = ""
    fixed_code: str = ""


class CitizenFix(BaseModel):
    scan_id: str
    fixed_scan_id: Optional[str] = None
    before: CitizenRisk
    after: CitizenRisk
    verified: bool
    applied_count: int
    remaining_count: int
    files: List[FileFix]
    notes: List[str]
    summary: str


@dataclass
class _Edit:
    start: Tuple[int, int]   # (linha, coluna em bytes UTF-8), como no AST
    end: Tuple[int, int]
    text: str
    rule_id: str
    line: int
    action: str
    before: str


def _span(node) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    return (node.lineno, node.col_offset), (node.end_lineno, node.end_col_offset)


def _segment(source: str, node) -> str:
    return ast.get_source_segment(source, node) or ""


def _inside_fstring(node, parents) -> bool:
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.JoinedStr):
            return True
    return False


class _Fixer:
    def __init__(self, source: str, file_path: str):
        self.source, self.file_path = source, file_path
        self.tree = ast.parse(source)
        self.parents = {child: parent for parent in ast.walk(self.tree) for child in ast.iter_child_nodes(parent)}
        self.edits: List[_Edit] = []
        self.uses_mask = self.uses_hash = False
        self.documentation = {id(node.value) for node in ast.walk(self.tree)
                              if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)}

    # ---- literais com dado pessoal -------------------------------------------------------------
    def _replace_values(self, node: ast.Constant, replacements, rule_id: str, action: str) -> None:
        segment = _segment(self.source, node)
        updated = segment
        for original, fake in replacements:
            updated = updated.replace(original, fake)
        if updated != segment:
            start, end = _span(node)
            self.edits.append(_Edit(start, end, updated, rule_id, node.lineno, action, segment))

    def literals(self) -> None:
        for node in ast.walk(self.tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            text = node.value
            self._replace_values(node, [(item, FICTITIOUS["cpf"][0] if "." in item else FICTITIOUS["cpf"][1]) for item in pii.find_cpfs(text)],
                                 "PY-P001", "CPF trocado por um valor fictício inválido (000.000.000-00)")
            self._replace_values(node, [(item, FICTITIOUS["cns"][0] if " " in item or "." in item else FICTITIOUS["cns"][1]) for item in pii.find_cns(text)],
                                 "PY-P004", "CNS trocado por zeros (número inválido)")
            self._replace_values(node, [(item, FICTITIOUS["cartao"][0] if " " in item or "-" in item else FICTITIOUS["cartao"][1]) for item in pii.find_cards(text)],
                                 "PY-P005", "Número de cartão trocado por zeros (número inválido)")
            if id(node) not in self.documentation:
                contacts = [(item, EMAIL_EXAMPLE) for item in pii.find_emails(text)] + [(item, PHONE_EXAMPLE) for item in pii.find_phones(text)]
                self._replace_values(node, contacts, "PY-P006", "Contato trocado por um exemplo (usuario@example.com, (00) 00000-0000)")

    def health_literals(self) -> None:
        pairs = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                pairs += [(PiiExposureRule._target_name(target), node.value) for target in node.targets]
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                pairs.append((PiiExposureRule._target_name(node.target), node.value))
            elif isinstance(node, ast.Dict):
                pairs += [(key.value, value) for key, value in zip(node.keys, node.values)
                          if isinstance(key, ast.Constant) and isinstance(key.value, str)]
            elif isinstance(node, ast.Call):
                pairs += [(keyword.arg, keyword.value) for keyword in node.keywords if keyword.arg]
        for name, value in pairs:
            if pii.classify_identifier(name) == pii.SAUDE and PiiExposureRule._meaningful_literal(value):
                start, end = _span(value)
                self.edits.append(_Edit(start, end, "None", "PY-P002", value.lineno,
                                        "Valor de saúde removido do código (None): carregue-o de uma base protegida", _segment(self.source, value)))

    # ---- senha com hash fraco ------------------------------------------------------------------
    def weak_password_hashes(self) -> None:
        for node in ast.walk(self.tree):
            if not (isinstance(node, ast.Call) and ast.unparse(node.func) in _WEAK_HASHES and node.args):
                continue
            if not any(PiiExposureRule._mentions_password(argument) for argument in node.args):
                continue
            argument, target = node.args[0], node
            parent = self.parents.get(node)
            grand = self.parents.get(parent) if parent is not None else None
            if isinstance(parent, ast.Attribute) and parent.attr in {"hexdigest", "digest"} and isinstance(grand, ast.Call) and grand.func is parent:
                target = grand
            if isinstance(argument, ast.Call) and isinstance(argument.func, ast.Attribute) and argument.func.attr == "encode":
                argument = argument.func.value
            start, end = _span(target)
            self.uses_hash = True
            self.edits.append(_Edit(start, end, f"{HASH_HELPER}({_segment(self.source, argument)})", "PY-P003", node.lineno,
                                    "MD5/SHA-1 trocado por bcrypt com salt (hash_senha)", _segment(self.source, target)))

    # ---- fluxos até saídas inseguras -----------------------------------------------------------
    def taint_flows(self) -> None:
        rule = PiiTaintRule()
        rule.scan(self.tree, self.file_path, self.source)
        for site in rule.fix_sites:
            if _inside_fstring(site.leaf, self.parents) and sys.version_info < (3, 12):
                continue  # antes do Python 3.12 as posições dentro de f-strings são imprecisas: fica para revisão manual
            helper = HASH_HELPER if site.helper == "hash" else MASK_HELPER
            leaf_text = _segment(self.source, site.leaf)
            self.uses_hash |= helper == HASH_HELPER
            self.uses_mask |= helper == MASK_HELPER
            start, end = _span(site.leaf)
            action = ("Senha gravada como hash bcrypt (hash_senha), não em texto claro" if helper == HASH_HELPER
                      else "Dado mascarado antes de sair do sistema (mascarar_pii)")
            self.edits.append(_Edit(start, end, f"{helper}({leaf_text})", site.rule_id, site.line, action, leaf_text))

    # ---- aplicação -----------------------------------------------------------------------------
    def apply(self) -> Tuple[str, List[_Edit]]:
        data = self.source.encode("utf-8")
        starts, total = [], 0
        for line in data.split(b"\n"):
            starts.append(total)
            total += len(line) + 1
        absolute = sorted(((starts[e.start[0] - 1] + e.start[1], starts[e.end[0] - 1] + e.end[1], e) for e in self.edits),
                          key=lambda item: (item[0], -item[1]))
        kept, last_end = [], -1
        for start, end, edit in absolute:
            if start >= last_end:  # descarta edições aninhadas ou repetidas: vale a mais externa
                kept.append((start, end, edit))
                last_end = end
        for start, end, edit in reversed(kept):
            data = data[:start] + edit.text.encode("utf-8") + data[end:]
        return data.decode("utf-8"), [edit for _, _, edit in kept]

    def with_helpers(self, fixed: str, need_mask: bool, need_hash: bool) -> str:
        tree = ast.parse(fixed)
        defined = {node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        imported = {alias.name.split(".")[0] for node in tree.body if isinstance(node, ast.Import) for alias in node.names}
        blocks = []
        if need_hash and "bcrypt" not in imported:
            blocks.append("import bcrypt\n")
        if need_mask and MASK_HELPER not in defined:
            blocks.append("# Proteção de dados pessoais (LGPD) · gerado pelo SAST Studio\n"
                          + _keys_literal() + "\n\n\n" + HELPERS[MASK_HELPER])
        if need_hash and HASH_HELPER not in defined:
            blocks.append(HELPERS[HASH_HELPER])
        if not blocks:
            return fixed
        imports = [node.end_lineno for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        docstring = tree.body[0].end_lineno if tree.body and isinstance(tree.body[0], ast.Expr) \
            and isinstance(tree.body[0].value, ast.Constant) and isinstance(tree.body[0].value.value, str) else 0
        after = max(imports + [docstring])
        lines = fixed.split("\n")
        header = blocks[0] if blocks[0].startswith("import bcrypt") else None
        if header:
            lines[after:after] = [header.rstrip("\n")]
            blocks = blocks[1:]
            after += 1
        if blocks:
            while after < len(lines) and lines[after] == "":
                del lines[after]  # as linhas em branco originais dão lugar às do bloco
            lines[after:after] = ["", ""] +"\n\n\n".join(block.rstrip("\n") for block in blocks).split("\n") + ["", ""]
        return "\n".join(lines)


def _pii_findings(findings: List[Finding]) -> List[Finding]:
    return [item for item in findings if item.data_categories]


def fix_file(source: str, file_path: str, engine: Optional[SASTEngine] = None) -> Tuple[FileFix, List[Finding], List[Finding], str]:
    """Corrige um arquivo. Retorna (resultado, achados antes, achados depois, código final)."""
    engine = engine or SASTEngine()
    before = engine.scan_code(source, file_path)
    result = FileFix(file_path=file_path, fixed_code=source)
    if not file_path.lower().endswith(".py"):
        result.skipped_reason = "A correção automática existe só para Python; revise este arquivo manualmente."
        result.remaining = [RemainingFinding(rule_id=i.rule_id, line=i.line_number, message=i.message) for i in _pii_findings(before.findings)]
        return result, before.findings, before.findings, source
    if before.has_errors:
        result.syntax_ok = False
        result.skipped_reason = "O arquivo tem erro de sintaxe e não pôde ser corrigido."
        return result, before.findings, before.findings, source
    fixer = _Fixer(source, file_path)
    fixer.literals()
    fixer.health_literals()
    fixer.weak_password_hashes()
    fixer.taint_flows()
    fixed, edits = fixer.apply()
    if edits:
        try:
            fixed = fixer.with_helpers(fixed, any(e.text.startswith(MASK_HELPER + "(") for e in edits),
                                       any(e.text.startswith(HASH_HELPER + "(") for e in edits))
            ast.parse(fixed)
        except SyntaxError:
            result.syntax_ok = False
            result.skipped_reason = "A correção gerou código inválido e foi descartada."
            return result, before.findings, before.findings, source
    after = engine.scan_code(fixed, file_path)
    result.changed = fixed != source
    result.fixed_code = fixed
    result.applied = [FixAction(rule_id=e.rule_id, line=e.line, action=e.action, before=e.before.strip(), after=e.text.strip())
                      for e in sorted(edits, key=lambda e: (e.line, e.rule_id))]
    result.remaining = [RemainingFinding(rule_id=i.rule_id, line=i.line_number, message=i.message) for i in _pii_findings(after.findings)]
    if result.changed:
        result.diff = "".join(difflib.unified_diff(source.splitlines(True), fixed.splitlines(True), f"a/{file_path}", f"b/{file_path}"))
    return result, before.findings, after.findings, fixed


def fix_project(scan_id: str, sources: Dict[str, str]) -> Tuple[CitizenFix, Dict[str, str]]:
    """Corrige todos os arquivos de uma análise e reanalisa. Retorna (resultado, código corrigido por arquivo)."""
    engine, files, fixed_sources = SASTEngine(), [], {}
    before_all, after_all = [], []
    for path, source in sorted(sources.items()):
        result, before, after, fixed = fix_file(source, path, engine)
        files.append(result)
        fixed_sources[path] = fixed
        before_all += before
        after_all += after
    before_risk, after_risk = compute_citizen_risk(before_all), compute_citizen_risk(after_all)
    applied = sum(len(item.applied) for item in files)
    remaining = sum(len(item.remaining) for item in files)
    verified = applied > 0 and after_risk.pii_findings == 0 and all(item.syntax_ok for item in files)
    notes = ["A prova é do motor de regras: o código foi reanalisado e nenhuma exposição de dados pessoais permaneceu. "
             "Ela não executa o programa: revise o resultado e rode os testes antes de publicar."]
    if any(HASH_HELPER + "(" in item.fixed_code for item in files):
        notes.append("As correções de senha usam bcrypt: instale com `pip install bcrypt` e atualize o login para comparar com `bcrypt.checkpw`.")
    if any(MASK_HELPER + "(" in item.fixed_code for item in files):
        notes.append("Onde o dado saía para log, resposta ou parceiro, ele agora sai mascarado. Se algum parceiro precisa do valor completo, "
                     "isso exige base legal e contrato (LGPD arts. 7º e 46), não só código.")
    if any(item.skipped_reason for item in files):
        notes.append("Arquivos que não são Python, ou com erro de sintaxe, não foram alterados.")
    if verified:
        summary = f"{applied} correção(ões) aplicada(s): Risco Cidadão de {before_risk.score} para {after_risk.score}."
    elif applied:
        summary = (f"{applied} correção(ões) aplicada(s): Risco Cidadão de {before_risk.score} para {after_risk.score}, "
                   f"mas {remaining} exposição(ões) exigem revisão manual.")
    else:
        summary = "Nenhuma correção automática se aplica a esta análise."
    return CitizenFix(scan_id=scan_id, before=before_risk, after=after_risk, verified=verified, applied_count=applied,
                      remaining_count=remaining, files=files, notes=notes, summary=summary), fixed_sources
