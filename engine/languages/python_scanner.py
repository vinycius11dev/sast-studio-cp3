from typing import List, Tuple
from engine.models import Finding, RuleMetadata
from engine.parser import CodeParser
from engine.rules import DEFAULT_RULES
from .base import LanguageScanner


class PythonScanner(LanguageScanner):
    """Analisador SAST para código Python baseado em Árvore de Sintaxe Abstrata (AST)."""

    language_name: str = "Python"

    def __init__(self, rule_classes=None):
        self.rule_classes = rule_classes or list(DEFAULT_RULES)

    def list_rules(self) -> List[RuleMetadata]:
        rules_meta = []
        for r_cls in self.rule_classes:
            instance = r_cls()
            rules_meta.append(instance.get_metadata())
            rules_meta.extend(instance.get_additional_metadata())
        return rules_meta

    def scan_source(self, source_code: str, file_path: str) -> Tuple[List[Finding], List[str]]:
        tree, code, error = CodeParser.parse_code(source_code, filename=file_path)
        if error:
            return [], [error]

        findings: List[Finding] = []
        if tree is not None:
            for rule_cls in self.rule_classes:
                rule_inst = rule_cls()
                rule_findings = rule_inst.scan(tree=tree, file_path=file_path, source_code=code)
                findings.extend(rule_findings)

        return findings, []
