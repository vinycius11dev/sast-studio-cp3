import ast
from abc import ABC
from typing import List, Optional
from engine.models import Finding, Severity, RuleMetadata


class BaseRule(ast.NodeVisitor, ABC):
    """Classe base para implementação de regras SAST baseadas em AST."""

    rule_id: str = "PY-BASE"
    name: str = "Regra Base"
    severity: Severity = Severity.MEDIUM
    cwe: str = "CWE-000"
    description: str = "Descrição da regra base"
    remediation: str = "Instrução geral de remediação"

    def __init__(self):
        super().__init__()
        self.findings: List[Finding] = []
        self.current_file_path: str = ""
        self.source_lines: List[str] = []

    def get_metadata(self) -> RuleMetadata:
        """Retorna os metadados descritivos da regra."""
        return RuleMetadata(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            cwe=self.cwe,
            description=self.description,
            remediation=self.remediation,
        )

    def get_additional_metadata(self) -> List[RuleMetadata]:
        """Retorna metadados de regras adicionais implementadas pela mesma classe, se houver."""
        return []

    def scan(self, tree: ast.AST, file_path: str, source_code: str) -> List[Finding]:
        """Executa a inspeção na árvore AST fornecida e retorna as violações."""
        self.findings = []
        self.current_file_path = file_path
        self.source_lines = source_code.splitlines()
        self.visit(tree)
        return self.findings

    def add_finding(
        self,
        node: ast.AST,
        message: Optional[str] = None,
        remediation: Optional[str] = None,
        severity: Optional[Severity] = None,
        cwe: Optional[str] = None,
        rule_id: Optional[str] = None,
        rule_name: Optional[str] = None,
    ) -> None:
        """Registra uma violação identificada em um nó específico da AST."""
        lineno = getattr(node, "lineno", 1)
        col_offset = getattr(node, "col_offset", 0)

        snippet = ""
        if 0 < lineno <= len(self.source_lines):
            snippet = self.source_lines[lineno - 1].strip()

        finding = Finding(
            rule_id=rule_id or self.rule_id,
            rule_name=rule_name or self.name,
            severity=severity or self.severity,
            cwe=cwe or self.cwe,
            message=message or self.description,
            file_path=self.current_file_path,
            line_number=lineno,
            column_number=col_offset,
            code_snippet=snippet,
            remediation_advice=remediation or self.remediation,
        )
        self.findings.append(finding)
