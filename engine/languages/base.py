from abc import ABC, abstractmethod
from typing import List, Tuple
from engine.models import Finding, RuleMetadata, Severity


class LanguageScanner(ABC):
    """Classe base abstrata para analisadores SAST especializados por linguagem."""

    language_name: str = "Generic"

    @abstractmethod
    def scan_source(self, source_code: str, file_path: str) -> Tuple[List[Finding], List[str]]:
        """Analisa o código-fonte da linguagem e retorna (findings, errors)."""
        pass

    @abstractmethod
    def list_rules(self) -> List[RuleMetadata]:
        """Retorna o catálogo de regras suportadas pela linguagem."""
        pass

    @staticmethod
    def create_finding(
        rule_id: str,
        rule_name: str,
        severity: Severity,
        cwe: str,
        message: str,
        file_path: str,
        line_number: int,
        column_number: int,
        code_snippet: str,
        remediation_advice: str,
    ) -> Finding:
        """Cria e retorna uma instância padronizada de Finding."""
        return Finding(
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            cwe=cwe,
            message=message,
            file_path=file_path,
            line_number=line_number,
            column_number=column_number,
            code_snippet=code_snippet.strip(),
            remediation_advice=remediation_advice,
        )
