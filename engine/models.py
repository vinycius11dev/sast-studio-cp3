from enum import Enum
from typing import List, Dict, Optional, Literal
from pydantic import BaseModel, Field, model_validator
from engine.owasp import OwaspCategory, owasp_category_for_cwe


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    rule_id: str = Field(..., description="Identificador único da regra (ex: PY-R001)")
    rule_name: str = Field(..., description="Nome descritivo da regra")
    severity: Severity = Field(..., description="Severidade da vulnerabilidade")
    cwe: str = Field(..., description="Identificador CWE (ex: CWE-95)")
    message: str = Field(..., description="Explicação detalhada da vulnerabilidade encontrada")
    file_path: str = Field(..., description="Caminho do arquivo analisado")
    line_number: int = Field(..., description="Número da linha onde a violação ocorre (1-indexed)")
    column_number: int = Field(..., description="Número da coluna do nó (0-indexed)")
    code_snippet: str = Field(..., description="Trecho de código com a violação")
    remediation_advice: str = Field(..., description="Orientação de como corrigir a falha de forma segura")
    owasp: Optional[OwaspCategory] = Field(default=None, description="Categoria OWASP Top 10:2025 associada ao CWE")

    @model_validator(mode="after")
    def map_owasp_category(self):
        # Recompute on load too, so older SQLite scans gain the versioned tag.
        self.owasp = owasp_category_for_cwe(self.cwe)
        return self


class RuleMetadata(BaseModel):
    rule_id: str
    name: str
    severity: Severity
    cwe: str
    description: str
    remediation: str
    owasp: Optional[OwaspCategory] = Field(default=None, description="Categoria OWASP Top 10:2025 associada ao CWE")

    @model_validator(mode="after")
    def map_owasp_category(self):
        self.owasp = owasp_category_for_cwe(self.cwe)
        return self


class SecurityGate(BaseModel):
    threshold: str
    status: str
    blocking_findings: int
    reason: str


class ScannedFile(BaseModel):
    path: str
    language: str
    size_bytes: int
    findings_count: int
    status: str = "completed"


class SemanticReview(BaseModel):
    review_id: Optional[str] = None
    scan_id: str
    created_at: Optional[str] = None
    finding_key: str
    rule_id: str
    file_path: str
    line_number: int
    column_number: int
    original_severity: Severity
    classification: Literal["confirmed", "likely_false_positive", "needs_review"]
    suggested_severity: Severity
    confidence: Literal["high", "medium", "low"]
    reasoning: str
    evidence_lines: List[int] = Field(default_factory=list)
    provider: Literal["ollama", "unavailable"]
    model_used: str
    fallback_reason: Optional[str] = None


class ScanResult(BaseModel):
    scan_id: Optional[str] = None
    created_at: Optional[str] = None
    project_name: Optional[str] = None
    security_gate: Optional[SecurityGate] = None
    files: List[ScannedFile] = Field(default_factory=list)
    ignored_files_count: int = 0
    semantic_reviews: List[SemanticReview] = Field(default_factory=list)
    target_path: str = Field(..., description="Caminho ou identificador do alvo analisado")
    scanned_files_count: int = Field(..., description="Quantidade de arquivos analisados com sucesso")
    total_findings: int = Field(..., description="Total de vulnerabilidades encontradas")
    findings: List[Finding] = Field(default_factory=list, description="Lista de achados")
    summary_by_severity: Dict[str, int] = Field(
        default_factory=lambda: {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        },
        description="Contagem agrupada por severidade",
    )
    scan_duration_ms: float = Field(..., description="Tempo de varredura em milissegundos")
    has_errors: bool = Field(default=False, description="Indica se houve arquivos com erro de sintaxe")
    errors: List[str] = Field(default_factory=list, description="Mensagens de erro de parsing ou IO")
