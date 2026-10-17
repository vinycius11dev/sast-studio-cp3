"""Política de bloqueio compartilhada pela API e pela CLI."""
from engine.models import ScanResult, SecurityGate

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def evaluate_gate(result: ScanResult, threshold: str = "HIGH") -> SecurityGate:
    threshold = threshold.upper()
    if threshold not in SEVERITY_ORDER[:4]:
        raise ValueError("Severidade de bloqueio inválida.")
    blocking = sum(result.summary_by_severity.get(level, 0) for level in SEVERITY_ORDER[:SEVERITY_ORDER.index(threshold) + 1])
    if result.has_errors:
        return SecurityGate(threshold=threshold, status="error", blocking_findings=blocking,
                            reason="Análise incompleta: há arquivos com erro de processamento.")
    if blocking:
        return SecurityGate(threshold=threshold, status="blocked", blocking_findings=blocking,
                            reason=f"{blocking} achado(s) com severidade {threshold} ou superior.")
    return SecurityGate(threshold=threshold, status="passed", blocking_findings=0,
                        reason=f"Nenhum achado com severidade {threshold} ou superior nas regras aplicadas.")
