"""Indicador Risco Cidadão: o quanto os achados expõem dados pessoais de quem usa o serviço.

Pontuação (0 a 100), determinística e auditável:

    pontos  = Σ peso_severidade × fator_dado × fator_fluxo
    score   = round(100 × (1 − e^(−pontos / 25)))

* peso_severidade: crítica 10, alta 6, média 3, baixa 1, informativa 0,25.
* fator_dado: saúde 1,5 · senha 1,4 · cartão 1,4 · documento 1,25 · contato 1,1 (achados de PII); falhas sem PII contam 0,4,
  porque podem abrir caminho a vazamentos, mas não expõem dados por si.
* fator_fluxo: 1,5 quando o Taint Analysis comprova que o dado chega a uma saída insegura
  (vazamento confirmado); 1,0 para dado escrito no código ou hash fraco.

A saturação exponencial evita que muitos achados leves "estourem" a escala e mantém a diferença
entre um projeto com um vazamento e outro com vários.
"""
import math
from collections import defaultdict
from typing import Iterable, List

from engine.models import CitizenRisk, CitizenRiskDriver, Finding, Severity
from engine.pii import CATEGORIES, most_severe

SEVERITY_POINTS = {Severity.CRITICAL: 10.0, Severity.HIGH: 6.0, Severity.MEDIUM: 3.0, Severity.LOW: 1.0, Severity.INFO: 0.25}
NON_PII_FACTOR = 0.4
LEAK_FACTOR = 1.5
SATURATION = 25.0
LEAK_RULES = {"PY-T004", "PY-T005", "PY-T006", "PY-T007"}
FORMULA = ("score = 100 × (1 − e^(−pontos/25)); pontos = Σ severidade (crítica 10, alta 6, média 3, baixa 1) "
           "× dado (saúde 1,5 · senha 1,4 · cartão 1,4 · documento 1,25 · contato 1,1; sem PII 0,4) × fluxo (vazamento confirmado por taint 1,5)")
LEVELS = [(70, "critical", "Crítico"), (45, "high", "Alto"), (20, "moderate", "Moderado"), (1, "low", "Baixo")]


def _level(score: int):
    for threshold, key, label in LEVELS:
        if score >= threshold:
            return key, label
    return "none", "Sem exposição detectada"


def compute_citizen_risk(findings: Iterable[Finding], complete: bool = True) -> CitizenRisk:
    findings = list(findings)
    total = 0.0
    per_category = defaultdict(lambda: {"findings": 0, "leaks": 0, "points": 0.0})
    pii_findings = leaks = 0
    for finding in findings:
        points = SEVERITY_POINTS.get(finding.severity, 0.0)
        if not finding.data_categories:
            total += points * NON_PII_FACTOR
            continue
        category = most_severe([item for item in finding.data_categories if item in CATEGORIES])
        is_leak = finding.rule_id in LEAK_RULES
        points *= CATEGORIES[category].weight * (LEAK_FACTOR if is_leak else 1.0)
        total += points
        pii_findings += 1
        leaks += is_leak
        bucket = per_category[category]
        bucket["findings"] += 1
        bucket["leaks"] += is_leak
        bucket["points"] += points
    score = round(100 * (1 - math.exp(-total / SATURATION)))
    level, label = _level(score)
    drivers: List[CitizenRiskDriver] = [
        CitizenRiskDriver(category=key, label=CATEGORIES[key].label, findings=item["findings"],
                          leaks=item["leaks"], points=round(item["points"], 1))
        for key, item in sorted(per_category.items(), key=lambda pair: -pair[1]["points"])
    ]
    if pii_findings:
        summary = (f"{pii_findings} achado(s) expõem dados pessoais; {leaks} vazamento(s) confirmado(s) pelo "
                   f"Taint Analysis. Dados envolvidos: {', '.join(driver.label for driver in drivers)}.")
    elif findings:
        summary = "Nenhum dado pessoal exposto foi encontrado, mas há falhas técnicas que podem abrir caminho a vazamentos."
    else:
        summary = "Nenhuma exposição de dados pessoais detectada pelas regras aplicadas. Isso não prova ausência de risco."
    if not complete:
        summary += " A análise teve erros e pode estar incompleta."
    return CitizenRisk(
        score=score, level=level, level_label=label, pii_findings=pii_findings, confirmed_leaks=leaks,
        affected_data=[driver.label for driver in drivers], drivers=drivers, summary=summary,
        formula=FORMULA, complete=complete,
    )
