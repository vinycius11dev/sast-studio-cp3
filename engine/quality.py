"""Expose recorded, reproducible measurements with their scope and freshness."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def detection_fingerprint():
    digest = hashlib.sha256()
    for path in sorted((ROOT / "engine").rglob("*.py")):
        if path.name in {"ai_remediation.py", "semantic_review.py", "patch_validation.py", "quality.py"}:
            continue
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def measured_quality():
    path = ROOT / "docs/benchmark-results.json"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"status": "unavailable", "scope": "Nenhuma medição salva para esta instalação."}
    fresh = report.get("detection_fingerprint") == detection_fingerprint()
    keys = ("scope", "unit", "case_count", "safe_cases", "true_positives", "false_positives", "false_negatives",
            "precision", "recall", "safe_case_false_positive_rate", "generated_at", "engine", "rule_count",
            "rules_exercised", "unexercised_rules", "by_language", "by_cwe", "by_engine", "median_ms", "p95_ms",
            "corpus_sha256", "detection_fingerprint")
    result = {key: report.get(key) for key in keys}
    result["status"] = "current" if fresh else "stale"
    result["limitations"] = ["Corpus local curado; não representa cobertura universal.",
        "As métricas deste relatório medem o motor nativo, sem avaliar as respostas do Ollama.",
        "Análise interarquivo e equivalência funcional dos patches ainda não são comprovadas."]
    external = ROOT / "docs/quality/owasp-native-results.json"
    if external.exists():
        try:
            official = json.loads(external.read_text(encoding="utf-8"))
            result["owasp_benchmark"] = {key: value for key, value in official.items() if key not in {"results", "cases"}}
        except (OSError, ValueError):
            pass
    return result
