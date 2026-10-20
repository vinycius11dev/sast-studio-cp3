"""Mede precisão e recall no corpus rotulado do projeto, sem executar as amostras."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import statistics
import time
from pathlib import Path

from engine.engine import SASTEngine
from engine.quality import detection_fingerprint

ROOT = Path(__file__).resolve().parents[1]


def load_cases():
    cases = []
    for path in [ROOT / "benchmarks/cases.json", *sorted((ROOT / "benchmarks").glob("coverage_*.json"))]:
        for case in json.loads(path.read_text(encoding="utf-8")):
            cases.append({**case, "id": path.stem + "/" + case["id"]})
    if len({case["id"] for case in cases}) != len(cases):
        raise ValueError("IDs duplicados no corpus de benchmark.")
    return cases


def metrics(tp, fp, fn, tn=0):
    return {"true_positives": tp, "false_positives": fp, "false_negatives": fn, "true_negatives": tn,
            "precision": round(tp / (tp + fp), 5) if tp + fp else 1.0,
            "recall": round(tp / (tp + fn), 5) if tp + fn else 1.0,
            "false_positive_rate": None}


def evaluate(cases=None, repeats=5):
    cases = cases if cases is not None else load_cases()
    engine = SASTEngine(engines=["native"])
    catalogue = {rule.rule_id: rule for rule in engine.list_rules()}
    results, timings = [], []
    tp = fp = fn = safe = safe_flagged = 0
    by_language = defaultdict(lambda: [0, 0, 0, 0])
    by_cwe = defaultdict(lambda: [0, 0, 0, 0])
    covered_rules = set()
    corpus_digest = hashlib.sha256(json.dumps(cases, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    for case in cases:
        measured = []
        for _ in range(max(1, repeats)):
            start = time.perf_counter()
            result = engine.scan_code(case["code"], case["filename"])
            measured.append((time.perf_counter() - start) * 1000)
        timings.extend(measured)
        located = bool(case.get("expected_locations"))
        expected = Counter((item["rule_id"], item["line_number"]) for item in case["expected_locations"]) if located else Counter(case["expected_rules"])
        detected = Counter((finding.rule_id, finding.line_number) for finding in result.findings) if located else Counter(finding.rule_id for finding in result.findings)
        matched, unexpected, missed = expected & detected, detected - expected, expected - detected
        counts = [sum(matched.values()), sum(unexpected.values()), sum(missed.values()), int(not expected and not detected and not result.has_errors)]
        tp += counts[0]; fp += counts[1]; fn += counts[2]
        language = case.get("language") or {".py": "python", ".java": "java"}.get(Path(case["filename"]).suffix, "javascript")
        for index, value in enumerate(counts):
            by_language[language][index] += value
        for group, index in ((matched, 0), (unexpected, 1), (missed, 2)):
            for identity, count in group.items():
                rule_id = identity[0] if located else identity
                cwe = catalogue[rule_id].cwe if rule_id in catalogue else "unmapped"
                by_cwe[cwe][index] += count
        covered_rules.update(case["expected_rules"])
        if not expected:
            safe += 1
            safe_flagged += bool(detected)
        results.append({"id": case["id"], "filename": case["filename"], "language": language,
                        "expected": sorted(case["expected_rules"]), "detected": sorted(finding.rule_id for finding in result.findings),
                        "expected_locations": case.get("expected_locations", []),
                        "detected_locations": [{"rule_id": finding.rule_id, "line_number": finding.line_number,
                                                "column_number": finding.column_number, "cwe": finding.cwe} for finding in result.findings],
                        "true_positives": counts[0], "false_positives": counts[1], "false_negatives": counts[2], "errors": result.errors,
                        "exact_match": expected == detected and not result.has_errors,
                        "median_ms": round(statistics.median(measured), 4)})
    precision = tp / (tp + fp) if tp + fp else 1
    recall = tp / (tp + fn) if tp + fn else 1
    ordered = sorted(timings)
    return {"scope": "Corpus curado do projeto; métricas não representam todos os códigos ou vulnerabilidades do mercado nem a qualidade do LLM.",
            "unit": "ocorrência de regra por caso; localização exata quando rotulada", "case_count": len(cases), "safe_cases": safe,
            "generated_at": datetime.now(timezone.utc).isoformat(), "engine": "native",
            "detection_fingerprint": detection_fingerprint(), "corpus_sha256": corpus_digest,
            "rule_count": len(catalogue), "rules_exercised": len(covered_rules),
            "unexercised_rules": sorted(set(catalogue) - covered_rules),
            "by_language": {key: metrics(*value) for key, value in sorted(by_language.items())},
            # Per-CWE negative denominators are not inferred from unrelated controls.
            "by_cwe": {key: {**metrics(*value), "false_positive_rate": None} for key, value in sorted(by_cwe.items())},
            "by_engine": {"native": metrics(tp, fp, fn, safe - safe_flagged)},
            "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": round(precision, 5), "recall": round(recall, 5),
            "safe_case_false_positive_rate": round(safe_flagged / safe, 5) if safe else None,
            "exact_case_accuracy": round(sum(case["exact_match"] for case in results) / len(cases), 5) if cases else 0,
            "median_ms": round(statistics.median(timings), 4) if timings else 0,
            "p95_ms": round(ordered[max(0, int(len(ordered) * .95) - 1)], 4) if ordered else 0,
            "repeats": repeats, "results": results}


def markdown(report):
    rows = ["# Benchmark do corpus rotulado", "", report["scope"], "",
            f"- Unidade de avaliação: {report['unit']}.", f"- Casos: {report['case_count']}; controles sem falhas esperadas: {report['safe_cases']}.",
            f"- Precisão: {report['precision']:.1%}; recall: {report['recall']:.1%}.",
            f"- Falsos positivos: {report['false_positives']}; falsos negativos: {report['false_negatives']}.",
            f"- Latência mediana: {report['median_ms']} ms; p95: {report['p95_ms']} ms; repetições: {report['repeats']}.", "",
            "Os rótulos são explícitos em benchmarks/cases.json. Este conjunto não substitui uma avaliação externa nem mede a precisão do LLM.", "",
            "A avaliação inclui coverage_python.json, coverage_javascript.json e coverage_java.json. Ocorrências repetidas são contadas e linhas rotuladas são verificadas.", "",
            "| Linguagem | TP | FP | FN | Precisão | Recall |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for language, item in report["by_language"].items():
        rows.append(f"| {language} | {item['true_positives']} | {item['false_positives']} | {item['false_negatives']} | {item['precision']:.1%} | {item['recall']:.1%} |")
    rows += ["", f"Regras exercitadas: {report['rules_exercised']}/{report['rule_count']}. SHA-256 do corpus: `{report['corpus_sha256']}`.", "",
            "| Caso | Esperado | Detectado | Resultado |", "| --- | --- | --- | --- |"]
    for case in report["results"]:
        rows.append(f"| {case['id']} | {', '.join(case['expected']) or 'Nenhum'} | {', '.join(case['detected']) or 'Nenhum'} | {'OK' if case['exact_match'] else 'Divergente'} |")
    return "\n".join(rows) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="docs/benchmark-results.json")
    parser.add_argument("--markdown", default="docs/BENCHMARK.md")
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    report = evaluate(repeats=max(1, args.repeats))
    for path, content in ((Path(args.output), json.dumps(report, indent=2, ensure_ascii=False) + "\n"),
                          (Path(args.markdown), markdown(report))):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "results"}, ensure_ascii=False))
    return 0 if report["precision"] >= .95 and report["recall"] >= .95 and all(not case["errors"] for case in report["results"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
