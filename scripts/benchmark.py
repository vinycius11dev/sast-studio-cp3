"""Mede precisão e recall no corpus rotulado do projeto, sem executar as amostras."""
import argparse
import json
import statistics
import time
from pathlib import Path

from engine.engine import SASTEngine

ROOT = Path(__file__).resolve().parents[1]


def evaluate(cases=None, repeats=5):
    cases = cases if cases is not None else json.loads((ROOT / "benchmarks/cases.json").read_text(encoding="utf-8"))
    engine = SASTEngine()
    results, timings = [], []
    tp = fp = fn = safe = safe_flagged = 0
    for case in cases:
        measured = []
        for _ in range(max(1, repeats)):
            start = time.perf_counter()
            result = engine.scan_code(case["code"], case["filename"])
            measured.append((time.perf_counter() - start) * 1000)
        timings.extend(measured)
        expected, detected = set(case["expected_rules"]), {finding.rule_id for finding in result.findings}
        tp += len(expected & detected)
        fp += len(detected - expected)
        fn += len(expected - detected)
        if not expected:
            safe += 1
            safe_flagged += bool(detected)
        results.append({"id": case["id"], "filename": case["filename"], "expected": sorted(expected),
                        "detected": sorted(detected), "errors": result.errors,
                        "exact_match": expected == detected and not result.has_errors,
                        "median_ms": round(statistics.median(measured), 4)})
    precision = tp / (tp + fp) if tp + fp else 1
    recall = tp / (tp + fn) if tp + fn else 1
    ordered = sorted(timings)
    return {"scope": "Corpus curado do projeto; métricas não representam todos os códigos ou vulnerabilidades do mercado.",
            "unit": "par (caso, regra)", "case_count": len(cases), "safe_cases": safe,
            "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": round(precision, 5), "recall": round(recall, 5),
            "safe_case_false_positive_rate": round(safe_flagged / safe, 5) if safe else None,
            "exact_case_accuracy": round(sum(case["exact_match"] for case in results) / len(cases), 5),
            "median_ms": round(statistics.median(timings), 4),
            "p95_ms": round(ordered[max(0, int(len(ordered) * .95) - 1)], 4),
            "repeats": repeats, "results": results}


def markdown(report):
    rows = ["# Benchmark do corpus rotulado", "", report["scope"], "",
            f"- Unidade de avaliação: {report['unit']}.", f"- Casos: {report['case_count']}; controles sem falhas esperadas: {report['safe_cases']}.",
            f"- Precisão: {report['precision']:.1%}; recall: {report['recall']:.1%}.",
            f"- Falsos positivos: {report['false_positives']}; falsos negativos: {report['false_negatives']}.",
            f"- Latência mediana: {report['median_ms']} ms; p95: {report['p95_ms']} ms; repetições: {report['repeats']}.", "",
            "Os rótulos são explícitos em benchmarks/cases.json. Este conjunto não substitui uma avaliação externa nem mede a precisão do LLM.", "",
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
