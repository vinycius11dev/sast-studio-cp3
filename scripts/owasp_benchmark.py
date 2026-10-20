"""Score the native Java scanner against an unchanged OWASP BenchmarkJava CSV.

Only source files and the published labels are read. The benchmark application,
its build, helper scripts, and analyzed source are never executed or imported.
Scoring is binary per labeled test file and exact target CWE, not finding count.
"""
import argparse
from collections import defaultdict
import csv
from datetime import datetime, timezone
import hashlib
from importlib.metadata import PackageNotFoundError, version
import io
import json
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time

from engine.languages.java_scanner import JavaScanner


ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_REPOSITORY = "https://github.com/OWASP-Benchmark/BenchmarkJava"


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _metrics(tp=0, fp=0, fn=0, tn=0):
    return {
        "true_positives": tp, "false_positives": fp, "false_negatives": fn, "true_negatives": tn,
        "precision": round(tp / (tp + fp), 6) if tp + fp else None,
        "recall": round(tp / (tp + fn), 6) if tp + fn else None,
        "false_positive_rate": round(fp / (fp + tn), 6) if fp + tn else None,
    }


def read_labels(path):
    contents = path.read_text(encoding="utf-8-sig")
    rows, seen = [], set()
    benchmark_version = None
    for raw in csv.reader(io.StringIO(contents)):
        if not raw or not raw[0].strip():
            continue
        if raw[0].lstrip().startswith("#"):
            match = re.search(r"Benchmark version:\s*([^,]+)", ",".join(raw), re.I)
            if match:
                benchmark_version = match.group(1).strip()
            continue
        if len(raw) < 4 or not re.fullmatch(r"BenchmarkTest\d+", raw[0].strip()):
            raise ValueError(f"Linha inválida no CSV de referência: {raw!r}")
        test_name, category, label, cwe = (item.strip() for item in raw[:4])
        if label.lower() not in {"true", "false"} or not cwe.isdigit():
            raise ValueError(f"Rótulo/CWE inválido em {test_name}")
        identity = (test_name, int(cwe))
        if identity in seen:
            raise ValueError(f"Rótulo duplicado: {test_name}, CWE-{cwe}")
        seen.add(identity)
        rows.append({"test_name": test_name, "category": category, "expected_vulnerable": label.lower() == "true", "target_cwe": f"CWE-{int(cwe)}"})
    if not rows:
        raise ValueError("O CSV não possui casos rotulados.")
    return rows, benchmark_version


def _commit(dataset):
    # rev-parse is read-only and invokes no benchmark scripts or build commands.
    try:
        result = subprocess.run(["git", "-C", str(dataset), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=10, check=False)
        value = result.stdout.strip()
        return value if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", value) else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _scanner_fingerprint():
    digest = hashlib.sha256()
    for relative in ("engine/languages/java_scanner.py", "engine/languages/java_flow.py",
                     "engine/languages/syntax_tree.py", "engine/languages/base.py", "engine/models.py"):
        path = ROOT / relative
        if path.is_file():
            digest.update(relative.encode("utf-8"))
            digest.update(path.read_bytes())
    return digest.hexdigest()


def evaluate(dataset, csv_path=None, progress=False):
    dataset = Path(dataset).resolve()
    if not dataset.is_dir():
        raise ValueError(f"Dataset inexistente: {dataset}")
    if csv_path is None:
        candidates = sorted(dataset.glob("expectedresults-*.csv"))
        if len(candidates) != 1:
            raise ValueError("Informe --labels quando não houver exatamente um expectedresults-*.csv.")
        csv_path = candidates[0]
    else:
        csv_path = Path(csv_path).resolve()
    labels, benchmark_version = read_labels(csv_path)
    index = {}
    for path in dataset.rglob("BenchmarkTest*.java"):
        if not path.is_file() or not path.resolve().is_relative_to(dataset):
            continue
        if path.stem in index:
            raise ValueError(f"Arquivo de teste ambíguo: {path.stem}")
        index[path.stem] = path

    scanner = JavaScanner()
    totals = [0, 0, 0, 0]
    per_cwe = defaultdict(lambda: [0, 0, 0, 0])
    timings, results, failures = [], [], []
    source_digest = hashlib.sha256()
    start_all = time.perf_counter()
    for number, label in enumerate(labels, 1):
        path = index.get(label["test_name"])
        errors, findings = [], []
        started = time.perf_counter()
        if path is None:
            errors = ["Arquivo rotulado ausente no dataset."]
        else:
            try:
                contents = path.read_bytes()
                source_digest.update(path.relative_to(dataset).as_posix().encode("utf-8"))
                source_digest.update(contents)
                findings, errors = scanner.scan_source(contents.decode("utf-8-sig"), path.relative_to(dataset).as_posix())
            except Exception as error:
                errors = [f"{type(error).__name__}: {error}"]
        elapsed = (time.perf_counter() - started) * 1000
        timings.append(elapsed)
        detected = any(finding.cwe == label["target_cwe"] for finding in findings)
        if label["expected_vulnerable"]:
            outcome = "true_positive" if detected and not errors else "false_negative"
            metric_index = 0 if outcome == "true_positive" else 2
        elif errors:
            # A parser failure is never evidence of a true negative. Positive
            # failures above are conservative misses; negative failures remain
            # explicitly unresolved and outside the valid negative denominator.
            outcome, metric_index = "unresolved_negative", None
        else:
            outcome = "false_positive" if detected else "true_negative"
            metric_index = 1 if detected else 3
        if metric_index is not None:
            totals[metric_index] += 1
            per_cwe[label["target_cwe"]][metric_index] += 1
        if errors:
            failures.append({"test_name": label["test_name"], "errors": errors})
        results.append({**label, "detected_target_cwe": detected, "outcome": outcome,
                        "findings": [{"rule_id": finding.rule_id, "cwe": finding.cwe, "line_number": finding.line_number} for finding in findings],
                        "errors": errors, "duration_ms": round(elapsed, 4)})
        if progress and number % 250 == 0:
            print(f"OWASP Java: {number}/{len(labels)} arquivos rotulados analisados", file=sys.stderr, flush=True)

    timings.sort()
    packages = {}
    for package in ("tree-sitter", "tree-sitter-java", "pydantic"):
        try:
            packages[package] = version(package)
        except PackageNotFoundError:
            packages[package] = None
    return {
        "scope": "Todos os casos rotulados presentes no CSV OWASP BenchmarkJava; motor Java nativo, análise estática sem executar a aplicação.",
        "scoring_unit": "arquivo de teste e CWE alvo, correspondência exata de CWE; múltiplos achados da mesma CWE contam uma vez",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "engine": "native", "language": "java", "dataset_repository": OFFICIAL_REPOSITORY,
        "dataset_commit": _commit(dataset), "dataset_version": benchmark_version,
        "labels_filename": csv_path.name, "labels_sha256": _sha256(csv_path.read_bytes()),
        "source_corpus_sha256": source_digest.hexdigest(), "scanner_sha256": _scanner_fingerprint(),
        "runtime": {"python": sys.version.split()[0], "packages": packages},
        "case_count": len(labels), "positive_cases": sum(item["expected_vulnerable"] for item in labels),
        "negative_cases": sum(not item["expected_vulnerable"] for item in labels),
        "complete": not failures, "analysis_failure_count": len(failures),
        "unresolved_negative_count": sum(item["outcome"] == "unresolved_negative" for item in results),
        **_metrics(*totals), "by_cwe": {cwe: _metrics(*values) for cwe, values in sorted(per_cwe.items())},
        "duration_seconds": round(time.perf_counter() - start_all, 4),
        "median_ms": round(statistics.median(timings), 4),
        "p95_ms": round(timings[max(0, int(len(timings) * .95) - 1)], 4),
        "limitations": [
            "Não é uma certificação nem o scorecard oficial OWASP. As métricas não medem o Ollama ou a qualidade dos patches.",
            "O motor Java usa análise lexical local, sem resolução interprocedural/interarquivo nem compilação ou typecheck Java.",
            "CWEs são comparadas exatamente. Hash rotulado CWE-328 não recebe crédito por um alerta CWE-327; Random CWE-330 não recebe crédito por CWE-338.",
            "Achados de outras CWEs são preservados no resultado, mas não pontuados como falso positivo de um rótulo diferente.",
            "Falha de análise positiva conta como FN; falha negativa fica inconclusiva e nunca como TN. complete deve ser conferido junto às métricas.",
        ],
        "failures": failures, "results": results,
    }


def markdown(report):
    def percent(value):
        return f"{value:.1%}" if value is not None else "não definido"
    lines = ["# Medição externa — OWASP BenchmarkJava", "", report["scope"], "",
             f"Origem: [{report['dataset_repository']}]({report['dataset_repository']}). Versão `{report['dataset_version']}`, commit `{report['dataset_commit']}`.",
             f"Unidade: {report['scoring_unit']}.", "",
             f"Casos: {report['case_count']} ({report['positive_cases']} positivos e {report['negative_cases']} negativos). Falhas de análise: {report['analysis_failure_count']}.",
             f"Precisão: {percent(report['precision'])}; recall: {percent(report['recall'])}; FPR: {percent(report['false_positive_rate'])}.", "",
             "| CWE | TP | FP | FN | TN | Precisão | Recall | FPR |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for cwe, row in report["by_cwe"].items():
        lines.append(f"| {cwe} | {row['true_positives']} | {row['false_positives']} | {row['false_negatives']} | {row['true_negatives']} | {percent(row['precision'])} | {percent(row['recall'])} | {percent(row['false_positive_rate'])} |")
    lines += ["", "Limitações:", "", *[f"- {item}" for item in report["limitations"]], "",
              "Reprodução (o dataset é obtido separadamente e seu código não é executado):", "", "```powershell",
              "git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git tmp/OWASP-BenchmarkJava",
              f"git -C tmp/OWASP-BenchmarkJava checkout {report['dataset_commit']}",
              "python -m scripts.owasp_benchmark --dataset tmp/OWASP-BenchmarkJava --output docs/quality/owasp-native-results.json", "```", "",
              f"SHA-256 dos rótulos: `{report['labels_sha256']}`.",
              f"SHA-256 das fontes: `{report['source_corpus_sha256']}`.",
              f"SHA-256 do scanner: `{report['scanner_sha256']}`.", ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--labels", type=Path, help="CSV expectedresults; autodetectado se houver exatamente um.")
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args(argv)
    report = evaluate(arguments.dataset, arguments.labels, progress=True)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    arguments.output.with_suffix(".md").write_text(markdown(report), encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("case_count", "dataset_commit", "complete", "true_positives", "false_positives", "false_negatives", "true_negatives", "precision", "recall", "false_positive_rate", "analysis_failure_count")}, indent=2))
    return 0 if report["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
