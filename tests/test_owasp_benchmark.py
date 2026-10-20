import json
from pathlib import Path

import pytest

from scripts.owasp_benchmark import evaluate, main, read_labels


def dataset_fixture(tmp_path, rows, sources):
    root = tmp_path / "dataset"
    root.mkdir()
    labels = root / "expectedresults-1.2.csv"
    labels.write_text("# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1\n" + "\n".join(rows) + "\n", encoding="utf-8")
    code_dir = root / "src/main/java/org/owasp/benchmark/testcode"
    code_dir.mkdir(parents=True)
    for name, source in sources.items():
        (code_dir / f"{name}.java").write_text(source, encoding="utf-8")
    return root


def test_file_target_cwe_scoring_has_real_positive_and_negative_denominators(tmp_path):
    root = dataset_fixture(tmp_path, [
        "BenchmarkTest00001,sqli,true,89",
        "BenchmarkTest00002,sqli,false,89",
        "BenchmarkTest00003,sqli,false,89",
        "BenchmarkTest00004,sqli,true,89",
    ], {
        "BenchmarkTest00001": 'class Sample {void run(String id) {stmt.executeQuery("SELECT "+id); stmt.executeQuery("SELECT "+id);}}',
        "BenchmarkTest00002": 'class Sample {void run(String id) {var p=conn.prepareStatement("SELECT * FROM u WHERE id=?"); p.setString(1,id); p.executeQuery();}}',
        "BenchmarkTest00003": 'class Sample {void run(String id) {stmt.executeQuery("SELECT "+id);}}',
        "BenchmarkTest00004": 'class Sample {}',
    })
    report = evaluate(root)
    assert report["complete"] is True
    assert report["dataset_version"] == "1.2"
    assert report["case_count"] == 4
    assert report["by_cwe"]["CWE-89"] == {
        "true_positives": 1, "false_positives": 1, "false_negatives": 1, "true_negatives": 1,
        "precision": .5, "recall": .5, "false_positive_rate": .5,
    }
    # Two SQL findings in one positive file count as one labeled true positive.
    assert len(report["results"][0]["findings"]) == 2


def test_other_cwe_is_not_misrepresented_as_detection_of_target_cwe(tmp_path):
    root = dataset_fixture(tmp_path, ["BenchmarkTest00001,hash,true,328"], {
        "BenchmarkTest00001": 'class Sample {void run() {MessageDigest.getInstance("MD5");}}',
    })
    report = evaluate(root)
    assert report["true_positives"] == 0
    assert report["false_negatives"] == 1
    assert report["results"][0]["findings"][0]["cwe"] == "CWE-327"
    assert report["results"][0]["target_cwe"] == "CWE-328"


def test_missing_and_unparseable_files_are_explicit_failures_never_true_negatives(tmp_path):
    root = dataset_fixture(tmp_path, [
        "BenchmarkTest00001,sqli,true,89",
        "BenchmarkTest00002,sqli,false,89",
    ], {"BenchmarkTest00002": "class Broken { void run( {"})
    report = evaluate(root)
    assert report["complete"] is False
    assert report["analysis_failure_count"] == 2
    assert report["false_negatives"] == 1
    assert report["true_negatives"] == 0
    assert report["unresolved_negative_count"] == 1


@pytest.mark.parametrize("row", [
    "BenchmarkTest00001,sqli,maybe,89",
    "BenchmarkTest00001,sqli,true,not-a-cwe",
    "../Outside,sqli,true,89",
])
def test_invalid_reference_labels_are_rejected(tmp_path, row):
    path = tmp_path / "labels.csv"
    path.write_text(row, encoding="utf-8")
    with pytest.raises(ValueError):
        read_labels(path)


def test_duplicate_label_cannot_inflate_the_score(tmp_path):
    path = tmp_path / "labels.csv"
    path.write_text("BenchmarkTest00001,sqli,true,89\nBenchmarkTest00001,sqli,true,89\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicado"):
        read_labels(path)


def test_csv_and_source_fingerprints_make_changed_corpora_visible(tmp_path):
    root = dataset_fixture(tmp_path, ["BenchmarkTest00001,sqli,true,89"], {"BenchmarkTest00001": "class Sample {}"})
    before = evaluate(root)
    source = next(root.rglob("BenchmarkTest00001.java"))
    source.write_text('class Sample {void run(String input) {stmt.executeQuery(input);}}', encoding="utf-8")
    after = evaluate(root)
    assert before["labels_sha256"] == after["labels_sha256"]
    assert before["source_corpus_sha256"] != after["source_corpus_sha256"]
    assert before["scanner_sha256"] == after["scanner_sha256"]


def test_cli_writes_reviewable_json_and_markdown(tmp_path):
    root = dataset_fixture(tmp_path, ["BenchmarkTest00001,sqli,false,89"], {"BenchmarkTest00001": "class Sample {}"})
    output = tmp_path / "reports/measurement.json"
    assert main(["--dataset", str(root), "--output", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["true_negatives"] == 1
    assert "Limitações" in output.with_suffix(".md").read_text(encoding="utf-8")
