from scripts.benchmark import evaluate


def test_curated_reference_corpus_has_no_regressions():
    report = evaluate(repeats=1)
    assert report["case_count"] >= 50
    assert report["safe_cases"] >= 20
    assert report["precision"] >= .95
    assert report["recall"] >= .95
    assert report["safe_case_false_positive_rate"] <= .05
    assert all(not case["errors"] for case in report["results"])


def test_benchmark_does_not_hide_missed_or_extra_findings():
    report = evaluate([
        {"id": "missed", "filename": "x.py", "code": "x = 1", "expected_rules": ["PY-R001"]},
        {"id": "extra", "filename": "x.py", "code": "eval(value)", "expected_rules": []},
    ], repeats=1)
    assert report["false_negatives"] == 1
    assert report["false_positives"] == 1
    assert report["precision"] == 0
    assert report["recall"] == 0
