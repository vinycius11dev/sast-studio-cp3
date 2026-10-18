from api.store import _top_files


def test_top_files_aggregates_severity_and_returns_ranked_five():
    findings = [
        {"file_path": "a.py", "severity": "LOW"},
        {"file_path": "a.py", "severity": "LOW"},
        {"file_path": "a.py", "severity": "LOW"},
        {"file_path": "b.py", "severity": "MEDIUM"},
        {"file_path": "b.py", "severity": "MEDIUM"},
        {"file_path": "c.py", "severity": "CRITICAL"},
        {"file_path": "c.py", "severity": "CRITICAL"},
        {"file_path": "d.py", "severity": "HIGH"},
        {"file_path": "d.py", "severity": "HIGH"},
        {"file_path": "e.py", "severity": "LOW"},
        {"file_path": "e.py", "severity": "LOW"},
        {"file_path": "f.py", "severity": "INFO"},
        {"file_path": "f.py", "severity": "INFO"},
    ]

    result = _top_files(findings)

    assert len(result) == 5
    assert [item["path"] for item in result] == ["a.py", "c.py", "d.py", "b.py", "e.py"]
    assert result[0]["summary_by_severity"]["LOW"] == 3
    assert result[1]["summary_by_severity"]["CRITICAL"] == 2
    assert result[2]["summary_by_severity"]["HIGH"] == 2
    assert _top_files([]) == []
