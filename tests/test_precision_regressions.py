import json
from pathlib import Path

import pytest
from engine.engine import SASTEngine

CASES = json.loads((Path(__file__).resolve().parents[1] / "benchmarks/precision-regressions.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_precision_regression(case):
    result = SASTEngine().scan_code(case["code"], case["filename"])
    assert not result.errors
    assert {finding.rule_id for finding in result.findings} == set(case["expected_rules"])
    locations = [(f.rule_id, f.line_number, f.column_number) for f in result.findings]
    assert len(locations) == len(set(locations)), "Laços não devem duplicar o mesmo alerta"
