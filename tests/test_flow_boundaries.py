import ast

import pytest
from engine.engine import SASTEngine
from engine.rules.taint_rule import TaintAnalysisRule


@pytest.mark.parametrize("code,expected", [
    ("path = input()\ntry:\n risky()\n path = 'safe'\nfinally:\n open(path)", {"PY-T002"}),
    ("path = input()\ntry:\n risky()\n path = 'safe'\nexcept OSError:\n path = 'safe'\nopen(path)", set()),
    ("a, b = input(), 'safe'\na, b = b, a\nopen(b)", {"PY-T002"}),
    ("a, b = input(), 'safe'\na, b = b, a\nopen(a)", set()),
    ("path = input()\ndef clean(path):\n open(path)\nopen(path)", {"PY-T002"}),
    ("def dirty():\n path = input()\nopen(path)", set()),
    ("import requests as rq\ndef dirty():\n rq.get(input())", {"PY-R004", "PY-T003"}),
    ("from flask import request as req\nopen(req.args['path'])", {"PY-T002"}),
    ("value = input()\nif flag:\n query = value\nelse:\n query = 'safe'\ndb.execute(query)", {"PY-T001"}),
    ("int = custom\ndb.execute(int(input()))", {"PY-T001"}),
    ("from httpx import request as send\nsend(method='GET', url=input())", {"PY-R004", "PY-T003"}),
    ("open('request.args.get(hello)')", set()),
])
def test_flow_boundary(code, expected):
    result = SASTEngine().scan_code(code, "boundary.py")
    assert not result.errors
    assert {finding.rule_id for finding in result.findings} == expected


@pytest.mark.parametrize("code,filename", [
    ("const url = 'fixed'; const load = url => fetch(url);", "demo.js"),
    ("const url = 'fixed'; const load = ({url}) => fetch(url);", "demo.js"),
    ("const url = 'fixed'; const load = (url: string) => fetch(url);", "demo.ts"),
])
def test_arrow_parameter_shadows_global(code, filename):
    result = SASTEngine().scan_code(code, filename)
    assert not result.errors
    assert {finding.rule_id for finding in result.findings} == {"JS-R006"}


def test_rule_instance_does_not_leak_state_between_files():
    rule = TaintAnalysisRule()
    code = "path = input()\nopen(path)"
    assert len(rule.scan(ast.parse(code), "first.py", code)) == 1
    assert rule.scan(ast.parse("open(path)"), "second.py", "open(path)") == []
