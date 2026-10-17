"""Fluxo real de API/fila/relatórios para validar a instalação local ou Docker."""
import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def run(base, require_llm=False):
    base = base.rstrip("/")

    def request(path, data=None, content_type="application/json", timeout=115):
        if data is not None and not isinstance(data, bytes):
            data = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(base + path, data=data, headers={"Content-Type": content_type})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            content = json.loads(raw) if "json" in response.headers.get("Content-Type", "") else raw
            return response.status, content

    deadline = time.monotonic() + 45
    while True:
        try:
            _, health = request("/health", timeout=3)
            break
        except (OSError, ValueError):
            if time.monotonic() > deadline:
                raise
            time.sleep(.5)
    _, queue = request("/api/v1/jobs/status")
    assert queue["active_workers"] >= 1, queue

    def finish(job):
        deadline = time.monotonic() + 30
        while job["status"] in {"queued", "running"} and time.monotonic() < deadline:
            time.sleep(.15)
            _, job = request("/api/v1/jobs/" + job["job_id"])
        assert job["status"] == "completed", job
        return request("/api/v1/scans/" + job["scan_id"])[1]

    code_cases = [("python-vulnerable", "demo.py", "eval(user_input)", 1, "blocked"),
                  ("python-corrected", "safe.py", "import json\njson.loads(user_input)", 0, "passed"),
                  ("javascript-ast", "safe.js", 'const example = "eval(input)"; /* eval(input); */', 0, "passed"),
                  ("typescript-ast", "demo.ts", 'const apiKey: string = "DEMO_NOT_REAL_1234";', 1, "blocked")]
    checks = []
    for name, filename, code, count, gate in code_cases:
        status, job = request("/api/v1/scan/code?queued=true", {"code": code, "filename": filename, "project_name": "Smoke - " + name})
        assert status == 202
        result = finish(job)
        assert result["total_findings"] == count and result["security_gate"]["status"] == gate, result
        checks.append({"case": name, "findings": count, "gate": gate, "job_id": job["job_id"], "scan_id": result["scan_id"]})

    boundary = "sast-smoke-" + uuid4().hex
    body = bytearray()
    for path in sorted((ROOT / "demonstracao/01-vulneravel").rglob("*")):
        if path.suffix not in {".py", ".js", ".java"}:
            continue
        relative = path.relative_to(ROOT / "demonstracao").as_posix()
        body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="{relative}"\r\nContent-Type: text/plain\r\n\r\n'.encode())
        body.extend(path.read_bytes())
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    status, job = request("/api/v1/scan/project?queued=true", bytes(body), "multipart/form-data; boundary=" + boundary)
    assert status == 202
    project = finish(job)
    assert project["scanned_files_count"] == 3 and project["total_findings"] == 9 and not project["errors"], project
    reports = {}
    for format in ("json", "sarif", "markdown"):
        status, report = request(f'/api/v1/scans/{project["scan_id"]}/report?format={format}')
        assert status == 200
        if format == "json":
            assert report["scan_id"] == project["scan_id"] and report["total_findings"] == 9
        elif format == "sarif":
            assert len(report["runs"][0]["results"]) == 9
        else:
            assert project["scan_id"] in report
        reports[format] = "ok"
    _, ai = request("/api/v1/ai/status")
    if require_llm:
        assert ai["model_available"], ai
    return {"base_url": base, "health": health, "active_workers": queue["active_workers"],
            "checks": checks, "project": {"files": 3, "findings": 9, "scan_id": project["scan_id"]},
            "reports": reports, "ollama_status": ai, "result": "passed"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--require-llm", action="store_true")
    parser.add_argument("--output", default=".playwright-mcp/smoke-result.json")
    args = parser.parse_args()
    report = run(args.base_url, args.require_llm)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
