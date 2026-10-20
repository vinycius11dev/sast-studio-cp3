"""Verifica a API real, a fila, as regras, os relatórios e, opcionalmente, a IA local."""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
SUPPORTED = {".py", ".js", ".java"}


def discover_base_url(state_file=None):
    """Use the active SAST server even when the supervisor chose a fallback port."""
    from iniciar import find_current_server

    port = find_current_server()
    if port:
        return f"http://127.0.0.1:{port}"

    state_path = Path(state_file) if state_file else ROOT / "data" / "runtime" / "state.json"
    try:
        saved_port = json.loads(state_path.read_text(encoding="utf-8")).get("port")
    except (OSError, ValueError, AttributeError):
        saved_port = None
    if isinstance(saved_port, int) and not isinstance(saved_port, bool) and 1 <= saved_port <= 65535:
        return f"http://127.0.0.1:{saved_port}"
    return "http://127.0.0.1:8000"


def run(base, require_llm=False):
    base = base.rstrip("/")

    def request(path, data=None, content_type="application/json", timeout=115):
        if data is not None and not isinstance(data, bytes):
            data = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(base + path, data=data, headers={"Content-Type": content_type})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                raw = response.read().decode("utf-8")
                content = json.loads(raw) if "json" in response.headers.get("Content-Type", "") else raw
                return response.status, content
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"{path} respondeu HTTP {error.code}: {detail}") from error

    deadline = time.monotonic() + 45
    while True:
        try:
            _, health = request("/health", timeout=3)
            break
        except (OSError, ValueError) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"API não respondeu em {base}. Inicie o SAST com iniciar.bat e tente novamente. ({error})"
                ) from error
            time.sleep(.5)
    if not isinstance(health, dict) or health.get("service") != "sast-engine-api":
        raise RuntimeError(f"{base} respondeu, mas não parece ser a API do SAST: {health}")

    queue_deadline = time.monotonic() + 15
    _, queue = request("/api/v1/jobs/status")
    while queue.get("active_workers", 0) < 1 and time.monotonic() < queue_deadline:
        time.sleep(.5)
        _, queue = request("/api/v1/jobs/status")
    assert queue["active_workers"] >= 1, f"Nenhum worker ativo: {queue}"

    def finish(job):
        deadline = time.monotonic() + 90
        while job["status"] in {"queued", "running"} and time.monotonic() < deadline:
            time.sleep(.2)
            _, job = request("/api/v1/jobs/" + job["job_id"])
        assert job["status"] == "completed", f"Job não concluiu: {job}"
        return request("/api/v1/scans/" + job["scan_id"])[1]

    checks = []
    ai_scan = None
    code_cases = [
        ("python-vulnerable", "demo.py", "eval(user_input)", 1, "blocked"),
        ("python-corrected", "safe.py", "import json\njson.loads(user_input)", 0, "passed"),
        ("javascript-ast", "safe.js", 'const example = "eval(input)"; /* eval(input); */', 0, "passed"),
        ("typescript-ast", "demo.ts", 'const apiKey: string = "DEMO_NOT_REAL_1234";', 1, "blocked"),
    ]
    for name, filename, code, count, gate in code_cases:
        status, job = request("/api/v1/scan/code?queued=true", {
            "code": code, "filename": filename, "project_name": "Smoke - " + name,
        })
        assert status == 202, f"A fila deveria aceitar {name}; recebeu HTTP {status}."
        result = finish(job)
        assert result["total_findings"] >= count and result["security_gate"]["status"] == gate, result
        checks.append({"case": name, "findings": count, "gate": gate, "job_id": job["job_id"], "scan_id": result["scan_id"]})
        if name == "python-vulnerable":
            ai_scan = result

    def scan_demo_project(folder_name, expected_findings, expected_gate):
        folder = ROOT / "demonstracao" / folder_name
        files = sorted(path for path in folder.rglob("*") if path.is_file() and path.suffix.lower() in SUPPORTED)
        assert files, f"A pasta de demonstração está vazia ou ausente: {folder}"

        boundary = "sast-smoke-" + uuid4().hex
        body = bytearray()
        for name, value in (("project_name", f"Smoke · {folder_name}"), ("gate_threshold", "HIGH")):
            body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode())
        for path in files:
            relative = path.relative_to(folder).as_posix()
            body.extend(
                f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="{relative}"\r\n'
                "Content-Type: text/plain; charset=utf-8\r\n\r\n".encode()
            )
            body.extend(path.read_bytes())
            body.extend(b"\r\n")
        body.extend(f"--{boundary}--\r\n".encode())

        status, job = request(
            "/api/v1/scan/project?queued=true", bytes(body),
            "multipart/form-data; boundary=" + boundary,
        )
        assert status == 202, f"A fila deveria aceitar {folder_name}; recebeu HTTP {status}."
        result = finish(job)
        assert result["scanned_files_count"] == len(files), result
        if expected_gate == "blocked":
            assert result["total_findings"] >= expected_findings, result
        else:
            native_runs = [run for run in result["engine_runs"] if run["engine"] == "native"]
            assert native_runs and native_runs[0]["findings_count"] == expected_findings, result
            assert result["security_gate"]["blocking_findings"] == 0, result
        assert result["security_gate"]["status"] == expected_gate, result
        assert not result["errors"], result
        return {
            "case": folder_name,
            "files": len(files),
            "findings": result["total_findings"],
            "gate": result["security_gate"]["status"],
            "scan_id": result["scan_id"],
        }, result

    vulnerable, vulnerable_scan = scan_demo_project("01-vulneravel", 22, "blocked")
    corrected, _ = scan_demo_project("02-corrigido", 0, "passed")
    checks.extend((vulnerable, corrected))

    reports = {}
    for output_format in ("json", "sarif", "markdown"):
        status, report = request(f'/api/v1/scans/{vulnerable["scan_id"]}/report?format={output_format}')
        assert status == 200, f"Exportação {output_format} respondeu HTTP {status}."
        if output_format == "json":
            assert report["scan_id"] == vulnerable["scan_id"] and report["total_findings"] == vulnerable_scan["total_findings"]
        elif output_format == "sarif":
            assert len(report["runs"][0]["results"]) == vulnerable_scan["total_findings"]
        else:
            assert vulnerable["scan_id"] in report
        reports[output_format] = "ok"

    _, ai_status = request("/api/v1/ai/status")
    ai = {"status": ai_status, "inference_checked": False}
    if require_llm:
        if not ai_status["model_available"]:
            model_name = ai_status.get("model") or "llama3.2:3b"
            raise RuntimeError(
                f"Ollama/modelo indisponível ({ai_status}). Abra o Ollama e execute `ollama pull {model_name}`."
            )
        if not ai_scan or not ai_scan["findings"]:
            raise RuntimeError("O exemplo vulnerável não gerou um achado para validar a IA.")

        finding = ai_scan["findings"][0]
        payload = {**finding, "scan_id": ai_scan["scan_id"]}
        triage_started = time.monotonic()
        _, review = request("/api/v1/triage", payload, timeout=115)
        triage_seconds = round(time.monotonic() - triage_started, 2)
        if review.get("provider") != "ollama" or not review.get("review_id"):
            raise RuntimeError(
                "A triagem não comprovou uma inferência Ollama. "
                f"Provedor: {review.get('provider')}; motivo: {review.get('fallback_reason') or 'sem detalhe'}."
            )

        remediation_started = time.monotonic()
        _, remediation = request("/api/v1/remediate", payload, timeout=115)
        remediation_seconds = round(time.monotonic() - remediation_started, 2)
        if remediation.get("provider") != "ollama" or not remediation.get("suggested_patch") or not remediation.get("diff"):
            raise RuntimeError(
                "A remediação não comprovou uma inferência Ollama. "
                f"Provedor: {remediation.get('provider')}; motivo: {remediation.get('fallback_reason') or 'sem detalhe'}."
            )
        _, ai_status_after = request("/api/v1/ai/status")
        ai = {
            "status": ai_status_after,
            "status_before_inference": ai_status,
            "inference_checked": True,
            "triage": {"provider": review["provider"], "model": review["model_used"],
                       "classification": review["classification"], "review_id": review["review_id"],
                       "seconds": triage_seconds},
            "remediation": {"provider": remediation["provider"], "model": remediation["model_used"],
                            "patch_scope": remediation.get("patch_scope"), "diff_available": True,
                            "seconds": remediation_seconds},
        }

    return {
        "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "base_url": base,
        "health": health,
        "active_workers": queue["active_workers"],
        "checks": checks,
        "reports": reports,
        "ai": ai,
        "result": "passed",
    }


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Valida o SAST pela API real e, com --require-llm, faz inferências Ollama de triagem e remediação."
    )
    parser.add_argument("--base-url", help="URL da API; por padrão, detecta a instância atual do iniciador")
    parser.add_argument("--require-llm", action="store_true", help="Exige e testa triagem e remediação com o modelo Ollama.")
    parser.add_argument("--output", default="reports/smoke-result.json", help="Arquivo JSON com o resultado da verificação.")
    args = parser.parse_args()

    try:
        report = run(args.base_url or discover_base_url(), args.require_llm)
    except (AssertionError, OSError, ValueError, RuntimeError) as error:
        print(f"SMOKE FALHOU: {error}", file=sys.stderr)
        return 1

    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("SAST smoke: APROVADO")
    print(f"API: {report['base_url']} | workers ativos: {report['active_workers']}")
    for item in report["checks"]:
        suffix = f" | {item['files']} arquivos" if "files" in item else ""
        print(f"- {item['case']}: {item['findings']} achado(s), gate {item['gate']}{suffix}")
    print(f"- Relatórios: {', '.join(report['reports'])}")
    if report["ai"]["inference_checked"]:
        triage_seconds = report["ai"]["triage"]["seconds"]
        remediation_seconds = report["ai"]["remediation"]["seconds"]
        print(
            f"- IA real: triagem {triage_seconds}s e remediação {remediation_seconds}s "
            f"via {report['ai']['triage']['model']}"
        )
    elif args.require_llm:
        print("- IA real: verificada")
    else:
        status = report["ai"]["status"]
        print(f"- Ollama: {'disponível' if status['model_available'] else 'indisponível'} (inferência não executada)")
    print(f"Resultado detalhado: {target.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
