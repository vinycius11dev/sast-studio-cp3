"""Independent scanner processes, normalized evidence, and conservative deduplication.

Only source files are written to a fresh workspace. Analyzed projects, their
configuration files, dependencies, and tests are never executed by these adapters.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import tempfile
import time

from engine.models import EngineRun, Finding, FindingEvidence, Severity

ROOT = Path(__file__).resolve().parents[1]
NATIVE_VERSION = "3.1.0"
RANK = {severity: index for index, severity in enumerate(Severity)}


def _anchor(finding: Finding, source: str):
    """Match the same AST operation, never just a CWE or a line number."""
    if finding.file_path.lower().endswith(".py"):
        try:
            tree = ast.parse(source)
            lines = source.splitlines()
            byte_col = len(lines[finding.line_number - 1][:finding.column_number].encode("utf-8"))
            kinds = (ast.Assign, ast.AnnAssign, ast.NamedExpr) if finding.cwe == "CWE-798" else (ast.Call,)
            nodes = [node for node in ast.walk(tree) if isinstance(node, kinds)
                     and (node.lineno, node.col_offset) <= (finding.line_number, byte_col)
                     < (node.end_lineno, node.end_col_offset)]
            if nodes:
                node = min(nodes, key=lambda n: (n.end_lineno - n.lineno, n.end_col_offset - n.col_offset))
                return (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
        except (SyntaxError, IndexError, ValueError):
            pass
    else:
        from engine.languages.syntax_tree import parse, walk
        ext = Path(finding.file_path).suffix.lower()
        dialect = "java" if ext == ".java" else "tsx" if ext == ".tsx" else "typescript" if ext == ".ts" else "javascript"
        try:
            root = parse(source, dialect).root_node
            lines = source.splitlines(keepends=True)
            offset = len("".join(lines[:finding.line_number - 1]).encode("utf-8"))
            offset += len(lines[finding.line_number - 1][:finding.column_number].encode("utf-8"))
            kinds = {"variable_declarator", "assignment_expression", "pair"} if finding.cwe == "CWE-798" else {
                "call_expression", "method_invocation", "new_expression", "object_creation_expression", "assignment_expression"}
            if finding.cwe in {"CWE-16", "CWE-295"}:
                kinds.add("pair")
            nodes = [node for node in walk(root) if node.type in kinds and node.start_byte <= offset < node.end_byte]
            if nodes:
                node = min(nodes, key=lambda n: n.end_byte - n.start_byte)
                return (node.start_point.row + 1, node.start_point.column, node.end_point.row + 1, node.end_point.column)
        except (IndexError, ValueError):
            pass
    return (finding.line_number, finding.column_number, re.sub(r"\s+", " ", finding.code_snippet).strip())


def normalize_findings(findings: list[Finding], sources: dict[str, str]) -> list[Finding]:
    merged = {}
    for original in findings:
        finding = original.model_copy(deep=True)
        finding.file_path = finding.file_path.replace("\\", "/")
        if not finding.evidence:
            finding.evidence = [FindingEvidence(engine=engine, rule_id=finding.rule_id, severity=finding.severity,
                message=finding.message, confidence=finding.confidence, line_number=finding.line_number,
                column_number=finding.column_number) for engine in finding.engines]
        # Keep native rules as separate signals for compatibility. Merge an
        # independent engine only when it identifies the very same AST operation.
        identity = (finding.file_path, finding.cwe, _anchor(finding, sources.get(finding.file_path, "")))
        finding.fingerprint = hashlib.sha256(repr(identity).encode("utf-8")).hexdigest()
        candidates = merged.setdefault(identity, [])
        match = next((item for item in candidates if (item.rule_id == finding.rule_id
                      and item.line_number == finding.line_number and item.column_number == finding.column_number) or
                      not set(item.engines).intersection(finding.engines)), None)
        if match is None:
            if candidates:
                finding.fingerprint = hashlib.sha256(repr((identity, finding.rule_id,
                    finding.line_number, finding.column_number)).encode("utf-8")).hexdigest()
            candidates.append(finding)
            continue
        match.engines = sorted(set(match.engines + finding.engines))
        evidence_ids = {(item.engine, item.rule_id, item.line_number, item.column_number) for item in match.evidence}
        match.evidence.extend(item for item in finding.evidence if
            (item.engine, item.rule_id, item.line_number, item.column_number) not in evidence_ids)
        if RANK[finding.severity] < RANK[match.severity]:
            match.severity = finding.severity
        if not match.data_flow and finding.data_flow:
            match.data_flow, match.analysis_scope = finding.data_flow, finding.analysis_scope
        match.limitations = list(dict.fromkeys(match.limitations + finding.limitations))
    return sorted((finding for group in merged.values() for finding in group),
                  key=lambda f: (f.file_path, f.line_number, f.column_number, f.rule_id))


def _stop_process(process):
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                       creationflags=subprocess.CREATE_NO_WINDOW, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=5)


class ExternalScanners:
    """Opt-in adapters. Missing requested engines make the analysis incomplete."""
    def __init__(self, engines=None, timeout=None, python=None):
        selected = engines if engines is not None else os.getenv("SAST_ENGINES", "native").split(",")
        self.engines = list(dict.fromkeys(str(item).strip().lower() for item in selected if str(item).strip()))
        unknown = set(self.engines) - {"native", "bandit", "semgrep"}
        if unknown:
            raise ValueError("Motores desconhecidos: " + ", ".join(sorted(unknown)))
        self.timeout = max(1, min(120, float(timeout or os.getenv("SAST_SCANNER_TIMEOUT", "40"))))
        local = ROOT / ".venv-scanners" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        self.python = str(python or os.getenv("SAST_SCANNER_PYTHON") or (local if local.exists() else "/opt/scanners/bin/python" if Path("/opt/scanners/bin/python").exists() else sys.executable))
        self.max_output = 16 * 1024 * 1024
        self._versions = {}

    def _environment(self, workspace):
        allowed = {"PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATHEXT", "LANG"}
        env = {key: value for key, value in os.environ.items() if key in allowed}
        home = workspace / "tool-home"
        home.mkdir(exist_ok=True)
        env.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home), LOCALAPPDATA=str(home),
                   PYTHONIOENCODING="utf-8", PYTHONUTF8="1", SEMGREP_SEND_METRICS="off",
                   SEMGREP_ENABLE_VERSION_CHECK="0", SEMGREP_SETTINGS_FILE=str(home / "settings.yml"))
        return env

    def _run(self, command, workspace, timeout=None):
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            options = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
            process = subprocess.Popen(command, cwd=workspace, env=self._environment(workspace),
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, shell=False, **options)
            deadline = time.monotonic() + (timeout or self.timeout)
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    _stop_process(process)
                    raise TimeoutError("Tempo limite do motor excedido.")
                if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > self.max_output:
                    _stop_process(process)
                    raise ValueError("Saída do motor excedeu 16 MiB; análise incompleta.")
                time.sleep(.05)
            stdout.seek(0); stderr.seek(0)
            out, err = stdout.read(self.max_output + 1), stderr.read(self.max_output + 1)
            if len(out) + len(err) > self.max_output:
                raise ValueError("Saída do motor excedeu 16 MiB; análise incompleta.")
            return process.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    def version(self, engine, workspace):
        if engine not in self._versions:
            code, output, _ = self._run([self.python, "-c",
                "from importlib.metadata import version; print(version(" + repr(engine) + "))"], workspace, timeout=8)
            self._versions[engine] = output.strip()[:80] if code == 0 else None
        return self._versions[engine]

    def status(self):
        output = [{"engine": "native", "enabled": True, "available": True, "version": NATIVE_VERSION}]
        with tempfile.TemporaryDirectory(prefix="sast-status-") as folder:
            for engine in ("bandit", "semgrep"):
                try:
                    version = self.version(engine, Path(folder))
                except (OSError, ValueError, TimeoutError):
                    version = None
                output.append({"engine": engine, "enabled": engine in self.engines,
                    "available": bool(version), "version": version})
        return output

    @staticmethod
    def _write_sources(sources, root):
        for path, source in sources.items():
            relative = PurePosixPath(path.replace("\\", "/"))
            if relative.is_absolute() or not relative.parts or any(part in {"..", "."} or ":" in part for part in relative.parts):
                raise ValueError("Caminho de código inválido para o workspace de análise.")
            target = root.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")

    def scan(self, sources):
        findings, runs, errors = [], [], []
        requested = [engine for engine in self.engines if engine != "native"]
        if not requested:
            return findings, runs, errors
        with tempfile.TemporaryDirectory(prefix="sast-engines-") as folder:
            workspace, code_root = Path(folder), Path(folder) / "source"
            code_root.mkdir()
            self._write_sources(sources, code_root)
            for engine in requested:
                started = time.perf_counter()
                run = EngineRun(engine=engine, status="completed")
                relevant = {p: code for p, code in sources.items() if engine != "bandit" or p.lower().endswith(".py")}
                run.files_count = len(relevant)
                if not relevant:
                    run.status = "skipped"
                    runs.append(run)
                    continue
                try:
                    run.version = self.version(engine, workspace)
                    if not run.version:
                        run.status = "unavailable"
                        raise ValueError("Motor solicitado não está instalado no ambiente de scanners.")
                    if engine == "bandit":
                        command = [self.python, "-m", "bandit", "-r", str(code_root), "-f", "json", "-q", "--ignore-nosec"]
                    else:
                        executable = Path(self.python).parent / ("semgrep.exe" if os.name == "nt" else "semgrep")
                        command = [str(executable), "scan", "--config", str(ROOT / "config/semgrep-security.yml"),
                            "--json", "--quiet", "--metrics=off", "--disable-version-check", "--disable-nosem",
                            "--no-git-ignore", "--timeout", "8", "--max-memory", "512", "--jobs", "2", str(code_root)]
                    code, output, _ = self._run(command, workspace)
                    if code not in {0, 1}:
                        raise ValueError(f"O motor terminou com código {code}; análise incompleta.")
                    data = json.loads(output)
                    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                        raise ValueError("Saída JSON do motor fora do contrato esperado.")
                    result_findings = self._bandit(data, code_root, sources) if engine == "bandit" else self._semgrep(data, code_root, sources)
                    findings.extend(result_findings)
                    run.findings_count = len(result_findings)
                    if data.get("errors"):
                        raise ValueError(f"O motor reportou {len(data['errors'])} erro(s) de análise; resultados parciais preservados.")
                except TimeoutError as error:
                    run.status, run.errors = "timeout", [str(error)]
                except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, subprocess.SubprocessError) as error:
                    if run.status != "unavailable":
                        run.status = "error"
                    run.errors = [str(error)[:300]]
                run.duration_ms = round((time.perf_counter() - started) * 1000, 2)
                errors.extend(f"{engine}: {error}" for error in run.errors)
                runs.append(run)
        return findings, runs, errors

    @staticmethod
    def _source_path(path, root, sources):
        path = Path(path)
        candidate = path if path.is_absolute() else root.parent / path
        try:
            relative = candidate.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            # Some tool versions emit paths relative to their scan root.
            relative = path.as_posix()
        if relative not in sources:
            raise ValueError("O motor retornou um caminho fora dos arquivos analisados.")
        return relative

    def _bandit(self, data, root, sources):
        output = []
        for item in data["results"]:
            path = self._source_path(item["filename"], root, sources)
            line = int(item["line_number"])
            source_lines = sources[path].splitlines()
            byte_column = int(item.get("col_offset", 0))
            column = len(source_lines[line - 1].encode("utf-8")[:byte_column].decode("utf-8", "replace"))
            cwe = item.get("issue_cwe", {}).get("id", 0)
            output.append(Finding(rule_id="BANDIT-" + item["test_id"], rule_name=item["test_name"],
                severity=Severity(item["issue_severity"]), cwe=f"CWE-{cwe}", message=item["issue_text"],
                file_path=path, line_number=line, column_number=column,
                code_snippet="\n".join(sources[path].splitlines()[line - 1:max(line, int(item.get("end_line_number") or line))]),
                remediation_advice="Revise a evidência do Bandit e aplique a API segura específica para esta CWE.",
                engines=["bandit"], confidence=str(item.get("issue_confidence", "MEDIUM")).lower(), analysis_scope="external",
                limitations=["Padrão reportado pelo Bandit; explorabilidade e comportamento da correção requerem revisão."]))
        return output

    def _semgrep(self, data, root, sources):
        output = []
        for item in data["results"]:
            path = self._source_path(item["path"], root, sources)
            extra, start, end = item["extra"], item["start"], item["end"]
            meta = extra.get("metadata", {})
            rule_id = item["check_id"].rsplit(".", 1)[-1]
            output.append(Finding(rule_id="SEMGREP-" + rule_id, rule_name=meta.get("title", rule_id),
                severity=Severity(meta.get("severity", {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(extra.get("severity"), "MEDIUM"))),
                cwe=meta.get("cwe", "CWE-0"), message=extra["message"], file_path=path,
                line_number=int(start["line"]), column_number=max(0, int(start["col"]) - 1),
                code_snippet="\n".join(sources[path].splitlines()[int(start["line"]) - 1:int(end["line"])]),
                remediation_advice=meta.get("remediation", "Revise o fluxo e use a API segura específica para esta CWE."),
                engines=["semgrep"], confidence="medium", analysis_scope="external",
                limitations=["Semgrep CE com regras locais versionadas; análise entre arquivos não habilitada."]))
        return output
