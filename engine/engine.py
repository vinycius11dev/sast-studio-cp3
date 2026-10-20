import os
import time
from typing import List, Type, Dict, Tuple
from engine.models import Finding, ScanResult, RuleMetadata, Severity, ScannedFile, EngineRun
from engine.orchestration import ExternalScanners, NATIVE_VERSION, normalize_findings
from engine.rules import BaseRule, DEFAULT_RULES
from engine.languages import (
    LanguageScanner,
    PythonScanner,
    JavaScriptScanner,
    JavaScanner,
    SUPPORTED_EXTENSIONS,
)

IGNORE_DIRS = {
    ".git",
    "__pycache__",
    "venv",
    ".venv",
    ".venv-scanners",
    "tmp",
    "graphify-out",
    "env",
    ".env",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".idea",
    ".vscode",
    "target",
    "bin",
}


class SASTEngine:
    """Motor central de análise estática de segurança (SAST) Multi-Linguagem (Python, JavaScript, Java)."""

    def __init__(self, rule_classes: List[Type[BaseRule]] = None, engines=None, external_scanners=None):
        self.rule_classes = rule_classes or list(DEFAULT_RULES)
        self.python_scanner = PythonScanner(rule_classes=self.rule_classes)
        self.js_scanner = JavaScriptScanner()
        self.java_scanner = JavaScanner()
        self.external_scanners = external_scanners or ExternalScanners(engines=engines)

        self.scanners_by_lang: Dict[str, LanguageScanner] = {
            "python": self.python_scanner,
            "javascript": self.js_scanner,
            "java": self.java_scanner,
        }

    def list_rules(self) -> List[RuleMetadata]:
        """Lista os metadados de todas as regras cadastradas no motor multi-linguagem."""
        all_rules: List[RuleMetadata] = []
        for scanner in self.scanners_by_lang.values():
            all_rules.extend(scanner.list_rules())
        return all_rules

    def _resolve_scanner(self, file_path: str, source_code: str = "") -> LanguageScanner:
        """Determina o scanner apropriado com base na extensão ou heurística de código."""
        _, ext = os.path.splitext(file_path.lower())
        if ext in SUPPORTED_EXTENSIONS:
            lang = SUPPORTED_EXTENSIONS[ext]
            return self.scanners_by_lang[lang]

        # Heurística para snippets sem extensão
        code_low = source_code.lower()
        if "public class " in source_code or "system.out." in code_low or "package " in source_code:
            return self.java_scanner
        if "const " in source_code or "let " in source_code or "function " in source_code or "console.log" in code_low:
            return self.js_scanner

        # Padrão: Python
        return self.python_scanner

    def _build_summary(self, findings: List[Finding]) -> Dict[str, int]:
        """Agrupa contagem de achados por severidade."""
        summary = {sev.value: 0 for sev in Severity}
        for f in findings:
            summary[f.severity.value] = summary.get(f.severity.value, 0) + 1
        return summary

    def scan_code(self, source_code: str, identifier: str = "<snippet>") -> ScanResult:
        """Executa varredura SAST sobre um snippet de código em memória identificando a linguagem."""
        return self.scan_sources({identifier: source_code}, target=identifier)

    def scan_sources(self, sources: Dict[str, str], target="project") -> ScanResult:
        """Analyze the whole upload once per engine; preserve partial results on failure."""
        started = time.perf_counter()
        sources = {str(path).replace("\\", "/"): source for path, source in sources.items()}
        findings, errors, files = [], [], []
        external_sources, path_map = {}, {}
        for index, (path, source) in enumerate(sorted(sources.items())):
            scanner = self._resolve_scanner(path, source)
            try:
                items, failures = scanner.scan_source(source, path)
            except Exception as error:
                items, failures = [], [f"Motor nativo falhou em {path}: {type(error).__name__}. Análise incompleta."]
            findings.extend(items)
            errors.extend(failures)
            files.append(ScannedFile(path=path, language=next(key for key, value in self.scanners_by_lang.items() if value is scanner),
                size_bytes=len(source.encode("utf-8")), findings_count=len(items), status="error" if failures else "completed"))
            # CLI absolute paths never become filesystem paths inside the subprocess workspace.
            extension = os.path.splitext(path)[1] or {"python": ".py", "javascript": ".js", "java": ".java"}[files[-1].language]
            virtual = f"file-{index}{extension}" if os.path.isabs(path) or path.startswith("<") else path
            if not failures:
                external_sources[virtual], path_map[virtual] = source, path
        native = EngineRun(engine="native", status="error" if errors else "completed", version=NATIVE_VERSION,
            duration_ms=round((time.perf_counter() - started) * 1000, 2), findings_count=len(findings),
            files_count=sum(item.status == "completed" for item in files), errors=list(errors))
        extra, engine_runs, engine_errors = self.external_scanners.scan(external_sources)
        for finding in extra:
            finding.file_path = path_map[finding.file_path]
        findings = normalize_findings(findings + extra, sources)
        for file in files:
            file.findings_count = sum(finding.file_path == file.path for finding in findings)
        errors.extend(engine_errors)
        if not sources:
            errors.append("Nenhum arquivo de código suportado foi analisado.")
        return ScanResult(target_path=target, scanned_files_count=sum(file.status == "completed" for file in files),
            files=files, total_findings=len(findings), findings=findings, summary_by_severity=self._build_summary(findings),
            scan_duration_ms=round((time.perf_counter() - started) * 1000, 2),
            engine_runs=[native] + engine_runs, has_errors=bool(errors), errors=errors)

    def scan_file(self, file_path: str) -> ScanResult:
        """Executa varredura SAST sobre um arquivo no disco, detectando sua extensão."""
        start_time = time.perf_counter()
        norm_path = os.path.abspath(file_path)

        if not os.path.exists(norm_path):
            return ScanResult(
                target_path=norm_path,
                scanned_files_count=0,
                total_findings=0,
                findings=[],
                summary_by_severity=self._build_summary([]),
                scan_duration_ms=0.0,
                has_errors=True,
                errors=[f"Arquivo não encontrado: {norm_path}"],
            )

        try:
            with open(norm_path, "r", encoding="utf-8") as f:
                source_code = f.read()
        except UnicodeDecodeError:
            try:
                with open(norm_path, "r", encoding="latin-1") as f:
                    source_code = f.read()
            except Exception as e:
                return ScanResult(
                    target_path=norm_path,
                    scanned_files_count=0,
                    total_findings=0,
                    findings=[],
                    summary_by_severity=self._build_summary([]),
                    scan_duration_ms=0.0,
                    has_errors=True,
                    errors=[f"Erro ao ler arquivo {norm_path}: {e}"],
                )

        return self.scan_code(source_code, identifier=norm_path)

    def scan_directory(self, dir_path: str, recursive: bool = True) -> ScanResult:
        """Varre um diretório procurando arquivos suportados (.py, .js, .jsx, .ts, .tsx, .java)."""
        start_time = time.perf_counter()
        norm_dir = os.path.abspath(dir_path)

        all_errors: List[str] = []
        sources = {}

        if not os.path.exists(norm_dir):
            return ScanResult(
                target_path=norm_dir,
                scanned_files_count=0,
                total_findings=0,
                findings=[],
                summary_by_severity=self._build_summary([]),
                scan_duration_ms=0.0,
                has_errors=True,
                errors=[f"Diretório não encontrado: {norm_dir}"],
            )

        valid_exts = tuple(SUPPORTED_EXTENSIONS.keys())

        for root, dirs, files in os.walk(norm_dir):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

            for file in files:
                _, ext = os.path.splitext(file.lower())
                if ext in valid_exts:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding="utf-8") as f:
                            code = f.read()
                    except Exception:
                        try:
                            with open(full_path, "r", encoding="latin-1") as f:
                                code = f.read()
                        except Exception as e:
                            all_errors.append(f"Erro ao ler {full_path}: {e}")
                            continue

                    relative_path = os.path.relpath(full_path, norm_dir).replace(os.sep, "/")
                    sources[relative_path] = code

            if not recursive:
                break

        result = self.scan_sources(sources, target=norm_dir)
        result.errors.extend(all_errors)
        result.has_errors = bool(result.errors)
        result.scan_duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return result
