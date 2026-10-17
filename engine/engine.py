import os
import time
from typing import List, Type, Dict, Tuple
from engine.models import Finding, ScanResult, RuleMetadata, Severity
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

    def __init__(self, rule_classes: List[Type[BaseRule]] = None):
        self.rule_classes = rule_classes or list(DEFAULT_RULES)
        self.python_scanner = PythonScanner(rule_classes=self.rule_classes)
        self.js_scanner = JavaScriptScanner()
        self.java_scanner = JavaScanner()

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
        start_time = time.perf_counter()

        scanner = self._resolve_scanner(file_path=identifier, source_code=source_code)
        findings, errors = scanner.scan_source(source_code=source_code, file_path=identifier)

        duration_ms = (time.perf_counter() - start_time) * 1000

        return ScanResult(
            target_path=identifier,
            scanned_files_count=1 if not errors else 0,
            total_findings=len(findings),
            findings=findings,
            summary_by_severity=self._build_summary(findings),
            scan_duration_ms=round(duration_ms, 2),
            has_errors=bool(errors),
            errors=errors,
        )

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

        scanner = self._resolve_scanner(file_path=norm_path, source_code=source_code)
        findings, errors = scanner.scan_source(source_code=source_code, file_path=norm_path)

        duration_ms = (time.perf_counter() - start_time) * 1000

        return ScanResult(
            target_path=norm_path,
            scanned_files_count=1 if not errors else 0,
            total_findings=len(findings),
            findings=findings,
            summary_by_severity=self._build_summary(findings),
            scan_duration_ms=round(duration_ms, 2),
            has_errors=bool(errors),
            errors=errors,
        )

    def scan_directory(self, dir_path: str, recursive: bool = True) -> ScanResult:
        """Varre um diretório procurando arquivos suportados (.py, .js, .jsx, .ts, .tsx, .java)."""
        start_time = time.perf_counter()
        norm_dir = os.path.abspath(dir_path)

        all_findings: List[Finding] = []
        all_errors: List[str] = []
        files_scanned = 0

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

                    scanner = self._resolve_scanner(file_path=full_path, source_code=code)
                    relative_path = os.path.relpath(full_path, norm_dir).replace(os.sep, "/")
                    f_list, err_list = scanner.scan_source(source_code=code, file_path=relative_path)
                    all_findings.extend(f_list)
                    all_errors.extend(err_list)
                    files_scanned += 0 if err_list else 1

            if not recursive:
                break

        duration_ms = (time.perf_counter() - start_time) * 1000

        return ScanResult(
            target_path=norm_dir,
            scanned_files_count=files_scanned,
            total_findings=len(all_findings),
            findings=all_findings,
            summary_by_severity=self._build_summary(all_findings),
            scan_duration_ms=round(duration_ms, 2),
            has_errors=bool(all_errors) or files_scanned == 0,
            errors=all_errors or (["Nenhum arquivo de código suportado foi analisado."] if files_scanned == 0 else []),
        )
