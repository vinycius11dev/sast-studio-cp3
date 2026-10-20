import json
from engine.models import ScanResult, Severity

# Cores ANSI para o terminal
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_CYAN = "\033[96m"
COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"


class Reporter:
    """Formatador de relatórios SAST para múltiplos formatos (Terminal, JSON, Markdown)."""

    @staticmethod
    def to_json(result: ScanResult, indent: int = 2) -> str:
        """Serializa o resultado para JSON formatado."""
        return result.model_dump_json(indent=indent)

    @staticmethod
    def to_text(result: ScanResult, use_colors: bool = True) -> str:
        """Formata o relatório com destaques e resumo para visualização no terminal."""
        def c(text: str, color_code: str) -> str:
            return f"{color_code}{text}{COLOR_RESET}" if use_colors else text

        lines = []
        lines.append(c("=" * 80, COLOR_GRAY))
        lines.append(c("  RELATÓRIO DE VARREDURA SAST & DEVSECOPS - FIAP", COLOR_BOLD + COLOR_CYAN))
        lines.append(c("=" * 80, COLOR_GRAY))
        lines.append(f"Alvo analisado:       {c(result.target_path, COLOR_BOLD)}")
        lines.append(f"Arquivos verificados: {result.scanned_files_count}")
        lines.append(f"Tempo de execução:    {result.scan_duration_ms} ms")
        lines.append(f"Total de vulnerabilidades: {c(str(result.total_findings), COLOR_BOLD)}")
        lines.append("-" * 80)

        # Resumo por Severidade
        summary = result.summary_by_severity
        summary_str = (
            f"  {c('CRÍTICO:', COLOR_RED)} {summary.get('CRITICAL', 0)} | "
            f"  {c('ALTO:', COLOR_YELLOW)} {summary.get('HIGH', 0)} | "
            f"  {c('MÉDIO:', COLOR_BLUE)} {summary.get('MEDIUM', 0)} | "
            f"  {c('BAIXO:', COLOR_GRAY)} {summary.get('LOW', 0)}"
        )
        lines.append(summary_str)
        lines.append("-" * 80)

        if not result.findings:
            lines.append(c("\n[OK] Nenhum achado nas regras aplicadas.", COLOR_GREEN))
        else:
            lines.append(c("\nVULNERABILIDADES DETECTADAS:\n", COLOR_BOLD))
            for i, f in enumerate(result.findings, 1):
                sev_color = COLOR_RED if f.severity in (Severity.CRITICAL, Severity.HIGH) else COLOR_YELLOW
                owasp_label = f" | OWASP {f.owasp.id} - {f.owasp.name}" if f.owasp else " | OWASP Top 10:2025 sem mapeamento"
                lines.append(
                    f"[{i}] {c(f.severity.value, COLOR_BOLD + sev_color)} - "
                    f"{c(f.rule_name, COLOR_BOLD)} ({c(f.rule_id, COLOR_CYAN)} | {f.cwe}{owasp_label})"
                )
                lines.append(f"    Arquivo: {f.file_path}:{f.line_number}:{f.column_number}")
                lines.append(f"    Mensagem: {f.message}")
                if f.code_snippet:
                    lines.append(f"    Código:   {c(f.code_snippet, COLOR_GRAY)}")
                lines.append(f"    Correção: {c(f.remediation_advice, COLOR_GREEN)}")
                lines.append("")

        if result.semantic_reviews:
            lines.append("REVISÕES SEMÂNTICAS (recomendações; gate original preservado):")
            for review in result.semantic_reviews:
                lines.append(f"  {review.rule_id} {review.file_path}:{review.line_number}: {review.classification}; IA sugere {review.suggested_severity.value}")
                lines.append(f"    {review.reasoning}")
        if result.errors:
            lines.append(c("\nAVISOS / ERROS DE PROCESSAMENTO:", COLOR_RED))
            for err in result.errors:
                lines.append(f"  - {err}")

        lines.append(c("=" * 80, COLOR_GRAY))
        return "\n".join(lines)

    @staticmethod
    def to_markdown(result: ScanResult) -> str:
        """Gera um relatório completo em formato Markdown (ideal para PRs ou relatórios de CI/CD)."""
        md = []
        md.append("# 🛡️ Relatório de Análise SAST & DevSecOps\n")
        md.append(f"- **Alvo Analisado:** `{result.target_path}`")
        md.append(f"- **Arquivos Escaneados:** {result.scanned_files_count}")
        md.append(f"- **Tempo de Varredura:** {result.scan_duration_ms} ms")
        md.append(f"- **Total de Achados:** **{result.total_findings}**\n")
        if result.scan_id:
            md.append(f"- **Análise:** `{result.scan_id}` · {result.created_at}")
        if result.security_gate:
            md.append(f"- **Security Gate:** {result.security_gate.status} (limiar {result.security_gate.threshold})")
            md.append(f"- **Decisão:** {result.security_gate.reason}\n")

        md.append("### 📊 Resumo de Severidade\n")
        md.append("| Severidade | Quantidade |")
        md.append("| :--- | :---: |")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            badge = "🔴" if sev == Severity.CRITICAL else ("🟠" if sev == Severity.HIGH else "🟡")
            md.append(f"| {badge} **{sev.value}** | {result.summary_by_severity.get(sev.value, 0)} |")
        md.append("\n---\n")

        if not result.findings:
            md.append("Nenhum achado nas regras aplicadas.\n")
        else:
            md.append("### 🔍 Detalhamento das Vulnerabilidades\n")
            for idx, f in enumerate(result.findings, 1):
                md.append(f"#### {idx}. [{f.severity.value}] {f.rule_name} (`{f.rule_id}` / `{f.cwe}`)")
                if f.owasp:
                    md.append(f"- **OWASP Top 10:{f.owasp.version}:** [{f.owasp.id} — {f.owasp.name}]({f.owasp.url})")
                else:
                    md.append("- **OWASP Top 10:2025:** Sem mapeamento para este CWE.")
                md.append(f"- **Localização:** `{f.file_path}:{f.line_number}`")
                md.append(f"- **Descrição:** {f.message}")
                if f.code_snippet:
                    extension = f.file_path.rsplit(".", 1)[-1].lower()
                    language = {"py": "python", "js": "javascript", "jsx": "jsx", "ts": "typescript", "tsx": "tsx", "java": "java"}.get(extension, "text")
                    md.append(f"```{language}\n{f.code_snippet}\n```")
                md.append(f"> 💡 **Sugestão de Remediação:**\n> {f.remediation_advice}\n")

        if result.semantic_reviews:
            md.append("### Revisões semânticas do LLM\n")
            md.append("As recomendações abaixo preservam os achados e o gate originais.\n")
            for review in result.semantic_reviews:
                md.append(f"- **{review.rule_id} — {review.file_path}:{review.line_number}**: {review.classification}")
                md.append(f"  - Provedor: {review.model_used}; severidade original: {review.original_severity.value}; sugerida: {review.suggested_severity.value}; confiança: {review.confidence}.")
                md.append(f"  - Justificativa: {review.reasoning}")
                md.append(f"  - Linhas de evidência: {', '.join(map(str, review.evidence_lines)) or 'indisponíveis'}; revisão: {review.review_id}.")
        if result.errors:
            md.append("### Erros de processamento\n")
            md.extend(f"- {error}" for error in result.errors)
        return "\n".join(md)

    @staticmethod
    def to_sarif(result: ScanResult) -> str:
        """Gera relatório em formato SARIF 2.1.0 compatível com GitHub Code Scanning e OASIS."""
        import os
        from urllib.parse import quote
        sarif_results = []
        rules_map = {}

        for f in result.findings:
            if f.rule_id not in rules_map:
                rule_properties = {
                    "problem.severity": "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning",
                    "security-severity": "9.0" if f.severity == Severity.CRITICAL else ("7.0" if f.severity == Severity.HIGH else "5.0"),
                    "tags": ["security", f.cwe.lower()],
                    "cwe": f.cwe,
                }
                if f.owasp:
                    rule_properties["tags"].append(f"owasp-top10:{f.owasp.id.lower()}")
                    rule_properties["owaspTop10"] = f.owasp.model_dump(mode="json")
                rules_map[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.rule_name,
                    "shortDescription": {"text": f.rule_name},
                    "fullDescription": {"text": f.message},
                    "help": {
                        "text": f"Remediação: {f.remediation_advice}",
                        "markdown": f"### Remediação Segura\n{f.remediation_advice}",
                    },
                    "properties": rule_properties,
                }

            level = "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
            uri_val = os.path.basename(f.file_path) if os.path.isabs(f.file_path) else f.file_path
            sarif_result = {
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": f.message},
                "properties": {"cwe": f.cwe, "engines": f.engines, "confidence": f.confidence,
                               "analysisScope": f.analysis_scope,
                               "evidence": [item.model_dump(mode="json") for item in f.evidence],
                               "limitations": f.limitations},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": quote(uri_val.replace("\\", "/"), safe="/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, f.line_number),
                                "startColumn": max(1, f.column_number + 1),
                                "snippet": {"text": f.code_snippet},
                            },
                        }
                    }
                ],
            }
            if f.owasp:
                sarif_result["properties"]["owaspTop10"] = f.owasp.model_dump(mode="json")
            if f.fingerprint:
                sarif_result["partialFingerprints"] = {"sastStudioSemantic/v1": f.fingerprint}
            if f.data_flow:
                sarif_result["codeFlows"] = [{"threadFlows": [{"locations": [
                    {"location": {"message": {"text": step.role}, "physicalLocation": {
                        "artifactLocation": {"uri": quote(step.file_path.replace("\\", "/"), safe="/"), "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": max(1, step.line_number), "startColumn": max(1, step.column_number + 1),
                                   "snippet": {"text": step.code_snippet}}}}} for step in f.data_flow]}]}]
            sarif_results.append(sarif_result)

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "FIAP-SAST-Platform",
                            "version": "3.0.0",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": sarif_results,
                    "properties": {"semanticReviews": [review.model_dump(mode="json") for review in result.semantic_reviews],
                                   "engineRuns": [run.model_dump(mode="json") for run in result.engine_runs]},
                    "invocations": [{"executionSuccessful": not result.has_errors,
                                     "toolExecutionNotifications": [{"level": "error", "message": {"text": error}} for error in result.errors]}],
                }
            ],
        }
        return json.dumps(sarif_data, indent=2, ensure_ascii=False)
