"""Auditoria do protótipo: gera a evidência do Taint Analysis de PII (GS CitizenTech, Cybersecurity).

Analisa a UBS de demonstração antes e depois das correções e escreve um relatório Markdown com o caminho
de cada dado sensível, da origem até a saída insegura, e o indicador Risco Cidadão de cada versão.

    python -m scripts.taint_audit
    python -m scripts.taint_audit --output docs/evidencias/AUDITORIA_TAINT_PII.md
"""
import argparse
from datetime import date
from pathlib import Path
from typing import Dict, List

from engine.citizen_risk import compute_citizen_risk
from engine.engine import SASTEngine
from engine.models import Finding

ROOT = Path(__file__).resolve().parents[1]
FOLDERS = (("04-pii-vulneravel", "Antes: dados expostos"), ("05-pii-corrigido", "Depois: dados protegidos"))
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def scan_folder(folder: str) -> List[Finding]:
    engine, findings = SASTEngine(), []
    for path in sorted((ROOT / "demonstracao" / folder).rglob("*.py")):
        relative = f"{folder}/{path.relative_to(ROOT / 'demonstracao' / folder).as_posix()}"
        findings.extend(engine.scan_code(path.read_text(encoding="utf-8"), relative).findings)
    return findings


def build_report() -> str:
    results: Dict[str, List[Finding]] = {folder: scan_folder(folder) for folder, _ in FOLDERS}
    lines = ["# Auditoria do protótipo: Taint Analysis de PII", "",
             f"Gerado em {date.today().isoformat()} por `python -m scripts.taint_audit`. "
             "Todos os dados do exemplo são fictícios. O relatório mostra risco encontrado no código, não vazamento ocorrido.", "",
             "## Resumo", "", "| Versão | Achados | Com PII | Vazamentos confirmados | Risco Cidadão |", "| --- | ---: | ---: | ---: | --- |"]
    for folder, label in FOLDERS:
        risk = compute_citizen_risk(results[folder])
        lines.append(f"| {label} (`{folder}`) | {len(results[folder])} | {risk.pii_findings} | {risk.confirmed_leaks} | **{risk.score}/100 · {risk.level_label}** |")
    for folder, label in FOLDERS:
        findings = sorted(results[folder], key=lambda item: (SEVERITY_ORDER.index(item.severity.value), item.file_path, item.line_number))
        lines += ["", f"## {label}", ""]
        if not findings:
            lines.append("Nenhum achado nas regras aplicadas: o CPF é mascarado antes de sair, a senha é guardada só como hash com salt "
                         "e nenhuma resposta devolve dado de saúde. Isso não prova ausência de risco.")
            continue
        for number, finding in enumerate(findings, 1):
            lines += [f"### {number}. [{finding.severity.value}] {finding.rule_name} (`{finding.rule_id}` · {finding.cwe})", "",
                      f"- **Local:** `{finding.file_path}:{finding.line_number}`",
                      f"- **Dados:** {', '.join(finding.data_categories)}", f"- **Mensagem:** {finding.message}"]
            if finding.taint_trace:
                lines.append("- **Caminho do dado:**")
                lines += [f"  {step_number}. {step}" for step_number, step in enumerate(finding.taint_trace, 1)]
            lines += ["", "```python", finding.code_snippet, "```", f"> Correção: {finding.remediation_advice}", ""]
    lines += ["", "## Como reproduzir", "", "```powershell", "python cli.py scan demonstracao/04-pii-vulneravel --fail-on HIGH",
              "python cli.py scan demonstracao/05-pii-corrigido --fail-on HIGH", "```", "",
              "A primeira análise termina com código 1 (gate bloqueado); a segunda, com 0 (aprovada)."]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", default="docs/evidencias/AUDITORIA_TAINT_PII.md")
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(build_report(), encoding="utf-8")
    print(f"Relatório gravado em {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
