#!/usr/bin/env python3
"""CLI da Plataforma SAST & DevSecOps.

Interface de linha de comando para varreduras de segurança em projetos Python.
"""
import argparse
import os
import sys
import json
from pathlib import Path
from engine.engine import SASTEngine
from engine.reporter import Reporter
from engine.models import Severity
from engine.policy import evaluate_gate


def cmd_rules(args):
    """Lista as regras ativas no motor SAST."""
    engine = SASTEngine(engines=getattr(args, "engines", None).split(",") if getattr(args, "engines", None) else None)
    rules = engine.list_rules()
    print("=" * 70)
    print("  REGRAS ATIVAS NO MOTOR SAST")
    print("=" * 70)
    for r in rules:
        print(f"[{r.rule_id}] {r.name}")
        print(f"  Severidade: {r.severity.value} | CWE: {r.cwe}")
        print(f"  Descrição:  {r.description}")
        print(f"  Correção:   {r.remediation}\n")
    print("=" * 70)
    return 0


def cmd_scan(args):
    """Executa a varredura SAST em um arquivo ou diretório."""
    target_path = os.path.abspath(args.path)

    if not os.path.exists(target_path):
        print(f"Erro: O caminho especificado não existe: {target_path}", file=sys.stderr)
        return 2

    engine = SASTEngine(engines=args.engines.split(",") if getattr(args, "engines", None) else None)

    if os.path.isdir(target_path):
        result = engine.scan_directory(target_path, recursive=not args.no_recursive)
    else:
        result = engine.scan_file(target_path)

    result.security_gate = evaluate_gate(result, args.fail_on)

    # Formatação de saída
    fmt = args.format.lower()
    if fmt == "json":
        output = Reporter.to_json(result)
    elif fmt == "markdown":
        output = Reporter.to_markdown(result)
    elif fmt == "sarif":
        output = Reporter.to_sarif(result)
    else:
        output = Reporter.to_text(result, use_colors=not args.no_color)

    if getattr(args, "ai", False) and result.findings:
        from engine.ai_remediation import AIRemediationEngine
        ai_engine = AIRemediationEngine()
        sources = {}
        remediations = []
        for finding in result.findings:
            source_path = Path(target_path) / finding.file_path if os.path.isdir(target_path) else Path(target_path)
            if source_path not in sources:
                try:
                    sources[source_path] = source_path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    sources[source_path] = source_path.read_text(encoding="latin-1")
                except OSError:
                    sources[source_path] = None
            remediations.append(ai_engine.remediate_finding(finding, original_code=sources[source_path]))
        if fmt in {"json", "sarif"}:
            document = json.loads(output)
            if fmt == "json":
                document["ai_remediations"] = [item.model_dump() for item in remediations]
            else:
                document["runs"][0]["properties"] = {"aiRemediations": [item.model_dump() for item in remediations]}
            output = json.dumps(document, ensure_ascii=False, indent=2)
        else:
            output += "\n\nSUGESTÕES DE REMEDIAÇÃO PARA REVISÃO\n"
        for idx, (f, remediation) in enumerate(zip(result.findings, remediations), 1):
            if fmt in {"json", "sarif"}:
                continue
            output += (
                f"\n[{idx}] Correção para {f.rule_name} ({f.cwe}) [{remediation.model_used}]:\n"
                f"    Análise de Risco: {remediation.risk_analysis}\n"
                f"    Código Seguro Sugerido:\n"
            )
            for line in remediation.suggested_patch.splitlines():
                output += f"      {line}\n"
            if remediation.diff:
                output += "    Diff / Patch:\n"
                for line in remediation.diff.splitlines():
                    output += f"      {line}\n"
        if fmt not in {"json", "sarif"}:
            output += "\n" + ("=" * 80) + "\n"

    # Gravação em arquivo ou console
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"[OK] Relatório salvo com sucesso em: {args.output}")
        except Exception as e:
            print(f"Erro ao salvar arquivo de saída: {e}", file=sys.stderr)
            return 2
    else:
        print(output)

    # Avaliação de Security Gate para saída em CI/CD
    if result.has_errors:
        return 2
    if result.security_gate.status == "blocked":
        return 1

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Plataforma SAST & DevSecOps - Motor de Análise Estática de Segurança",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando: scan
    scan_parser = subparsers.add_parser("scan", help="Executa varredura SAST em arquivos ou pastas")
    scan_parser.add_argument("path", help="Caminho do arquivo (.py, .js, .java) ou pasta a ser analisada")
    scan_parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "markdown", "sarif"],
        default="text",
        help="Formato do relatório de saída: text, json, markdown, sarif (padrão: text)",
    )
    scan_parser.add_argument("-o", "--output", help="Caminho para salvar o relatório em arquivo")
    scan_parser.add_argument("--no-color", action="store_true", help="Desativa cores no terminal")
    scan_parser.add_argument("--engines", help="Motores: native ou native,bandit,semgrep. Prevalece sobre SAST_ENGINES.")
    scan_parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Desativa busca recursiva em subdiretórios",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="CRITICAL",
        help="Nível de severidade mínimo para retornar código de saída 1 (Security Gate CI/CD)",
    )
    scan_parser.add_argument(
        "--ai",
        action="store_true",
        help="Gera sugestões de remediação e diffs de código com IA (Ollama / Llama 3)",
    )
    scan_parser.set_defaults(func=cmd_scan)

    # Subcomando: rules
    rules_parser = subparsers.add_parser("rules", help="Lista todas as regras ativas de detecção")
    rules_parser.set_defaults(func=cmd_rules)

    args = parser.parse_args()
    exit_code = args.func(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
