"""Resumo dos relatórios do gate para o GitHub Actions."""
import json
import sys
from pathlib import Path


def main():
    directory = Path(sys.argv[1] if len(sys.argv) > 1 else "reports")
    print("## SAST Studio — Security Gate\n")
    print("| Alvo | Achados | Processamento |\n| --- | ---: | --- |")
    for path in sorted(directory.glob("*.sarif")):
        run = json.loads(path.read_text(encoding="utf-8"))["runs"][0]
        success = all(invocation.get("executionSuccessful", True) for invocation in run.get("invocations", []))
        print(f"| {path.stem} | {len(run.get('results', []))} | {'Concluído' if success else 'Incompleto'} |")
    benchmark = directory / "benchmark.json"
    if benchmark.is_file():
        report = json.loads(benchmark.read_text(encoding="utf-8"))
        print(f"\nCorpus rotulado: {report['case_count']} casos; precisão {report['precision']:.1%}; recall {report['recall']:.1%}.")
        print("Essas métricas se limitam ao corpus do projeto.")
    print("\nAchados HIGH/CRITICAL ou erros reprovam o job. O bloqueio de merge exige checks obrigatórios na branch.")


if __name__ == "__main__":
    main()
