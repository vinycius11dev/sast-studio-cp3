"""Empacota a entrega de Cybersecurity da GS (ZIP com o código atualizado e as evidências).

    python -m scripts.package_gs            # grava reports/GS_Cybersecurity_SAST_Studio.zip

Não entram no pacote: histórico do Git, banco local (data/), relatórios gerados, caches e ambientes virtuais.
"""
import argparse
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {".git", "data", "reports", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules", ".claude", "dist"}
EXCLUDED_SUFFIXES = {".pyc", ".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".zip"}


def files_to_pack(root: Path = ROOT):
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_file() and not EXCLUDED_DIRS.intersection(relative.parts) and path.suffix not in EXCLUDED_SUFFIXES:
            yield path, relative


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", default="reports/GS_Cybersecurity_SAST_Studio.zip")
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, relative in files_to_pack():
            archive.write(path, Path("sast-studio-cp3") / relative)
            count += 1
    print(f"{count} arquivos em {output} ({output.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
