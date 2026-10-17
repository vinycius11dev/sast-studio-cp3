"""Inicia a demonstração local sem criar servidores duplicados."""
import argparse
import json
import os
import socket
import threading
import urllib.request
import webbrowser
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Iniciar SAST Studio")
    parser.add_argument("--no-browser", action="store_true", help="Não abrir o navegador automaticamente")
    args = parser.parse_args()
    os.chdir(Path(__file__).resolve().parent)
    address = "http://127.0.0.1:8000"
    try:
        with urllib.request.urlopen(address + "/health", timeout=2) as response:
            health = json.load(response)
        if health.get("service") == "sast-engine-api":
            print(f"SAST Studio já está em execução: {address}/dashboard")
            if not args.no_browser:
                webbrowser.open(address + "/dashboard?v=studio-2")
            return 0
    except (OSError, ValueError):
        pass
    with socket.socket() as connection:
        if connection.connect_ex(("127.0.0.1", 8000)) == 0:
            print("A porta 8000 está sendo usada por outro serviço. Encerre esse serviço antes de iniciar.")
            return 1
    try:
        import uvicorn
        import fastapi
        import httpx
        import multipart
        import tree_sitter
        import tree_sitter_java
        import tree_sitter_javascript
        import tree_sitter_typescript
    except ImportError:
        print("Instale as dependências primeiro: python -m pip install -r requirements.txt")
        return 1
    print(f"SAST Studio: {address}/dashboard")
    print("Mantenha esta janela aberta durante a apresentação. Ctrl+C encerra o servidor.")
    print("Abra o aplicativo Ollama para utilizar o modelo local nas remediações.")
    if not args.no_browser:
        browser = threading.Timer(1.5, lambda: webbrowser.open(address + "/dashboard?v=studio-2"))
        browser.daemon = True
        browser.start()
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
