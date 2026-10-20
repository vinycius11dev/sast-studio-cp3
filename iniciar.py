"""Inicia a demonstração local sem criar servidores duplicados."""
import argparse
import json
import os
import socket
import threading
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path


def existing_server_status(address):
    """Distinguish the current app from an older SAST process on port 8000."""
    try:
        with urllib.request.urlopen(address + "/health", timeout=2) as response:
            health = json.load(response)
    except (OSError, ValueError):
        return "unavailable"

    if health.get("service") != "sast-engine-api":
        return "other"

    try:
        with urllib.request.urlopen(address + "/apresentacao", timeout=2) as response:
            if response.status != 200:
                return "stale"
        with urllib.request.urlopen(address + "/api/v1/engines", timeout=8) as response:
            engines = json.load(response).get("items", [])
        return "ready" if any(item.get("engine") == "native" and item.get("version") == "3.1.0" for item in engines) else "stale"
    except urllib.error.HTTPError as error:
        return "stale" if error.code == 404 else "unavailable"
    except (OSError, ValueError):
        return "unavailable"


def find_current_server(start_port=8000, end_port=8100):
    """Find a running current SAST instance, including one using a fallback port."""
    for port in range(start_port, end_port):
        with socket.socket() as connection:
            connection.settimeout(0.2)
            if connection.connect_ex(("127.0.0.1", port)) != 0:
                continue
        address = f"http://127.0.0.1:{port}"
        if existing_server_status(address) == "ready":
            return port
    return None


def find_free_port(start_port=8000, end_port=8100):
    """Return the first loopback port that can be bound by the launcher."""
    for port in range(start_port, end_port):
        with socket.socket() as connection:
            try:
                connection.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    return None


def main():
    parser = argparse.ArgumentParser(description="Iniciar SAST Studio")
    parser.add_argument("--no-browser", action="store_true", help="Não abrir o navegador automaticamente")
    args = parser.parse_args()
    os.chdir(Path(__file__).resolve().parent)
    preferred_port = 8000
    address = f"http://127.0.0.1:{preferred_port}"
    server_status = existing_server_status(address)
    if server_status == "ready":
        print(f"SAST Studio já está em execução: {address}/dashboard")
        if not args.no_browser:
            webbrowser.open(address + "/dashboard?v=studio-2")
        return 0

    running_port = find_current_server(preferred_port + 1)
    if running_port is not None:
        address = f"http://127.0.0.1:{running_port}"
        print(f"SAST Studio já está em execução: {address}/dashboard")
        if not args.no_browser:
            webbrowser.open(address + "/dashboard?v=studio-2")
        return 0

    port = find_free_port(preferred_port)
    if port is None:
        print("Não encontrei uma porta livre entre 8000 e 8099. Feche outro serviço e tente novamente.")
        return 1
    address = f"http://127.0.0.1:{port}"
    if port != preferred_port:
        print(f"A porta 8000 está ocupada. A versão atual será iniciada em {address}.")
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
    scanners = Path(__file__).resolve().parent / ".venv-scanners" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if scanners.exists() and "SAST_ENGINES" not in os.environ:
        os.environ["SAST_ENGINES"] = "native,bandit,semgrep"
        print("Motores: nativo + Bandit + Semgrep CE (ambiente de scanners instalado).")
    print(f"SAST Studio: {address}/dashboard")
    print("Mantenha esta janela aberta durante a apresentação. Ctrl+C encerra o servidor.")
    print("Abra o aplicativo Ollama para utilizar o modelo local nas remediações.")
    if not args.no_browser:
        browser = threading.Timer(1.5, lambda: webbrowser.open(address + "/dashboard?v=studio-2"))
        browser.daemon = True
        browser.start()
    uvicorn.run("api.main:app", host="127.0.0.1", port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
