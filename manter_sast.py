"""Local service supervisor. It never exposes process control through the web API."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser

from iniciar import existing_server_status, find_current_server, find_free_port

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / "data" / "runtime"
PUBLIC_URL = re.compile(r"https://[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com\b")


def healthy(address: str) -> bool:
    try:
        with urllib.request.urlopen(address + "/health", timeout=3) as response:
            data = json.loads(response.read(65536))
        return data.get("service") == "sast-engine-api" and data.get("status") == "healthy"
    except (OSError, ValueError):
        return False


def ollama_ready() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=2) as response:
            return isinstance(json.loads(response.read(1048576)).get("models"), list)
    except (OSError, ValueError):
        return False


def port_free(port: int) -> bool:
    with socket.socket() as connection:
        try:
            connection.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def read_state(runtime: Path = RUNTIME) -> dict:
    try:
        return json.loads((runtime / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def write_state(runtime: Path, state: dict) -> None:
    runtime.mkdir(parents=True, exist_ok=True)
    target = runtime / "state.json"
    temporary = runtime / "state.tmp"
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(target)


class InstanceLock:
    """OS lock: automatically released even if the launcher crashes."""
    def __init__(self, runtime: Path):
        runtime.mkdir(parents=True, exist_ok=True)
        self.file = (runtime / "supervisor.lock").open("a+b")
        if self.file.seek(0, 2) == 0:
            self.file.write(b"0")
            self.file.flush()
        self.file.seek(0)

    def acquire(self) -> bool:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            self.file.close()
            return False

    def close(self):
        self.file.close()


def executable(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    candidates = {
        "ollama": [Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/Ollama/ollama.exe"],
        "cloudflared": [ROOT / "tools/cloudflared.exe", Path(os.environ.get("TEMP", "")) / "cloudflared-windows-amd64.exe"],
    }
    return next((str(path) for path in candidates.get(name, []) if path.is_file()), None)


class Supervisor:
    def __init__(self, port: int, data_dir: Path, *, cloudflare=False, public_url="", runtime=RUNTIME, protocol="http2"):
        self.port, self.data_dir, self.runtime = port, data_dir.resolve(), Path(runtime)
        self.address = f"http://127.0.0.1:{port}"
        self.cloudflare, self.public_url, self.protocol = cloudflare, public_url, protocol
        self.runtime.mkdir(parents=True, exist_ok=True)
        self.children: dict[str, subprocess.Popen] = {}
        self.logs = {}
        self.failures = 0
        self.public_failures = 0
        self.attempts: dict[str, int] = {}
        self.next_start: dict[str, float] = {}
        self.next_public_check = 0.0
        self.next_ollama_check = 0.0
        self.tunnel_log = self.runtime / "tunnel.log"
        self.api_status = "starting"
        self.tunnel_status = "checking" if cloudflare else "disabled"
        self.ollama_status = "checking"
        self.last_message = ""

    def message(self, message: str):
        if message != self.last_message:
            print(message, flush=True)
            self.last_message = message

    def spawn(self, name: str, command: list[str], *, env=None, log=None) -> bool:
        if time.monotonic() < self.next_start.get(name, 0):
            return False
        if name in self.children and self.children[name].poll() is None:
            return False
        self.attempts[name] = self.attempts.get(name, 0) + 1
        self.next_start[name] = time.monotonic() + min(30, 2 ** min(self.attempts[name], 5))
        if name in self.logs:
            self.logs.pop(name).close()
        output = open(log or self.runtime / f"{name}.log", "ab", buffering=0)
        try:
            self.children[name] = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        except OSError as error:
            output.close()
            self.message(f"Não foi possível iniciar {name}: {error}")
            return False
        self.logs[name] = output
        self.message(f"Serviço {name} iniciado (PID {self.children[name].pid}).")
        return True

    def stop_child(self, name: str):
        # Only a Popen handle created by this supervisor can reach terminate().
        process = self.children.get(name)
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def ensure_api(self):
        if healthy(self.address):
            self.failures = 0
            self.api_status = "healthy"
            self.attempts["api"] = 0
            return
        self.failures += 1
        self.api_status = "recovering"
        child = self.children.get("api")
        if child and child.poll() is None:
            # Allow startup and transient load; never terminate an adopted process.
            if self.failures < 6:
                return
            self.stop_child("api")
        elif not port_free(self.port):
            self.api_status = "unresponsive"
            self.message(f"A porta {self.port} está ocupada, mas a API não respondeu. Nenhum processo externo foi encerrado.")
            return
        env = os.environ.copy()
        env["SAST_DATA_DIR"] = str(self.data_dir)
        scanner = ROOT / ".venv-scanners" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if scanner.exists():
            env.setdefault("SAST_ENGINES", "native,bandit,semgrep")
        if self.spawn("api", [sys.executable, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", str(self.port)], env=env):
            self.failures = 0

    def ensure_ollama(self):
        now = time.monotonic()
        if now < self.next_ollama_check:
            return
        self.next_ollama_check = now + 15
        if ollama_ready():
            self.ollama_status = "available"
            self.attempts["ollama"] = 0
        elif port_free(11434):
            binary = executable("ollama")
            self.ollama_status = "recovering" if binary else "not_installed"
            if binary:
                self.spawn("ollama", [binary, "serve"])
        else:
            self.ollama_status = "unresponsive"

    def start_tunnel(self):
        binary = executable("cloudflared")
        if not binary:
            self.tunnel_status = "not_installed"
            self.message("Cloudflared não encontrado. O endereço local continua disponível. Consulte docs/CONEXAO.md.")
            return
        child = self.children.get("tunnel")
        if child and child.poll() is None:
            return
        if time.monotonic() < self.next_start.get("tunnel", 0):
            return
        # A new log cannot accidentally resurrect an expired URL from a former run.
        self.tunnel_log.write_bytes(b"")
        if self.spawn("tunnel", [binary, "tunnel", "--url", self.address, "--no-autoupdate", "--protocol", self.protocol], log=self.tunnel_log):
            self.public_url = ""
            self.tunnel_status = "starting"
            self.public_failures = 0

    def ensure_tunnel(self):
        if not self.cloudflare:
            return
        child = self.children.get("tunnel")
        if child is not None:
            if child.poll() is not None:
                self.tunnel_status = "recovering"
                self.start_tunnel()
                return
            if not self.public_url:
                try:
                    with self.tunnel_log.open("rb") as log:
                        log.seek(max(0, self.tunnel_log.stat().st_size - 65536))
                        matches = PUBLIC_URL.findall(log.read().decode("utf-8", errors="replace"))
                    if matches:
                        self.public_url = matches[-1]
                        self.message(f"Link público: {self.public_url}/dashboard")
                except OSError:
                    pass
        if not self.public_url:
            self.start_tunnel()
            return
        now = time.monotonic()
        if now < self.next_public_check or self.api_status != "healthy":
            return
        self.next_public_check = now + 15
        if healthy(self.public_url):
            self.public_failures = 0
            self.tunnel_status = "healthy"
            self.attempts["tunnel"] = 0
        else:
            self.public_failures += 1
            self.tunnel_status = "reconnecting"
            # cloudflared normally reconnects by itself. A gateway failure never restarts the API.
            if self.public_failures >= 6:
                self.stop_child("tunnel")
                self.message("O túnel não se recuperou. Criando novo link temporário; o endereço poderá mudar.")
                self.start_tunnel()

    def tick(self):
        self.ensure_api()
        self.ensure_ollama()
        self.ensure_tunnel()
        write_state(self.runtime, {
            "supervisor_pid": os.getpid(), "checked_at": time.time(), "port": self.port,
            "local_url": self.address, "public_url": self.public_url, "data_dir": str(self.data_dir),
            "cloudflare": self.cloudflare, "protocol": self.protocol, "api": self.api_status,
            "tunnel": self.tunnel_status, "ollama": self.ollama_status,
            "owned_pids": {name: process.pid for name, process in self.children.items() if process.poll() is None},
        })

    def close(self):
        for name in list(self.children):
            self.stop_child(name)
        for log in self.logs.values():
            log.close()


def main():
    parser = argparse.ArgumentParser(description="Inicia e acompanha os serviços do SAST Studio")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--cloudflare", action="store_true", help="Habilitar o link temporário público")
    parser.add_argument("--port", type=int)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--public-url", default="", help="Reutilizar um túnel atual desta máquina")
    parser.add_argument("--protocol", choices=["http2", "quic", "auto"], default=None)
    args = parser.parse_args()
    saved = read_state()
    lock = InstanceLock(RUNTIME)
    if not lock.acquire():
        address = saved.get("public_url") or saved.get("local_url", "http://127.0.0.1:8000")
        print(f"O acompanhamento já está ativo. SAST: {address}/dashboard", flush=True)
        if not args.no_browser:
            webbrowser.open(address + "/dashboard")
        return 0
    supervisor = None
    try:
        port = args.port or saved.get("port") or find_current_server() or find_free_port()
        if port is None or not 1 <= port <= 65535:
            print("Não foi possível escolher uma porta local.")
            return 1
        # Never attach to an unrelated listener or an outdated app.
        address = f"http://127.0.0.1:{port}"
        if not port_free(port) and existing_server_status(address) != "ready":
            port = find_current_server() or find_free_port()
            if port is None:
                return 1
        data_dir = args.data_dir or Path(saved.get("data_dir") or os.environ.get("SAST_DATA_DIR") or ROOT / "data")
        public_url = args.public_url or saved.get("public_url", "")
        if public_url and not PUBLIC_URL.fullmatch(public_url):
            print("O endereço público deve ser um link HTTPS trycloudflare.com válido.")
            return 1
        supervisor = Supervisor(port, data_dir, cloudflare=args.cloudflare or saved.get("cloudflare", False),
            public_url=public_url, protocol=args.protocol or saved.get("protocol", "http2"))
        print(f"SAST local: {supervisor.address}/dashboard", flush=True)
        if public_url:
            print(f"Link público: {public_url}/dashboard", flush=True)
        print("Acompanhamento automático ativo. Mantenha esta janela aberta. Ctrl+C encerra os serviços iniciados por ela.", flush=True)
        opened = args.no_browser
        while True:
            supervisor.tick()
            if not opened and supervisor.api_status == "healthy":
                webbrowser.open(supervisor.address + "/dashboard")
                opened = True
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nEncerrando acompanhamento.", flush=True)
        return 0
    finally:
        if supervisor:
            supervisor.close()
        lock.close()


if __name__ == "__main__":
    raise SystemExit(main())
