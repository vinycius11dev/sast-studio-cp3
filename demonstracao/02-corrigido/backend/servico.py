"""Versao corrigida dos mesmos exemplos para comparar no SAST."""
import ipaddress
import json
import os
import subprocess
import sys

db_password = os.getenv("DEMO_DB_PASSWORD")


def ler_preferencias(user_input: str):
    return json.loads(user_input)


def verificar_host(host: str):
    endereco = str(ipaddress.ip_address(host))
    parametro = "-n" if sys.platform == "win32" else "-c"
    return subprocess.run(
        ["ping", parametro, "1", endereco],
        shell=False,
        capture_output=True,
        timeout=5,
        check=False,
    )
