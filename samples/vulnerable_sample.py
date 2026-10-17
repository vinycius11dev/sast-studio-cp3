"""Amostra de código intencionalmente vulnerável para demonstração do SAST (CP 1 - FIAP).

Contém:
1. Violação PY-R001 (CWE-95): Chamadas a eval() e exec().
2. Violação PY-R002 (CWE-798): Credenciais e tokens hardcoded.
3. Violação PY-R003 (CWE-78): Injeção de comandos de sistema (os.system e shell=True).
"""
import os
import subprocess


# [PY-R002 / CWE-798] Hardcoded Secrets
db_password = "SuperSecretPassword123!"
api_key = "AIzaSyD-FakeApiKeyForTestingPurposes"
jwt_secret = "my-hardcoded-jwt-signing-secret"

credentials = {
    "access_token": "ghp_9876543210abcdefghijklmnop",
}


def execute_dynamic_calculation(user_formula: str):
    # [PY-R001 / CWE-95] Dangerous Eval
    print("Calculando formula:")
    return eval(user_formula)


def run_arbitrary_script(script_body: str):
    # [PY-R001 / CWE-95] Dangerous Exec
    exec(script_body)


def ping_host(host_ip: str):
    # [PY-R003 / CWE-78] OS Command Injection via os.system
    command = "ping -c 1 " + host_ip
    os.system(command)


def backup_database(db_name: str):
    # [PY-R003 / CWE-78] OS Command Injection via subprocess com shell=True
    dump_cmd = f"mysqldump -u root {db_name} > backup.sql"
    subprocess.Popen(dump_cmd, shell=True)
