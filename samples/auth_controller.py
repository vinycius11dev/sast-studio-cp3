"""auth_controller.py - Módulo de Autenticação e Controle de Sessão (Amostra do Slide 8).

Este arquivo contém exatamente 12 vulnerabilidades identificáveis pelo motor SAST,
espelhando as métricas do painel executivo apresentado no Slide 8 do Projeto Integrador.
"""
import os
import subprocess
import requests

# [PY-R002 / CWE-798] Hardcoded Secrets (5 ocorrências)
jwt_secret = "secret-auth-key-super-hardcoded-12345"
db_password = "AdminSuperPassword2026!"
api_key = "AIzaSyD-GoogleApiKeyExample998877"
admin_token = "ghp_000000000000000000000000000000000000"
redis_passwd = "RedisClusterPasswd2026"

def dynamic_auth_hook(hook_code: str):
    # [PY-R001 / CWE-95] Dynamic Execution (2 ocorrências)
    eval(hook_code)
    exec(hook_code)

def execute_diagnostic(host: str, cli_cmd: str):
    # [PY-R003 / CWE-78] OS Command Injection (3 ocorrências)
    os.system("ping -c 1 " + host)
    subprocess.Popen("whoami", shell=True)
    subprocess.run(cli_cmd, shell=True)

def authenticate_user(request, db_cursor):
    # [PY-T001 / CWE-89] Taint SQL Injection (1 ocorrência)
    username = request.args.get("username")
    query = "SELECT * FROM users WHERE login = '" + username + "'"
    db_cursor.execute(query)

def fetch_external_avatar(request):
    # [PY-T001 / PY-R004 / CWE-918] SSRF via URL dinâmica (1 ocorrência)
    avatar_url = request.args.get("avatar_url")
    requests.get(avatar_url)
