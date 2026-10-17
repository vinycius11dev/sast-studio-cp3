"""Amostra de código seguro (Remediado) para validação de falso positivo."""
import ast
import json
import os
import subprocess

# [Seguro] Credenciais obtidas de variáveis de ambiente do sistema
db_password = os.getenv("DB_PASSWORD", "")
api_key = os.getenv("API_KEY", "")
jwt_secret = os.getenv("JWT_SECRET", "")


def parse_safe_data(user_json_string: str):
    # [Seguro] Em vez de eval(), usamos json.loads ou ast.literal_eval
    return json.loads(user_json_string)


def parse_safe_literal(safe_literal_str: str):
    # [Seguro] Para parsing de estruturas Python sem execução de código
    return ast.literal_eval(safe_literal_str)


def ping_host_safely(host_ip: str):
    # [Seguro] Passando lista de argumentos e garantindo shell=False
    # Em produção, adicionar validação de regex ou formato de IP
    return subprocess.run(
        ["ping", "-c", "1", host_ip],
        shell=False,
        capture_output=True,
        check=False,
    )
