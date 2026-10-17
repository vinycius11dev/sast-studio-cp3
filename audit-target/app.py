"""Alvo seguro para demonstrar o gate com Pull Requests separados."""
import json


def ler_configuracao(user_input: str):
    return json.loads(user_input)
