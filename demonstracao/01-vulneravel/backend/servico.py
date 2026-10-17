"""Exemplos intencionalmente vulneraveis para analisar no SAST. Nao executar."""
import os

# Credencial ficticia: usada apenas para demonstrar a regra de segredo no codigo.
db_password = "DEMO_SENHA_FICTICIA_1234"


def ler_preferencias(user_input: str):
    return eval(user_input)


def verificar_host(host: str):
    return os.system("ping -n 1 " + host)
