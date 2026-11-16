"""Cadastro de atendimentos de uma UBS (versão corrigida). Não executar.

Os dados sensíveis são mascarados nos logs e a senha é guardada só como hash com salt.
"""
import logging

import bcrypt

logger = logging.getLogger("ubs")


def mascarar_cpf(cpf):
    return "***.***.***-" + cpf[-2:]


def registrar_atendimento(paciente, db):
    cpf = paciente["cpf"]
    diagnostico = paciente["diagnostico"]
    logger.info("Atendimento registrado para o CPF %s", mascarar_cpf(cpf))
    db.execute(
        "INSERT INTO atendimentos (cpf, diagnostico) VALUES (%s, %s)",
        (cpf, diagnostico),
    )


def criar_usuario(nome, senha, db):
    senha_hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())
    db.execute("INSERT INTO usuarios (nome, senha_hash) VALUES (%s, %s)", (nome, senha_hash))
