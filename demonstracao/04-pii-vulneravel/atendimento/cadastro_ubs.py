"""Cadastro de atendimentos de uma UBS (exemplo fictício e vulnerável). Não executar.

Todos os dados abaixo são inventados para demonstrar a detecção de PII.
"""
import hashlib
import logging

logger = logging.getLogger("ubs")

# CPF fictício, válido só pelos dígitos verificadores, usado como massa de teste.
CPF_TESTE = "529.982.247-25"


def registrar_atendimento(paciente, db):
    cpf = paciente["cpf"]
    diagnostico = paciente["diagnostico"]
    logger.info(f"Atendimento do CPF {cpf} com diagnóstico {diagnostico}")
    print("Paciente atendido:", cpf)
    db.execute(
        "INSERT INTO atendimentos (cpf, diagnostico) VALUES (%s, %s)",
        (cpf, diagnostico),
    )


def criar_usuario(nome, senha, db):
    verificador = hashlib.md5(senha.encode()).hexdigest()
    db.execute("INSERT INTO usuarios (nome, senha) VALUES (%s, %s)", (nome, senha))
    with open("usuarios.csv", "a") as arquivo:
        arquivo.write(f"{nome};{senha}\n")
    return verificador


def prontuario_de_exemplo():
    return {"nome": "Maria de Teste", "diagnostico": "Hipertensão arterial"}
