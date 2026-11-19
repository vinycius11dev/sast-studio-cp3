"""Cobrança de procedimentos de uma clínica conveniada ao SUS (exemplo fictício e vulnerável). Não executar.

Todos os dados abaixo são inventados para demonstrar a detecção de CNS, cartão, e-mail e telefone.
"""
import logging

logger = logging.getLogger("cobranca")

# Massa de teste que não deveria estar no repositório (todos os valores são fictícios).
CNS_PACIENTE = "700000000000005"
CARTAO_TESTE = "5500 0000 0000 0004"
RESPONSAVEL = "maria.silva@gmail.com"
TELEFONE_PLANTAO = "(11) 91234-5678"


def cobrar_procedimento(numero_cartao, valor):
    logger.info(f"Cobrança de R$ {valor} no cartão {numero_cartao}")
    return {"status": "enviado"}


def avisar_paciente(email, telefone):
    logger.info("Aviso enviado para %s / %s", email, telefone)
