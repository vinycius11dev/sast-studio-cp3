"""API de consulta de pacientes (versão corrigida). Não executar."""
import hashlib

import requests
from flask import Flask, jsonify

app = Flask(__name__)


def carregar_cpf(paciente_id):
    return "00000000000"


def mascarar_cpf(cpf):
    return "***.***.***-" + cpf[-2:]


@app.get("/pacientes/<int:paciente_id>")
def obter_paciente(paciente_id):
    cpf = carregar_cpf(paciente_id)
    return jsonify({"id": paciente_id, "cpf": mascarar_cpf(cpf)})


def enviar_para_parceiro(paciente_id):
    cpf = carregar_cpf(paciente_id)
    identificador = hashlib.sha256(cpf.encode()).hexdigest()
    requests.post("https://parceiro.example/api/consulta", json={"identificador": identificador})
