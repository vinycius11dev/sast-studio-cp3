"""API de consulta de pacientes (exemplo fictício e vulnerável). Não executar."""
import requests
from flask import Flask, jsonify

app = Flask(__name__)


def carregar_cpf(paciente_id):
    return "00000000000"


def carregar_diagnostico(paciente_id):
    return "não informado"


def buscar_paciente(paciente_id):
    return {
        "id": paciente_id,
        "cpf": carregar_cpf(paciente_id),
        "diagnostico": carregar_diagnostico(paciente_id),
    }


@app.get("/pacientes/<int:paciente_id>")
def obter_paciente(paciente_id):
    paciente = buscar_paciente(paciente_id)
    return jsonify(paciente)


def enviar_para_parceiro(paciente_id):
    cpf = carregar_cpf(paciente_id)
    requests.post("https://parceiro.example/api/consulta", json={"cpf": cpf})
