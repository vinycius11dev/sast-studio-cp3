"""Amostra de código com fluxo de Taint Analysis (CP 2 - FIAP).

Demonstra dados de entrada de usuário (Sources) que fluem através de variáveis
e concatenações até funções sensíveis (Sinks), sem sanitização.
"""


def handle_login(request, db_cursor):
    # [Source] Entrada de usuário via query parameter
    untrusted_username = request.args.get("username")

    # [Propagação] A variável contamina a query SQL por concatenação direta
    query = "SELECT * FROM users WHERE username = '" + untrusted_username + "'"

    # [Sink 1] Execução de query vulnerável a SQL Injection (CWE-89)
    db_cursor.execute(query)


def download_report(request):
    # [Source] Entrada via parâmetro de formulário
    untrusted_file = request.form.get("report_name")

    # [Sink 2] Acesso direto ao sistema de arquivos vulnerável a Path Traversal (CWE-22)
    with open(untrusted_file, "r") as f:
        return f.read()
