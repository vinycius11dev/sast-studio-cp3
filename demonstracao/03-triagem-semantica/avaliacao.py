"""Exemplos para comparar a regra estática e a revisão contextual do LLM."""


def constante_interna():
    return eval("2 + 2")


def entrada_externa():
    user_input = input("Expressao recebida do usuario: ")
    return eval(user_input)
