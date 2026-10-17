# GitHub — entrega pública CP3

Repositório: https://github.com/vinycius11dev/sast-studio-cp3

Esta cópia tem histórico novo e apenas código, exemplos fictícios, testes e
documentação. Não contém bancos, uploads locais ou o PDF do enunciado.

## Publicação em validação

A publicação executa os checks **Security Gate** e **Docker smoke**. A proteção
da branch main e os PRs vulnerável/corrigido serão conferidos em seguida.
Este documento será atualizado com os resultados e links das execuções reais.

## Como outra pessoa executa

```powershell
git clone https://github.com/vinycius11dev/sast-studio-cp3.git
cd sast-studio-cp3
python -m pip install -r requirements.txt
ollama pull llama3.2:3b
python iniciar.py
```

Instale Python 3.11+ e Ollama antes desses comandos. No Windows também pode usar
iniciar.bat. A pessoa começa com seu próprio histórico local.
GitHub Actions executa o CI; o dashboard roda localmente ou em servidor
configurado. Publicar o código não hospeda automaticamente a aplicação.
