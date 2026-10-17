# GitHub — entrega pública CP3

Repositório: [vinycius11dev/sast-studio-cp3](https://github.com/vinycius11dev/sast-studio-cp3).
Branch de entrega: **main**. Histórico novo, sem commits antigos, bancos locais,
uploads ou PDF do enunciado. As credenciais das amostras são fictícias.

## Evidências verificadas em 17/10/2026

| Evidência | Resultado |
| --- | --- |
| [CI da publicação](https://github.com/vinycius11dev/sast-studio-cp3/actions/runs/39063473391) | Security Gate e Docker smoke aprovados |
| [PR #1 — vulnerável](https://github.com/vinycius11dev/sast-studio-cp3/pull/1) | Security Gate reprovado; merge BLOCKED |
| [CI vulnerável](https://github.com/vinycius11dev/sast-studio-cp3/actions/runs/39063516829) | Saída 1; SARIF: PY-R001, linha 2, eval(entrada); Docker aprovado |
| [PR #2 — corrigido](https://github.com/vinycius11dev/sast-studio-cp3/pull/2) | Ambos os checks aprovados; merge CLEAN |
| [CI corrigido](https://github.com/vinycius11dev/sast-studio-cp3/actions/runs/39063520697) | Testes, benchmark, auditoria e Docker aprovados |

Os dois PRs alteram somente audit-target/demo.py e permanecem abertos como
evidência. A função vulnerável não é executada: o SAST inspeciona o código.
O PR corrigido demonstra a alternativa json.loads ao eval; não precisa ser
mesclado para utilizar a plataforma.

## Proteção de main — ativa

A configuração foi aplicada e relida pela API do GitHub:

- **Security Gate** e **Docker smoke** obrigatórios, vinculados ao GitHub Actions.
- Branch do PR precisa estar atualizada com main.
- Regras aplicadas **inclusive a administradores**.
- Mudanças por Pull Request; sem obrigar aprovação de outra pessoa nesta demonstração individual.
- Force push e exclusão da branch desabilitados.
- Conversas precisam estar resolvidas.

A consulta do PR #1 confirmou **mergeStateStatus = BLOCKED** com Security Gate
FAILURE. O PR #2 confirmou **CLEAN** com ambos os checks SUCCESS. O registro
estruturado desta verificação está em [github-protection.json](github-protection.json).
O estado pode mudar se novos commits ou configurações forem alterados.

## Como mostrar em sala

1. Abra o PR #1 → Checks → Security Gate → etapa de auditoria: falha com saída 1.
2. Na execução de Actions, abra o resumo e baixe o artifact **sast-reports**.
   O arquivo audit-target.sarif contém PY-R001/CWE-95, linha 2.
3. Volte à conversa do PR e mostre o bloqueio de merge.
4. Abra o PR #2 e mostre os checks verdes. Compare os arquivos: eval versus json.loads.
5. Explique que o CI aplica a mesma política de severidade da CLI e da API.

O CI usa Ubuntu 24.04 e Python 3.11. O runner não contém o modelo Ollama;
a inferência real foi exercitada localmente e no Docker com o modelo do host.
A IA auxilia a revisão e a remediação; os checks de gate são determinísticos.

## Como outra pessoa baixa e executa

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
