# Roteiro de defesa — entrega final CP3

A página de apresentação usa o endereço exibido ao iniciar o aplicativo
(normalmente http://127.0.0.1:8000/apresentacao). Ela reúne a proposta, o fluxo
técnico, capturas reais e os comandos para iniciar.
Use **Abrir sistema** para sair da apresentação e voltar ao dashboard.

## Antes da aula

1. Abra o Ollama e execute `ollama list`: o modelo deve ser `llama3.2:3b`.
2. Dê dois cliques em `iniciar.bat` e abra o endereço que ele mostrar. Se a
   porta 8000 estiver ocupada, o iniciador reutiliza outra instância atual ou
   escolhe uma porta livre para não abrir uma versão antiga.
3. Em **Integrações**, confirme API, worker da fila e Ollama disponíveis.
4. Gere uma sugestão antes de apresentar para carregar o modelo na memória.
   A primeira chamada fria levou 81 segundos nesta máquina; depois que o modelo
   carregou, a remediação levou 28 segundos. Inferências têm limite de 90 segundos.
5. Abra antecipadamente os Pull Requests e os logs de Actions indicados em
   `docs/GITHUB_CP3.md` (PR #1 vulnerável e PR #2 corrigido).
6. Mantenha notebook, carregador, servidor e Ollama ligados. A análise e a IA locais
   funcionam sem internet depois de instalar dependências e baixar o modelo; o GitHub exige rede.

## Demonstração em 8 a 10 minutos

| Tempo | Ação e explicação |
| --- | --- |
| 0–1 min | Explique que SAST inspeciona fontes sem executar o projeto. Mostre a arquitetura: API, fila persistente, worker, parsers, histórico e LLM. Python usa AST; JS/TS e Java usam Tree-sitter. |
| 1–3 min | Scanner → **Carregar pasta vulnerável** → **Executar análise**. São 3 arquivos, 9 achados (6 críticos e 3 altos), gate bloqueado. A tela envia um job e acompanha o worker. Abra um achado e mostre regra, CWE, arquivo, linha e contexto. |
| 3–5 min | Selecione **PY-R001** em `backend/servico.py`, clique **Revisar com IA** e mostre a classificação contextual, severidade sugerida, confiança e evidências. Depois clique **Gerar remediação**: mostre o selo Ollama, a sugestão e **Ver alterações (diff)**. Vermelho remove, verde adiciona. **Analisar sugestão** roda novamente o scanner. |
| 5–6 min | Scanner → **Carregar pasta corrigida** → executar. São 3 arquivos, 0 achados nas regras atuais e gate aprovado. Volte à Visão geral: compare as duas execuções salvas e mostre o ranking de arquivos da análise vulnerável. Clique em um arquivo para abrir seus achados filtrados. A IA não sobrescreve os arquivos do computador. |
| 6–7 min | Escolha a pasta `demonstracao/03-triagem-semantica`: há dois eval detectados. Revise os dois pela IA: um opera sobre constante e o outro recebe `input()`. Compare o contexto e o filtro de possíveis falsos positivos. Respostas do LLM variam; o gate original permanece rastreável. |
| 7–8 min | Histórico → reabra a execução vulnerável → exporte JSON, Markdown ou SARIF. Mostre CWE e OWASP Top 10:2025 nos achados e relatórios, a análise correta e as revisões de IA persistidas. |
| 8–10 min | GitHub → PR vulnerável com Security Gate vermelho, depois PR corrigido com checks verdes. Mostre o log, a regra detectada e os relatórios. Mostre que main exige os checks: o PR #1 fica bloqueado e o #2 passa. |

Para selecionar uma pasta use **Escolher pasta** e selecione somente a subpasta
desejada. Os botões de demonstração carregam as mesmas fontes sem usar a janela
do Windows. Não selecione `demonstracao` inteira: isso mistura as versões.

## Como testar antes de apresentar

Primeiro abra o Ollama e inicie o aplicativo com `iniciar.bat`. Deixe as duas
janelas abertas. Depois dê dois cliques em `verificar_apresentacao.bat`, ou
execute este comando no PowerShell, dentro da pasta do projeto:

```powershell
python -m scripts.smoke --require-llm
```

O resultado esperado é **SAST smoke: APROVADO**. A verificação percorre os
exemplos vulnerável e corrigido, confirma os gates e os três formatos de relatório.
Com `--require-llm`, ela também faz chamadas novas de triagem e remediação e
exige que ambas retornem `Ollama`; fallback não conta como IA aprovada. O resumo
JSON fica em `reports/smoke-result.json`.

Se quiser validar os fluxos sem gastar tempo com inferências do modelo, execute
`python -m scripts.smoke`. Para a conferência completa, use o comando com
`--require-llm` antes da aula, pois a geração pode levar até 90 segundos por ação.

Para conferir a suíte automatizada e o corpus rotulado:

```powershell
python -m pytest -q -W error::pytest.PytestUnhandledThreadExceptionWarning
node --test tests/diff-viewer.test.cjs
python -m scripts.benchmark --output reports/benchmark.json --markdown reports/benchmark.md
```

Se a checagem de IA falhar, abra o Ollama, confirme `ollama list` e carregue o
modelo com `ollama run llama3.2:3b`; depois repita o smoke completo. Na interface,
mostre o selo do provedor retornado. Fallback determinístico não deve ser
apresentado como resposta do LLM.

## Respostas para a defesa

- **Por que AST?** Analisa a estrutura do código e evita tratar texto de comentários e strings como chamadas reais.
- **Por que fila?** Desacopla o pedido HTTP do processamento, persiste jobs e permite workers concorrentes no mesmo host.
- **Por que SQLite, e não Redis/Celery?** O enunciado apresenta tecnologias recomendadas. A fila SQLite atende ao processamento assíncrono e persistente em um host, com menos dependências; Redis/Celery e banco distribuído seriam o próximo passo para escalar entre hosts.
- **Onde entra a IA?** Revisa contexto, possível falso positivo e severidade; também propõe correções. As regras estáticas continuam sendo a origem dos achados e do gate.
- **Como mediu?** Testes de regressão, smoke de API/Docker e corpus rotulado com 53 casos e 24 controles seguros. Os números desse corpus não provam precisão universal nem medem a precisão do LLM.
- **O que significa zero achados?** Nenhuma regra atual detectou risco naquela entrada. Não comprova segurança absoluta.
- **Limites?** Fluxo Python básico, sem prova completa entre arquivos; LLM pode errar; fila SQLite local; sem autenticação multiusuário.
- **Onde roda?** Localmente ou em um servidor configurado. GitHub Actions executa a análise e guarda evidências; publicar o código no GitHub não hospeda automaticamente o dashboard.


## Demonstração após ampliar os motores

As contagens do roteiro acima pertencem ao conjunto original de três arquivos e ao perfil nativo. A instalação pode incluir um quarto arquivo de testes adicionado pelo usuário; Bandit e Semgrep também podem acrescentar evidências e alertas. Use a contagem real da execução. Em **Regras de análise**, mostre o corpus curado e o OWASP Benchmark separadamente e explique as limitações. Em **Integrações**, confirme os motores ativos; em **Achados**, abra as evidências e, quando existente, o fluxo local rastreado. A aprovação estática de um patch não equivale a executar testes da aplicação.
