# Validação — SAST Studio 3.0 — 18/10/2026

## Recuperação de conexão — 19/10/2026

- Suíte completa: **516 testes Python aprovados**, 1 teste opcional ignorado e 2 avisos de dependências. Inclui recuperação real de um processo de API isolado, com PID novo, mesma porta e reabertura da análise salva no mesmo diretório de dados.
- JavaScript: **13 testes aprovados**, incluindo falha 502, reconexão, timeout, proteção contra pedidos duplicados e retomada da consulta de um trabalho já enviado.
- Navegador público: queda de rede simulada mostrou o aviso e preservou o editor após reconectar. Um 502 injetado na consulta de trabalho não reenviou a análise; o scanner concluiu o arquivo JavaScript com 0 achados, gate aprovado e execução nativa/Semgrep concluída (`b4b1e706`).
- O botão e a reconexão estão servidos no dashboard atual. A ativação do acompanhamento local em segundo plano foi bloqueada pela revisão automática da ferramenta. O usuário pode ativá-lo com dois cliques em `iniciar.bat`; a porta e o diretório de histórico atuais já estão configurados localmente.
- Registro desta rodada: [reliability-validation.json](quality/reliability-validation.json). Instruções e limites: [CONEXAO.md](CONEXAO.md). Docker, GitHub e inferências de IA não foram repetidos nesta mudança de conectividade.

Rechecagem local em 18/10/2026: suíte Python, scripts JavaScript, benchmark,
smoke da API e inferências reais de triagem/remediação via Ollama. Depois foi
reexecutada a suíte com as novas verificações do iniciador e o smoke completo
na prévia local da apresentação. Os itens de Docker, GitHub e concorrência/
persistência da fila abaixo são evidências da execução anterior, registradas em
17/10/2026; não foram repetidos nesta rechecagem.

## Testes e integração

| Verificação | Resultado |
| --- | --- |
| Pytest — 18/10 | 98 aprovados; 2 avisos de depreciação vindos de dependências; nenhum erro de teste |
| Node — 18/10 | 4 testes de diff aprovados; sintaxe dos dois scripts validada |
| Iniciador — 18/10 | Versão antiga na porta 8000 detectada e instrução de recuperação exibida; 3 testes novos aprovados |
| Corpus rotulado — 18/10 | 53 casos, 24 controles seguros, TP 30, FP 0, FN 0 nesta base; mediana 0,1769 ms; p95 0,6102 ms |
| Smoke local — 18/10 | API na prévia `8004`; 4 casos de código e projetos vulnerável/corrigido; 9 achados/bloqueado versus 0/aprovado; JSON, SARIF e Markdown |
| IA local — 18/10 | Triagem e remediação reais via Ollama `llama3.2:3b`; 81,25 s na primeira chamada com modelo frio e 28,21 s na remediação; modelo carregado ao final |
| Docker — 17/10 | API e worker saudáveis; usuário uid 1001; dados preservados após reiniciar os containers |
| Fila — 17/10 | Persistência, claim concorrente, lease expirado, falha e limpeza de payload testados |
| Ollama no Docker — 17/10 | Inferência real via host.docker.internal, risco externo confirmado como CRITICAL |
| GitHub — 17/10 | Evidências e status próprios em GITHUB_CP3.md; main protegida e bloqueio de merge comprovado |

## Rechecagem de correção — 19/10/2026

| Verificação | Resultado |
| --- | --- |
| Pytest — 19/10 | 114 aprovados; 2 avisos de depreciação em dependências; nenhum erro de teste. |
| Node — 19/10 | 4 testes do visualizador de diff aprovados; sintaxe do dashboard JavaScript validada. |
| Iniciador — 19/10 | Detectou a instância atual em `8004` apesar da versão antiga em `8000`; 5 testes do iniciador aprovados. |
| Apresentação — 19/10 | Página `200` local; as 5 capturas são embutidas no HTML e carregam sem pedidos externos de imagem. |
| Cloudflare protegido — 19/10 | Após o PIN, o dashboard carregou o histórico e indicou o Ollama disponível. Porém, `/api/v1/samples` voltou a ser redirecionado pelo Cloudflare Access; o scanner exibiu erro de rede e não iniciou uma nova varredura por esse túnel. |
| Cloudflare temporário aberto — 19/10 | Túnel sem PIN para `8004`: `/health`, status Ollama e `/api/v1/samples` responderam. Pela interface, a amostra vulnerável gerou 9 achados/bloqueado (`f7023e6a`); a corrigida gerou 0/aprovado (`ec8e6209`). Ollama `llama3.2:3b` gerou remediação real; a análise estática da sugestão retornou 0 achados (`57998459`). Nenhuma dessas execuções teve erro de processamento. |
| Scanner — 19/10 | Amostra JavaScript vulnerável: 3 achados e gate bloqueado; versão corrigida: 0 achados e gate aprovado. |
| IA — 19/10 | Revisão semântica real e remediação via Ollama `llama3.2:3b`; sugestão Python validada com 0 achados, sem fallback. |
| Patches JavaScript — 19/10 | Testes cobrem rejeição de identificador inventado, exigência de validação antes de `execFile`, ausência de troca genérica de `eval()` por `JSON.parse()` e segredo de ambiente com falha explícita se ausente. |
| Varredura completa local — 19/10 | Na instância local `8004`, amostra multilíngue: 8 arquivos, 47 achados, gate bloqueado; demonstração corrigida: 3 arquivos, 0 achados, gate aprovado. Nenhum erro de processamento. |

## Evidências adicionais de inferência — 17/10

- Dois eval em funções diferentes: a revisão do caso com constante retornou
  possível falso positivo/INFO; input→eval retornou confirmado/CRITICAL/alta confiança.
- A inferência também foi executada no Docker usando o Ollama do host.
- O modelo produziu uma classificação incorreta durante o desenvolvimento. Foram
  acrescentadas observações AST e validação contra rebaixamento de input→eval.
  As recomendações permanecem consultivas; achado e gate originais são preservados.

## Interface e fluxos — conferência de 17/10

Os testes anteriores de upload pelo seletor, editor inválido, filtros,
paginação, relatórios, diff, navegação e largura de 390 px foram mantidos.
A versão 3.0 acrescenta acompanhamento de jobs e revisão semântica com filtros.
A conferência final desses fluxos é registrada também nas capturas de tela.

As pastas de demonstração produzem 9 achados em 3 arquivos vulneráveis e
0 nas regras atuais em 3 arquivos corrigidos. A pasta samples produz
47 achados em 8 arquivos. Não há execução das funções vulneráveis.

A remediação Python real propôs ast.literal_eval. O diff foi verificado com
git apply --check. A correção Java SQL preservou o arquivo e compilou com javac 17;
as outras regras do mesmo arquivo permaneceram visíveis. A validação estática da
sugestão não substitui testes de comportamento ou revisão humana.

## Reprodução local

```powershell
python -m pytest -q -W error::pytest.PytestUnhandledThreadExceptionWarning
node --test tests/diff-viewer.test.cjs
python -m scripts.benchmark --output reports/benchmark.json --markdown reports/benchmark.md
python -m scripts.smoke
python -m scripts.smoke --require-llm
```

Inicie o aplicativo com `iniciar.bat` antes dos comandos de smoke. O comando sem
`--require-llm` verifica a API, a fila, os exemplos, os gates e os relatórios. O
comando com `--require-llm` também executa inferências novas de triagem e
remediação e falha se o resultado for fallback. Os arquivos JSON são ignorados
pelo Git; a evidência detalhada desta execução fica em `reports/smoke-result.json`.
O tempo de resposta varia conforme o computador. O resultado do corpus é uma
medição interna delimitada, não uma avaliação externa da segurança de qualquer projeto.

## Conferência final da interface 3.0

- Nova análise pela fila: vulnerável 3 arquivos/9 achados; corrigida 3/0.
- Revisar com IA pela interface retornou Ollama, confirmado/CRITICAL/alta confiança.
- Gerar remediação retornou Ollama e ast.literal_eval; Analisar sugestão encontrou 0 achados no trecho.
- O modal do diff abriu com contexto, linhas removidas/adicionadas e downloads.
- As seis telas foram navegadas pelo menu móvel em 390 × 844, sem overflow horizontal.
- Docker final: dois workers ativos e saudáveis; smoke completo aprovado.
- GitHub: entrega verde; PR vulnerável vermelho por PY-R001; corrigido verde.

## Publicação pública

A cópia pública passou no CI. Proteção de main aplicada inclusive a administradores,
com Security Gate e Docker smoke obrigatórios. PR #1: FAILURE/BLOCKED; PR #2:
SUCCESS/CLEAN. A consulta e os links estão em GITHUB_CP3.md e github-protection.json.


## Evolução de cobertura — 19/10/2026

- 43 IDs de regras nativas: Python 18, JavaScript/TypeScript 13 e Java 12.
- Corpus ampliado: 320 casos/124 controles seguros,200 ocorrências positivas esperadas, sem FP/FN nesta base curada; cinco repetições. Ver BENCHMARK.md e o hash do corpus.
- OWASP BenchmarkJava 1.2: 2.740 casos completos, resultados e falhas por CWE em quality/owasp-native-results.{json,md}; o score externo revela limitações substanciais de precisão/recall. O snapshot anterior é preservado.
- Motores reais instalados em ambiente independente: Bandit 1.9.4 e Semgrep CE 1.181.0, com 9 regras Semgrep locais versionadas.
- Teste pelo túnel público, com fila/worker: três arquivos vulneráveis (Java, Python, JS),4 achados após deduplicação conservadora e gate bloqueado; três arquivos parametrizados,0 achados e gate aprovado. Os três motores concluíram sem erro. Cada execução foi salva de fato; não são contadores simulados.
- Ollama real llama3.2:3b: geração de patch SQL MySQL concluída em 58,8s, preservando callback/resposta e parâmetros?, com validador estático aprovado. A primeira revisão semântica excedeu o tempo; após limitar o orçamento da revisão, uma chamada real concluiu em 62,7s. Ambos os resultados estão registrados em quality/live-validation.json.
- Ambiente durante a análise de lentidão: modelo em CPU, sem VRAM e cerca de 0,6GiB livres de RAM. Isso limita latência/estabilidade; nenhum programa do usuário foi encerrado para recuperar memória.
- UI conferida no navegador em 1600x1000, sem overflow horizontal ou erros de console nas telas alteradas. Evidência combinada nativo/Semgrep e fluxo Python local foram exibidos.
- SARIF validado contra cópia oficial do esquema OASIS 2.1.0; 4 testes Node do diff aprovados. Typecheck, testes de aplicações submetidas, equivalência funcional e isolamento por OS são explicitamente não executados no gate de patches.
- A versão atual roda em 127.0.0.1:8001 com histórico/fila próprios em data/coverage-v3. O launcher foi validado para encontrar essa instância e não reutilizar o motor anterior da porta 8000. O túnel temporário aponta para 8001.

O diagnóstico, as funcionalidades parciais e as prioridades estão em [EVOLUCAO_SAST.md](EVOLUCAO_SAST.md). Esta evolução não declara atendimento integral a todos os itens do plano de arquitetura nem cobertura universal.

Suíte final desta evolução: **504 testes Python aprovados**, incluindo a integração real com os motores opcionais, e **4 testes Node aprovados**. Após o último ajuste de exclusão dos diretórios locais tmp/graphify-out, os 37 testes relevantes de API/workspace/orquestração passaram; a integração opcional já havia sido executada na suíte completa.
