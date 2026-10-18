# Validação — SAST Studio 3.0 — 18/10/2026

Rechecagem local em 18/10/2026: suíte Python, scripts JavaScript, benchmark,
smoke da API e inferências reais de triagem/remediação via Ollama. Os itens de
Docker, GitHub e concorrência/persistência da fila abaixo são evidências da
execução anterior, registradas em 17/10/2026; não foram repetidos nesta rechecagem.

## Testes e integração

| Verificação | Resultado |
| --- | --- |
| Pytest — 18/10 | 95 aprovados; 2 avisos de depreciação vindos de dependências; nenhum erro de teste |
| Node — 18/10 | 4 testes de diff aprovados; sintaxe dos dois scripts validada |
| Corpus rotulado — 18/10 | 53 casos, 24 controles seguros, TP 30, FP 0, FN 0 nesta base; mediana 0,1769 ms; p95 0,6102 ms |
| Smoke local — 18/10 | 4 casos de código e projetos vulnerável/corrigido; 9 achados/bloqueado versus 0/aprovado; JSON, SARIF e Markdown |
| IA local — 18/10 | Triagem e remediação reais via Ollama `llama3.2:3b`; 19,54 s e 13,29 s nesta máquina; modelo carregado ao final |
| Docker — 17/10 | API e worker saudáveis; usuário uid 1001; dados preservados após reiniciar os containers |
| Fila — 17/10 | Persistência, claim concorrente, lease expirado, falha e limpeza de payload testados |
| Ollama no Docker — 17/10 | Inferência real via host.docker.internal, risco externo confirmado como CRITICAL |
| GitHub — 17/10 | Evidências e status próprios em GITHUB_CP3.md; main protegida e bloqueio de merge comprovado |

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
