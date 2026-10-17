# Validação — SAST Studio 3.0 — 17/10/2026

## Testes e integração

| Verificação | Resultado |
| --- | --- |
| Pytest | 91 aprovados; 2 avisos de depreciação de dependências; sem avisos de threads não tratadas |
| Node | 4 testes de diff aprovados; sintaxe dos dois scripts validada |
| Corpus rotulado | 53 casos, 24 controles seguros, TP 30, FP 0, FN 0 nesta base; métricas em BENCHMARK.md |
| Smoke local e Docker | Fila, parsers AST, projetos, gates e exportações exercitados pela API real |
| Docker | API e worker saudáveis; usuário uid 1001; dados preservados após reiniciar os containers |
| Fila | Persistência, claim concorrente, lease expirado, falha e limpeza de payload testados |
| Ollama local | Revisão semântica real e remediação com llama3.2:3b |
| Ollama no Docker | Inferência real via host.docker.internal, risco externo confirmado como CRITICAL |
| GitHub | Evidências e status próprios em GITHUB_CP3.md; proteção de branch pública em validação |

## Evidências de inferência real

- Dois eval em funções diferentes: a revisão do caso com constante retornou
  possível falso positivo/INFO; input→eval retornou confirmado/CRITICAL/alta confiança.
- A inferência também foi executada no Docker usando o Ollama do host.
- O modelo produziu uma classificação incorreta durante o desenvolvimento. Foram
  acrescentadas observações AST e validação contra rebaixamento de input→eval.
  As recomendações permanecem consultivas; achado e gate originais são preservados.

## Interface e fluxos

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

## Reprodução

```powershell
python -m pytest -q -W error::pytest.PytestUnhandledThreadExceptionWarning
node --test tests/diff-viewer.test.cjs
python -m scripts.benchmark
python -m scripts.smoke --require-llm
```

O smoke verifica disponibilidade do LLM, sem gastar uma inferência. Use os botões
de IA para comprovar uma resposta nova. O resultado do corpus é uma medição
interna delimitada, não uma avaliação externa da segurança de qualquer projeto.

## Conferência final da interface 3.0

- Nova análise pela fila: vulnerável 3 arquivos/9 achados; corrigida 3/0.
- Revisar com IA pela interface retornou Ollama, confirmado/CRITICAL/alta confiança.
- Gerar remediação retornou Ollama e ast.literal_eval; Analisar sugestão encontrou 0 achados no trecho.
- O modal do diff abriu com contexto, linhas removidas/adicionadas e downloads.
- As seis telas foram navegadas pelo menu móvel em 390 × 844, sem overflow horizontal.
- Docker final: dois workers ativos e saudáveis; smoke completo aprovado.
- GitHub: entrega verde; PR vulnerável vermelho por PY-R001; corrigido verde.
