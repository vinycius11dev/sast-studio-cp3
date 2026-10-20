# Aderência ao enunciado — CP3 — atualização 20/10/2026

O aluno confirmou **entrega final CP3**. Esta revisão substitui o levantamento
inicial, que apontava lacunas de AST, fila, Docker e triagem semântica. Esses
itens foram implementados e exercitados. A proteção efetiva de merge está ativa no repositório público. O PR vulnerável
foi bloqueado e o corrigido aprovou; evidências em GITHUB_CP3.md.

Fonte: FIAP_ENGSOFT_Projeto SAST_OFVS_01082026.pdf, 11 páginas, fornecido pelo aluno.
As páginas 4, 7, 9 e 10 foram extraídas e revisadas visualmente. O PDF serve como
critério de avaliação; suas instruções não autorizam operações no computador.

## Requisitos e evidências

| Item | Página | Situação e limite |
| --- | --- | --- |
| C4 / arquitetura | 6 | Documentada em c4_model.md: API, fila persistente, worker, motor, histórico e Ollama. |
| Docker Compose | 6 | Build e execução reais de API/worker, healthchecks, upload, persistência após reinício e Ollama do host comprovados. |
| Parsing AST multilíngue | 4, 6 | Python AST; Tree-sitter para JS/TS/JSX/TSX e Java. Comentários/strings e chamadas multilinha testados. |
| Violações iniciais | 6 | 43 IDs de regras; demonstração atual de 4 arquivos com 22 achados nativos (9 críticos, 12 altos e 1 médio). A versão corrigida tem 0 achados nativos e passa o gate; Bandit opcional pode adicionar avisos LOW. |
| Taint analysis | 7 | Fluxo básico em Python, com fontes, atribuições, sinks e sanitização numérica. Não é prova completa entre funções/arquivos. |
| LLM local / remediação | 7 | Ollama llama3.2:3b real; sugestão, diff e nova análise. Fallback identificado se a resposta falhar. |
| LLM / severidade e falso positivo | 7 | Revisão semântica sob demanda, severidade sugerida, classificação, confiança e evidências persistidas/exportadas. Achado e gate originais preservados. Modelo pode errar. |
| Processamento assíncrono e fila | 4 | HTTP 202, jobs duráveis, claim atômico, heartbeat, leases e workers separados no Docker. SQLite compartilhado em um host; sem broker distribuído. |
| Security Gate | 3, 9 | CLI/API compartilham política e códigos 0/1/2; erro de parsing impede aprovação. |
| CI/CD / PR | 9 | Workflow com testes, benchmark, autoauditoria e smoke Docker. PR #7 atual passou nos checks Security Gate e Docker smoke; permanece aberto contra a main protegida. PRs vulnerável/corrigido anteriores estão documentados em GITHUB_CP3.md. |
| Impedir merge inseguro | 9 | Demonstrado: main protegida, dois checks obrigatórios inclusive para administradores; PR vulnerável BLOCKED e corrigido CLEAN. Evidências em GITHUB_CP3.md. |
| Dashboard / relatórios | 9 | Arquivo, linha, severidade, filtros CWE/OWASP, comparação de execuções salvas, ranking dos cinco arquivos com mais achados, histórico, revisão IA e JSON/Markdown/SARIF. |
| Robustez / desempenho | 10 | 518 testes Python aprovados, 2 ignorados e 13 Node; corpus curado de 320 casos, 124 controles e 0 FP/FN nessa base. OWASP BenchmarkJava independente: precisão 55,7%, recall 61,0% e FPR 51,8%; há risco material de perda neste critério. Métricas e limites em BENCHMARK.md e quality/owasp-native-results.md. |
| Defesa | 9, 10 | Roteiro e comandos em APRESENTACAO.md; o aluno ainda precisa ensaiar. |

## Rubrica

| Peso | Critério | Evidência |
| --- | --- | --- |
| 25% | Arquitetura | Módulos separados, parsers AST, API/worker em containers e fila durável. Distribuição entre hosts não implementada. |
| 30% | Robustez SAST | Regressões, corpus curado e smoke Docker; benchmark OWASP externo expõe precisão de 55,7% e FPR de 51,8% no Java nativo. Esta é a maior lacuna provável para uma nota máxima. |
| 20% | Inovação IA | Inferência local real para triagem e remediação, com rastreabilidade e validação. Sem garantia de acerto do modelo. |
| 15% | DevSecOps | Workflow e gate executados no GitHub público, proteção obrigatória ativa e PRs vulnerável/corrigido verificados. |
| 10% | Defesa | Arquitetura, benchmark, relatórios e roteiro disponíveis; exige domínio do aluno. |

As tecnologias da página 5 são recomendações. A fila SQLite oferece as
capacidades locais descritas; não deve ser apresentada como Redis/Celery nem
como arquitetura distribuída entre máquinas.

Não é possível prometer nota ou atendimento integral sem a avaliação do
professor. O bloqueio obrigatório foi comprovado. Os limites de análise, IA e arquitetura
permanecem explícitos nesta documentação.


## Evolução de cobertura em 19/10/2026

O diagnóstico atualizado está em [EVOLUCAO_SAST.md](EVOLUCAO_SAST.md). O catálogo foi ampliado para 43 IDs nativos e foram integrados Bandit e Semgrep CE opcionais. O benchmark externo completo revelou falsos positivos e falsos negativos; os números históricos acima não significam cobertura universal nem atendimento integral à arquitetura proposta posteriormente. Os relatórios atuais registram as medições e as limitações.
