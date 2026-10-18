# Aderência ao enunciado — CP3 — atualização 18/10/2026

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
| Violações iniciais | 6 | 19 regras; demonstração de 3 arquivos com 9 achados e versão corrigida com 0 nas regras atuais. |
| Taint analysis | 7 | Fluxo básico em Python, com fontes, atribuições, sinks e sanitização numérica. Não é prova completa entre funções/arquivos. |
| LLM local / remediação | 7 | Ollama llama3.2:3b real; sugestão, diff e nova análise. Fallback identificado se a resposta falhar. |
| LLM / severidade e falso positivo | 7 | Revisão semântica sob demanda, severidade sugerida, classificação, confiança e evidências persistidas/exportadas. Achado e gate originais preservados. Modelo pode errar. |
| Processamento assíncrono e fila | 4 | HTTP 202, jobs duráveis, claim atômico, heartbeat, leases e workers separados no Docker. SQLite compartilhado em um host; sem broker distribuído. |
| Security Gate | 3, 9 | CLI/API compartilham política e códigos 0/1/2; erro de parsing impede aprovação. |
| CI/CD / PR | 9 | Workflow com testes, benchmark, autoauditoria e smoke Docker. Esta versão passou no GitHub; PR vulnerável reprovou por PY-R001 e PR corrigido aprovou. Links em GITHUB_CP3.md. |
| Impedir merge inseguro | 9 | Demonstrado: main protegida, dois checks obrigatórios inclusive para administradores; PR vulnerável BLOCKED e corrigido CLEAN. Evidências em GITHUB_CP3.md. |
| Dashboard / relatórios | 9 | Arquivo, linha, severidade, filtros CWE/OWASP, comparação de execuções salvas, ranking dos cinco arquivos com mais achados, histórico, revisão IA e JSON/Markdown/SARIF. |
| Robustez / desempenho | 10 | 95 testes Python e 4 Node; corpus curado de 53 casos, 24 controles seguros, 0 FP/FN nesta base. BENCHMARK.md delimita a medição; não representa precisão universal. |
| Defesa | 9, 10 | Roteiro e comandos em APRESENTACAO.md; o aluno ainda precisa ensaiar. |

## Rubrica

| Peso | Critério | Evidência |
| --- | --- | --- |
| 25% | Arquitetura | Módulos separados, parsers AST, API/worker em containers e fila durável. Distribuição entre hosts não implementada. |
| 30% | Robustez SAST | Regressões e corpus rotulado, exemplos seguros/vulneráveis e erros tratados. Cobertura limitada às regras e ao fluxo implementados. |
| 20% | Inovação IA | Inferência local real para triagem e remediação, com rastreabilidade e validação. Sem garantia de acerto do modelo. |
| 15% | DevSecOps | Workflow e gate executados no GitHub público, proteção obrigatória ativa e PRs vulnerável/corrigido verificados. |
| 10% | Defesa | Arquitetura, benchmark, relatórios e roteiro disponíveis; exige domínio do aluno. |

As tecnologias da página 5 são recomendações. A fila SQLite oferece as
capacidades locais descritas; não deve ser apresentada como Redis/Celery nem
como arquitetura distribuída entre máquinas.

Não é possível prometer nota ou atendimento integral sem a avaliação do
professor. O bloqueio obrigatório foi comprovado. Os limites de análise, IA e arquitetura
permanecem explícitos nesta documentação.
