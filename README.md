# SAST Studio

Workspace de segurança de código com parsers estruturais, fila persistente, triagem semântica, histórico, relatórios e remediação assistida por Ollama. Projeto acadêmico de Engenharia de Software — FIAP, CP3, 2026. Versão 3.0.0.

## Iniciar

```powershell
git clone https://github.com/vinycius11dev/sast-studio-cp3.git
cd sast-studio-cp3
```


Instale as dependências uma vez:

```powershell
python -m pip install -r requirements.txt
```

No Windows, dê dois cliques em **iniciar.bat** ou execute **python iniciar.py**. O inicializador abre o navegador e reutiliza o servidor quando a aplicação já está na porta 8000. Mantenha a janela do servidor aberta durante a apresentação.

- Workspace: http://127.0.0.1:8000/dashboard
- API: http://127.0.0.1:8000/docs
- Saúde: http://127.0.0.1:8000/health

Para desenvolvimento:

```powershell
python -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

## Fluxo da interface

1. No Scanner, escolha pasta, arquivo ou Editor. Confira a seleção e o limiar do gate.
2. Clique em Executar análise.
3. Em Achados, filtre por severidade, arquivo, regra ou CWE. Selecione um item para ver o contexto e a linha.
4. Use **Revisar com IA** para avaliar severidade e possíveis falsos positivos com evidências. Os filtros de revisão usam a avaliação mais recente. O achado e o gate originais são preservados.
5. Gere uma remediação e abra **Ver alterações (diff)**. Vermelho indica remoção; verde indica adição. Há download .patch e .txt. Analisar sugestão executa as regras sobre o código proposto.
6. Exporte SARIF, JSON ou Markdown da análise selecionada, incluindo as revisões semânticas registradas.
7. Reabra execuções no Histórico. A visão geral usa os dados dessas execuções.

O código não é executado. Limites: 200 arquivos, 25 MB por projeto e 5 MB por arquivo. Dependências, caches e builds são ignorados no navegador e na API.

Fontes, resultados e revisões ficam em **data/scans.sqlite3**. A fila usa **data/jobs.sqlite3**. O diretório é ignorado pelo Git e pelo build Docker. Os testes usam bancos temporários.

## Fila e workers

A interface envia análises com `?queued=true`, recebe HTTP 202 com um job_id e consulta o andamento até obter o scan_id. A fila é persistente, com reserva atômica, lease renovável e recuperação de jobs de workers interrompidos.

Na execução local, a API inicia um worker embutido para permitir o uso de iniciar.bat. No Docker, **API e worker são processos em contêineres separados** e compartilham um volume persistente. Para outro worker local, use `python -m api.worker`; configure `SAST_EMBEDDED_WORKER=0` se quiser desativar o consumidor embutido. Integrações mostra workers ativos e contagens da fila.

## IA local

Deixe o aplicativo Ollama em execução. Para uma nova instalação:

```powershell
ollama pull llama3.2:3b
ollama list
```

Integrações consulta a disponibilidade do serviço e do modelo. Na remediação, **Ollama (llama3.2:3b)** identifica uma resposta real do modelo; **Motor determinístico (Fallback)** identifica orientação por regras e explica o motivo da contingência.

A primeira geração pode demorar. Gere uma revisão ou sugestão antes da aula para carregar o modelo. As respostas são recomendações para revisão, sem aplicação automática. A detecção usa as regras SAST; o LLM faz triagem contextual e sugere remediações. No caso JDBC, a sugestão pode conter o arquivo completo. Respostas inválidas recebem uma segunda tentativa dentro do mesmo limite total de tempo. Falhas de triagem permanecem identificadas como indisponíveis e não alteram o gate.

| Variável | Padrão |
| --- | --- |
| OLLAMA_BASE_URL | http://localhost:11434 |
| OLLAMA_MODEL | llama3.2:3b |
| OLLAMA_REQUEST_TIMEOUT | 90 segundos |
| OLLAMA_KEEP_ALIVE | 30m |
| SAST_DATA_DIR | ./data |
| SAST_EMBEDDED_WORKER | 1 local; 0 nos serviços Docker |
| SAST_PORT | 8000 (porta publicada pelo Compose) |
| ALLOWED_ORIGINS | localhost/127.0.0.1:8000 |

## Motor e cobertura

| Linguagem | Extensões | Técnica |
| --- | --- | --- |
| Python | .py | AST nativa e fluxo de dados básico |
| JavaScript / TypeScript | .js .jsx .ts .tsx | AST Tree-sitter com gramáticas JS/TS/TSX e regras estruturais |
| Java | .java | AST Tree-sitter e regras estruturais |

Consulte o catálogo da interface ou **python cli.py rules** para a cobertura exata. Há regras para execução dinâmica, segredos, comandos, SQL Injection, XSS, SSRF e arquivos inseguros, conforme a linguagem.

Limites acadêmicos: o fluxo de dados é básico e não há análise completa entre arquivos. Tree-sitter verifica estrutura sintática, sem substituir a compilação ou a resolução de tipos/dependências. A triagem do LLM pode errar, é contextual e não suprime achados automaticamente. A fila SQLite atende uma instalação em um host; não é um broker para distribuição entre vários servidores. Ausência de achados significa que as regras aplicadas não encontraram um padrão de risco.

## CLI e gate

```powershell
python cli.py rules
python cli.py scan ./samples/vulnerable_sample.py --fail-on HIGH
python cli.py scan ./samples/secure_sample.py --fail-on HIGH
python cli.py scan ./samples -f sarif -o sast-results.sarif --fail-on HIGH
python cli.py scan ./samples/vulnerable_sample.py --ai -f json -o resultado.json
```

A API e a CLI compartilham a decisão do gate. A API usa HIGH por padrão; use --fail-on HIGH na CLI para a mesma política.

| Saída | Significado |
| --- | --- |
| 0 | Concluída sem achados bloqueantes |
| 1 | Achados no limiar ou acima |
| 2 | Erro de leitura, sintaxe ou processamento incompleto |

Erros impedem a aprovação. JSON e SARIF continuam estruturados quando usados com --ai.

## GitHub Actions e Docker

O workflow **.github/workflows/sast_security_gate.yml** cobre main, master, develop e a branch de entrega codex/cp3-studio. O check **Security Gate** executa testes Python/JavaScript, benchmark e auditoria de engine/, api/, cli.py e audit-target/. O check **Docker smoke** constrói os contêineres e exercita a API/fila/relatórios. Os relatórios ficam como artifacts e resumo do job. Para impedir merges, configure ambos como obrigatórios. A disponibilidade de proteção em repositórios privados depende do plano do GitHub.

A tela Integrações oferece o workflow e o comando CLI. Para outro repositório, inclua o motor e suas dependências e ajuste os caminhos do alvo. A prévia local não altera Pull Requests.

```powershell
docker compose up --build
docker compose up -d --scale sast-worker=2
docker compose --profile cli run --rm sast-cli-runner scan /app/samples --fail-on HIGH
```

O contêiner roda sem root. O volume sast-data preserva o histórico. O Ollama do host é acessado por host.docker.internal:11434; altere OLLAMA_BASE_URL para outro serviço.

## API e estrutura

As rotas /api/v1/scan/code, /scan/file e /scan/project analisam fontes. /api/v1/scans lista o histórico; /scans/{id} reabre um resultado; /scans/{id}/source consulta apenas fontes daquela análise; /scans/{id}/report exporta o resultado escolhido. /api/v1/remediate gera sugestões, /ai/status diagnostica o modelo e /rules expõe o catálogo. Consulte /docs para os contratos completos.

- api/main.py: endpoints, validação e orquestração.
- api/store.py: persistência SQLite.
- engine/engine.py e languages/: roteamento e scanners.
- engine/rules/: AST e taint Python.
- engine/policy.py: política compartilhada.
- engine/ai_remediation.py: Ollama, validações e fallback.
- engine/reporter.py: JSON, Markdown e SARIF.
- static/: workspace web sem etapa de build.
- tests/: motor, API, histórico, relatórios e gate.

## Verificação e defesa

```powershell
python -m pytest -q
node --check static/js/dashboard.js
node --test tests/diff-viewer.test.cjs
python -m scripts.benchmark
python -m scripts.smoke --base-url http://127.0.0.1:8000 --require-llm
```

Veja [o roteiro de apresentação](docs/APRESENTACAO.md), [a arquitetura](docs/c4_model.md) e [o benchmark rotulado](docs/BENCHMARK.md). A execução Docker foi validada com API/worker separados, persistência após reinício e acesso ao Ollama do host. Autenticação multiusuário e distribuição entre vários hosts não estão implementadas.

## Entrega e demonstração CP3

- [Roteiro de apresentação](docs/APRESENTACAO.md)
- [PRs e evidências reais no GitHub](docs/GITHUB_CP3.md)
- [Aderência ao enunciado](docs/ADERENCIA_AO_ENUNCIADO.md)
- [Validação e limites](docs/VALIDACAO.md)

A entrega pública está na branch `main` de
[vinycius11dev/sast-studio-cp3](https://github.com/vinycius11dev/sast-studio-cp3).
As evidências de checks e proteção de merge estão em [GITHUB_CP3.md](docs/GITHUB_CP3.md).
As credenciais nos exemplos são fictícias. O repositório não contém histórico
anterior, arquivos enviados pelo usuário, bancos locais ou o PDF do enunciado.
