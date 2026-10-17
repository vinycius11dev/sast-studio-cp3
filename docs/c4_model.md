# Arquitetura em execução — SAST Studio 3.0

## C1 — Contexto

```mermaid
flowchart LR
    pessoa[Desenvolvedor / analista] -->|Fontes e triagem| sast[SAST Studio]
    sast -->|Revisão semântica e remediação| ollama[Ollama local]
    sast -->|JSON / Markdown / SARIF| relatorio[Relatórios]
    ci[GitHub Actions] -->|CLI e código de saída| sast
```

## C2 — Containers e armazenamento

```mermaid
flowchart TD
    web[Workspace HTML / CSS / JS] --> api[API FastAPI]
    api -->|Enfileira / consulta| fila[(Fila durável SQLite)]
    worker[Processo worker] -->|Claim atômico / lease| fila
    worker --> motor[Motor SAST]
    worker --> db[(Histórico e fontes SQLite)]
    api -->|Histórico / relatórios| db
    api -->|HTTP| ollama[Ollama / Llama 3.2]
    cli[CLI Python] --> motor
    motor --> py[Python AST e taint básico]
    motor --> js[Tree-sitter JS / TS / JSX / TSX]
    motor --> java[Tree-sitter Java]
    api --> reporter[Exportador]
    cli --> reporter
    motor --> gate[Política de severidade]
```

O Compose executa API e worker em processos e containers separados, com volume
compartilhado. O inicializador local usa um worker embutido para simplificar a
instalação. A fila persiste jobs, usa transação para impedir dois workers de
assumirem o mesmo job, heartbeat e recuperação de lease expirado (até 3 tentativas).
A instalação aceita vários workers no mesmo host; não implementa broker Redis
nem uma fila distribuída entre hosts.

## C3 — Módulos

| Módulo | Responsabilidade |
| --- | --- |
| api/main.py | Validação, upload, jobs, histórico, triagem e relatórios |
| api/jobs.py | Fila durável, claim atômico, lease e heartbeat |
| api/worker.py | Consumo de jobs, execução e persistência |
| api/store.py | Fontes, resultados e revisões de IA em SQLite |
| engine/engine.py | Roteamento por linguagem e consolidação |
| engine/languages/ e rules/ | AST, regras e fluxo básico de dados |
| engine/policy.py | Decisão passed / blocked / error |
| engine/semantic_review.py | Classificação contextual, evidências e validação do LLM |
| engine/ai_remediation.py | Ollama, validação de sugestões e fallback identificado |
| engine/reporter.py | JSON, Markdown e SARIF da análise selecionada |
| static/js/dashboard.js | Upload, acompanhamento, filtros, IA e downloads |

## Visão dinâmica — análise assíncrona

```mermaid
sequenceDiagram
    actor Pessoa
    participant UI as Workspace
    participant API as FastAPI
    participant Fila as Jobs SQLite
    participant Worker
    participant Motor as SASTEngine
    participant DB as Histórico SQLite
    Pessoa->>UI: Seleciona pasta e política
    UI->>API: POST /scan/project?queued=true
    API->>API: Valida limites e caminhos
    API->>Fila: Persiste job e fontes
    API-->>UI: HTTP 202 e job_id
    Worker->>Fila: Assume job atomicamente
    Worker->>Motor: Analisa fontes e avalia gate
    Motor-->>Worker: Achados e erros
    Worker->>DB: Salva resultado e fontes
    Worker->>Fila: Conclui com scan_id
    loop Até conclusão
        UI->>API: GET /jobs/{job_id}
        API->>Fila: Consulta estado
        API-->>UI: Estado e scan_id
    end
    UI->>API: GET /scans/{scan_id}
    API->>DB: Recupera execução
    API-->>UI: Resultado rastreável
```

## Decisões e limites

O upload não executa código. Erros de parsing impedem a aprovação. A IA recebe
o contexto armazenado do achado, pode sugerir severidade e possível falso positivo,
e registra justificativa, linhas de evidência e modelo. A recomendação não apaga
o resultado original nem altera silenciosamente o gate. Falhas são identificadas.

SQLite atende a demonstração em um host. Autenticação multiusuário, distribuição
entre hosts e fluxo completo entre arquivos não estão implementados. Tree-sitter
valida a estrutura sintática; não substitui compilação ou testes da aplicação alvo.
