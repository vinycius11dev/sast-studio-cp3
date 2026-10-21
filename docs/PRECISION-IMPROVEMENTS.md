# Melhorias locais de precisão — 20/10/2026

As correções foram feitas no motor determinístico, não no modelo Ollama.
Os alertas continuam exigindo revisão de contexto e não comprovam exploração.

## O que mudou

- Fontes Python são reconhecidas na AST, sem interpretar texto dentro de strings como código.
- Propagação em atribuições anotadas, aumentadas, desempacotamento e expressões de atribuição.
- União conservadora de caminhos `if`/`else`, exceções e laços, incluindo zero iterações e realimentação do laço.
- URLs HTTP por argumento nomeado, posição correta de `request(method, url)` e aliases importados de requests, httpx e urllib.
- Entradas diretas em operações de arquivo e separação entre consulta SQL e parâmetros de valores.
- Conversões numéricas aninhadas reconhecidas, sem confiar em builtins ocultos por parâmetros/atribuições locais.
- Parâmetros de funções JS/TS/Java não são mais confundidos com constantes globais de mesmo nome.
- Uma posição/regra é reportada uma única vez mesmo quando o fluxo do laço é revisitado.

## Medição antes e depois

Mesmo corpus rotulado: 53 casos existentes mais 35 regressões novas, incluindo
37 controles sem achados esperados. Unidade: par `(caso, regra)`, não cada achado.
O resultado anterior foi capturado antes de alterar o motor.

| Medida | Antes | Depois |
| --- | --- | --- |
| Casos | 88 | 88 |
| Verdadeiros positivos | 34 | 59 |
| Falsos positivos | 7 | 0 |
| Falsos negativos | 25 | 0 |
| Precisão | 82,9% | 100% |
| Recall | 57,6% | 100% |

Os casos novos foram escolhidos para reproduzir defeitos encontrados; portanto
estes números medem regressões internas, **não uma avaliação independente**.
Não representam precisão universal, desempenho sobre projetos reais ou qualidade
da IA. Os relatórios completos desta execução estão em
`reports/precision-before.json` e `reports/precision-after.json` (arquivos locais).

Validação local adicional: **156 testes Python e 4 testes Node aprovados**.
A suíte Python emitiu um aviso de depreciação de uma dependência do TestClient,
sem falhas. A limpeza foi exercitada na interface com dados de teste em uma
instalação separada (`8001`), confirmando histórico vazio e criação dos dois
backups SQLite. Na instalação de uso (`8000`), a confirmação foi cancelada e
as duas análises existentes foram preservadas. API, worker e Ollama foram
conferidos ativos depois do reinício do SAST.

Para repetir a medição atual:

```powershell
python -m scripts.benchmark --output reports/precision-after.json --markdown reports/precision-after.md --repeats 5
python -m pytest -q
```

## Limites que permanecem

Análise Python intraprocedural, sem resolução completa de tipos, aliases de
objetos, chamadas entre funções/arquivos, alcance real de todos os caminhos ou
validação de allow-lists. Laços usam até 32 passos de ponto fixo, com estado
conservador no limite. A cobertura estrutural JS/TS/Java não é análise completa
de fluxo. `PY-R004` é uma heurística de URL dinâmica; `PY-T003` acrescenta evidência
de entrada externa e pode coexistir com ela. Zero achados não comprova segurança.
