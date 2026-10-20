# Diagnóstico e evolução do SAST

Data: 19/10/2026. Escopo: Python, JavaScript/TypeScript e Java. Este relatório avalia a arquitetura proposta no texto anexado pelo usuário; não substitui o enunciado oficial nem atribui nota acadêmica.

## Viabilidade

É viável evoluir a plataforma existente em etapas. Não é tecnicamente justificável prometer detecção perfeita ou correções sempre equivalentes ao código original. A arquitetura atual é uma base acadêmica funcional, com parsers reais, regras de segurança, evidências, histórico, revisão por Ollama e diffs. Ela ainda não tem a análise de fluxo de controle, de tipos e entre procedimentos de um produto SAST maduro.

O percentual informal de “40%” não veio acompanhado de um conjunto rotulado de casos. Portanto, não foi tratado como uma medição confirmada. O teste independente de Java em [OWASP BenchmarkJava](quality/owasp-native-results.md) demonstra limitações que o corpus interno, menor e mais simples, não revela.

## Diagnóstico inicial

- Existiam 19 IDs de regras: Python 7, JavaScript 6 e Java 6.
- Python usava AST nativa e rastreamento local de algumas entradas. JavaScript/TypeScript e Java usavam Tree-sitter e resolução simples de atribuições.
- Não havia corte global no número de achados do motor. A interface pagina 40 itens por página; a API retorna todos os achados da análise. São coisas diferentes.
- Há limites explícitos de upload: 200 arquivos, 25 MiB por projeto e 5 MiB por arquivo; snippets têm limite de 500 mil caracteres. Dependências e diretórios de build são ignorados. Erros de sintaxe são apresentados como análise incompleta.
- O benchmark interno tinha 53 casos e contava cada par caso/regra uma única vez. Isso podia ocultar a perda de uma segunda ocorrência da mesma regra.
- Ollama atuava na revisão e na sugestão de correções. A detecção determinística e o security gate já eram preservados.

A medição inicial está em [baseline-before-expansion.json](quality/baseline-before-expansion.json). Ela é do corpus antigo e não deve ser comparada diretamente com percentuais do corpus ampliado.

## Implementado nesta evolução

| Área | Resultado | Limite real |
| --- | --- | --- |
| Detecção nativa | 43 IDs: Python 18, JavaScript/TypeScript 13, Java 12; casos positivos e negativos | Não cobre todas as bibliotecas ou CWEs |
| Regras novas | Desserialização, arquivos, hash/criptografia fraca, PRNG em segredos, logs sensíveis, debug, temporários, XXE explícito, TLS, XSS e templates, conforme linguagem | Vários alertas são padrões potenciais; explorabilidade exige contexto |
| Fluxo local | Aliases, atribuições, alguns ramos e estruturas; passos reais de source/propagação/sink em fluxos Python rastreados | Sem CFG completo e sem resolução arbitrária entre funções/arquivos |
| Motores independentes | Bandit 1.9.4 e Semgrep CE 1.181.0 integrados por processos separados e opt-in; 9 regras Semgrep locais versionadas | Não equivale ao catálogo inteiro do Semgrep nem habilita Semgrep Pro |
| Execução | Workspace temporário, comandos sem shell, ambiente sem tokens herdados, limite de tempo, saída limitada, memória/timeout configurados no Semgrep | Diretório temporário não é sandbox de sistema operacional; Bandit não tem cota rígida de memória |
| Falhas | Resultados parciais preservados; motor solicitado ausente/com erro impede gate aprovado | Uma análise parcial continua exigindo nova execução |
| Normalização | Motor, regra original, confiança, fingerprint e evidências; deduplicação conservadora pela mesma operação AST | Casos ambíguos ficam separados; sinais nativos distintos são preservados |
| IA | JSON estruturado, evidências, confiança, condições e recomendação; checagem de referências explícitas ausentes; gate original preservado | O modelo ainda pode errar; o validador não prova todas as alegações em linguagem natural |
| Patches completos | Sintaxe, referências JS/Python, contratos reconhecidos, callbacks, driver SQL e nova varredura; proposta inválida rejeitada | Java não é compilado; typecheck, testes da aplicação e equivalência funcional ficam explicitamente não executados |
| Regras sem patch verificado | Orientação e revisão manual, sem diff genérico apresentado como correção pronta | Não existe autocorreção universal |
| Métricas | Ocorrências repetidas e linhas rotuladas; agrupamento por linguagem/CWE; indicadores reais na tela de regras | Corpus curado não é uma medição de cobertura universal nem da qualidade do Ollama |
| Exportação | JSON/SARIF mantêm proveniência e fluxo comprovado; SARIF validado contra esquema oficial OASIS nos testes | Integração de cada repositório CI ainda depende da configuração desse repositório |

## Como executar os motores adicionais

O motor nativo continua funcionando com `requirements.txt`. Os dois motores adicionais usam um ambiente independente:

```powershell
py -3.12 -m venv .venv-scanners
.\.venv-scanners\Scripts\python.exe -m pip install -r requirements-scanners.txt
python iniciar.py
```

O launcher reconhece `.venv-scanners` e habilita os três motores quando `SAST_ENGINES` não foi definido. Para configurar explicitamente:

```powershell
$env:SAST_ENGINES = "native,bandit,semgrep"
$env:SAST_SCANNER_TIMEOUT = "40"
python iniciar.py
```

Se já existe um servidor aberto, reinicie a API para aplicar a configuração. O túnel Cloudflare pode continuar no mesmo processo/endereço. A tela **Integrações** mostra quais motores estão ativos; cada análise registra o estado, a versão, o tempo e os achados brutos de cada motor.

Na CLI:

```powershell
python cli.py scan ./src --engines native,bandit,semgrep --fail-on HIGH -f sarif -o sast-results.sarif
```

Para Docker, a instalação adicional é opt-in: `docker build --build-arg WITH_SCANNERS=1 -t sast-studio .` e a execução deve definir `SAST_ENGINES=native,bandit,semgrep`. O interpretador `/opt/scanners/bin/python` é descoberto automaticamente. O build atualizado deve ser validado no ambiente de destino.

## Medição e reprodução

```powershell
python -m pytest -q
$env:SAST_TEST_EXTERNAL = "1"
python -m pytest -q tests/test_engine_orchestration.py
python -m scripts.benchmark --repeats 5
python -m scripts.owasp_benchmark --dataset tmp/OWASP-BenchmarkJava --output docs/quality/owasp-native-results.json
node --test tests/diff-viewer.test.cjs
```

O dataset externo precisa ser obtido do [repositório oficial](https://github.com/OWASP-Benchmark/BenchmarkJava), no commit registrado no relatório. Sua aplicação e seus scripts não são executados. A pontuação externa compara arquivo e CWE alvo, incluindo controles negativos. Nenhum caso é removido para melhorar o score.

- [Benchmark interno atual](BENCHMARK.md): leitura por ocorrência e controles seguros.
- [Benchmark externo completo](quality/owasp-native-results.md): precisão, recall, falsos positivos e causas das lacunas.
- [Dados internos](benchmark-results.json) e [dados OWASP](quality/owasp-native-results.json): hashes, versões e resultados reproduzíveis.

## Prioridades restantes

1. Consolidar fluxo de controle e propagação entre funções, parâmetros e retornos, com resumos de funções/bibliotecas. Isso ataca falsos positivos de valores constantes e falsos negativos de aliases complexos.
2. Acrescentar resolução incremental entre arquivos e tipos Java/TypeScript; reconhecer sanitizadores específicos da CWE, sem assumir que validação genérica remove todo risco.
3. Expandir CWEs e frameworks a partir de casos reais não detectados, sempre com controles seguros e regressões.
4. Medir Bandit e Semgrep em benchmarks externos próprios, além do teste de integração real já executado. Os números da tela são explicitamente do motor nativo.
5. Criar execução isolada em container descartável para typecheck e testes de projetos analisados. Até lá, o sistema não executa os testes de aplicações enviadas.
6. Implementar análise incremental por Git, histórico persistente detalhado de propostas/validações e medição separada da taxa de aprovação de patches. Atualmente o histórico de scans/revisões é persistido; propostas e verificações da sessão ficam no navegador.

## Referências técnicas

- [Semgrep CLI: JSON, métricas, regras locais e timeouts](https://semgrep.dev/docs/cli-reference).
- [Bandit CLI](https://bandit.readthedocs.io/en/latest/man/bandit.html) e [contrato JSON](https://bandit.readthedocs.io/en/latest/formatters/json.html).
- [OWASP Benchmark](https://owasp.org/www-project-benchmark/).
- [Esquema oficial SARIF 2.1.0](https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json).
