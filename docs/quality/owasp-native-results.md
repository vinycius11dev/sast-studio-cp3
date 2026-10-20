# Medição externa — OWASP BenchmarkJava

Todos os casos rotulados presentes no CSV OWASP BenchmarkJava; motor Java nativo, análise estática sem executar a aplicação.

Origem: [https://github.com/OWASP-Benchmark/BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava). Versão `1.2`, commit `bc5ffeb09fb18ab039806d84ca1f718c2e332c54`.
Unidade: arquivo de teste e CWE alvo, correspondência exata de CWE; múltiplos achados da mesma CWE contam uma vez.

Casos: 2740 (1415 positivos e 1325 negativos). Falhas de análise: 0.
Precisão: 55.7%; recall: 61.0%; FPR: 51.8%.

| CWE | TP | FP | FN | TN | Precisão | Recall | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-22 | 122 | 125 | 11 | 10 | 49.4% | 91.7% | 92.6% |
| CWE-327 | 97 | 0 | 33 | 116 | 100.0% | 74.6% | 0.0% |
| CWE-328 | 0 | 0 | 129 | 107 | não definido | 0.0% | 0.0% |
| CWE-330 | 0 | 0 | 218 | 275 | não definido | 0.0% | 0.0% |
| CWE-501 | 0 | 0 | 83 | 43 | não definido | 0.0% | 0.0% |
| CWE-614 | 0 | 0 | 36 | 31 | não definido | 0.0% | 0.0% |
| CWE-643 | 0 | 0 | 15 | 20 | não definido | 0.0% | 0.0% |
| CWE-78 | 126 | 125 | 0 | 0 | 50.2% | 100.0% | 100.0% |
| CWE-79 | 246 | 205 | 0 | 4 | 54.5% | 100.0% | 98.1% |
| CWE-89 | 272 | 232 | 0 | 0 | 54.0% | 100.0% | 100.0% |
| CWE-90 | 0 | 0 | 27 | 32 | não definido | 0.0% | 0.0% |

Limitações:

- Não é uma certificação nem o scorecard oficial OWASP. As métricas não medem o Ollama ou a qualidade dos patches.
- O motor Java usa análise lexical local, sem resolução interprocedural/interarquivo nem compilação ou typecheck Java.
- CWEs são comparadas exatamente. Hash rotulado CWE-328 não recebe crédito por um alerta CWE-327; Random CWE-330 não recebe crédito por CWE-338.
- Achados de outras CWEs são preservados no resultado, mas não pontuados como falso positivo de um rótulo diferente.
- Falha de análise positiva conta como FN; falha negativa fica inconclusiva e nunca como TN. complete deve ser conferido junto às métricas.

Reprodução (o dataset é obtido separadamente e seu código não é executado):

```powershell
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git tmp/OWASP-BenchmarkJava
git -C tmp/OWASP-BenchmarkJava checkout bc5ffeb09fb18ab039806d84ca1f718c2e332c54
python -m scripts.owasp_benchmark --dataset tmp/OWASP-BenchmarkJava --output docs/quality/owasp-native-results.json
```

SHA-256 dos rótulos: `f0311c850dea7f15125113f7cfdbd7ad612d7f5951c7331584f6981b6ae2d630`.
SHA-256 das fontes: `daa35e202e13e5d5e1e98a7efe6a6c45528a9b93c2bc428a632f559075899756`.
SHA-256 do scanner: `3969c38c1d80fb4f3eaf3dfe63ac0baab8b0ab087186f4f13b2acc6437821835`.

## Diagnóstico manual — medição anterior e correções verificadas

Esta revisão leu os arquivos do commit acima, os helpers chamados e os rótulos oficiais. A fotografia anterior permanece em [owasp-native-before-fixes.json](owasp-native-before-fixes.json). As correções gerais de fluxo e ProcessBuilder foram verificadas com exemplos independentes e, depois, reavaliadas em todos os 2.740 casos. A aplicação não foi executada e os rótulos não foram alterados. Os exemplos abaixo distinguem a falha observada antes da correção de seu estado atual.

### Comparação no mesmo dataset

| Medida | Antes das correções | Atual |
| --- | ---: | ---: |
| TP | 848 | 863 |
| FP | 672 | 687 |
| FN | 567 | 552 |
| TN | 653 | 638 |
| Precisão | 55.79% | 55.68% |
| Recall | 59.93% | 60.99% |
| FPR | 50.72% | 51.85% |

Os fingerprints dos rótulos e das fontes são idênticos entre as duas medições; o fingerprint do scanner mudou. Houve zero falhas de análise em ambas. O aumento de cobertura encontrou 15 positivos antes perdidos e acrescentou 15 alertas em controles negativos: a precisão diminuiu ligeiramente e o FPR aumentou. Isso não representa melhora de precisão nem comprova prontidão para bloqueio automático em produção.

As categorias SQL, XSS e Command Injection agora têm recall de 100% neste snapshot, com FPR respectivamente de 100%, 98,1% e 100%. Esses pares devem ser apresentados juntos; citar apenas o recall esconderia a principal limitação do motor.

### Três falsos positivos que permanecem confirmados pelo rótulo e pelo código

| Caso oficial | Resultado nativo | Evidência e causa real |
| --- | --- | --- |
| [BenchmarkTest00052](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00052.java#L44-L58) — SQL, rótulo `false` | JAVA-R001, linha 54 | `param` vem de `SeparateClassRequest.getTheValue`, e depois compõe uma consulta passada a `prepareCall`. Porém, [o helper retorna sempre a constante `"bar"`](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/src/main/java/org/owasp/benchmark/helpers/SeparateClassRequest.java#L51-L54). O motor não resolve esse retorno entre arquivos e trata a chamada como dinâmica. A concatenação existe, mas não há fluxo controlável pelo atacante neste caso. |
| [BenchmarkTest00063](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00063.java#L66-L78) — Path Traversal, rótulo `false` | JAVA-R005, linha 78 | O ternário escolhe entre uma constante e `param`, mas sua condição contém somente constantes: `(7 * 18) + 106 > 200`, portanto é sempre verdadeira. O caminho usa exclusivamente o ramo constante. Falta avaliação abstrata dessa expressão aritmética e eliminação do ramo impossível; uma expressão ternária desconhecida permanece dinâmica. |
| [BenchmarkTest00147](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00147.java#L51-L65) — XSS, rótulo `false` | JAVA-R007, linha 65 | A lista recebe uma constante, `param` e outra constante; remove o índice zero e lê o novo índice um. O valor recuperado é a última constante, não a entrada externa. Fora do bloco, o valor inicial de `bar` também é constante. O scanner não modela o conteúdo, os índices e a mutação da lista, tratando `get(1)` e o array usado na formatação como valores desconhecidos. |

Os rótulos correspondentes estão nas linhas [53](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/expectedresults-1.2.csv#L53), [64](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/expectedresults-1.2.csv#L64) e [148](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/expectedresults-1.2.csv#L148) do CSV oficial.

### Três falsos negativos da medição anterior e seu estado atual

| Caso oficial | Resultado nativo | Evidência e causa real |
| --- | --- | --- |
| [BenchmarkTest00512](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00512.java#L43-L57) — SQL, rótulo `true` | Antes: nenhum CWE-89. **Atual: JAVA-R001, linha 57; TP** | O mapa de parâmetros fornece `values[0]`, atribuído condicionalmente a `param`. `bar` recebe `param`, integra a consulta e chega a `Statement.execute`. O sink já está no catálogo. Na medição anterior, a inspeção do analisador mostrou `dynamic(sql) == false`: a resolução transitiva do alias chega ao inicializador vazio de `param` e perde as alternativas condicionais desse símbolo intermediário. A correção visita uma definição por vez, preservando e mesclando as alternativas de cada símbolo intermediário. Regressões independentes cobrem SQL/XSS, ramo constante e sobrescrita segura. O caso oficial passou a TP; isso não adiciona análise interprocedural ou um CFG completo. |
| [BenchmarkTest00006](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00006.java#L44-L69) — Command Injection, rótulo `true` | Antes: nenhum CWE-78. **Atual: JAVA-R003, linha 66; TP** | A entrada HTTP é acrescentada à lista de argumentos de um shell. O `ProcessBuilder` nasce sem argumentos; a lista é fornecida depois por `pb.command(argList)`, antes de `start()`. Antes, a regra verificava somente os argumentos do construtor. Agora também examina `command`, arrays e listas locais com adições, incluindo alternativas condicionais limitadas. Os controles negativos preservam o limite entre um executável fixo e seus argumentos dinâmicos. Esse caso passou a TP. Operações desconhecidas em coleções continuam conservadoras, e o estado retornado por funções externas não é resolvido. |
| [BenchmarkTest00012](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00012.java#L44-L68) — LDAP Injection, rótulo `true` | **Atual: continua sem CWE-90; FN** | Um header é incorporado ao filtro LDAP e chega a `InitialDirContext.search`. Os placeholders usados para outro campo não neutralizam a parte concatenada. Não existe regra LDAP/CWE-90 no catálogo Java atual; os alertas XSS emitidos em outras linhas não representam detecção do alvo LDAP e não recebem crédito. |

Os rótulos correspondentes estão nas linhas [513](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/expectedresults-1.2.csv#L513), [7](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/expectedresults-1.2.csv#L7) e [13](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/bc5ffeb09fb18ab039806d84ca1f718c2e332c54/expectedresults-1.2.csv#L13) do CSV oficial.

### Sanitização observada fora do alvo pontuado

Em `BenchmarkTest00012`, as linhas 77 e 97 recebem JAVA-R007 apesar de a saída passar por `ESAPI.encoder().encodeForHTML`. O reconhecedor atual contempla algumas APIs de codificação HTML, mas não essa cadeia do ESAPI. Esse é um indício concreto de sanitizador não modelado. Como o rótulo oficial desse arquivo é LDAP/CWE-90, esses alertas XSS adicionais foram preservados no JSON e ficaram fora do cálculo de FP para o alvo; não foram contabilizados como novos falsos positivos oficiais. Qualquer extensão deve reconhecer o contexto HTML específico, sem promover um encoder a sanitizador universal para SQL, shell ou JavaScript.

### Prioridades após as correções

1. **P0 — Reduzir os falsos positivos sem perder a propagação corrigida.** A visita por definição corrigiu o alias que descartava entrada condicional. Ainda falta avaliação abstrata de ramos e conteúdo de coleções para distinguir os três FP demonstrados. O reconhecimento de ProcessBuilder é limitado a varargs, arrays e listas locais, com no máximo 32 alternativas; operações desconhecidas e origem externa do builder permanecem conservadoras. Um argumento separado elimina a interpretação por shell, mas ainda exige validação adequada ao executável escolhido.
2. **P1 — Introduzir resumos de funções e sanitizadores por contexto.** Propagar retornos constantes e origens de entrada entre métodos/arquivos com orçamento e cache; reconhecer encoders HTML como o ESAPI na posição adequada. Uma chamada desconhecida deve preservar a necessidade de revisão, sem ser apresentada como fluxo externo comprovado. Isso é necessário para não confundir `getTheValue`, que retorna constante, com `getTheParameter`, que lê a requisição.
3. **P1 — Ampliar o modelo de estado e de controle.** Modelar condições comprovadas, índices e transformações de listas; preservar relações entre aliases de objetos mutáveis, exceções e laços. A análise lexical atual com junções conservadoras não equivale a interpretação abstrata completa, resolução de tipos Java ou cobertura interprocedural.
4. **P2 — Ampliar e separar o catálogo com medição independente.** LDAP/CWE-90 continua sem regra; XPath, configurações de cookie e outras categorias também têm cobertura ausente. Hashing e cifragem usam hoje uma categoria comum e a taxonomia de aleatoriedade diverge do dataset. Separar regras e documentar o mapeamento prospectivamente; não alterar rótulos nem reclassificar um resultado já medido para aumentar sua pontuação.
5. **P2 — Manter as duas medições e comparar ambos os erros.** As regressões mínimas acrescentadas ao corpus não reproduzem nomes nem IDs do OWASP. O conjunto externo continua completo e preserva os resultados anteriores. Qualquer mudança deve ser avaliada por recall e FPR, por CWE. O corpus curado evita regressões conhecidas, mas não representa precisão em projetos arbitrários.

O motor cobre mais padrões e deixou de perder os dois fluxos descritos, porém o FPR externo continua elevado. Não há evidência para declarar perfeição, qualidade de um SAST comercial ou segurança de um gate de produção sem revisão. Esta seção mantém a distinção entre a medição anterior e a atual; os números completos e fingerprints de cada versão permanecem nos respectivos JSONs.
