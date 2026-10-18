# Benchmark do corpus rotulado

Corpus curado do projeto; métricas não representam todos os códigos ou vulnerabilidades do mercado.

- Unidade de avaliação: par (caso, regra).
- Casos: 53; controles sem falhas esperadas: 24.
- Precisão: 100.0%; recall: 100.0%.
- Falsos positivos: 0; falsos negativos: 0.
- Latência mediana: 0.1769 ms; p95: 0.6102 ms; repetições: 5 (medição local em 18/10/2026).
- Tempos variam por computador; consulte `reports/benchmark.json` para a última execução local.

Os rótulos são explícitos em benchmarks/cases.json. Este conjunto não substitui uma avaliação externa nem mede a precisão do LLM.

| Caso | Esperado | Detectado | Resultado |
| --- | --- | --- | --- |
| py-eval | PY-R001 | PY-R001 | OK |
| py-exec | PY-R001 | PY-R001 | OK |
| py-secret | PY-R002 | PY-R002 | OK |
| py-command | PY-R003 | PY-R003 | OK |
| py-shell | PY-R003 | PY-R003 | OK |
| py-sql-flow | PY-T001 | PY-T001 | OK |
| py-path-flow | PY-T002 | PY-T002 | OK |
| py-ssrf-flow | PY-R004, PY-T003 | PY-R004, PY-T003 | OK |
| py-http-url | PY-R004 | PY-R004 | OK |
| py-http-keyword | PY-R004 | PY-R004 | OK |
| py-request-method | PY-R004 | PY-R004 | OK |
| py-sanitizer-name-collision | PY-T001 | PY-T001 | OK |
| py-html-escape-is-not-sql-binding | PY-T001 | PY-T001 | OK |
| py-string-example | Nenhum | Nenhum | OK |
| py-comment-example | Nenhum | Nenhum | OK |
| py-json | Nenhum | Nenhum | OK |
| py-secret-env | Nenhum | Nenhum | OK |
| py-argv-array | Nenhum | Nenhum | OK |
| py-bound-sql | Nenhum | Nenhum | OK |
| py-int-sanitizer | Nenhum | Nenhum | OK |
| py-scope-isolation | Nenhum | Nenhum | OK |
| py-static-url-variable | Nenhum | Nenhum | OK |
| js-eval | JS-R001 | JS-R001 | OK |
| js-function-constructor | JS-R001 | JS-R001 | OK |
| js-secret | JS-R002 | JS-R002 | OK |
| js-command | JS-R003 | JS-R003 | OK |
| js-shell-option | JS-R003 | JS-R003 | OK |
| js-dom | JS-R004 | JS-R004 | OK |
| js-sql-template | JS-R005 | JS-R005 | OK |
| js-sql-multiline | JS-R005 | JS-R005 | OK |
| js-ssrf | JS-R006 | JS-R006 | OK |
| ts-typed-secret | JS-R002 | JS-R002 | OK |
| js-string-example | Nenhum | Nenhum | OK |
| js-comment-example | Nenhum | Nenhum | OK |
| js-json | Nenhum | Nenhum | OK |
| js-dom-text | Nenhum | Nenhum | OK |
| js-bound-sql | Nenhum | Nenhum | OK |
| js-static-sql-concat | Nenhum | Nenhum | OK |
| js-static-url | Nenhum | Nenhum | OK |
| tsx-safe-markup | Nenhum | Nenhum | OK |
| java-sql | JAVA-R001 | JAVA-R001 | OK |
| java-secret | JAVA-R002 | JAVA-R002 | OK |
| java-command | JAVA-R003 | JAVA-R003 | OK |
| java-deserialize | JAVA-R004 | JAVA-R004 | OK |
| java-path | JAVA-R005 | JAVA-R005 | OK |
| java-ssrf | JAVA-R006 | JAVA-R006 | OK |
| java-comment-example | Nenhum | Nenhum | OK |
| java-string-example | Nenhum | Nenhum | OK |
| java-secret-env | Nenhum | Nenhum | OK |
| java-bound-sql | Nenhum | Nenhum | OK |
| java-command-array | Nenhum | Nenhum | OK |
| java-static-file | Nenhum | Nenhum | OK |
| java-static-url | Nenhum | Nenhum | OK |
