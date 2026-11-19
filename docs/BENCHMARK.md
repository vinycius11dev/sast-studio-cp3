# Benchmark do corpus rotulado

Corpus curado do projeto; métricas não representam todos os códigos ou vulnerabilidades do mercado.

- Unidade de avaliação: par (caso, regra).
- Casos: 89; controles sem falhas esperadas: 40.
- Precisão: 100.0%; recall: 100.0%.
- Falsos positivos: 0; falsos negativos: 0.
- Latência mediana: 0.1546 ms; p95: 0.5416 ms; repetições: 5.

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
| pii-cpf-literal | PY-P001 | PY-P001 | OK |
| pii-health-literal | PY-P002 | PY-P002 | OK |
| pii-weak-hash | PY-P003 | PY-P003 | OK |
| pii-log-param | PY-T004 | PY-T004 | OK |
| pii-log-fstring | PY-T004 | PY-T004 | OK |
| pii-response-route | PY-T005 | PY-T005 | OK |
| pii-storage-file | PY-T006 | PY-T006 | OK |
| pii-external-post | PY-T007 | PY-T007 | OK |
| pii-interprocedural | PY-T004 | PY-T004 | OK |
| pii-js-cpf | JS-P001 | JS-P001 | OK |
| pii-java-health | JAVA-P002 | JAVA-P002 | OK |
| safe-pii-masked-log | Nenhum | Nenhum | OK |
| safe-pii-password-hash | Nenhum | Nenhum | OK |
| safe-pii-short-slice | Nenhum | Nenhum | OK |
| safe-pii-non-sensitive | Nenhum | Nenhum | OK |
| safe-pii-invalid-cpf | Nenhum | Nenhum | OK |
| safe-pii-masked-response | Nenhum | Nenhum | OK |
| safe-pii-db-cpf | Nenhum | Nenhum | OK |
| py-cns-literal | PY-P004 | PY-P004 | OK |
| py-card-literal | PY-P005 | PY-P005 | OK |
| py-email-literal | PY-P006 | PY-P006 | OK |
| py-phone-literal | PY-P006 | PY-P006 | OK |
| py-card-log-flow | PY-T004 | PY-T004 | OK |
| py-card-response-flow | PY-T005 | PY-T005 | OK |
| py-email-log-flow | PY-T004 | PY-T004 | OK |
| js-cns-literal | JS-P003 | JS-P003 | OK |
| java-card-literal | JAVA-P004 | JAVA-P004 | OK |
| safe-pii-test-card | Nenhum | Nenhum | OK |
| safe-pii-invalid-card | Nenhum | Nenhum | OK |
| safe-pii-invalid-cns | Nenhum | Nenhum | OK |
| safe-pii-role-mailbox | Nenhum | Nenhum | OK |
| safe-pii-example-email | Nenhum | Nenhum | OK |
| safe-pii-invalid-ddd | Nenhum | Nenhum | OK |
| safe-pii-doc-email | Nenhum | Nenhum | OK |
| safe-pii-card-masked-log | Nenhum | Nenhum | OK |
| safe-pii-email-response | Nenhum | Nenhum | OK |
