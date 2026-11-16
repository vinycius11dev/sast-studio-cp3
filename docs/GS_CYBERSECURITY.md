# GS CitizenTech · Cybersecurity: Missão Técnica

O SAST Studio ganhou uma camada de **privacidade do cidadão**: encontra dados pessoais (CPF, saúde, senhas) no código, rastreia
se eles chegam a saídas inseguras, explica o risco em linguagem simples com IA e resume tudo em um indicador executivo,
o **Risco Cidadão**. Todos os exemplos usam dados fictícios.

| Critério do professor | Peso | Onde está |
| --- | ---: | --- |
| Robustez do motor de Parsing PII | 3,0 | [`engine/pii.py`](../engine/pii.py), [`engine/rules/pii_rule.py`](../engine/rules/pii_rule.py), scanners JS e Java |
| Eficácia do Taint Analysis | 3,0 | [`engine/rules/pii_taint_rule.py`](../engine/rules/pii_taint_rule.py) |
| Inovação com IA na remediação | 2,0 | [`engine/citizen_alert.py`](../engine/citizen_alert.py) |
| Dashboard Executivo (Risco Cidadão) | 2,0 | [`engine/citizen_risk.py`](../engine/citizen_risk.py), tela **Risco Cidadão** do dashboard |

## 1. Mapeamento de PII

| Regra | Detecta | Severidade | CWE |
| --- | --- | --- | --- |
| `PY-P001` · `JS-P001` · `JAVA-P001` | CPF **válido** escrito no código | Alta | 359 |
| `PY-P002` · `JS-P002` · `JAVA-P002` | Dado de saúde literal (diagnóstico, prontuário, exame…) | Alta | 359 |
| `PY-P003` | Senha processada com MD5 ou SHA-1 | Alta | 328 |
| `PY-P004` · `JS-P003` · `JAVA-P003` | **CNS** (Cartão Nacional de Saúde) válido pelo algoritmo oficial do SUS | Alta | 359 |
| `PY-P005` · `JS-P004` · `JAVA-P004` | **Cartão de pagamento** com bandeira conhecida e dígito de Luhn correto | Alta | 359 |
| `PY-P006` | **E-mail ou telefone** pessoal (DDD válido) escrito no código | Média | 359 |

Como a detecção funciona, para reduzir falsos positivos:

- O CPF só é acusado se os **dois dígitos verificadores** conferem. `111.111.111-11`, `123.456.789-00` e números soltos em texto não geram achado.
  Onze dígitos sem pontuação só contam se forem o valor inteiro do literal.
- Os nomes de variáveis, atributos, chaves de dicionário e argumentos nomeados são divididos em tokens (`numeroCPF` → `numero`, `cpf`).
  Formas já protegidas (`senha_hash`, `cpf_mascarado`, `is_valid_cpf`, `password_length`) são ignoradas.
- Valores vazios ou placeholders (`""`, `"teste"`, `"changeme"`) não contam como dado de saúde.
- A mensagem do achado nunca repete o CPF completo: mostra só a máscara `***.***.***-25`.
- **CNS:** os 15 dígitos precisam fechar o cálculo oficial (definitivo, iniciado em 1 ou 2, derivado do PIS; provisório, iniciado em 7, 8 ou 9, com soma múltipla de 11).
- **Cartão:** exige bandeira conhecida e dígito de Luhn. Os **números de teste publicados pelos provedores** (`4111 1111 1111 1111`, `4242…`, etc.) são ignorados, porque não são cartões de pessoas.
- **Contato:** e-mails de domínio de exemplo (`example.com`), caixas genéricas (`contato@`, `suporte@`) e texto de docstring são ignorados; telefone só com formatação explícita e DDD que existe (`(00) 91234-5678` e `99999-9999` não contam).
- Os identificadores também ganham categorias: **financeiro** (`numero_cartao`, `cvv`) e **contato** (`email`, `telefone`, `celular`).

As categorias seguem a LGPD: documento (art. 5º, I), saúde, que é dado pessoal sensível (art. 5º, II), e senha/credencial (dever de segurança do art. 46).

## 2. Taint Analysis

O dado sensível é rastreado da **origem** até uma **saída insegura**. Cada achado guarda o caminho percorrido em `taint_trace`.

| Regra | Saída insegura (sink) | CWE |
| --- | --- | --- |
| `PY-T004` | `print`, `logging.*`, `logger.*` | 532 |
| `PY-T005` | `jsonify`, `JSONResponse`, `HTTPException`, `return` de rota (`@app.get/post/...`) | 201 |
| `PY-T006` | `.write()`, `json.dump`, `pickle.dump`; senha em `cursor.execute` | 312 |
| `PY-T007` | `requests.*`, `httpx.*`, `urlopen`, envio de e-mail | 359 |

- **Origens:** parâmetros, variáveis, atributos (`paciente.cpf`), campos (`dados["cpf"]`, `.get("cpf")`), argumentos nomeados e prompts (`input("Digite o CPF")`).
- **Propagação:** atribuições, f-strings, concatenação, desempacotamento, chamadas e **retornos de funções do mesmo arquivo**, mesmo declaradas depois. Ramos `if/else` são unidos.
- **Sanitizadores:** funções de máscara, hash, criptografia, anonimização (`mascarar_cpf`, `bcrypt.hashpw`, `hashlib.sha256(...).hexdigest()`), `len`/`bool`, funções `is_*`/`valid*`,
  e fatias curtas como `cpf[-2:]`. Reatribuir um valor limpo remove a contaminação.
- **Gravidade:** a categoria mais grave decide. Senha, saúde e cartão em log são **críticas**; CPF em log é **alta**; CPF enviado a parceiro é **média**.
  Contato (e-mail, telefone) só é acusado em log, com gravidade **baixa**: devolver o e-mail ao próprio usuário ou enviá-lo num cadastro é fluxo normal.
  PII no banco de dados é esperado e não é acusada, exceto senha em texto claro.

Evidência gerada por `python -m scripts.taint_audit`: [`docs/evidencias/AUDITORIA_TAINT_PII.md`](evidencias/AUDITORIA_TAINT_PII.md).
Exemplo real do relatório:

```text
campo 'cpf' de paciente (linha 15) → cpf (linha 15) → logger.info() (linha 17) ← saída insegura
```

## 3. IA na remediação: do erro técnico ao alerta ao cidadão

Para cada achado com dado pessoal, o botão **Traduzir para o cidadão** (ou `POST /api/v1/citizen-alert`) pede ao LLM local (Ollama) um alerta com
título, o que acontece, o risco para o cidadão, quem é afetado e o que fazer, em português simples.

Proteções para a IA não enfraquecer a análise:

- O **nível de risco vem da severidade do achado**, não do modelo: a IA não consegue rebaixar uma falha crítica.
- Respostas com jargão (`taint`, `sink`, `CWE`…) ou código são rejeitadas e regeneradas uma vez.
- Se o Ollama estiver indisponível ou a resposta falhar, o texto vem de um **modelo determinístico por regra**, claramente identificado
  como `Motor determinístico (Fallback)`. A IA nunca é simulada.
- O alerta é salvo no histórico da análise (tabela `citizen_alerts`) e aparece nos relatórios por análise.

## 4. Dashboard: indicador Risco Cidadão

Menu **Risco Cidadão**: medidor de 0 a 100, nível (Sem exposição, Baixo, Moderado, Alto, Crítico), vazamentos confirmados,
dados mais afetados, lista de exposições com o caminho do taint, alertas ao cidadão e evolução entre análises.
O indicador também sai na API (`citizen_risk` em cada análise; `GET /api/v1/scans/{id}/citizen-risk`), na CLI, no Markdown e no SARIF.

```text
score  = 100 × (1 − e^(−pontos / 25))
pontos = Σ severidade (crítica 10, alta 6, média 3, baixa 1)
         × dado (saúde 1,5 · senha 1,4 · cartão 1,4 · documento 1,25 · contato 1,1 · sem PII 0,4)
         × fluxo (vazamento confirmado por taint 1,5)
```

É um indicador de **risco de exposição encontrado no código**, não prova de que algum vazamento aconteceu.

## 5. Corrigir e provar

Na tela **Risco Cidadão**, o botão **Corrigir e provar** (ou `POST /api/v1/scans/{id}/citizen-fix`) aplica uma proteção a cada exposição de
dado pessoal e **reanalisa o código corrigido com o mesmo motor**. A correção só aparece como **provada** quando o arquivo continua sendo
Python válido e nenhuma exposição de PII permanece. A análise original é mantida e a versão corrigida entra no histórico, então a
tela de evolução mostra o antes e o depois (ex.: 99 → 0).

| Exposição | Correção aplicada |
| --- | --- |
| CPF, CNS, cartão, e-mail ou telefone escritos no código | Trocados por valores fictícios inválidos (`000.000.000-00`, zeros, `usuario@example.com`) |
| Dado de saúde escrito no código | Removido (`None`): carregar de uma base protegida |
| Senha com MD5/SHA-1 | `hash_senha(...)`: bcrypt com salt |
| Dado que chega a log, resposta ou parceiro | `mascarar_pii(...)`: CPF vira `***.***.***-25`; só os campos sensíveis de um dicionário são mascarados |
| Senha que seria gravada em arquivo ou banco | `hash_senha(...)` em vez do texto claro |

As funções auxiliares (`mascarar_pii`, `hash_senha`) são inseridas no próprio arquivo, e `import bcrypt` é adicionado se faltar. Cada mudança
aparece com o antes, o depois e o diff, e o arquivo corrigido pode ser baixado. A correção é **determinística**: não depende da IA, então
funciona sem Ollama e não inventa código.

- **O que a prova garante:** que as regras de PII e o Taint Analysis não encontram mais exposição e que o código ainda é Python válido.
- **O que ela não garante:** o comportamento do programa. Mascarar o CPF enviado a um parceiro pode quebrar uma integração que precisa do
  valor completo; isso exige base legal e contrato, não só código. Revise e rode os testes antes de publicar.
- Só Python é corrigido automaticamente. Arquivos JavaScript e Java com achados ficam para revisão manual e impedem a marca de "provado".
- Dentro de f-strings, a correção exige Python 3.12 ou mais novo (nas versões anteriores a posição das expressões é imprecisa e o trecho fica para revisão manual).
- A senha corrigida usa `bcrypt` (`pip install bcrypt`), e o login precisa comparar com `bcrypt.checkpw`.

## Como demonstrar (vídeo e print)

1. `python iniciar.py` e abra <http://127.0.0.1:8000/dashboard>.
2. **Scanner → Carregar UBS com dados expostos → Executar análise**: 9 achados, gate bloqueado.
3. Menu **Risco Cidadão**: Risco **99/100 · Crítico**, 6 vazamentos confirmados. Mostre o caminho do dado de um achado e clique em **Traduzir para o cidadão**.
   Com o Ollama aberto, o selo deve mostrar `Ollama (llama3.2:3b)`; a primeira chamada pode levar até 90 s.
4. Ainda na tela Risco Cidadão, clique em **Corrigir e provar**: o painel mostra **99 → 0**, "Provado pelo motor", as 10 correções e os diffs.
   Clique em **Abrir análise corrigida** para ver o gate aprovado e a evolução entre as duas análises.
5. Opcional, para mostrar CNS, cartão e contato: no Scanner, escolha a pasta `demonstracao/06-pii-cartao-e-contato`, execute a análise
   (6 achados, Risco 84) e use **Corrigir e provar** (84 → 0).
6. **Scanner → Carregar UBS protegida → Executar análise**: 0 achados, Risco **0/100**, gate aprovado.
7. Print de tela da tela Risco Cidadão (antes e depois) para a entrega.

Terminal: `python cli.py scan demonstracao/04-pii-vulneravel --fail-on HIGH` termina com código 1; a pasta `05-pii-corrigido`, com 0.

## Pacote ZIP da entrega

```powershell
python -m scripts.package_gs
```

Gera `reports/GS_Cybersecurity_SAST_Studio.zip` com o código atualizado e as evidências, sem histórico do Git, banco local nem caches.

## Validação (16/11/2026)

- 230 testes Python aprovados (132 novos: PII, CNS/cartão/contato, taint, indicador, alertas, correção automática, API e demonstração).
- Benchmark interno ampliado para 89 casos, 40 controles seguros: precisão e recall de 100% nesse corpus delimitado
  ([BENCHMARK.md](BENCHMARK.md)). Não é uma avaliação independente.
- IA real: com o Ollama 0.40.16 e o `llama3.2:3b`, os 9 achados da UBS vulnerável foram traduzidos pelo modelo (nenhum caiu no fallback),
  em cerca de 8 s cada; a primeira chamada, com o modelo ainda fora da memória, levou 76 s e fica perto do limite de 90 s, então
  vale fazer um alerta de aquecimento antes de gravar o vídeo. O fluxo completo pela API (`POST /api/v1/citizen-alert`) também foi
  confirmado com `provider: ollama`.
- Para os tipos novos (CNS, cartão, e-mail, telefone), 4 de 5 alertas saíram do Ollama; o do CNS caiu no fallback identificado porque o modelo
  afirmou exposição pública nas duas tentativas, o que o validador recusa.
- O teste com o modelo real mostrou que um modelo de 3B pode afirmar vazamento que não ocorreu ("arquivo aberto ao público"),
  citar SHA-256 como solução para senhas e repetir dicas fora de contexto. O prompt e o validador agora rejeitam essas respostas
  (com uma nova tentativa e, depois, o fallback determinístico). O texto continua sendo de um modelo pequeno: revise antes de usar em produção.

## Limites conhecidos

- O Taint Analysis de PII existe para **Python** e é **intra-arquivo**: não segue dados entre arquivos nem resolve tipos. JavaScript e Java têm as regras de literal (CPF e saúde), sem rastreio de fluxo.
- A detecção por nome de variável pode errar: um dado sensível com nome genérico (`x = paciente.campo7`) não é reconhecido, e um nome sensível com conteúdo inofensivo pode gerar alerta.
- Fatias curtas (até 5 caracteres) são tratadas como máscara parcial; isso é uma suposição.
- Os achados de PII não têm categoria OWASP Top 10:2025 mapeada, porque o projeto só exibe mapeamentos documentados e não adivinha categorias.
- O resultado indica risco de exposição, não que um vazamento tenha ocorrido.
