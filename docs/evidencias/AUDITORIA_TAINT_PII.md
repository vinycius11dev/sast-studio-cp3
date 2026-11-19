# Auditoria do protótipo: Taint Analysis de PII

Gerado em 2026-11-16 por `python -m scripts.taint_audit`. Todos os dados do exemplo são fictícios. O relatório mostra risco encontrado no código, não vazamento ocorrido.

## Resumo

| Versão | Achados | Com PII | Vazamentos confirmados | Risco Cidadão |
| --- | ---: | ---: | ---: | --- |
| Antes: dados expostos (`04-pii-vulneravel`) | 9 | 9 | 6 | **99/100 · Crítico** |
| Depois: dados protegidos (`05-pii-corrigido`) | 0 | 0 | 0 | **0/100 · Sem exposição detectada** |

## Antes: dados expostos

### 1. [CRITICAL] PII em log ou console (`PY-T004` · CWE-532)

- **Local:** `04-pii-vulneravel/atendimento/cadastro_ubs.py:17`
- **Dados:** documento, saude
- **Mensagem:** [Taint Analysis · PII] Dado de saúde + Documento pessoal (CPF, RG, CNH, CNS) flui de campo 'cpf' de paciente (linha 15) até logger.info(), que leva para o console ou arquivo de log, sem máscara, hash ou criptografia. LGPD art. 5º, II (dado pessoal sensível).
- **Caminho do dado:**
  1. campo 'cpf' de paciente (linha 15)
  2. cpf (linha 15)
  3. logger.info() (linha 17) ← saída insegura

```python
logger.info(f"Atendimento do CPF {cpf} com diagnóstico {diagnostico}")
```
> Correção: Registre apenas identificadores internos ou valores mascarados (ex.: ***.***.***-25). Nunca registre senhas nem dados de saúde.

### 2. [CRITICAL] PII gravada em texto claro (`PY-T006` · CWE-312)

- **Local:** `04-pii-vulneravel/atendimento/cadastro_ubs.py:27`
- **Dados:** senha
- **Mensagem:** [Taint Analysis · PII] Senha ou credencial flui de parâmetro 'senha' (linha 25) até db.execute(), que leva para um arquivo ou banco de dados, sem máscara, hash ou criptografia. LGPD art. 46 (medidas de segurança).
- **Caminho do dado:**
  1. parâmetro 'senha' (linha 25)
  2. db.execute() (linha 27) ← saída insegura

```python
db.execute("INSERT INTO usuarios (nome, senha) VALUES (%s, %s)", (nome, senha))
```
> Correção: Armazene senhas somente como hash com salt (bcrypt/Argon2) e proteja CPF e dados de saúde com criptografia (ex.: Fernet/AES) e permissão restrita.

### 3. [CRITICAL] PII gravada em texto claro (`PY-T006` · CWE-312)

- **Local:** `04-pii-vulneravel/atendimento/cadastro_ubs.py:29`
- **Dados:** senha
- **Mensagem:** [Taint Analysis · PII] Senha ou credencial flui de parâmetro 'senha' (linha 25) até arquivo.write(), que leva para um arquivo ou banco de dados, sem máscara, hash ou criptografia. LGPD art. 46 (medidas de segurança).
- **Caminho do dado:**
  1. parâmetro 'senha' (linha 25)
  2. arquivo.write() (linha 29) ← saída insegura

```python
arquivo.write(f"{nome};{senha}\n")
```
> Correção: Armazene senhas somente como hash com salt (bcrypt/Argon2) e proteja CPF e dados de saúde com criptografia (ex.: Fernet/AES) e permissão restrita.

### 4. [HIGH] CPF em texto claro no código-fonte (`PY-P001` · CWE-359)

- **Local:** `04-pii-vulneravel/atendimento/cadastro_ubs.py:11`
- **Dados:** documento
- **Mensagem:** [PII · Documento] CPF válido (***.***.***-25) escrito em texto claro no código-fonte. Mesmo exemplos ficam registrados no histórico do repositório.

```python
CPF_TESTE = "529.982.247-25"
```
> Correção: Remova o CPF do código. Use dados sintéticos claramente fictícios em testes, ou leia o valor de uma fonte controlada (banco, cofre). Se precisar exibi-lo, mascare: ***.***.***-NN.

### 5. [HIGH] PII em log ou console (`PY-T004` · CWE-532)

- **Local:** `04-pii-vulneravel/atendimento/cadastro_ubs.py:18`
- **Dados:** documento
- **Mensagem:** [Taint Analysis · PII] Documento pessoal (CPF, RG, CNH, CNS) flui de campo 'cpf' de paciente (linha 15) até print(), que leva para o console ou arquivo de log, sem máscara, hash ou criptografia. LGPD art. 5º, I (dado pessoal).
- **Caminho do dado:**
  1. campo 'cpf' de paciente (linha 15)
  2. cpf (linha 15)
  3. print() (linha 18) ← saída insegura

```python
print("Paciente atendido:", cpf)
```
> Correção: Registre apenas identificadores internos ou valores mascarados (ex.: ***.***.***-25). Nunca registre senhas nem dados de saúde.

### 6. [HIGH] Senha protegida com hash fraco (MD5/SHA-1) (`PY-P003` · CWE-328)

- **Local:** `04-pii-vulneravel/atendimento/cadastro_ubs.py:26`
- **Dados:** senha
- **Mensagem:** [PII · Senha] A senha é processada por 'hashlib.md5()', algoritmo rápido e sem salt: um vazamento do banco permite recuperar as senhas por força bruta em minutos.

```python
verificador = hashlib.md5(senha.encode()).hexdigest()
```
> Correção: Use bcrypt, scrypt ou Argon2 com salt individual (ex.: bcrypt.hashpw(senha, bcrypt.gensalt())).

### 7. [HIGH] Dado de saúde hardcoded no código-fonte (`PY-P002` · CWE-359)

- **Local:** `04-pii-vulneravel/atendimento/cadastro_ubs.py:34`
- **Dados:** saude
- **Mensagem:** [PII · Saúde] 'diagnostico' recebe um valor de saúde escrito direto no código. LGPD art. 5º, II (dado pessoal sensível).

```python
return {"nome": "Maria de Teste", "diagnostico": "Hipertensão arterial"}
```
> Correção: Não grave dados de saúde no código. Use dados sintéticos em testes e armazene registros reais criptografados.

### 8. [HIGH] PII em resposta HTTP sem mascaramento (`PY-T005` · CWE-201)

- **Local:** `04-pii-vulneravel/atendimento/consulta_api.py:27`
- **Dados:** documento, saude
- **Mensagem:** [Taint Analysis · PII] Dado de saúde + Documento pessoal (CPF, RG, CNH, CNS) flui de chave 'cpf' (linha 19) até jsonify(), que leva para a resposta enviada ao cliente, sem máscara, hash ou criptografia. LGPD art. 5º, II (dado pessoal sensível).
- **Caminho do dado:**
  1. chave 'cpf' (linha 19)
  2. retorno de buscar_paciente() (linha 26)
  3. paciente (linha 26)
  4. jsonify() (linha 27) ← saída insegura

```python
return jsonify(paciente)
```
> Correção: Devolva apenas os campos necessários e mascare o CPF. Senha e hash nunca devem sair da API; dados de saúde só com autorização.

### 9. [MEDIUM] PII enviada a serviço externo (`PY-T007` · CWE-359)

- **Local:** `04-pii-vulneravel/atendimento/consulta_api.py:32`
- **Dados:** documento
- **Mensagem:** [Taint Analysis · PII] Documento pessoal (CPF, RG, CNH, CNS) flui de chave 'cpf' (linha 32) até requests.post(), que leva para um serviço fora do sistema, sem máscara, hash ou criptografia. LGPD art. 5º, I (dado pessoal).
- **Caminho do dado:**
  1. chave 'cpf' (linha 32)
  2. requests.post() (linha 32) ← saída insegura

```python
requests.post("https://parceiro.example/api/consulta", json={"cpf": cpf})
```
> Correção: Envie o mínimo necessário, mascarado ou pseudonimizado, e só a operadores com base legal e contrato (LGPD arts. 7º e 46).


## Depois: dados protegidos

Nenhum achado nas regras aplicadas: o CPF é mascarado antes de sair, a senha é guardada só como hash com salt e nenhuma resposta devolve dado de saúde. Isso não prova ausência de risco.

## Como reproduzir

```powershell
python cli.py scan demonstracao/04-pii-vulneravel --fail-on HIGH
python cli.py scan demonstracao/05-pii-corrigido --fail-on HIGH
```

A primeira análise termina com código 1 (gate bloqueado); a segunda, com 0 (aprovada).
