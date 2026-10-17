# Remediação assistida para JDBC — 17/10/2026

## Problema observado

A interface apresentou fallback por resposta incompleta ou fora do JSON esperado.
Na reprodução com o arquivo `demonstracao/01-vulneravel/java/UsuarioRepository.java`,
o modelo também produziu um trecho interrompido em `statement.executeQuery(`,
que foi rejeitado pela validação de SQL parametrizado.

O achado corresponde à linha de declaração de um ResultSet dentro de um
try-with-resources. Substituir somente essa linha não fornece uma correção
completa para o bloco JDBC.

## Alterações

- Geração inicial com 1024 tokens, em lugar de 320.
- Uma nova geração com até 1536 tokens quando o JSON vem truncado, inválido,
  com campos de tipos incorretos ou com uma sugestão rejeitada pela validação;
  as duas tentativas compartilham o limite total
  de tempo da solicitação.
- O schema é enviado no campo `format` e no prompt, conforme a
  [documentação oficial do Ollama](https://docs.ollama.com/capabilities/structured-outputs).
- Para JAVA-R001 com fonte de até 12.000 caracteres, o modelo recebe o arquivo
  completo e deve preservar classe, nomes e métodos, corrigindo a consulta JDBC.
- Imports originais e a declaração de pacote são preservados ao integrar a resposta.
- O resultado deve conter parâmetros vinculados e reduzir os achados da regra
  SQL; respostas que removem métodos ou alteram classe/pacote são rejeitadas.
- O diff da sugestão considera o arquivo completo nesse caso.
- A interface diferencia a remoção da regra selecionada dos problemas de outras
  regras que ainda aparecem no arquivo sugerido.
- Falhas continuam identificadas como fallback; uma orientação determinística
  não recebe o rótulo de resposta do modelo.

## Verificação

- 60 testes automatizados passaram, incluindo recuperação de JSON inválido,
  aumento de orçamento na segunda tentativa, campos incorretos, preservação de
  pacote/imports, diff integral para Java, retorno da validação na nova tentativa
  e respeito ao limite total de tempo.
- Uma geração real do `llama3.2:3b` retornou código com PreparedStatement,
  `setString(1, userId)` e `executeQuery()` sem argumentos.
- Após preservar o import original de IOException, o diff passou em
  `git apply --check`, foi aplicado em uma pasta temporária e o resultado
  compilou com `javac -proc:none`.
- A consulta não gerou JAVA-R001. JAVA-R002 e JAVA-R003 permaneceram, pois a
  correção solicitada foi a de SQL Injection.
- O fluxo final pela interface retornou **Ollama (llama3.2:3b)**; o botão
  **Analisar sugestão** respondeu HTTP 200 e exibiu: "A regra JAVA-R001 não foi
  detectada na sugestão. 2 achado(s) de outras regras permanecem."
- O diff desse resultado da interface também foi aplicado em diretório
  temporário e compilou com `javac -proc:none`.

A compilação acima verifica o exemplo da demonstração. A validação na interface
é uma nova análise estática pelas regras disponíveis; não executa o código Java.
