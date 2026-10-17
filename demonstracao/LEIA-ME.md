# Pastas para demonstrar o SAST Studio

## Teste direto, sem janela de seleção

Na tela **Scanner**, clique em **Carregar pasta vulnerável** e depois em
**Executar análise**: são 3 arquivos e 9 achados. Para comparar, use
**Carregar pasta corrigida** e execute novamente: são 3 arquivos e 0 achados
nas regras atuais. Esses botões carregam os arquivos reais das pastas abaixo
e submetem uma nova análise ao motor.

Se estiver com uma versão anterior da tela aberta, atualize com **Ctrl+F5**.
Para usar o seletor do Windows, abra o endereço do sistema no Chrome ou Edge
comum. O navegador usado pela automação pode interceptar a janela de seleção.

Os caminhos Windows abaixo correspondem à instalação de demonstração. Em outro
computador, use a pasta onde clonou ou extraiu o projeto.

## Selecionar os arquivos do computador

Abra o sistema em http://127.0.0.1:8000/dashboard e entre em **Scanner**.
Os arquivos são exemplos de código para análise estática: não é necessário
executá-los, instalar dependências ou conectar um banco de dados.

## Primeiro teste: detectar problemas

1. Clique em **Escolher pasta**.
2. Cole este caminho na janela do Windows e confirme a seleção da pasta:

   ```text
   C:\wamp64\www\sast-studio-cp3\demonstracao\01-vulneravel
   ```

3. Confira os **3 arquivos selecionados** e mantenha o bloqueio em **Alta**.
4. Clique em **Executar análise**.
5. O resultado esperado é **9 achados: 6 críticos e 3 altos**, com **Gate bloqueado**.

| Arquivo | Regra | Linha | Problema |
| --- | --- | --- | --- |
| backend/servico.py | PY-R001 | 9 | Execução dinâmica com eval |
| backend/servico.py | PY-R002 | 5 | Senha escrita no código |
| backend/servico.py | PY-R003 | 13 | Comando do sistema montado com entrada externa |
| javascript/usuarios.js | JS-R001 | 5 | Execução dinâmica com eval |
| javascript/usuarios.js | JS-R002 | 2 | Chave escrita no código |
| javascript/usuarios.js | JS-R005 | 10 | Consulta SQL por concatenação |
| java/UsuarioRepository.java | JAVA-R001 | 14 | Consulta SQL por concatenação |
| java/UsuarioRepository.java | JAVA-R002 | 9 | Senha escrita no código |
| java/UsuarioRepository.java | JAVA-R003 | 20 | Execução de comando com Runtime.exec |

As senhas e chaves desses exemplos são fictícias. Use a pasta como entrada do
scanner; as funções vulneráveis não devem ser executadas.

## Mostrar a IA

1. Na tela **Achados**, selecione o item **PY-R001**, do arquivo `backend/servico.py`.
2. Clique em **Gerar remediação** e aguarde a resposta.
3. Mostre o modelo informado, a explicação, a sugestão e **Ver alterações (diff)**.
4. Clique em **Analisar sugestão** para verificar o trecho sugerido com o próprio SAST.

O Ollama precisa estar aberto com o modelo `llama3.2:3b` disponível. A tela
identifica quando a resposta vem do modelo e quando utiliza fallback determinístico.
A validação da sugestão verifica o trecho proposto; não altera os arquivos nem
significa que todos os outros problemas do projeto foram corrigidos.

**Ver alterações (diff)** abre uma janela no sistema: vermelho mostra as linhas
removidas, e verde mostra as linhas adicionadas. Use **Baixar como .txt** para
abrir o conteúdo em um editor de texto comum ou **Baixar .patch** para revisar e
aplicar a alteração em ferramentas de desenvolvimento. **Esc** fecha a janela.

Para **JAVA-R001**, o modelo recebe o arquivo Java completo e a sugestão contém
o arquivo com a correção SQL, incluindo os imports preservados. No exemplo
vulnerável, a validação pode indicar que **JAVA-R001 não foi detectada**, enquanto
os outros dois problemas (senha no código e execução de comando) permanecem.
Isso permite apresentar uma correção por vez, sem tratar o restante do arquivo
como se já estivesse corrigido.

Se a geração não concluir um JSON válido, o sistema tenta novamente uma vez,
dentro do limite total de 90 segundos. Caso ainda falhe ou a sugestão seja
rejeitada, o fallback continua identificado na tela.

## Segundo teste: comparar com as correções

Volte a **Scanner**, clique em **Escolher pasta** e selecione:

```text
C:\wamp64\www\sast-studio-cp3\demonstracao\02-corrigido
```

Execute a análise. O resultado esperado é **3 arquivos, 0 achados nas regras
atuais e Gate aprovado**, mantendo o limite em **Alta**.

As correções usam JSON no lugar de eval, variáveis de ambiente para credenciais,
consultas parametrizadas e comandos com argumentos separados e validação de entrada.
Essa pasta foi preparada previamente para a comparação; a IA não aplica correções
automaticamente aos arquivos originais. Zero achados não comprova ausência de todas
as possíveis vulnerabilidades.

Selecione uma das duas subpastas por vez. Selecionar a pasta `demonstracao`
inteira mistura as versões vulnerável e corrigida em uma mesma análise.

## O que dizer na apresentação

> Vou analisar três arquivos em linguagens diferentes, sem executá-los.
> O scanner identifica nove problemas e bloqueia o gate porque há achados altos e críticos.
> Posso abrir cada problema, mostrar o código e pedir uma sugestão à IA local.
> Depois analiso uma versão que preparei com as correções e comparo os resultados.

Use **Histórico** para reabrir as análises e **Exportar** para mostrar
os resultados em JSON, Markdown ou SARIF.

## Validação realizada em 17/10/2026

- As duas pastas foram selecionadas pelo botão **Escolher pasta** e analisadas pelo painel.
- A API respondeu HTTP 200 nos dois testes: 9 achados/bloqueado e 0 achados/aprovado.
- Nenhum erro de processamento nos dois casos.
- Sintaxe dos arquivos Python validada com `ast.parse`.
- Sintaxe dos arquivos JavaScript validada com `node --check`.
- As duas versões Java compilaram com `javac` 17, sem executar as funções de exemplo.
- A remediação do achado PY-R001 respondeu pelo Ollama (`llama3.2:3b`), sugerindo
  `ast.literal_eval` no lugar de `eval`.
- O botão **Analisar sugestão** retornou HTTP 200, sem erros e com 0 achados no
  trecho sugerido. O diff preservou o contexto da função original.

## Terceiro teste: triagem semântica

Selecione somente `03-triagem-semantica`. O scanner detecta dois eval.
Use **Revisar com IA** em cada um: um recebe constante, outro recebe `input()`.
A IA sugere classificação e severidade, com confiança e linhas de evidência.
O resultado pode variar; o achado original e o gate são preservados.
As revisões ficam no histórico e nos relatórios. Use o filtro de revisão IA.

Na versão 3.0 o dashboard envia o projeto à fila com HTTP 202 e acompanha o
job até concluir; a resposta padrão síncrona da API continua disponível.
