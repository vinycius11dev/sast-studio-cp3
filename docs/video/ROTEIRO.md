# Roteiro do vídeo · GS CitizenTech · Cybersecurity

Vídeo de demonstração do SAST Studio com o indicador **Risco Cidadão** (cerca de 3 minutos). Todos os dados mostrados são fictícios.
Cada bloco de narração vira um áudio; a tela acompanha o que o bloco diz.

| # | Tela | Narração |
| --- | --- | --- |
| 1 | Visão geral do dashboard | Este é o SAST Studio, atualizado para a Global Solution CitizenTech. Agora ele enxerga a privacidade do cidadão. Ele acha CPF, dados de saúde e senhas no código, rastreia se esses dados vazam, explica o risco em linguagem simples com inteligência artificial, e resume tudo em um indicador executivo, o Risco Cidadão. |
| 2 | Scanner: carregar a UBS fictícia e executar a análise | Para a demonstração, carrego o código de uma unidade básica de saúde fictícia, com dados inventados. Ele tem um CPF escrito no código, um diagnóstico, uma senha protegida com MD5, e dados que saem em log, em resposta de API e para um parceiro. Executo a análise. |
| 3 | Risco Cidadão: medidor 99, crítico | O resultado aparece na tela Risco Cidadão. O indicador é 99 de 100, nível crítico, e o gate de segurança está bloqueado. São nove achados com dados pessoais, e seis deles são vazamentos confirmados pelo Taint Analysis. |
| 4 | Rolar até as exposições e o caminho do dado | Cada exposição mostra o caminho do dado. Aqui, o CPF nasce no campo cpf do paciente, passa por uma variável, e chega ao logger, uma saída insegura. É assim que o sistema prova o vazamento, em vez de só desconfiar. |
| 5 | Clicar em Traduzir para o cidadão | Agora a inteligência artificial entra. Um modelo local, o Llama três ponto dois no Ollama, traduz a falha técnica em um alerta que um gestor público entende, com o que acontece, o risco para o cidadão, quem é afetado e o que fazer. O nível de risco vem da gravidade do achado, e não do modelo, então a IA não consegue minimizar uma falha crítica. |
| 6 | Clicar em Corrigir e provar | O passo final é corrigir e provar. O sistema mascara os dados que saem em log, resposta e parceiro, troca o MD5 por bcrypt, e tira o CPF do código. Depois, ele analisa o código corrigido de novo. O Risco Cidadão cai de 99 para zero, e a correção aparece como provada pelo motor. |
| 7 | Abrir análise corrigida e ver o diff | A versão corrigida entra no histórico, com o gate aprovado, e dá para ver cada mudança no código. A prova é das regras do motor. Ela não executa o programa, então a revisão humana continua necessária. |
| 8 | Fechamento | Resumindo: regras de dados pessoais, rastreio do vazamento, alertas em linguagem simples com IA, e um indicador executivo com correção verificada. São duzentos e trinta testes automáticos, e o indicador mostra risco encontrado no código, e não prova de que um vazamento aconteceu. Obrigado. |

## Como a tela é gravada

1. `python iniciar.py` e abra <http://127.0.0.1:8000/dashboard> (ou a porta que subir).
2. Aqueça a IA antes: `ollama run llama3.2:3b "diga olá" --keepalive 30m`.
3. Siga a ordem da tabela. Na etapa 5, a primeira resposta da IA pode levar alguns segundos: espere o selo `Ollama (llama3.2:3b)`.
