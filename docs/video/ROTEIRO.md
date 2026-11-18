# Roteiro do vídeo · GS CitizenTech · Cybersecurity

Vídeo de apresentação do SAST Studio com o indicador **Risco Cidadão**: [`SAST_Studio_GS_CitizenTech.mp4`](SAST_Studio_GS_CitizenTech.mp4), com 3min14 (abaixo do limite de 4 minutos).
Todos os dados mostrados são fictícios. A narração é lida pela voz **Cleo** do Gemini (AI Studio, modelo Gemini 3.8 Flash TTS), com a instrução de estilo
*"falante nativa de português do Brasil, de São Paulo, sem sotaque estrangeiro, animada e confiante, como estudante apresentando um projeto"*.

Cada bloco de narração vira um áudio. A tela é gravada seguindo o roteiro, com legenda fixa embaixo, aviso no início de cada parte e anel amarelo no que a fala cita.

## Estrutura

| # | Tela | Narração |
| --- | --- | --- |
| 1 | Cartão de abertura: SAST Studio · Risco Cidadão | Olá! Somos estudantes de Engenharia de Software da FIAP, e este é o nosso projeto da Global Solution CitizenTech, em Cybersecurity. Vamos apresentar o Sást Stúdio, um analisador de código que protege os dados pessoais do cidadão. |
| 2 | Cartão "A missão técnica tem quatro partes" (aparecem uma a uma) | O problema é simples: sistemas públicos, como uma unidade de saúde, guardam CPF, diagnóstico e senha de milhares de pessoas. Se esses dados ficam escritos no código, ou vão parar no registro interno do sistema, o cidadão fica exposto. Nossa missão técnica tem quatro partes, e vamos mostrar cada uma funcionando. |
| 3 | **Parte 1** · Regras de análise filtradas por PII, Scanner, carregar a UBS fictícia e executar | Parte um: regras de dados pessoais. O sistema reconhece CPF, cartão do SUS, cartão de crédito, e-mail, telefone e dado de saúde, e confere o valor pelos dígitos verificadores, para não dar alarme falso. Vou carregar o código de uma unidade de saúde fictícia, com dados inventados, e executar a análise. |
| 4 | **Resultado** · achados de CPF, saúde e senha com MD5 | A análise encontrou nove problemas. Aqui, um CPF escrito direto no código. Aqui, um diagnóstico dentro do programa. E aqui, uma senha protegida com um método fraco, o M D cinco. |
| 5 | **Parte 2** · Taint Analysis: origem, variável e saída insegura | Parte dois: análise de contaminação de dados. Ela acompanha o dado desde a origem até uma saída insegura. Aqui, o CPF nasce no campo cpf do paciente, passa por uma variável, e termina no registro interno do sistema. Assim o sistema prova o vazamento, em vez de só desconfiar. |
| 6 | **Parte 3** · Risco Cidadão, "Traduzir para o cidadão" com o Ollama | Parte três: inteligência artificial. Um modelo que roda no próprio computador, o Lama três, pelo Olama, traduz a falha técnica para uma linguagem que um gestor público entende: o que acontece, o risco, quem é afetado e o que fazer. O nível de risco vem do achado, e não da IA, então ela não minimiza uma falha crítica. |
| 7 | **Parte 4** · Painel Risco Cidadão: 99/100, gate bloqueado | Parte quatro: o painel Risco Cidadão. O indicador é noventa e nove de cem, nível crítico, e o portão de segurança fica bloqueado. São nove achados com dados pessoais, e seis são vazamentos confirmados pela análise de contaminação. |
| 8 | **Diferencial** · Corrigir e provar (99 → 0) | Como diferencial, o sistema também corrige e prova. Ele mascara os dados que saem no registro, na resposta e para parceiros, troca o M D cinco por bicrípt, e tira o CPF do código. Depois, analisa de novo, e o risco cai de noventa e nove para zero. |
| 9 | **Histórico** · diff, análise corrigida e evolução | A versão corrigida entra no histórico, com o portão aprovado, e dá para ver cada mudança no código. A prova vem das regras do motor e não executa o programa, então a revisão humana continua necessária. |
| 10 | Cartão final: os quatro critérios marcados | Resumindo: cumprimos os quatro critérios, com regras de dados pessoais, rastreio do fluxo do dado, alertas com inteligência artificial, e o indicador Risco Cidadão com correção verificada. São duzentos e trinta testes automáticos. O indicador mostra risco no código, e não prova de vazamento. Obrigado! |

## Por que a grafia do texto é diferente do que aparece na tela

A voz foi gerada com grafia pensada para a pronúncia em português: "Lama três" (Llama 3), "Olama" (Ollama), "M D cinco" (MD5), "bicrípt" (bcrypt), "Sást Stúdio" (SAST Studio),
"portão de segurança" (gate) e "registro interno" (log). Na tela, os nomes aparecem com a grafia original.

## Como a tela é gravada

1. `python iniciar.py` e abra <http://127.0.0.1:8000/dashboard> (ou a porta que subir).
2. Aqueça a IA antes: `ollama run llama3.2:3b "diga olá" --keepalive 30m`. Na Parte 3, o alerta leva alguns segundos para aparecer; espere o selo `Ollama (llama3.2:3b)`.
3. Siga a ordem da tabela. Se for gravar outra versão, use as telas da própria tabela: Regras de análise (filtro "PII") → Scanner → Achados → Risco Cidadão.
