# Iniciar e recuperar a conexão

## No computador que hospeda o sistema

1. Dê dois cliques em **iniciar.bat**. Ele inicia o acompanhamento dos serviços e abre o dashboard local.
2. Mantenha a janela aberta, o computador ligado e sem suspender durante a apresentação.
3. Para habilitar um link público temporário, use **iniciar_com_link.bat** desde o início. O executável `cloudflared` deve estar no PATH, em `tools/cloudflared.exe` ou no caminho temporário já utilizado nesta instalação. Consulte a [instalação oficial](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/).
4. O endereço local e o link público aparecem na janela. Se o acompanhamento já estiver ativo, abrir o iniciador novamente reutiliza a instância. Para mudar de modo local para público, encerre a janela anterior com Ctrl+C antes de abrir o iniciador com link.

O programa `manter_sast.py` verifica a API a cada ciclo (intervalo de 5 segundos mais o tempo das verificações), reutiliza serviços saudáveis, inicia o Ollama instalado se necessário e recupera a API na mesma porta e com o mesmo diretório de histórico se o processo encerrar. Não baixa modelos automaticamente. Somente processos que ele próprio iniciou podem ser encerrados por ele. Um processo antigo que continua ocupando a porta e não responde exige intervenção local; o programa informa essa condição.

As verificações de saúde do Ollama confirmam acesso ao serviço e ao catálogo. Elas não garantem que uma inferência terminará dentro do tempo limite nem que a sugestão gerada estará correta. Confira o selo do provedor ao demonstrar a IA.

O estado local fica em `data/runtime/state.json` e os logs ficam na mesma pasta. Nenhum controle de processos é disponibilizado na API pública. A configuração salva mantém a porta, o diretório de dados e a opção de túnel nas próximas aberturas. Esse diretório é ignorado pelo Git.

Alternativa pela linha de comando:

```powershell
python manter_sast.py
# Link temporário público:
python manter_sast.py --cloudflare
```

`python iniciar.py` continua disponível como iniciador simples, sem acompanhamento de recuperação.

## No navegador

- **Reconectar API**, no topo, verifica a conexão e atualiza os serviços, regras e histórico.
- Se houver uma interrupção, a página tenta novamente após 2, 4, 8, 15 e depois 30 segundos. Com conexão normal, verifica a API a cada 20 segundos.
- A reconexão preserva o editor, os arquivos selecionados, a análise aberta e as sugestões já exibidas. Não recarrega a página.
- O botão não inicia um servidor desligado remotamente. Se o site inteiro mostrar a página de erro do Cloudflare, execute o iniciador no computador servidor e abra o link informado por ele.
- A reconexão não reenvia solicitações de análise ou IA. Se uma solicitação perdeu a resposta, confira o histórico antes de reenviá-la para evitar execuções duplicadas.

## Erro HTTP 502 e link temporário

O acompanhamento verifica separadamente a API local e o acesso público. Um erro público com API local saudável não reinicia a API. O túnel recebe tempo para se reconectar; após seis verificações públicas consecutivas com falha, pode ser criado um novo túnel. Nesse caso, **o endereço muda**: copie o novo link exibido na janela ou consulte `data/runtime/state.json`.

Novos túneis usam HTTP/2, configurável por `--protocol auto`, `--protocol quic` ou `--protocol http2`. Isso oferece uma alternativa em redes que restringem UDP; não garante disponibilidade. [Documentação de protocolos](https://developers.cloudflare.com/tunnel/configuration/).

A Cloudflare descreve o 502 como falha de acesso à origem pelo túnel. Quick Tunnels são temporários e **não têm garantia de disponibilidade**. Para apresentar, mantenha o endereço local como alternativa no próprio computador servidor. [Diagnóstico de túneis](https://developers.cloudflare.com/tunnel/troubleshooting/), [limitações do Quick Tunnel](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).

## Verificações de recuperação

```powershell
python -m pytest tests/test_service_supervisor.py tests/test_launcher.py -q
node --test tests/test_connection.js tests/queued-recovery.test.cjs tests/diff-viewer.test.cjs
# Teste real opcional: inicia e encerra apenas a API de teste em porta e dados temporários.
$env:SAST_TEST_SUPERVISOR = "1"
python -m pytest tests/test_service_supervisor.py -q
Remove-Item Env:SAST_TEST_SUPERVISOR
```
