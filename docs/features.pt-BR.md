# Recursos

O que o Kiri suporta hoje, pelo contexto Docker `kiri`.

## Plataformas

Macs com Apple silicon e Intel (macOS 14+), Windows 10 e 11 (x86-64 e Arm, via WSL 2) e Linux (.deb e .rpm, testado no Ubuntu e no Fedora).

## O que funciona

- **Containers**: `run` (`--rm`, `-d`, `-it`, `-e`, `-u`, `-w`, `--name`,
  `--restart`, `--entrypoint`), `exec`, `logs`, `attach`, `stop`, `kill`,
  `restart`, `rm`, `wait`, `rename`, `pause`/`unpause`, `update`, `stats`,
  `top`, `diff`, `export`, `commit`, `cp` (nos dois sentidos, rodando ou não),
  `container prune`; os registros sobrevivem a um restart do daemon; filtros em todas as listagens
- **Limites e segurança**: `--memory`, `--cpus`, `--cpu-shares`,
  `--pids-limit`, `--shm-size`; as capabilities padrão do Docker e um filtro
  seccomp padrão; `--cap-add`/`--cap-drop`, `--privileged`, `--read-only`,
  `--security-opt seccomp=unconfined` e `no-new-privileges`. Mesmo
  containers privilegiados e sem confinamento mantêm a fronteira com o host: sem sockets
  vsock (o caminho até o Mac) e sem io_uring
- **Rede**: uma bridge padrão, redes de usuário com DNS por nome e
  alias, `network connect`/`disconnect`, `--network host|none`, `-p`/`-P`
  (TCP e UDP) em todas as interfaces (como o Docker faz; `-p 127.0.0.1:8080:80`
  mantém uma porta local), `--add-host`, `host.docker.internal`,
  `--network container:<nome>` (`network_mode: service:x` do Compose; como no
  Docker, se esse container reiniciar, os que compartilham a rede dele ficam com o
  namespace antigo, agora vazio, até serem reiniciados também), IPAM (`--subnet`,
  `--gateway`, `--ip-range`, `--aux-address`), `--ip`, `--mac-address`,
  `--dns`, `--dns-search`, `--dns-option`, `--domainname`, `--link`,
  `--ipv6` (`enable_ipv6` do Compose: uma sub-rede IPv6 ao lado da IPv4, vinda de
  `--subnet` ou de um /64 do próprio Kiri dentro de fd00::/8; a bridge padrão continua
  só IPv4, como a do Docker), e
  `http://<nome>.kiri.local` depois que você ativa (o app pergunta na primeira abertura;
  Configurações → Domínios altera isso), ou `http://<nome>.kiri.localhost` sem
  configuração. Os serviços do Compose respondem em `<serviço>.<projeto>.kiri.local`, e um
  label `dev.kiri.domain=api.myapp` escolhe os nomes de um container; HTTPS também
  (`https://<nome>.kiri.local`), com a autoridade certificadora do próprio Kiri em
  `~/.kiri/tls`, cujas name constraints permitem apenas `*.kiri.local` e
  `*.kiri.localhost` (Configurações → Domínios → HTTPS pede ao macOS para confiar nela)
- **Armazenamento**: volumes nomeados e anônimos, bind mounts de caminhos do Mac
  (virtiofs), `--tmpfs`, `--mount`, comandos `volume`
- **Imagens**: `pull` (com as credenciais do `docker login`), `push`, `tag`,
  `save`, `load`, `history`, `search`, `image prune`, `system df`;
  **imagens amd64 rodam via Rosetta**, `--platform` respeitado
- **Builds**: `docker build` / `buildx build` via BuildKit rodando em um
  container do Kiri (driver docker-container do buildx), parado quando ocioso;
  no Apple silicon, as etapas de build amd64 também rodam via Rosetta
- **Compose**: `up`, `down`, `ps`, `logs`, `exec`, múltiplas redes, eventos
- **Integração com o Mac**: arquivos dos containers em `~/Kiri` no Finder (NFS
  somente leitura, sempre atualizado), encaminhamento do agente SSH em
  `/run/host-services/ssh-auth.sock`
- **Memória**: um balloon devolve a memória não usada enquanto roda, e a VM
  dorme após 60 s ociosa (o daemon fica em ~15 MB; acordar leva ~0,15 s)
- **A janela**: containers, imagens, volumes e redes, com os projetos
  Compose agrupados (iniciar, parar, reiniciar ou remover um projeto inteiro); cada
  container tem sua própria página com detalhes, logs ao vivo (busca, filtro de nível),
  uma linha de comando (e "Abrir no Terminal" para um shell completo) e seus arquivos
  (pré-visualização, Salvar em Downloads, Mostrar no Finder); Configurações de fontes, tamanho
  do texto, CPUs e memória da VM (`~/.kiri/vm.json`, usado a partir do próximo
  início da VM; `KIRI_CPUS` e `KIRI_MEMORY_MIB` têm precedência) e nomes locais
- **Barra de menus**: o Kiri fica na barra de menus quando a janela fecha, com o
  estado da VM, os containers em execução (clique em um para abri-lo) e Iniciar/Parar
- **Kubernetes**: `kiri k8s start` — um cluster k3s de um só nó em um único
  container, pronto em ~20 s, como o contexto kubectl `kiri`
- **Máquinas Linux**: `kiri machine create dev --distro ubuntu` e
  `kiri machine shell dev` — seu usuário, sudo e `/Users` no mesmo caminho
- **O app**: `cargo xtask app` gera o `Kiri.app` com o `docker` CLI,
  Compose e buildx dentro; abri-lo executa `kiri setup` (contexto docker,
  LaunchAgent, builder de build) e a janela; `kiri update` instala novas
  versões depois de verificar o SHA-256 e a assinatura
- **Hosts Linux**: o mesmo `kiri` sem VM — o agente roda no kernel do
  host (`cargo xtask linux`, `contrib/linux/kiri.service`); arm64 e
  x86-64; `tests/linux-host.sh` verifica isso. Empacotado como `.deb` e `.rpm`
  (`packaging/linux`): `kiri` com o docker CLI, Compose e buildx, ou
  `kiri-lite` só com o engine. Pertencer ao grupo `kiri` equivale a ter
  root, exatamente como o grupo `docker`
- **Windows**: o build Linux x86-64 em uma distro WSL2, e o `kiri-win.exe`,
  que serve a API em `npipe:////./pipe/kiri` (o contexto docker `kiri`) e
  a leva para dentro do WSL por um único `wsl.exe … kiri bridge`, então não
  exige mudanças nos ajustes de rede do WSL nem do Windows (`cargo xtask
  msi` gera `target/Kiri-<versão>-x86_64.msi`, um instalador por usuário
  em torno de `target/kiri-windows-x86_64`; o `kiri.ps1` nessa pasta instala
  o mesmo sem MSI). Não usa TCP:
  o relay de localhost do WSL descarta half-closes, e o `docker run` perde
  a saída

Os serviços LoadBalancer do Kubernetes são publicados em `localhost`, e
`kiri machine create NOME --systemd` inicia o systemd como init da máquina.

## Versões

O app e os DMGs são assinados com um Developer ID e notarizados. As versões e
os feeds de atualização ficam em `https://download.runkiri.com`, e cada arquivo e
feed indica sua arquitetura: `Kiri-<versão>-arm64.dmg`, `Kiri-<versão>-arm64.tar.gz`
e `latest-mac-arm64.json` para Apple silicon (`-x86_64` para Macs Intel),
`Kiri-<versão>-x86_64.msi` / `-arm64.msi` com `latest-windows-x86_64.json` /
`latest-windows-arm64.json` para Windows. Cada app lê apenas o próprio feed, e
cada plataforma é publicada separadamente. Dois DMGs: `Kiri-<versão>-arm64.dmg`
inclui o docker CLI, Compose e buildx; `Kiri-Lite-<versão>-arm64.dmg`
(`cargo xtask app-lite`) os deixa de fora e baixa as mesmas versões fixadas
na primeira abertura (`crates/kiri/src/cli_pins.rs`, verificadas por SHA-256),
a menos que o Mac já tenha um docker CLI.

## Problemas conhecidos

- **`docker build --add-host name:host-gateway` com BuildKit falha** com
  `host-gateway is not supported by the docker-container driver`. O buildx
  recusa `host-gateway` em todo builder exceto o embutido do Docker, e o
  builder do Kiri é um builder docker-container, então o build para antes de o
  Kiri recebê-lo. Os builders docker-container do próprio Docker fazem o mesmo. Até
  o Kiri ter um builder embutido (planejado), use o próprio endereço
  (`--add-host name:172.18.0.1` no Windows e no Linux, o gateway da bridge
  padrão; `198.19.248.254` em um Mac) ou `DOCKER_BUILDKIT=0`, em que o Kiri
  mapeia `host-gateway` por conta própria.
