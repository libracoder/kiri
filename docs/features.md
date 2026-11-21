# Features

What Kiri supports today, through the `kiri` Docker context.

## Platforms

Apple silicon and Intel Macs (macOS 14+), Windows 10 and 11 (x86-64 and Arm, through WSL 2), and Linux (.deb and .rpm, tested on Ubuntu and Fedora). 
## What works

- **Containers**: `run` (`--rm`, `-d`, `-it`, `-e`, `-u`, `-w`, `--name`,
  `--restart`, `--entrypoint`), `exec`, `logs`, `attach`, `stop`, `kill`,
  `restart`, `rm`, `wait`, `rename`, `pause`/`unpause`, `update`, `stats`,
  `top`, `diff`, `export`, `commit`, `cp` (both ways, running or not),
  `container prune`; records survive a daemon restart; filters on every list;
  healthchecks (`--health-cmd` and the other `--health-*` options, including
  `--health-start-interval`; `ps --filter health=`)
- **Limits and security**: `--memory`, `--cpus`, `--cpu-shares`,
  `--pids-limit`, `--shm-size`; Docker's default capabilities and a default
  seccomp filter; `--cap-add`/`--cap-drop`, `--privileged`, `--read-only`,
  `--security-opt seccomp=unconfined` and `no-new-privileges`. Even
  privileged and unconfined containers keep the host boundary: no vsock
  sockets (the way to the Mac) and no io_uring
- **Networking**: a default bridge, user networks with DNS by name and
  alias, `network connect`/`disconnect` (as with Docker, a container can
  leave any of its networks, its first one too: another of its networks
  then gives its default route, and with none left it has no network, as
  with `--network none`; to leave its first network a running container is
  stopped first), `--network host|none`, `-p`/`-P`
  (TCP and UDP) on all interfaces (as Docker does; `-p 127.0.0.1:8080:80`
  keeps a port local), `--add-host`, `host.docker.internal`,
  `--network container:<name>` (Compose `network_mode: service:x`; as with
  Docker, if that container restarts, the ones sharing its network keep the
  old, now empty namespace until they are restarted too), IPAM (`--subnet`,
  `--gateway`, `--ip-range`, `--aux-address`), `--ip`, `--mac-address`,
  `--dns`, `--dns-search`, `--dns-option`, `--domainname`, `--link`,
  `--ipv6` (Compose `enable_ipv6`: an IPv6 subnet beside the IPv4 one, from
  `--subnet` or a /64 of Kiri's own under fd00::/8; the default bridge stays
  IPv4-only, as Docker's does), and
  `http://<name>.kiri.local` once you turn it on (the app asks on first open;
  Settings → Domains changes it), or `http://<name>.kiri.localhost` with no
  setup. Compose services answer at `<service>.<project>.kiri.local`, and a
  `dev.kiri.domain=api.myapp` label picks a container's own names; HTTPS too
  (`https://<name>.kiri.local`), with Kiri's own certificate authority in
  `~/.kiri/tls`, whose name constraints allow only `*.kiri.local` and
  `*.kiri.localhost` (Settings → Domains → HTTPS asks macOS to trust it).
  The routers' ports from the terminal: `kiri domains` shows them,
  `kiri domains set --http 8080 --https 8443` moves them with no restart,
  `kiri domains reset` puts back 80 and 443
- **Storage**: named and anonymous volumes, bind mounts of Mac paths
  (virtiofs), `--tmpfs`, `--mount`, `volume` commands; local volumes that
  bind a folder (`driver_opts: {type: none, o: bind, device: /path}`)
- **Images**: `pull` (with `docker login` credentials), `push`, `tag`,
  `save`, `load`, `history`, `search`, `image prune`, `system df`;
  **amd64 images run through Rosetta**, `--platform` honoured
- **Builds**: `docker build` / `buildx build` through BuildKit running in a
  Kiri container (buildx's docker-container driver), stopped when idle;
  `--platform` for one platform at a time; on Apple silicon, amd64 build
  steps run through Rosetta too
- **Compose**: `up` (with `--build` and `--wait`), `down`, `ps`, `logs`,
  `exec`, `build:`, healthchecks, `depends_on` conditions
  (`service_healthy`, `service_completed_successfully`), `platform:`,
  multiple networks, events
- **USB devices (beta)**: the USB tab hands a device (a serial adapter, a
  Zigbee stick, a development board) to your containers on Mac, Windows and
  Linux, and shows where it is inside Linux with the `--device` line to
  copy. On a Mac, a device that drops off the bus while attached (the board
  resets, or the Mac sleeps) is attached again when it comes back
- **Mac integration**: container files at `~/Kiri` in Finder (read-only
  NFS, always current), SSH agent forwarding at
  `/run/host-services/ssh-auth.sock`
- **Memory**: a balloon gives unused memory back while running, and the VM
  sleeps after 60 s idle (the daemon stays at ~15 MB; waking takes ~0.15 s)
- **The window**: containers, images, volumes and networks, with Compose
  projects grouped (start, stop, restart or remove a whole project); each
  container has its own page with details, live logs (find, level filter),
  a command line (and "Open in Terminal" for a full shell) and its files
  (preview, Save to Downloads, Show in Finder); Settings for fonts, text
  size, the VM's CPUs and memory (`~/.kiri/vm.json`, used from the VM's
  next start; `KIRI_CPUS` and `KIRI_MEMORY_MIB` override it) and local names
- **Menu bar**: Kiri stays in the menu bar when its window closes, with the
  VM's state, running containers (click one to open it) and Start/Stop
- **Kubernetes**: `kiri k8s start` — a single-node k3s cluster in one
  container, ready in ~20 s, as the `kiri` kubectl context
- **Linux machines**: `kiri machine create dev --distro ubuntu` and
  `kiri machine shell dev` — your user, sudo, and `/Users` at the same path
- **The app**: `cargo xtask app` builds `Kiri.app` with the `docker` CLI,
  Compose and buildx inside; opening it runs `kiri setup` (docker context,
  LaunchAgent, build builder) and the window; `kiri update` installs new
  releases after checking their SHA-256 and signature
- **Linux hosts**: the same `kiri` with no VM — the agent runs on the host's
  kernel (`cargo xtask linux`, `contrib/linux/kiri.service`); arm64 and
  x86-64; `tests/linux-host.sh` checks it. Packaged as `.deb` and `.rpm`
  (`packaging/linux`): `kiri` with the docker CLI, Compose and buildx, or
  `kiri-lite` for the engine alone. Membership of the `kiri` group is
  root-equivalent, exactly like the `docker` group
- **Windows**: the x86-64 Linux build in a WSL2 distro, and `kiri-win.exe`,
  which serves the API on `npipe:////./pipe/kiri` (the `kiri` docker
  context) and carries it into WSL over one `wsl.exe … kiri bridge`, so it
  needs no change to WSL's or Windows' network settings (`cargo xtask
  msi` builds `target/Kiri-<version>-x86_64.msi`, a per-user installer
  around `target/kiri-windows-x86_64`; `kiri.ps1` in that folder installs
  the same without an MSI). Not TCP:
  WSL's localhost relay drops half-closes, and `docker run` loses its
  output

Kubernetes LoadBalancer services are published on `localhost`, and
`kiri machine create NAME --systemd` boots systemd as the machine's init.

## Releases

The app and DMGs are signed with a Developer ID and notarized. Releases and
the update feeds are at `https://download.runkiri.com`, and every file and
feed names its architecture: `Kiri-<version>-arm64.dmg`, `Kiri-<version>-arm64.tar.gz`
and `latest-mac-arm64.json` for Apple silicon (`-x86_64` for Intel Macs),
`Kiri-<version>-x86_64.msi` / `-arm64.msi` with `latest-windows-x86_64.json` /
`latest-windows-arm64.json` for Windows. Each app reads only its own feed, and
each platform is published on its own. Two DMGs: `Kiri-<version>-arm64.dmg`
bundles the docker CLI, Compose and buildx; `Kiri-Lite-<version>-arm64.dmg`
(`cargo xtask app-lite`) leaves them out and downloads the same pinned
versions on first launch (`crates/kiri/src/cli_pins.rs`, checked by SHA-256)
unless the Mac already has a docker CLI.

## Known issues

- **Mac: an attached USB device leaves your containers while the Mac
  sleeps.** macOS takes USB devices off the bus when it sleeps, so a device
  such as `/dev/ttyACM0` is gone from containers until the Mac wakes. Kiri
  then attaches it again by itself. Kiri doesn't keep the Mac awake for a
  device, since that would drain a laptop's battery. For a long job that
  runs unattended (flashing boards, logging a serial port), keep the Mac
  awake while it runs: `caffeinate -s` in a terminal (on power), or turn on
  "Prevent automatic sleeping when the display is off" in System Settings
  (Battery › Options on a laptop, Energy on a desktop Mac).

- **`docker build --add-host name:host-gateway` with BuildKit fails** with
  `host-gateway is not supported by the docker-container driver`. buildx
  refuses `host-gateway` for every builder except Docker's built-in one, and
  Kiri's builder is a docker-container builder, so the build stops before
  Kiri sees it. Docker's own docker-container builders do the same. Until
  Kiri has a built-in builder (planned), use the address itself
  (`--add-host name:172.18.0.1` on Windows and Linux, the default bridge's
  gateway; `198.19.248.254` on a Mac) or `DOCKER_BUILDKIT=0`, where Kiri
  maps `host-gateway` itself.

- **`docker build --platform linux/amd64,linux/arm64` fails** with
  `docker exporter does not currently support exporting manifest lists`:
  Kiri's builder loads one platform into Kiri per build. Build each
  platform with its own `--platform`, or write all of them to an OCI
  archive with `-o type=oci,dest=image.tar` (Kiri's `docker load` does not
  read OCI archives).

- **A build that cannot reach a registry says `not found`.** When BuildKit
  cannot reach the registry (for example, no DNS in the builder), a base
  image Kiri doesn't hold fails with `failed to resolve source metadata for
  docker.io/library/alpine:3.15: docker.io/library/alpine:3.15: not found`.
  So does a digest-pinned base (`FROM alpine:3.13@sha256:...`) right after
  `docker pull` fetched it by that digest. Kiri's builder asks Kiri's image
  mirror first; the mirror has no answer for that tag or digest, and when
  the registry then can't be reached BuildKit reports the mirror's
  "not found" instead of the network error. A docker-container builder
  with no mirror shows the real cause (`dial tcp: lookup
  registry-1.docker.io ...`). The builder runs on the default bridge, so
  check from a container there:
  `docker run --rm alpine nslookup registry-1.docker.io`.
