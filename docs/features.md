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
  bind a folder (`driver_opts: {type: none, o: bind, device: /path}`);
  local-driver volumes with `driver_opts` `type=nfs` mount a remote NFS
  export — NFSv4 (minorversion 4.0 and 4.1) and NFSv3, honouring `addr=`,
  `nfsvers=`, `hard`/`soft`, `timeo`, `retrans`, `ro`/`rw` and `noatime`;
  LUKS / `dm-crypt` in the guest kernel (`CONFIG_DM_CRYPT`)
- **Images**: `pull` (with `docker login` credentials), `push`, `tag`,
  `save`, `load`, `history`, `search`, `image prune`, `system df`;
  **amd64 images run through Rosetta**, `--platform` honoured
- **Private registries**: Kiri's own `~/.kiri/daemon.json` takes Docker's
  `insecure-registries` (hosts such as `registry.lan:5000`, or networks
  such as `10.0.0.0/8`, reached with a self-signed certificate or plain
  HTTP: HTTPS without checking the certificate first, then HTTP) and
  `registry-mirrors` (Docker Hub pull-through mirrors, tried in order,
  each over the scheme it is written with: `http://` straight over plain
  HTTP, `https://` never down to it, as in Docker).
  They apply to `pull`, `push`, `login` and `build`, only for the hosts
  listed, and an edit applies without a restart. Docker Hub is always
  reached directly over verified HTTPS, whatever the file lists or its
  name resolves to, and a registry on this machine (`localhost` or a
  loopback address; not a name under `.localhost`) is tried over HTTPS
  without a certificate check, then HTTP, as in Docker. Where
  Kiri is stricter than Docker: a network covers registries named by an
  address in it (`10.1.2.3:5000`), not host names that resolve into it
  (list those by name), and must be a private range or a small one (a
  /16 or longer for IPv4, /48 for IPv6); a plain-HTTP (`http://`) mirror
  is used only when its host is listed as insecure too; a pull signed in
  to Docker Hub asks the mirrors only for official (`library/`) images; a
  mirror that fails mid-pull, or serves an image for another platform,
  hands the pull to the next mirror and then Docker Hub, and an image a
  mirror served records which; a plain-HTTP token service is asked only
  on the registry's own host and port; and no redirect goes from HTTPS down to
  plain HTTP except to a listed host. BuildKit's settings name hosts, not
  networks, so a network reaches `docker build` for a registry once an
  image from it has been pulled (until then such a `FROM` fails rather
  than going unchecked): pull from a new registry in a listed network once,
  or list it by name. The lists, like Kiri's other settings, are changed
  from this machine (the window, `kiri registry` or the file). Containers
  can't change Kiri's settings through the engine's API, even with its
  socket. As with Docker, a container you give writable host folders can
  change your files there, Kiri's settings among them, and a container
  that can create containers with `--privileged`, `--pid=host`,
  `SYS_ADMIN`, `--device` or a mount of the host's root is as good as root
  on this machine. A daemon.json larger than
  256 KiB, or not a regular file, is ignored, and at most 256 hosts and
  16 mirrors are read. Settings → Registries and `kiri registry
  insecure|mirror add|remove` edit the same file; Docker Desktop's
  daemon.json is never read or changed. A registry with a self-signed
  certificate is reached only once it is listed, as with Docker
- **Builds**: `docker build` / `buildx build` through BuildKit running in a
  Kiri container (buildx's docker-container driver), stopped when idle;
  `--platform` for one platform at a time; on Apple silicon, amd64 build
  steps run through Rosetta too
- **Vulnerability scanning**: `kiri scan <image>` (or an image's Security
  tab in the window) finds known CVEs in an image with Grype, on Mac,
  Windows and Linux — also what every build's page shows. Nothing leaves
  your machine: Grype reads the image through an OCI layout of Kiri's own
  store, and the first scan downloads Grype and its database (about
  230 MB, 3 GB unpacked), kept for every scan after. The last 20 scans of
  an image are kept, with `--history` and `--json`, and finding
  descriptions link their advisories
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
  size, starting at sign-in, stopping the engine when Kiri quits, the VM's
  CPUs, memory, swap and disk image size (`~/.kiri/vm.json`, used from the VM's
  next start; `KIRI_CPUS`, `KIRI_MEMORY_MIB`, `KIRI_SWAP_MIB` and `KIRI_DISK_GB`
  override it; the disk grows online on boot and never shrinks) and local names
- **Menu bar**: Kiri stays in the menu bar (or the tray on Windows and Linux)
  when its window closes, with the VM's state, running containers (click one
  to open it) and Start/Stop; Settings → Appearance → Closing the window can
  either keep the window hidden or free its page's memory until opened again
- **Kubernetes**: `kiri k8s start` — a single-node k3s cluster in one
  container, ready in ~20 s, as the `kiri` kubectl context
- **Linux machines**: `kiri machine create dev --distro ubuntu` and
  `kiri machine shell dev` — your user, sudo, and `/Users` at the same path;
  `docker container prune` and `docker system prune` leave a stopped machine
  alone (`kiri machine delete` removes it)
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
  output. Settings → Resources → WSL integration exposes per-distro engine
  sockets under `/mnt/wsl/kiri/sockets/<distro>/docker.sock` (linked from
  `/var/run/docker.sock` and a `kiri` Docker context when no `dockerd` is
  running in that distro) and translates bind mounts from each enabled WSL 2
  distro's Linux filesystem through `/mnt/wsl/kiri/roots/<distro>` (off by
  default; Windows paths like `\\wsl.localhost\<distro>\…` work too)

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

## Company certificates

Kiri trusts the root certificates of the operating system and the Mozilla set that Kiri bundles. This applies to pulls, pushes, `docker login`, the update check, CLI and grype downloads, and Kiri Share. A registry signed by a company root certificate works when the system trusts that certificate.

- **macOS**: Kiri reads the trust settings of the user, admin and system keychains. Mark the root certificate as trusted, for example: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.pem`
- **Linux**: Kiri reads the system CA bundle, for example in `/etc/ssl/certs`.
- **Windows**: pulls run in the engine in WSL 2, away from the Windows certificate store, so the Kiri window copies the store into the engine: the root certificates of the current user (which include the machine's and those Group Policy adds) that the bundled set lacks, and the certificates in the Disallowed store (as well as bundled roots disabled for Server Authentication). It sends them when the engine starts and every minute while Kiri runs, and the engine keeps them for its next start. Kiri Share uses the Windows certificate store of the current user. Trust the company root certificate in Windows, for example `certutil -user -addstore Root ca.cer`; pulls trust it within a minute.

A root certificate that an administrator distrusts stays distrusted, even though the bundled Mozilla set has it:

- **macOS**: "Never Trust" in the user or admin trust settings. Settings in the system domain are not read.
- **Windows**: the certificates in the Disallowed store (and bundled roots disabled for Server Authentication in `ROOT`), for Kiri Share and for pulls in the engine (only the engine in WSL accepts Windows roots, and only from Kiri on Windows; a native Linux engine, containers, and other WSL distros are refused). A re-issued copy of a distrusted self-issued root, with the same subject and public key, is distrusted too; a distrusted cross-certificate leaves the self-signed root it shares a key with trusted.
- **Linux**: there is no list of distrusted certificates to read. A Mozilla root certificate that you remove from the system bundle (for example with `!` in `/etc/ca-certificates.conf`) is still trusted through the bundled set.

Kiri does not check online revocation (CRL or OCSP).

NOTE: If `SSL_CERT_FILE` or `SSL_CERT_DIR` is set, Kiri reads the root certificates there instead of the system store, as OpenSSL does. The bundled Mozilla set stays in use, so these variables add root certificates and cannot limit trust to a private CA only. Kiri writes a warning when this occurs, and a company CA trusted in the keychain or system store is then not trusted.

If the system store causes a problem, set `KIRI_TLS_ROOTS=webpki`. Kiri then trusts only the bundled Mozilla set, as before: nothing is read from the system, so the roots an administrator distrusted are trusted again too. The Kiri app and the daemon do not read your shell environment; set the variable for them and restart Kiri:

- **macOS**: `launchctl setenv KIRI_TLS_ROOTS webpki`
- **Linux**: `sudo systemctl edit kiri`, add `Environment=KIRI_TLS_ROOTS=webpki` under `[Service]`, then `sudo systemctl restart kiri`.

To trust a private certificate authority at a Kiri Share edge only, set `KIRI_SHARE_CA` to a PEM file of extra root certificates. Kiri adds them to the trusted roots for that edge only; a file that does not parse is an error, not a silent skip.

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
  image from a registry fails with `failed to resolve source metadata for
  docker.io/library/alpine:3.15: docker.io/library/alpine:3.15: not found`,
  even if `docker pull` already fetched that tag or digest
  (`FROM alpine:3.13@sha256:...`). Kiri's builder asks Kiri's image mirror
  first; the mirror serves only images no registry has (built, loaded,
  committed, or tagged into another repository) and answers 404 for
  registry tags and digests so BuildKit resolves them from the registry.
  When the registry then can't be reached, BuildKit reports the mirror's
  "not found" instead of the network error. A docker-container builder
  with no mirror shows the real cause (`dial tcp: lookup
  registry-1.docker.io ...`). The builder runs on the default bridge, so
  check from a container there:
  `docker run --rm alpine nslookup registry-1.docker.io`.

- **`type=cifs` (SMB) volumes don't mount yet.** Kiri's guest kernel has no
  CIFS client, so a local-driver volume with `driver_opts: {type: cifs}`
  fails the same way NFS-backed volumes did before NFS support landed.
  SMB support is a separate change.
