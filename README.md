<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo/kiri-horizontal-dark.svg">
    <img src="brand/logo/kiri-horizontal-light.svg" alt="Kiri" width="240">
  </picture>
</p>

# Kiri

A tiny, fast container runtime for macOS, written in Rust. It runs Docker
images in one lightweight Linux VM and speaks the Docker Engine API, so the
ordinary `docker` CLI, Compose and buildx work against it, with no need for
OrbStack or Docker Desktop.

The name comes from the Igbo word *ntakịrị*, "small".

## Status

Apple silicon and Intel Macs (macOS 14+), Windows 10 and 11 (x86-64 and Arm, through WSL 2), and Linux (.deb and .rpm, tested on Ubuntu and Fedora). Through the `kiri` Docker context, today:

- **Containers**: `run` (`--rm`, `-d`, `-it`, `-e`, `-u`, `-w`, `--name`,
  `--restart`, `--entrypoint`), `exec`, `logs`, `attach`, `stop`, `kill`,
  `restart`, `rm`, `wait`, `rename`, `pause`/`unpause`, `update`, `stats`,
  `top`, `diff`, `export`, `commit`, `cp` (both ways, running or not),
  `container prune`; records survive a daemon restart; filters on every list
- **Limits and security**: `--memory`, `--cpus`, `--cpu-shares`,
  `--pids-limit`, `--shm-size`; Docker's default capabilities and a default
  seccomp filter; `--cap-add`/`--cap-drop`, `--privileged`, `--read-only`,
  `--security-opt seccomp=unconfined` and `no-new-privileges`. Even
  privileged and unconfined containers keep the host boundary: no vsock
  sockets (the way to the Mac) and no io_uring
- **Networking**: a default bridge, user networks with DNS by name and
  alias, `network connect`/`disconnect`, `--network host|none`, `-p`/`-P`
  (TCP and UDP) on all interfaces (as Docker does; `-p 127.0.0.1:8080:80`
  keeps a port local), `--add-host`, `host.docker.internal`,
  `--network container:<name>` (Compose `network_mode: service:x`; as with
  Docker, if that container restarts, the ones sharing its network keep the
  old, now empty namespace until they are restarted too), IPAM (`--subnet`,
  `--gateway`, `--ip-range`, `--aux-address`), `--ip`, `--mac-address`,
  `--dns`, `--dns-search`, `--dns-option`, `--domainname` and `--link`
  (IPv6 networks are refused, not ignored), and
  `http://<name>.kiri.local` once you turn it on (the app asks on first open;
  Settings → Domains changes it), or `http://<name>.kiri.localhost` with no
  setup. Compose services answer at `<service>.<project>.kiri.local`, and a
  `dev.kiri.domain=api.myapp` label picks a container's own names; HTTPS too
  (`https://<name>.kiri.local`), with Kiri's own certificate authority in
  `~/.kiri/tls`, whose name constraints allow only `*.kiri.local` and
  `*.kiri.localhost` (Settings → Domains → HTTPS asks macOS to trust it)
- **Storage**: named and anonymous volumes, bind mounts of Mac paths
  (virtiofs), `--tmpfs`, `--mount`, `volume` commands
- **Images**: `pull` (with `docker login` credentials), `push`, `tag`,
  `save`, `load`, `history`, `search`, `image prune`, `system df`;
  **amd64 images run through Rosetta**, `--platform` honoured
- **Builds**: `docker build` / `buildx build` through BuildKit running in a
  Kiri container (buildx's docker-container driver), stopped when idle
- **Compose**: `up`, `down`, `ps`, `logs`, `exec`, multiple networks, events
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

## Numbers

Measured on one Apple Silicon Mac, `alpine` running `true` and removed,
default bridge network, median of 30 runs, all three engines driven by the
same `docker` CLI 29.7.2 in one run:

|                | Docker Engine API | `docker` CLI |
|----------------|------------------:|-------------:|
| Kiri           | 2.55 ms           | 14.2 ms      |
| Docker Desktop | 213 ms            | 243 ms       |
| OrbStack       | 380 ms            | 442 ms       |

With `--network none`: Kiri 2.68 / 14.0 ms, Docker Desktop 110 / 111 ms,
OrbStack 310 / 317 ms. Most of Kiri's CLI figure is the `docker` CLI
starting up. Caveats and every other figure are in
[`bench/results.json`](bench/results.json); rerun with `kiri bench`.

## How it works

```
docker CLI ─┐
compose ────┼─ ~/.kiri/run/docker.sock ─► kiri daemon ── vsock ──► guest agent (PID 1)
buildx ─────┤     Docker Engine API          owns the VM            clone3 → container
kiri UI ────┘
```

- **VM**: Apple's Virtualization.framework, driven from Rust through objc2.
  A custom 10 MB kernel (`guest/kernel/`) built from allnoconfig, with one
  patch that cuts virtio-pci reset waits from a scheduler tick to
  microseconds. Rosetta is shared in over virtiofs and registered with
  binfmt_misc.
- **Guest agent**: a ~900 KB static Rust binary that is PID 1. One `poll()`
  loop serves the host, reaps children, forwards container output, relays
  ports, answers DNS and runs DHCP. `docker cp` and friends run in forked
  children so a large copy never stalls it.
- **Containers**: one `clone3` straight into new namespaces and the
  container's cgroup (`CLONE_INTO_CGROUP`), overlayfs over layers unpacked
  on an ext4 data disk, `pivot_root`, capabilities and a seccomp filter.
  Networking is set up with hand-written rtnetlink and nf_tables messages.
  No runc, no shim, no dockerd.
- **Images**: pulled and pushed on the Mac (`crates/kiri-image`), streamed
  into the guest once and unpacked there.

## Layout

| Path | What |
|------|------|
| `crates/kiri` | the `kiri` binary: daemon, Docker API, CLI, UI, bench |
| `crates/kiri-vmm` | Virtualization.framework VM |
| `crates/kiri-init` | guest PID 1, agent and container runtime |
| `crates/kiri-proto` | host ↔ guest wire protocol (no_std, no allocation per message) |
| `crates/kiri-image` | image references, registry client, blob store, archives |
| `guest/kernel` | kernel config and patches |
| `tests/e2e.sh` | ~350 checks through the real `docker` CLI, plus a leak soak (`K8S=1` adds Kubernetes) |
| `tests/linux-host.sh` | the Linux host build, driven in a privileged container |
| `contrib/` | systemd unit, WSL2 and Windows install scripts |
| `installer/windows` | the Windows MSI (WiX 5): `kiri.wxs`, licence, dialog bitmaps |
| `packaging/` | Linux `.deb` and `.rpm` (`kiri` with the docker CLI, `kiri-lite` engine only), the Homebrew plan |
| `xtask` | build tasks |
| `bench/results.json` | measured results; the website keeps a copy |
| `brand/` | brand (the website and raw benchmark output live outside this repository) |

## Build

Needs Rust and, for the kernel and disk template, a Docker engine. Kiri can
build its own kernel: `DOCKER_CONTEXT=kiri cargo xtask kernel`.

```sh
cargo xtask kernel    # guest/out/Image
cargo xtask disk      # guest/out/data.img (sparse 64 GiB ext4 template)
cargo xtask guest     # guest/out/initramfs.cpio
cargo xtask host      # target/release/kiri, signed with the virtualization entitlement
```

For Intel Macs add `--arch x86_64` to `kernel`, `guest`, `host`, `app`,
`dmg` and `release`: an x86-64 guest in `guest/out/x86_64` (a `bzImage`,
cross-compiled on Apple Silicon), the host for `x86_64-apple-darwin`
(`rustup target add x86_64-apple-darwin x86_64-unknown-linux-musl`), and
`target/intel/Kiri.app` with Intel builds of the docker CLI, Compose and
buildx, released as `Kiri-<version>-x86_64.dmg`/`.tar.gz` with its own feed,
`latest-mac-x86_64.json`. Each Mac gets its own app rather than one universal
app, which would carry both builds of the docker tools. On Intel there is
no Rosetta for Linux: amd64 images run natively, and images with no amd64
build are refused.

On Windows, `cargo xtask windows-dev` builds the Linux engine, Kiri Linux and
Docker tools into `target/kiri-windows-x86_64` with a debug `kiri-win.exe`.
`cargo run -p kiri-win` uses that bundle automatically. Use `cargo xtask
windows` for the release bundle and `cargo xtask msi` for the installer.
Add `--arch arm64` to any of the three for Windows on Arm
(`target/kiri-windows-aarch64`, `Kiri-<version>-arm64.msi`); testing it in
a VM on a Mac is in [docs/testing-windows-arm.md](docs/testing-windows-arm.md).

## Use

```sh
./target/release/kiri daemon &      # serves ~/.kiri/run/docker.sock; the VM boots on first use
docker context create kiri --docker host=unix://$HOME/.kiri/run/docker.sock
docker --context kiri run --rm alpine echo hello
docker buildx create --name kiri-build --driver docker-container \
  --driver-opt default-load=true --use kiri    # for docker build
./target/release/kiri bench         # Kiri vs OrbStack vs Docker Desktop
SOAK=600 tests/e2e.sh               # every check, then 600 runs watching for leaks
```

Docker's commands also work as `kiri` commands, always on Kiri whatever
docker context is selected: `kiri run`, `kiri ps`, `kiri exec`, `kiri logs`,
`kiri build`, `kiri compose up` and the rest run the docker CLI against
Kiri's socket. (`kiri import` is Kiri's own: it brings images, volumes and
containers over from OrbStack or Docker Desktop.) The daemon-free tools
that boot their own guest are `kiri raw run|pull|images|rmi`.

`kiri` keeps its data in `~/Library/Application Support/Kiri` (override with
`KIRI_DATA_DIR`). It does not touch `/usr/local/bin/docker` or
`/var/run/docker.sock`.

## Known issues

- **`docker build --add-host name:host-gateway` with BuildKit fails** with
  `host-gateway is not supported by the docker-container driver`. buildx
  refuses `host-gateway` for every builder except Docker's built-in one, and
  Kiri's builder is a docker-container builder, so the build stops before
  Kiri sees it. Docker's own docker-container builders do the same. Until
  Kiri has a built-in builder (planned), use the address itself
  (`--add-host name:172.18.0.1` on Windows and Linux, the default bridge's
  gateway; `198.19.248.254` on a Mac) or `DOCKER_BUILDKIT=0`, where Kiri
  maps `host-gateway` itself.

## Roadmap


1. ~~Docker CLI, Docker Engine API, background daemon~~
2. ~~Detached containers that persist, `exec`, `-it`~~
3. ~~Networking~~
4. ~~Ports forwarded to `localhost`~~
5. ~~Container domain names~~
6. ~~`host.docker.internal`~~
7. ~~Container files in Finder~~
8. ~~SSH agent forwarding~~
9. ~~Memory and CPU: return memory to macOS, idle at zero~~
10. ~~Volumes, Compose, builds, registries, Rosetta, seccomp~~
11. ~~`Kiri.app` with a bundled CLI, `kiri setup`, auto-update~~
12. ~~Kubernetes, Linux machines, Linux hosts, WSL2~~
13. ~~Developer ID signing and notarization, a public release feed~~
14. ~~Windows and Linux releases~~
15. A built-in builder (next): Docker's own build endpoints (`/grpc`,
    `/session`) served by Kiri, so buildx uses its docker driver against
    Kiri as it does against Docker Desktop. That brings `host-gateway` in
    BuildKit builds, loads images straight into Kiri, and retires the
    separate `kiri-build` builder and the Build with Kiri setting.
16. Clippy with rustc 1.98: its new lints (about 170 lines over 20 files,
    mostly mechanical) before CI moves to that toolchain.

## License

Kiri is licensed under [AGPL-3.0-only](LICENSE). Third-party licences and
attribution are in [NOTICE](NOTICE).

The guest kernel is Linux, under GPL-2.0. Its build script, configuration and
Kiri's patches are in [`guest/kernel`](guest/kernel). Complete corresponding
source and the source offer are described in
[`guest/kernel/SOURCE_OFFER.md`](guest/kernel/SOURCE_OFFER.md).

The name "Kiri" and the Kiri logo are not covered by this licence. Forks are
welcome, but please give yours a different name and logo.

See [CONTRIBUTING.md](CONTRIBUTING.md) to help, the
[Code of Conduct](CODE_OF_CONDUCT.md) for community expectations, and
[SECURITY.md](SECURITY.md) to report a vulnerability.
