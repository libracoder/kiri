# Kiri UI on Arch Linux

`kiri-ui` packages the Linux desktop window (`kiri --features window`) for Arch
Linux (`x86_64` and `aarch64`, including Omarchy and Asahi). It installs the
executable at `/usr/lib/kiri/kiri-window`, where `kiri ui` launches it, along
with the desktop entry and icons.

The package intentionally leaves the Kiri engine, CLI, Docker context, and
container store untouched. Install it alongside an existing Kiri Linux engine
and CLI. GTK 3 and WebKitGTK 4.1 are required to build and run the window.

Build and install locally:

```sh
cd packaging/arch
makepkg -si
kiri ui --view containers
```

When updating `pkgver`, update `sha256sums` to the matching upstream release tag
archive (`v${pkgver}.tar.gz`) and keep the offline workspace version stamp in
`prepare()` so the window reports the installed package version.
