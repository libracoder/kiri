# Kiri UI on Arch Linux

`kiri-ui` packages the upstream Linux window for x86-64 Arch systems, including
Omarchy. It adds the executable at `/usr/lib/kiri/kiri-window`, which the
upstream `kiri ui` command already launches, plus the desktop entry and icons.

The package intentionally leaves the Kiri engine, CLI, Docker context, and
containers untouched. Install it alongside an existing Kiri Linux engine and
CLI. GTK 3 and WebKitGTK 4.1 are required to build and run the window.

Build and install locally:

```sh
cd packaging/arch
makepkg -si
kiri ui --view containers
```

The package is x86-64 only, matching the upstream Linux window build. When
updating `pkgver`, use the SHA-256 of the matching upstream source archive and
keep the workspace version patch in `prepare()` so the window reports the
package version.
