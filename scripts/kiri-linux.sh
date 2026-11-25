#!/bin/sh
# Kiri Linux, the WSL2 distro Kiri runs in on Windows: Alpine's minirootfs
# (pinned, checked), the static kiri binaries and contrib/wsl/kiri-linux.
# Runs as an ordinary user in WSL; the archive's files are owned by root.
# x86_64 for x86-64 PCs, aarch64 for Windows on Arm (the binaries in <dir>
# must be the same architecture). SHA-256s are Alpine's own .sha256 files.
#   scripts/kiri-linux.sh <repo> <dir with kiri and kiri-init> <out.tar.gz> [x86_64|aarch64]
set -eu
repo=$1 bin=$2 out=$3 arch=${4:-x86_64}
case "$arch" in
  x86_64) ALPINE_SHA256=f8e1cafba9b1b283b5d30d06f9885c8d2bc161ffe9083ade8e2e157813a53407 ;;
  aarch64) ALPINE_SHA256=4d3f80afaebd447c5591a63a73bde380a149fe8b2d85488cafabb2ff97551f50 ;;
  *) echo "arch is x86_64 or aarch64, not $arch" >&2; exit 2 ;;
esac
ALPINE=alpine-minirootfs-3.24.3-$arch.tar.gz
ALPINE_URL=https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/$arch/$ALPINE
cache=${XDG_CACHE_HOME:-$HOME/.cache}/kiri-build
mkdir -p "$cache"
# The .part is this process's own: CI jobs on one machine share the cache.
[ -f "$cache/$ALPINE" ] || { curl -fsSL --retry 3 -o "$cache/$ALPINE.$$.part" "$ALPINE_URL" && mv -f "$cache/$ALPINE.$$.part" "$cache/$ALPINE"; } || rm -f "$cache/$ALPINE.$$.part"
echo "$ALPINE_SHA256  $cache/$ALPINE" | sha256sum -c - >/dev/null || { rm -f "$cache/$ALPINE"; echo "$ALPINE: SHA-256 mismatch" >&2; exit 1; }
write_utc_tzif() {
  # Canonical RFC 8536 TZif2 binary for UTC (UTC0): v1 header+data (54 B),
  # v2 header+data (54 B), POSIX TZ footer ("\nUTC0\n", 6 B).
  for _ in 1 2; do
    printf 'TZif2'
    printf '\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000'
    printf '\001\000\000\000\004\000\000\000\000\000\000UTC\000'
  done
  printf '\nUTC0\n'
}
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
tar --no-same-owner -xzf "$cache/$ALPINE" -C "$root"
install -m 755 "$bin/kiri" "$bin/kiri-init" "$repo/contrib/wsl/kiri-linux/kiri-start" "$root/usr/local/bin/"
install -m 644 "$repo/contrib/wsl/kiri-linux/wsl.conf" "$root/etc/wsl.conf"
# Bundle zoneinfo and /etc/localtime so WSL 2's Windows-to-Linux timezone sync
# finds /usr/share/zoneinfo and common `-v /etc/localtime:...` bind mounts
# never turn /etc/localtime into a directory (#938).
if [ -d /usr/share/zoneinfo ]; then
  mkdir -p "$root/usr/share/zoneinfo"
  cp -a /usr/share/zoneinfo/. "$root/usr/share/zoneinfo"
fi
if [ -L "$root/usr/share/zoneinfo/Etc/UTC" ] || [ ! -f "$root/usr/share/zoneinfo/Etc/UTC" ]; then
  mkdir -p "$root/usr/share/zoneinfo/Etc"
  rm -f "$root/usr/share/zoneinfo/Etc/UTC"
  write_utc_tzif > "$root/usr/share/zoneinfo/Etc/UTC"
  chmod 644 "$root/usr/share/zoneinfo/Etc/UTC"
fi
if [ -L "$root/usr/share/zoneinfo/UTC" ] || [ ! -f "$root/usr/share/zoneinfo/UTC" ]; then
  rm -f "$root/usr/share/zoneinfo/UTC"
  write_utc_tzif > "$root/usr/share/zoneinfo/UTC"
  chmod 644 "$root/usr/share/zoneinfo/UTC"
fi
ln -snf /usr/share/zoneinfo/Etc/UTC "$root/etc/localtime"
rm -f "$root/etc/timezone"
printf 'Etc/UTC\n' > "$root/etc/timezone"
chmod 644 "$root/etc/timezone"
tar -C "$root" --numeric-owner --owner=0 --group=0 -czf "$out" .
