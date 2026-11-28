#!/bin/sh
# Builds the complete corresponding source archive for the guest kernel.
set -eu
out=${1:?"usage: scripts/ci/kernel-source.sh <output.tar.xz>"}
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
case $out in
  /* | [A-Za-z]:*) ;;
  *) out=$PWD/$out ;;
esac
kver=$(sed -n 's/^KVER="${KVER:-\([^}]*\)}"/\1/p' guest/kernel/build.sh)
[ -n "$kver" ] || { echo "could not read KVER from guest/kernel/build.sh" >&2; exit 1; }
# Pinned SHA-256 of the upstream kernel.org tarball matching KVER in guest/kernel/build.sh.
# Override with KVER_SHA256 when building a different KVER.
if [ -z "${KVER_SHA256:-}" ]; then
  case "$kver" in
    6.18.58) KVER_SHA256=069b19f9032c4dac8149ae4b6520c35debca0f42a9f6d52ee55ba6ca9b818013 ;;
    *) echo "no pinned KVER_SHA256 for linux-$kver.tar.xz; set KVER_SHA256 or update scripts/ci/kernel-source.sh" >&2; exit 1 ;;
  esac
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$kver.tar.xz" -o "$tmp/linux.tar.xz"
if command -v sha256sum >/dev/null 2>&1; then
  printf '%s  %s\n' "$KVER_SHA256" "$tmp/linux.tar.xz" | sha256sum -c - >/dev/null
else
  printf '%s  %s\n' "$KVER_SHA256" "$tmp/linux.tar.xz" | shasum -a 256 -c - >/dev/null
fi
tar -xJf "$tmp/linux.tar.xz" -C "$tmp"
cd "$tmp/linux-$kver"
for patch in "$root"/guest/kernel/patches/*.patch; do
  patch -p1 -s < "$patch"
done
mkdir kiri
cp "$root/guest/kernel/build.sh" "$root/guest/kernel/kiri.config" "$root/guest/kernel/kiri-x86_64.config" kiri/
cp -R "$root/guest/kernel/patches" kiri/
printf '%s\n' \
  "Kiri guest kernel corresponding source" \
  "Upstream: https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$kver.tar.xz" \
  "All patches in kiri/patches have already been applied to this tree." \
  "Build with kiri/build.sh as described in the Kiri repository." > kiri/SOURCE
mkdir -p "$(dirname "$out")"
XZ_OPT=${XZ_OPT:--T0} tar -cJf "$out" -C "$tmp" "linux-$kver"
