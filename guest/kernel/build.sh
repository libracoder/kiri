#!/bin/sh
# Builds Kiri's guest kernel: allnoconfig + kiri.config, no modules.
# KARCH=arm64 (default): arm64 Image for Apple Silicon. KARCH=x86_64: a
# bzImage for Intel Macs, from kiri.config without its Arm platform lines
# plus kiri-x86_64.config, cross-compiled when the container is not x86-64.
# Runs inside a Debian container and writes /out/Image or /out/bzImage.
set -eu
KVER="${KVER:-6.18.58}"
KSHA256="${KSHA256:-069b19f9032c4dac8149ae4b6520c35debca0f42a9f6d52ee55ba6ca9b818013}"
KARCH="${KARCH:-arm64}"
if [ "$KVER" != "6.18.58" ] && [ "$KSHA256" = "069b19f9032c4dac8149ae4b6520c35debca0f42a9f6d52ee55ba6ca9b818013" ]; then
  echo "KSHA256 must be updated when overriding KVER=$KVER" >&2
  exit 1
fi
if [ -z "$KSHA256" ]; then
  echo "KSHA256 must not be empty" >&2
  exit 1
fi
case "$KARCH-$(uname -m)" in
  arm64-aarch64) cross="" pkgs="" ;;
  x86_64-x86_64) cross="" pkgs=lz4 ;;
  x86_64-*) cross=x86_64-linux-gnu- pkgs="gcc-x86-64-linux-gnu lz4" ;;
  arm64-*) cross=aarch64-linux-gnu- pkgs=gcc-aarch64-linux-gnu ;;
  *) echo "KARCH must be arm64 or x86_64" >&2; exit 1 ;;
esac
apt-get update -qq && apt-get install -y -qq build-essential flex bison bc libssl-dev libelf-dev dwarves curl xz-utils python3 $pkgs >/dev/null
cd /build
if [ ! -f "linux-$KVER/Makefile" ] || [ ! -f "linux-$KVER/scripts/Kbuild.include" ]; then
  rm -rf "linux-$KVER" "linux-$KVER.tar.xz.tmp"
  curl -fsSL -o "linux-$KVER.tar.xz.tmp" "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz"
  printf '%s  %s\n' "$KSHA256" "linux-$KVER.tar.xz.tmp" | sha256sum -c -
  tar xJf "linux-$KVER.tar.xz.tmp"
  rm -f "linux-$KVER.tar.xz.tmp"
fi
cd "linux-$KVER"
# Kiri's kernel patches. Reverse-apply in reverse order first so stacked
# patches on a cached tree stay clean.
printf '%s\n' /src/patches/*.patch | sort -r | while IFS= read -r p; do
  patch -p1 -R -s -f --dry-run < "$p" >/dev/null 2>&1 && patch -p1 -R -s < "$p" || true
done
for p in /src/patches/*.patch; do
  patch -p1 -s < "$p"
done
config=/src/kiri.config
if [ "$KARCH" = x86_64 ]; then
  config=/tmp/kiri-x86_64.all.config
  grep -vE '^CONFIG_(ARM|ARM64)_|^CONFIG_(RTC_DRV_PL031|PCI_HOST_GENERIC)=' /src/kiri.config > "$config"
  cat /src/kiri-x86_64.config >> "$config"
fi
make -s ARCH="$KARCH" CROSS_COMPILE="$cross" allnoconfig KCONFIG_ALLCONFIG="$config"
missing=0
for line in $(grep -E '^CONFIG_[A-Z0-9_]+=y' "$config"); do
  grep -qx "$line" .config || { echo "MISSING: $line"; missing=1; }
done
[ "$missing" = 0 ] || { echo "some options were not applied (dependency not met)" >&2; exit 1; }
if [ "$KARCH" = x86_64 ]; then
  make -s -j"$(nproc)" ARCH=x86_64 CROSS_COMPILE="$cross" bzImage
  cp arch/x86/boot/bzImage .config /out/
  ls -la /out/bzImage
else
  make -s -j"$(nproc)" ARCH=arm64 CROSS_COMPILE="$cross" Image
  cp arch/arm64/boot/Image .config /out/
  ls -la /out/Image
fi
