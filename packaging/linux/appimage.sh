#!/bin/bash
set -euo pipefail
umask 022
bindir=$1 window=$2 outdir=$3 cache=${4:-${XDG_CACHE_HOME:-$HOME/.cache}/kiri-appimage}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1 | tr -d '\r')
for b in "$bindir/kiri" "$bindir/kiri-init" "$window"; do
  [ -x "$b" ] || { echo "no $b" >&2; exit 1; }
done
mkdir -p "$outdir" "$cache"
get() { # url file sum
  local f=$cache/$2
  if [ ! -f "$f" ]; then
    curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 -o "$f.$$.part" "$1" || { rm -f "$f.$$.part"; echo "could not download $1" >&2; exit 1; }
    mv "$f.$$.part" "$f"
  fi
  echo "$3  $f" | sha256sum -c --quiet - || { echo "$2 does not match the pinned SHA-256; delete $f and retry" >&2; exit 1; }
}
arch=$(uname -m)
case $arch in
  x86_64) tool_sum=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0 runtime_sum=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d ;;
  aarch64) tool_sum=f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158 runtime_sum=00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444 ;;
  *) echo "no AppImage for $arch" >&2; exit 1 ;;
esac
get "https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-$arch.AppImage" "appimagetool-1.9.1-$arch.AppImage" "$tool_sum"
get "https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-$arch" "runtime-20251108-$arch" "$runtime_sum"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
app=$work/Kiri.AppDir
install -D -m 755 "$bindir/kiri" "$app/usr/bin/kiri"
install -m 755 "$bindir/kiri-init" "$app/usr/bin/kiri-init"
install -m 755 "$window" "$app/usr/bin/kiri-window"
install -m 755 "$here/AppRun" "$app/AppRun"
# The launcher runs the AppImage itself; the icon is the AppDir's kiri.svg.
sed -e 's|^Exec=.*|Exec=kiri|' -e 's|^Icon=.*|Icon=kiri|' "$root/contrib/linux/kiri.desktop" > "$app/kiri.desktop"
install -m 644 "$root/brand/icon/kiri-app-icon.svg" "$app/kiri.svg"
mkdir -p "$app/usr/share/metainfo"
sed -e "s/@VERSION@/$version/" -e "s/@DATE@/$(date -u +%Y-%m-%d)/" "$root/contrib/linux/dev.kiri.Kiri.metainfo.xml" > "$app/usr/share/metainfo/dev.kiri.Kiri.metainfo.xml"
install -D -m 644 "$root/LICENSE" "$app/usr/share/doc/kiri/LICENSE"
install -m 644 "$root/NOTICE" "$app/usr/share/doc/kiri/NOTICE"
tool=$work/appimagetool
install -m 755 "$cache/appimagetool-1.9.1-$arch.AppImage" "$tool"
out=$outdir/Kiri-$version-$arch.AppImage
# Extract-and-run: build machines and containers often have no FUSE.
ARCH=$arch APPIMAGE_EXTRACT_AND_RUN=1 "$tool" --no-appstream --runtime-file "$cache/runtime-20251108-$arch" "$app" "$out" >&2
echo "$out"
