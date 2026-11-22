#!/bin/bash
# The Mac's Finder mount at ~/Kiribra covers only what is safe to cover (issue
# #40): no folder, an empty one, one holding only Finder's .DS_Store and
# .localized, or a mount this engine left behind. A folder with files (also
# ~/kiri on a case-insensitive disk), a file, a link, or someone else's mount
# is left alone, and stopping the engine unmounts only its own mount.
#
# Each case runs a real `kiri daemon` in a throwaway HOME, so the real ~/Kiribra
# is never touched. macOS only; needs no VM image or admin rights:
#
#   cargo xtask host && tests/finder-mount.sh [target/release/kiri]
[ "$(uname)" = Darwin ] || { echo "macOS only"; exit 0; }
BIN=${1:-target/release/kiri}
[ -x "$BIN" ] || { echo "no kiri binary at $BIN (cargo xtask host)"; exit 1; }
pass=0; fail=0
ok() { echo "  PASS $*"; pass=$((pass+1)); }
no() { echo "  FAIL $*"; fail=$((fail+1)); }
ours() { mount | grep -F "<$H/.kiribra/files/nfs.sock>:/ on $H/Kiribra " >/dev/null; }
start() { HOME="$H" KIRIBRA_DATA_DIR="$H/data" "$BIN" daemon >"$H/out.log" 2>&1 & PID=$!
  for i in $(seq 1 60); do grep -qE "container files in Finder|Finder mount failed" "$H/out.log" "$H"/.kiribra/*.log 2>/dev/null && return; sleep 0.25; done; echo "  (no Finder line in log)"; }
stop() { kill ${1:-} $PID 2>/dev/null; wait $PID 2>/dev/null; sleep 0.5; }
logline() { grep -hE "container files in Finder|Finder mount failed" "$H/out.log" "$H"/.kiribra/*.log 2>/dev/null | tail -1; }
fresh() { H=$(mktemp -d "$HOME/.kiri-e2e-XXXX"); echo "== $1"; }
done_() { mount | grep -F "$H" | awk '{print $3}' | while read m; do umount -f "$m" 2>/dev/null || diskutil unmount force "$m" >/dev/null 2>&1; done; rm -rf "$H"; }

fresh "folder with files"; mkdir "$H/Kiribra"; echo keep > "$H/Kiribra/keep.txt"; start
[ -f "$H/Kiribra/keep.txt" ] && ok "keep.txt still visible while running" || no "keep.txt hidden"
ours && no "mounted over files" || ok "no mount"
logline | grep -q "already has files" && ok "warning logged: $(logline | cut -c1-160)" || no "no clear warning: $(logline)"
stop; [ "$(cat $H/Kiribra/keep.txt)" = keep ] && ok "keep.txt intact after stop" || no "keep.txt lost"; done_

fresh "lowercase ~/kiri git clone (case-insensitive disk)"; mkdir -p "$H/kiri/.git"; echo x > "$H/kiri/README.md"; start
[ -f "$H/kiri/README.md" ] && ok "clone visible" || no "clone hidden"; ours && no "mounted" || ok "no mount"; stop; done_

fresh "only hidden files (.git)"; mkdir -p "$H/Kiribra/.git"; start; ours && no "mounted over .git" || ok "no mount"; stop; done_

fresh "another mount (disk image)"; hdiutil create -quiet -size 2m -fs HFS+ -volname KTEST "$H/t.dmg"; mkdir "$H/Kiribra"
hdiutil attach -quiet -nobrowse -mountpoint "$H/Kiribra" "$H/t.dmg"; echo img > "$H/Kiribra/img.txt"; start
mount | grep -q " on $H/Kiribra (hfs" && ok "disk image still mounted while running" || no "disk image unmounted"
ours && no "nfs mounted over it" || ok "no nfs mount"
logline | grep -q "mounted on it" && ok "warning logged" || no "no warning: $(logline)"
stop; mount | grep -q " on $H/Kiribra (hfs" && ok "disk image still mounted after stop" || no "disk image force-unmounted on stop"
hdiutil detach -quiet "$H/Kiribra" 2>/dev/null; done_

fresh "empty folder"; mkdir "$H/Kiribra"; start; ours && ok "mounted" || no "not mounted: $(logline)"; stop; ours && no "still mounted after stop" || ok "unmounted on stop"; done_

fresh "only .DS_Store and .localized"; mkdir "$H/Kiribra"; touch "$H/Kiribra/.DS_Store" "$H/Kiribra/.localized"; start; ours && ok "mounted" || no "not mounted: $(logline)"; stop; [ -f "$H/Kiribra/.DS_Store" ] && ok ".DS_Store kept" || no ".DS_Store gone"; done_

fresh "no folder"; start; [ -d "$H/Kiribra" ] && ok "folder made" || no "no folder"; ours && ok "mounted" || no "not mounted: $(logline)"; stop; done_

fresh "file at ~/Kiribra"; echo f > "$H/Kiribra"; start; [ "$(cat $H/Kiribra)" = f ] && ok "file left alone" || no "file changed"; ours && no mounted || ok "no mount"; stop; done_

fresh "symlink at ~/Kiribra"; mkdir "$H/elsewhere"; ln -s "$H/elsewhere" "$H/Kiribra"; start; [ -L "$H/Kiribra" ] && ok "link left alone" || no "link changed"; ours && no mounted || ok "no mount"; stop; done_

fresh "mount left by kill -9"; start; ours && ok "first mount" || no "first not mounted"; stop -9
ours && ok "stale mount left behind (expected after -9)" || echo "  (no stale mount after -9)"
start; [ "$(mount | grep -cF " on $H/Kiribra ")" = 1 ] && ours && ok "replaced with one fresh mount" || no "not replaced: $(logline)"
stop; ours && no "still mounted" || ok "unmounted on stop"; done_

echo; echo "passed $pass, failed $fail"; [ $fail = 0 ]
