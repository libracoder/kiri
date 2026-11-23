#!/bin/bash
# A name cached by virtiofs must be reusable and show its new length and
# contents after the Mac deletes or replaces the file (#399), with and
# without an inotify watcher:
#   DOCKER_CONTEXT=kiri tests/bind-recreate.sh
set -eu

D=${D:-docker}
bind=$(mktemp -d)
bind=$(cd "$bind" && pwd -P)
container="kiri-bind-recreate-$$"
cleanup() {
  $D rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$bind"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP ALRM
failed=0
cat > "$bind/onchange.sh" <<'SH'
#!/bin/sh
cat "$2/$3" > "/tmp/seen-$3" 2>&1
SH
chmod +x "$bind/onchange.sh"

for watched in no yes; do
  if [ "$watched" = yes ]; then
    # Watch both modify (c, raised by /proc/kiri-fsnotify on macOS) and
    # moved-to (y, raised by mv onto a file on Linux and WSL).
    $D run -d --name "$container" -v "$bind:/w" alpine inotifyd /w/onchange.sh /w:cy >/dev/null
  else
    $D run -d --name "$container" -v "$bind:/w" alpine sleep 60 >/dev/null
  fi
  # The daemon scans for new bind sources once a second. Let FSEvents
  # subscribe before testing changes, so this tests the guest's cache.
  sleep 2
  for change in guest-create host-replace host-recreate; do
    for i in 1 2 3 4 5; do
      file="$watched-$change-$i"
      # Alternate shorter->longer and longer->shorter replacements so a
      # stale cached file size shows up as a truncated or trailing read,
      # not only as ENOENT.
      if [ $((i % 2)) -eq 1 ]; then
        before="old"
        after="three-much-longer"
      else
        before="three-much-longer"
        after="xy"
      fi
      echo "$before" > "$bind/$file"
      $D exec "$container" cat "/w/$file" >/dev/null
      if [ "$watched" = yes ]; then
        $D exec "$container" sh -c '
          for attempt in 1 2 3 4 5 6 7 8 9 10; do
            [ -f "/tmp/seen-$1" ] && break
            sleep 0.05
          done
          rm -f "/tmp/seen-$1"' sh "$file"
      fi
      case "$change" in
        guest-create) rm "$bind/$file" ;;
        host-replace) echo "$after" > "$bind/tmp"; mv "$bind/tmp" "$bind/$file" ;;
        host-recreate) rm "$bind/$file"; echo "$after" > "$bind/$file" ;;
      esac
      # FSEvents batches changes for 50 ms. Allow delivery, but stay well
      # inside Apple's roughly one-second positive-entry cache timeout.
      sleep 0.2
      if [ "$change" = guest-create ] &&
         ! $D exec "$container" sh -c 'printf "%s\n" "$2" > "/w/$1"' sh "$file" "$after"; then
        echo "FAIL $change (watcher: $watched, file: $file)" >&2
        failed=1
        continue
      fi
      # The watcher's first read after the event must already see the
      # replacement, before the explicit read below can refresh its name.
      if [ "$watched" = yes ]; then
        if ! content=$($D exec "$container" sh -c '
          for attempt in 1 2 3 4 5 6 7 8 9 10; do
            if [ -f "/tmp/seen-$1" ]; then cat "/tmp/seen-$1"; exit; fi
            sleep 0.02
          done
          exit 1' sh "$file") || [ "$content" != "$after" ]; then
          echo "FAIL watcher read after $change (file: $file): got ${content:-no event}, want $after" >&2
          failed=1
        fi
      fi
      if ! content=$($D exec "$container" cat "/w/$file") ||
         [ "$content" != "$after" ] || [ "$(cat "$bind/$file" 2>/dev/null)" != "$after" ]; then
        echo "FAIL $change (watcher: $watched, file: $file): got ${content:-err}, want $after" >&2
        failed=1
      fi
    done
  done
  $D rm -f "$container" >/dev/null
done
if [ "$failed" = 0 ]; then
  echo "PASS bind recreate and replace, with and without a watcher (30 attempts)"
fi
exit "$failed"
