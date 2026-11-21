#!/bin/bash
# A name cached by virtiofs must be reusable after the Mac deletes or
# replaces the file (#399), with and without an inotify watcher:
#   DOCKER_CONTEXT=kiri tests/bind-recreate.sh
set -eu

bind=$(mktemp -d)
bind=$(cd "$bind" && pwd -P)
container="kiri-bind-recreate-$$"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$bind"
}
trap cleanup EXIT
failed=0
cat > "$bind/onchange.sh" <<'SH'
#!/bin/sh
cat "$2/$3" > "/tmp/seen-$3" 2>&1
SH
chmod +x "$bind/onchange.sh"

for watched in no yes; do
  if [ "$watched" = yes ]; then
    docker run -d --name "$container" -v "$bind:/w" alpine inotifyd /w/onchange.sh /w:c >/dev/null
  else
    docker run -d --name "$container" -v "$bind:/w" alpine sleep 60 >/dev/null
  fi
  # The daemon scans for new bind sources once a second. Let FSEvents
  # subscribe before testing changes, so this tests the guest's cache.
  sleep 2
  for change in guest-create host-replace host-recreate; do
    for i in 1 2 3 4 5; do
      file="$watched-$change-$i"
      echo old > "$bind/$file"
      docker exec "$container" cat "/w/$file" >/dev/null
      if [ "$watched" = yes ]; then
        sleep 0.1
        docker exec "$container" rm -f "/tmp/seen-$file"
      fi
      case "$change" in
        guest-create) rm "$bind/$file" ;;
        host-replace) echo new > "$bind/tmp"; mv "$bind/tmp" "$bind/$file" ;;
        host-recreate) rm "$bind/$file"; echo new > "$bind/$file" ;;
      esac
      # FSEvents batches changes for 50 ms. Allow delivery, but stay well
      # inside Apple's roughly one-second positive-entry cache timeout.
      sleep 0.2
      if [ "$change" = guest-create ] &&
         ! docker exec "$container" sh -c 'echo new > "/w/$1"' sh "$file"; then
        echo "FAIL $change (watcher: $watched, file: $file)" >&2
        failed=1
        continue
      fi
      # The watcher's first read after the event must already see the
      # replacement, before the explicit read below can refresh its name.
      if [ "$watched" = yes ]; then
        if ! content=$(docker exec "$container" sh -c '
          for attempt in 1 2 3 4 5 6 7 8 9 10; do
            if [ -f "/tmp/seen-$1" ]; then cat "/tmp/seen-$1"; exit; fi
            sleep 0.02
          done
          exit 1' sh "$file") || [ "$content" != new ]; then
          echo "FAIL watcher read after $change (file: $file): ${content:-no event}" >&2
          failed=1
        fi
      fi
      if ! content=$(docker exec "$container" cat "/w/$file") ||
         [ "$content" != new ] || [ "$(cat "$bind/$file" 2>/dev/null)" != new ]; then
        echo "FAIL $change (watcher: $watched, file: $file)" >&2
        failed=1
      fi
    done
  done
  docker rm -f "$container" >/dev/null
done
if [ "$failed" = 0 ]; then
  echo "PASS bind recreate and replace, with and without a watcher (30 attempts)"
fi
exit "$failed"
