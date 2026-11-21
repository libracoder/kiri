#!/bin/bash
# The native build route reads the context as the user who asked: a
# non-root user in a privileged engine container calls the engine's socket
# as their own uid and builds. The kernel decides what may be read; a read
# it refuses fails the build as the client's own read fails on the
# reference (`error from sender: open d: permission denied`).
#
#   D=docker BIN=target/x86_64-unknown-linux-musl/fast tests/native-build-access.sh
#
# Where BuildKit is wrong the expected result is the correct one, marked
# "BK FAIL": it copies an
# unreadable file as an empty one and takes an unreadable .dockerignore
# as absent.
set -u
if [ "${1:-}" != --inside ]; then
  D=${D:-docker}
  T=$(cd "$(dirname "$0")" && pwd)
  BIN=${BIN:-$T/../target/x86_64-unknown-linux-musl/fast}
  N=${N:-kiri-native-build-access}
  [ -x "$BIN/kiri" ] && [ -x "$BIN/kiri-init" ] || { echo "build first: cargo build --profile fast --target x86_64-unknown-linux-musl -p kiri -p kiri-init"; exit 1; }
  $D rm -f "$N" >/dev/null 2>&1
  # Docker Hub is not reached from here: the cases need no base image.
  $D run -d --name "$N" --privileged --cpus 2 --tmpfs /run \
    --add-host registry-1.docker.io:127.0.0.1 --add-host auth.docker.io:127.0.0.1 \
    --add-host index.docker.io:127.0.0.1 --add-host production.cloudfront.docker.com:127.0.0.1 \
    -v "$N":/var/lib/kiri -v "$N"-store:/root/.local/share/kiri \
    -v "${BIN_MOUNT:-$BIN}:/opt/kiri:ro" -v "${TESTS_MOUNT:-$T}:/t:ro" \
    --entrypoint /opt/kiri/kiri "${IMAGE:-alpine}" daemon >/dev/null || exit 1
  for _ in $(seq 60); do
    $D exec "$N" test -S /root/.kiri/run/docker.sock && break
    sleep 1
  done
  # IMAGE needs python3 and the docker CLI (alpine gets them from apk)
  $D exec "$N" sh -c 'command -v python3 >/dev/null && command -v docker >/dev/null || apk add -q python3 docker-cli >/dev/null 2>&1; sh /t/native-build-access.sh --inside'
  r=$?
  [ -n "${KEEP:-}" ] || { $D rm -f "$N" >/dev/null; $D volume rm "$N" "$N"-store >/dev/null 2>&1; }
  exit $r
fi

SOCK=/root/.kiri/run/docker.sock
export DOCKER_HOST=unix://$SOCK
# u (4243) is in group g (4242); the socket is opened up to u for the test
id u >/dev/null 2>&1 || { addgroup -g 4243 u; adduser -D -u 4243 -G u u; addgroup -g 4242 g; addgroup u g; } >/dev/null 2>&1
chmod 711 /root /root/.kiri /root/.kiri/run; chmod 666 $SOCK
R=/home/u/t$$; mkdir -p $R; chown u:u $R
PASS=0; FAIL=0
asu() { su u -s /bin/sh -c "$1"; }
mk() { asu "mkdir -p $R/$1 && cd $R/$1 && printf 'FROM scratch\nCOPY . /\n' > Dockerfile && echo ok > a.txt"; }
build() { asu "cd $R/$1 && KIRI_SOCKET=$SOCK /opt/kiri/kiri build --builder kiri -t kiri-access-test:$1 . > $R/$1.out 2>&1"; }
fs() { local c; c=$(docker create kiri-access-test:$1 x 2>/dev/null) || return; docker export $c > $R/$1.fs.tar; docker rm $c >/dev/null; }
check() {
  local name=$1 cond=$2 got=$3
  if [ "$cond" = 1 ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); printf '  FAIL %s\n    got: %s\n' "$name" "$got"; fi
}
# builds, with a file in the image
ok() { local n=$1 f=$2; build $n; local rc=$?; local has=0; [ $rc = 0 ] && fs $n && tar -tf $R/$n.fs.tar | grep -qx "$f" && has=1; check "$n" $has "rc=$rc $(grep ERROR $R/$n.out | head -1)"; }
# fails with this last line
fails() { local n=$1 want=$2; build $n; local rc=$?; local last c=0; last=$(grep '^ERROR' $R/$n.out | tail -1); [ $rc != 0 ] && [ "$last" = "$want" ] && c=1; check "$n" $c "rc=$rc $last"; }
E='ERROR: failed to build: failed to solve:'

mk readable; ok readable a.txt
# BK FAIL: the reference copies it as
# an empty file
mk file000; asu "cd $R/file000 && echo SECRET > secret && chmod 000 secret"
fails file000 "$E error from sender: open secret: permission denied"
# BK FAIL: another user's file the
# caller may not read
mk otheruser; echo SECRET > $R/otheruser/rootonly; chmod 600 $R/otheruser/rootonly
fails otheruser "$E error from sender: open rootonly: permission denied"
mk group; echo grp > $R/group/grp; chown root:g $R/group/grp; chmod 640 $R/group/grp
ok group grp
# BK FAIL: a POSIX ACL that leaves this user out (system.posix_acl_access)
mk acl; echo SECRET > $R/acl/acl; chmod 644 $R/acl/acl
if python3 - "$R/acl/acl" <<'PY'
import os, struct, sys
e = [(1, 6, 0xffffffff), (2, 0, 4243), (4, 4, 0xffffffff), (0x10, 4, 0xffffffff), (0x20, 4, 0xffffffff)]
os.setxattr(sys.argv[1], "system.posix_acl_access", struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *x) for x in e))
PY
then fails acl "$E error from sender: open acl: permission denied"; else echo "  skip acl: no POSIX ACLs here"; fi
# as on the reference
mk dir000; asu "cd $R/dir000 && mkdir -p d/x && echo SECRET > d/x/f && chmod 000 d"
fails dir000 "$E error from sender: open d: permission denied"
mk dirnosearch; asu "cd $R/dirnosearch && mkdir d && echo SECRET > d/f && chmod 600 d"
fails dirnosearch "$E error from sender: lstat d/f: permission denied"
mk ignored; asu "cd $R/ignored && echo SECRET > secret && chmod 000 secret && mkdir d && chmod 000 d && printf 'secret\nd\n' > .dockerignore"
ok ignored a.txt
mk notcopied; asu "cd $R/notcopied && mkdir d && echo SECRET > d/f && chmod 000 d && printf 'FROM scratch\nCOPY a.txt /\n' > Dockerfile"
ok notcopied a.txt
# BK FAIL: the reference takes it as
# absent and copies `secret`
mk ignore000; asu "cd $R/ignore000 && echo SECRET > secret && echo secret > .dockerignore && chmod 000 .dockerignore"
fails ignore000 "$E error from sender: open .dockerignore: permission denied"
# BK FAIL: the reference reads it as empty ("the Dockerfile cannot be empty")
mk dockerfile000; asu "cd $R/dockerfile000 && chmod 000 Dockerfile"
fails dockerfile000 "$E failed to read dockerfile: open Dockerfile: permission denied"

# RUN --mount=type=bind from the context: what the mount shows is checked
# as the caller first, as a copy of it would be. Shell builtins only: the
# base is this container's own /bin and /lib.
if [ -z "$(docker images -q kiri-access-base 2>/dev/null)" ]; then
  tar -C / -cf - bin lib 2>/dev/null | docker import - kiri-access-base >/dev/null 2>&1
fi
if [ -n "$(docker images -q kiri-access-base 2>/dev/null)" ]; then
  mk bind; asu "cd $R/bind && mkdir d && echo inside > d/f && printf 'FROM kiri-access-base\nRUN --mount=type=bind,source=d,target=/in read l < /in/f && echo \$l > /seen\n' > Dockerfile"
  ok bind seen
  fs bind; check "bind content" $(tar -xOf $R/bind.fs.tar seen 2>/dev/null | grep -qx inside && echo 1 || echo 0) "$(tar -xOf $R/bind.fs.tar seen 2>/dev/null)"
  mk bind000; asu "cd $R/bind000 && mkdir d && echo SECRET > d/secret && chmod 000 d/secret && printf 'FROM kiri-access-base\nRUN --mount=type=bind,source=d,target=/in read l < /in/secret\n' > Dockerfile"
  fails bind000 "$E error from sender: open d/secret: permission denied"
else
  echo "  skip bind: no base image could be made here"
fi

# A folder on the way turned into a link out and back while builds run:
# a build may fail, but no image may hold the bytes from outside.
asu "mkdir -p $R/outside && echo SECRET > $R/outside/f"
mk swap; asu "cd $R/swap && printf 'FROM scratch\nCOPY a /a\n' > Dockerfile && mkdir a && echo inside > a/f && ln -s $R/outside a.lnk"
asu "python3 -c '
import os, time
os.chdir(\"$R/swap\")
end = time.time() + 120
while time.time() < end and not os.path.exists(\"$R/stop\"):
    os.rename(\"a\", \"a.tmp\"); os.rename(\"a.lnk\", \"a\"); os.rename(\"a\", \"a.lnk\"); os.rename(\"a.tmp\", \"a\")
'" &
built=0; leaks=0
for i in $(seq 15); do
  if asu "cd $R/swap && KIRI_SOCKET=$SOCK /opt/kiri/kiri build --builder kiri --no-cache -t kiri-access-test:swap . > $R/swap.out 2>&1"; then
    built=$((built + 1)); fs swap; tar -xOf $R/swap.fs.tar | grep -q SECRET && leaks=$((leaks + 1))
  fi
done
touch $R/stop; wait
check "swap (built $built of 15)" $([ $leaks = 0 ] && echo 1 || echo 0) "$leaks images hold bytes from outside the context"

grep -l -i fallback $R/*.out 2>/dev/null | sed 's/^/  note: fell back to BuildKit: /'
echo "native-build-access: $PASS passed, $FAIL failed"
[ $FAIL = 0 ]
