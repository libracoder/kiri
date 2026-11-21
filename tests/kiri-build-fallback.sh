#!/bin/sh
# `kiri build`'s fallback gives what Kiri gave before the native builder:
# for every reason the native builder hands a build to BuildKit, and for a
# few plain builds with the native builder switched off (`--no-native`;
# the reason cases ask for it with `--builder kiri`, as it is off by default),
# the image `kiri build` makes has the same config and the same layers as
# the image of `docker build` on the same engine (the path `kiri build`
# always ran), or both fail. A fallback prints its reason; a build with the
# native builder off prints none. Contexts are made where the engine can
# read them (WORK, default /work).
#
# Runs where a Kiri engine and its docker CLI are (the engine's test
# container, or a client sharing its socket and WORK):
#   BASE=alpine:latest@sha256:... sh tests/kiri-build-fallback.sh
# Cases needing the internet are left out.
set -u
KIRI=${KIRI:-kiri}
# What `kiri build` ran before the native builder: the docker CLI's build
# on Kiri's builder (docker.rs).
MAIN=${MAIN:-env BUILDX_BUILDER=kiri-build docker build}
BASE=${BASE:-alpine:latest}
W=$(mktemp -d "${WORK:-/work}/kfb.XXXXXX")
PASS=0; FAIL=0

# check NAME REASON FLAGS DOCKERFILE: REASON "" means --no-native.
check() {
  name=$1 reason=$2 flags=$3
  d=$W/$name; mkdir -p "$d"; printf '%b' "$4" > "$d/Dockerfile"; echo a > "$d/a.txt"; echo b > "$d/b.md"
  # A bind of a context with ignored files goes to BuildKit, which hides them.
  [ "$name" = bind-ignored ] && echo b.md > "$d/.dockerignore"
  if [ -z "$reason" ]; then kflags="--no-native $flags"; else kflags="--builder kiri $flags"; fi
  # shellcheck disable=SC2086
  $KIRI build $kflags -t kfb-kiri:$name "$d" > "$d/kiri.log" 2>&1; k=$?
  # shellcheck disable=SC2086
  $MAIN $flags -t kfb-main:$name "$d" > "$d/main.log" 2>&1; m=$?
  why=
  if [ -n "$reason" ]; then
    grep -qxF "falling back to BuildKit: $reason" "$d/kiri.log" || why="no line 'falling back to BuildKit: $reason'"
  elif grep -q "falling back to BuildKit" "$d/kiri.log"; then
    why="a fallback line with the native builder off"
  fi
  if [ $k != $m ]; then
    why="$why; exit kiri=$k main=$m"
  elif [ $k = 0 ]; then
    a=$(docker image inspect -f '{{json .Config}} {{json .RootFS}}' kfb-kiri:$name)
    b=$(docker image inspect -f '{{json .Config}} {{json .RootFS}}' kfb-main:$name)
    [ "$a" = "$b" ] || why="$why; images differ: $a / $b"
  fi
  if [ -z "$why" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); echo "FAIL $name: $why"; tail -5 "$d/kiri.log"; fi
  docker rmi -f kfb-kiri:$name kfb-main:$name > /dev/null 2>&1
}

F="FROM $BASE"
# With the native builder off: plain builds, as main makes them.
check off-copy "" "" "$F\nENV A=1\nCOPY a.txt /a\nCMD [\"sh\"]\n"
check off-stages "" "" "$F AS b\nCOPY a.txt /x\n$F\nCOPY --from=b /x /y\nWORKDIR /w\n"
check off-run "" "--label k=v" "$F\nRUN true\nLABEL l=v\n"
check off-fails "" "" "$F\nRUN exit 3\n"

# Every reason the native builder gives that can be built here.
check network-host "RUN --network=host" "" "$F\nRUN --network=host true\n"
check security-insecure "RUN --security=insecure" "" "$F\nRUN --security=insecure true\n"
check syntax-other "# syntax=docker/dockerfile:1.28" "" "# syntax=docker/dockerfile:1.28\n$F\nCOPY a.txt /\n"
# A git source: Kiri's builder hands it to BuildKit before fetching; the
# address answers nobody, so both builds fail the same way.
check add-git "ADD of a git repository" "" "$F\nADD http://127.0.0.1:9/r.git /r\n"
check bind-ignored "RUN --mount=type=bind of a context with a .dockerignore" "" "$F\nRUN --mount=type=bind,target=/x true\n"
# Command-line flags the native builder does not take.
check flag-pull "--pull" "--pull" "$F\nCOPY a.txt /\n"
check flag-network "--network" "--network none" "$F\nCOPY a.txt /\n"
check flag-add-host "--add-host" "--add-host h:1.2.3.4" "$F\nCOPY a.txt /\n"
check flag-shm-size "--shm-size" "--shm-size 64m" "$F\nRUN true\n"
check flag-ulimit "--ulimit" "--ulimit nofile=1024:1024" "$F\nRUN true\n"

rm -rf "$W"
echo "$PASS passed, $FAIL failed"
[ $FAIL = 0 ]
