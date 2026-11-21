#!/bin/sh
# Which builder `kiri build` uses, on a real engine with a fresh state:
# Forge, Kiri's own build engine, is off by default; `kiri builder use
# forge|buildkit` switches it and it stays (`kiri`, Forge's name before, is
# still taken); `kiri build --builder forge|kiri|buildkit` picks one for one
# build; KIRI_NATIVE_BUILD picks one for a terminal. The first one
# given wins: --builder, then KIRI_NATIVE_BUILD, then the setting. Who built
# each image is read from the engine's build-path record
# (`GET /kiri/build-path?image=`: `native`, `fallback <reason>`, or none for
# a plain BuildKit build). Every build has a RUN of its own, so no image is
# one an earlier build made.
#
# Runs where a Kiri engine and its docker CLI are (the engine's test
# container, or a client sharing its socket), on an engine nobody has
# switched yet:
#   BASE=alpine:latest@sha256:... sh tests/kiri-builder-switch.sh
# Leaves the setting as it found it (BuildKit) and removes its images.
set -u
KIRI=${KIRI:-kiri}
BASE=${BASE:-alpine:latest}
SOCK=${KIRI_SOCKET:-${DOCKER_HOST#unix://}}
W=$(mktemp -d "${WORK:-/tmp}/kbs.XXXXXX")
unset KIRI_NATIVE_BUILD
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && sed 's/^/       /' "$2" | tail -8; return 0; }

# path ID: the engine's build-path record of an image, or "none".
path() {
  r=$(curl -s --unix-socket "$SOCK" -w '\n%{http_code}' "http://d/kiri/build-path?image=$1")
  case $r in *404) echo none ;; *) echo "$r" | head -1 ;; esac
}

# build NAME [kiri build flags...]: P = its build-path record, L = its log.
# KENV: environment for that one build (KIRI_NATIVE_BUILD=...).
KENV=
build() {
  n=$1; shift
  d=$W/$n; mkdir -p "$d"; printf 'FROM %s\nRUN echo %s-%s > /x\n' "$BASE" "$n" "$$" > "$d/Dockerfile"
  L=$d/log; P=failed
  # shellcheck disable=SC2086
  if env $KENV "$KIRI" build "$@" --iidfile "$d/iid" -t "kbs-$n:1" "$d" > "$L" 2>&1; then P=$(path "$(cat "$d/iid")"); fi
}
expect() { # NAME WANT (native | not-native)
  case "$2:$P" in
    native:native) ok "$1: built by Forge" ;;
    not-native:failed|native:*) bad "$1: wanted $2, record: $P" "$L" ;;
    not-native:native) bad "$1: built natively, wanted BuildKit" "$L" ;;
    not-native:*) ok "$1: built by BuildKit ($P)" ;;
  esac
}
no_fallback_line() { if grep -q "falling back to BuildKit" "$L"; then bad "$1: a fallback line, but nothing was handed over" "$L"; else ok "$1: no fallback line"; fi; }
setting() { curl -s --unix-socket "$SOCK" http://d/kiri/builder | python3 -c 'import json,sys; print(json.load(sys.stdin)["native"])'; }

echo "== a fresh engine: BuildKit"
s=$("$KIRI" builder 2>&1)
case $s in "kiri build uses BuildKit."*) ok "kiri builder says BuildKit" ;; *) bad "kiri builder says: $s"; echo "not a fresh engine (or switched on already): stopping"; exit 1 ;; esac
[ "$(setting)" = False ] && ok "GET /kiri/builder: native false" || bad "GET /kiri/builder: native $(setting)"
build fresh; expect "fresh state" not-native; no_fallback_line "fresh state"
build fresh-unsupported --add-host a:192.0.2.1; expect "fresh state, a flag only BuildKit takes" not-native; no_fallback_line "fresh state, a flag only BuildKit takes"

echo "== kiri builder use forge"
s=$("$KIRI" builder use forge 2>&1)
case $s in "Set: kiri build uses Forge"*) ok "use forge says what it set" ;; *) bad "use forge says: $s" ;; esac
[ "$(setting)" = True ] && ok "GET /kiri/builder: native true" || bad "GET /kiri/builder: native $(setting)"
case $("$KIRI" builder 2>&1) in "kiri build uses Forge, Kiri's own build engine."*) ok "kiri builder says Forge" ;; *) bad "kiri builder: $("$KIRI" builder 2>&1)" ;; esac
build on; expect "switched on" native
if grep -q "^building with" "$L"; then bad "the builder line went to a log file" "$L"; else ok "no builder line when the output is not a terminal"; fi
build on-buildkit --builder buildkit; expect "switched on, --builder buildkit" not-native
KENV=KIRI_NATIVE_BUILD=0; build on-env0; KENV=; expect "switched on, KIRI_NATIVE_BUILD=0" not-native
KENV=KIRI_NATIVE_BUILD=0; build on-env0-flag --builder kiri; KENV=; expect "KIRI_NATIVE_BUILD=0 and --builder kiri: the flag wins" native
build on-unsupported --add-host a:192.0.2.1; expect "switched on, a flag only BuildKit takes" not-native
grep -qxF "falling back to BuildKit: --add-host" "$L" && [ "$P" = "fallback --add-host" ] && ok "switched on: the fallback says why and is recorded" || bad "switched on: fallback line/record ($P)" "$L"
d=$W/quiet; mkdir -p "$d"; printf 'FROM %s\nRUN echo quiet-%s > /x\n' "$BASE" "$$" > "$d/Dockerfile"
out=$("$KIRI" build -q -t kbs-quiet:1 "$d" 2>"$d/err")
case $out in sha256:*) [ ! -s "$d/err" ] && ok "-q: the image id only" || bad "-q: stderr not empty" "$d/err" ;; *) bad "-q printed: $out" ;; esac
if command -v script >/dev/null 2>&1; then
  d=$W/tty; mkdir -p "$d"; printf 'FROM %s\nRUN echo tty-%s > /x\n' "$BASE" "$$" > "$d/Dockerfile"
  script -qec "$KIRI build --progress=plain -t kbs-tty:1 $d" /dev/null > "$d/log" 2>&1
  grep -q "building with Forge" "$d/log" && ok "at a terminal: says Forge ran" || bad "at a terminal: no builder line" "$d/log"
  script -qec "$KIRI build --builder buildkit --progress=plain -t kbs-tty2:1 $d" /dev/null > "$d/log2" 2>&1
  grep -q "building with BuildKit" "$d/log2" && ok "at a terminal: says BuildKit ran" || bad "at a terminal: no BuildKit line" "$d/log2"
else
  echo "  skip the terminal line (no script(1) here)"
fi

echo "== kiri builder use buildkit"
s=$("$KIRI" builder use buildkit 2>&1)
case $s in "Set: kiri build uses BuildKit"*) ok "use buildkit says what it set" ;; *) bad "use buildkit says: $s" ;; esac
build off; expect "switched back" not-native; no_fallback_line "switched back"
build off-flag --builder forge; expect "switched off, --builder forge" native
build off-flag-kiri --builder kiri; expect "switched off, --builder kiri (Forge's name before)" native
KENV=KIRI_NATIVE_BUILD=1; build off-env1; KENV=; expect "switched off, KIRI_NATIVE_BUILD=1" native
KENV=KIRI_NATIVE_BUILD=1; build off-env1-flag --builder buildkit; KENV=; expect "KIRI_NATIVE_BUILD=1 and --builder buildkit: the flag wins" not-native
build off-nonative --no-native; expect "--no-native" not-native
s=$("$KIRI" builder use kiri 2>&1)
case $s in "Set: kiri build uses Forge"*) ok "use kiri (Forge's name before) is still taken" ;; *) bad "use kiri says: $s" ;; esac
"$KIRI" builder use buildkit > /dev/null 2>&1

echo "== docker's kiri builder is still docker's"
"$KIRI" builder --help | grep -q "^Usage:  kiri builder" && ok "kiri builder --help" || bad "kiri builder --help"
"$KIRI" builder prune -f > "$W/prune.log" 2>&1 && ok "kiri builder prune -f (docker's)" || bad "kiri builder prune -f" "$W/prune.log"

docker images --format '{{.Repository}}:{{.Tag}}' | grep '^kbs-' | xargs -r docker rmi -f >/dev/null 2>&1
rm -rf "$W"
echo "kiri-builder-switch: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
