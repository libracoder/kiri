#!/bin/bash
# Engine-only latency: one container lifecycle (create, start, wait, delete)
# and one exec, straight over the Docker API with curl, no docker CLI.
#   SOCK=/run/dockerd-bench.sock bench/api.sh docker-engine
set -euo pipefail
label=$1; S=${SOCK:?}; OUT=${OUT:-$(dirname "$0")/results}; RUNS=${RUNS:-30}
mkdir -p "$OUT"
c() { curl -fsS --unix-socket "$S" "$@"; }
id=""
trap '[[ -n "$id" ]] && c -X DELETE "http://x/containers/$id?force=true" >/dev/null || true' EXIT
c -X POST -H 'Content-Type: application/json' -d '{"Image":"alpine","Cmd":["true"]}' http://x/containers/create >/dev/null
cat > /tmp/api-run.sh <<R
set -euo pipefail
c() { curl -fsS --unix-socket "$S" "\$@"; }
id=\$(c -X POST -H 'Content-Type: application/json' -d '{"Image":"alpine","Cmd":["true"]}' http://x/containers/create | jq -r .Id)
c -X POST http://x/containers/\$id/start >/dev/null && c -X POST http://x/containers/\$id/wait >/dev/null && c -X DELETE http://x/containers/\$id >/dev/null
R
id=$(c -X POST -H 'Content-Type: application/json' -d '{"Image":"alpine","Cmd":["sleep","600"]}' http://x/containers/create | jq -r .Id); c -X POST "http://x/containers/$id/start" >/dev/null
cat > /tmp/api-exec.sh <<R
set -euo pipefail
c() { curl -fsS --unix-socket "$S" "\$@"; }
e=\$(c -X POST -H 'Content-Type: application/json' -d '{"Cmd":["true"],"AttachStdout":true}' http://x/containers/$id/exec | jq -r .Id)
c -X POST -H 'Content-Type: application/json' -d '{}' http://x/exec/\$e/start >/dev/null
R
out=$(hyperfine --warmup 3 --runs "$RUNS" --export-json "$OUT/$label.api-run.json" 'bash /tmp/api-run.sh' 2>&1) || { printf '%s\n' "$out" >&2; exit 1; }
out=$(hyperfine --warmup 3 --runs "$RUNS" --export-json "$OUT/$label.api-exec.json" 'bash /tmp/api-exec.sh' 2>&1) || { printf '%s\n' "$out" >&2; exit 1; }
ms() { jq -r ".results[0] | (.summary.time_wall_clock // .) | .$1 * 1000 | round" "$OUT/$label.$2.json"; }
r_med=$(ms median api-run); r_min=$(ms min api-run); e_med=$(ms median api-exec); e_min=$(ms min api-exec)
printf '%-14s API run %4s ms (min %4s)   API exec %4s ms (min %4s)\n' "$label" "$r_med" "$r_min" "$e_med" "$e_min"
