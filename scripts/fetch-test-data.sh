#!/bin/sh
# Fetches the builder's test data (the golden vectors and the wire captures,
# kept in a separate repository) into tests/data-cache, at exactly the
# commit tests/test-data.pin names, and checks that it got that commit.
#   scripts/fetch-test-data.sh
# The repository's address is not in this repository: it comes from
# KIRI_TEST_DATA_URL, else from the untracked tests/test-data.local
# (`url=...`, see tests/test-data.local.example).
# Uses your own git credentials; nothing here holds a token. The tests find
# the data in tests/data-cache (or wherever KIRI_TEST_DATA points); without
# it, the tests that need it print SKIPPED and pass, and fail only when
# KIRI_TEST_DATA_REQUIRED=1.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
pin=$root/tests/test-data.pin
dest=$root/tests/data-cache
local=$root/tests/test-data.local
val() { sed -n "s/^$1=//p" "$2" | head -n 1; }
commit=$(val commit "$pin")
tag=$(val tag "$pin")
url=${KIRI_TEST_DATA_URL:-}
if [ -z "$url" ] && [ -f "$local" ]; then url=$(val url "$local"); fi
case $commit in
*[!0-9a-f]* | "") echo "fetch-test-data: $pin: commit must be a full SHA" >&2; exit 2 ;;
esac
[ ${#commit} = 40 ] || { echo "fetch-test-data: $pin: commit must be a full 40-character SHA" >&2; exit 2; }
if [ -z "$url" ]; then
  echo "fetch-test-data: no repository address: set KIRI_TEST_DATA_URL, or copy tests/test-data.local.example to tests/test-data.local and set its url" >&2
  exit 2
fi

if [ -d "$dest/.git" ] && [ "$(git -C "$dest" rev-parse -q --verify HEAD 2>/dev/null)" = "$commit" ] &&
  [ -z "$(git -C "$dest" status --porcelain 2>/dev/null)" ]; then
  echo "test data already at ${tag:-$commit} ($commit) in tests/data-cache"
  exit 0
fi

mkdir -p "$dest"
[ -d "$dest/.git" ] || git -C "$dest" init -q
git -C "$dest" remote remove origin 2>/dev/null || true
git -C "$dest" remote add origin "$url"
# Never wait for a password prompt: a refusal must end the script.
if ! GIT_TERMINAL_PROMPT=0 git -C "$dest" fetch -q --depth 1 --no-tags origin "$commit" 2>"$dest/.git/fetch-error"; then
  sed 's/^/  /' "$dest/.git/fetch-error" >&2
  cat >&2 <<EOF
fetch-test-data: could not fetch $url
Fetching the builder test data repository needs access to it; without it the
tests that need it are skipped (each prints "SKIPPED: needs the builder test
data"). With access:
sign in for git to the host that serves it and run this script again, or
point KIRI_TEST_DATA at a checkout of that repository.
EOF
  exit 1
fi
git -C "$dest" -c advice.detachedHead=false checkout -q -f --detach FETCH_HEAD
git -C "$dest" clean -q -f -d -x
got=$(git -C "$dest" rev-parse HEAD)
if [ "$got" != "$commit" ]; then
  echo "fetch-test-data: checked out $got, but the pin says $commit; tests/data-cache is not trusted" >&2
  exit 1
fi
echo "test data at ${tag:-$commit} ($commit) in tests/data-cache"
