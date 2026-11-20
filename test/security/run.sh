#!/bin/sh
# OpenSASE security suite: black-box area scripts plus the Go package test/security/go,
# against the running dev stack (deploy/dev/bootstrap.sh). Exits non-zero on any FAIL;
# KNOWN-FAIL (reproduced, reported findings) and SKIP do not fail the run.
#
#   test/security/run.sh                 # everything
#   test/security/run.sh 10-tls 70-deploy  # only these shell areas (no Go)
#   SECTEST_GO=0 test/security/run.sh    # shell areas only
#   SECTEST_DESTRUCTIVE=1 ...            # also floods (local stack only)
#   SECTEST_GO_RUN='TestAuth|TestPKI'    # subset of the Go checks
set -u
SEC_DIR="$(cd "$(dirname "$0")" && pwd)"
export SEC_DIR
REPO="$(cd "$SEC_DIR/../.." && pwd)"
SECTEST_RESULTS="${SECTEST_RESULTS:-$(mktemp "${TMPDIR:-/tmp}/sectest.XXXXXX")}"
: >"$SECTEST_RESULTS"
export SECTEST_RESULTS
. "$SEC_DIR/lib.sh"

[ -f "$DEV/.env" ] || { echo "run.sh: deploy/dev/.env missing: run deploy/dev/bootstrap.sh first" >&2; exit 2; }
code "$CP_URL/v1/pki/ca" | grep -q 200 || { echo "run.sh: Control Plane not reachable at $CP_URL" >&2; exit 2; }

areas="$*"
[ -z "$areas" ] && areas="$(cd "$SEC_DIR" && ls [0-9][0-9]-*.sh | sed 's/\.sh$//')"
for a in $areas; do
  printf '\033[1;34m==>\033[0m %s\n' "$a"
  sh "$SEC_DIR/${a%.sh}.sh" || echo "run.sh: $a exited $?" >&2
done

if [ -z "$*" ] && [ "${SECTEST_GO:-1}" = 1 ]; then
  printf '\033[1;34m==>\033[0m go test ./test/security/go (OPENSASE_SECTEST=1)\n'
  (cd "$REPO" && OPENSASE_SECTEST=1 go test -count=1 -timeout 15m -v ${SECTEST_GO_RUN:+-run "$SECTEST_GO_RUN"} ./test/security/go/ >"$SECTEST_RESULTS.go.log" 2>&1)
  rc=$?
  grep -E '^(PASS|FAIL|KNOWN-FAIL|SKIP) SEC-' "$SECTEST_RESULTS.go.log" | while IFS= read -r l; do
    case "$l" in PASS*) c='1;32' ;; FAIL*) c='1;31' ;; KNOWN-FAIL*) c='1;33' ;; *) c='1;36' ;; esac
    printf '\033[%sm%s\033[0m%s\n' "$c" "${l%% *}" " ${l#* }"
  done
  if [ "$rc" != 0 ] && ! grep -q '^FAIL SEC-' "$SECTEST_RESULTS.go.log"; then
    echo "FAIL SEC-GO-000 go test failed outside a check (see $SECTEST_RESULTS.go.log)" | tee -a "$SECTEST_RESULTS"
    tail -20 "$SECTEST_RESULTS.go.log" >&2
  fi
fi

p="$(grep -c '^PASS ' "$SECTEST_RESULTS")"
f="$(grep -c '^FAIL ' "$SECTEST_RESULTS")"
k="$(grep -c '^KNOWN-FAIL ' "$SECTEST_RESULTS")"
s="$(grep -c '^SKIP ' "$SECTEST_RESULTS")"
echo
printf 'sectest: %d PASS, %d FAIL, %d KNOWN-FAIL, %d SKIP (results: %s)\n' "$p" "$f" "$k" "$s" "$SECTEST_RESULTS"
[ "$f" -eq 0 ]
