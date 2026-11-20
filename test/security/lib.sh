# Shared helpers for the OpenSASE black-box security suite. Sourced by run.sh and by every
# area script; POSIX sh.
#
# Result lines: "PASS|FAIL|KNOWN-FAIL|SKIP <ID> <description> [-- detail]", printed and
# appended to $SECTEST_RESULTS. Secrets (admin token, provisioning keys) are read from
# deploy/dev/.env into shell variables only: never echoed, never on a command line.

SEC_DIR="${SEC_DIR:-$(cd "$(dirname "$0")" && pwd)}"
REPO="${REPO:-$(cd "$SEC_DIR/../.." && pwd)}"
DEV="${SECTEST_DEV_DIR:-$REPO/deploy/dev}"
CP_URL="${SECTEST_CP_URL:-https://localhost:9443}"
EDGE_URL="${SECTEST_EDGE_URL:-https://localhost:8443}"
CA="$DEV/pki/root.crt"
: "${SECTEST_RESULTS:=$(mktemp)}"
export SECTEST_RESULTS

_out() { # _out STATUS ID DESC [DETAIL]
  line="$1 $2 $3"
  [ -n "${4:-}" ] && line="$line -- $(printf '%s' "$4" | tr '\n' ' ' | cut -c1-400)"
  case "$1" in
    PASS) c='1;32' ;; FAIL) c='1;31' ;; KNOWN-FAIL) c='1;33' ;; *) c='1;36' ;;
  esac
  printf '\033[%sm%s\033[0m%s\n' "$c" "$1" "${line#"$1"}"
  printf '%s\n' "$line" >>"$SECTEST_RESULTS"
}
pass() { _out PASS "$1" "$2"; }
skip() { _out SKIP "$1" "$2" "${3:-}"; }
# fail ID DESC DETAIL [KNOWN_FINDING]: a known finding prints KNOWN-FAIL and does not fail the run.
fail() {
  if [ -n "${4:-}" ]; then _out KNOWN-FAIL "$1" "$2" "[$4] ${3:-}"; else _out FAIL "$1" "$2" "${3:-}"; fi
}
# known_pass ID DESC FINDING: a known finding that no longer reproduces.
known_pass() { _out PASS "$1" "$2" "known finding $3 no longer reproduces: update the report"; }

# Admin token: loaded once into ADMIN_TOKEN (not exported).
load_token() {
  [ -n "${ADMIN_TOKEN:-}" ] && return 0
  [ -r "$DEV/.env" ] || return 1
  ADMIN_TOKEN="$(sed -n 's/^OPENSASE_ADMIN_TOKEN=//p' "$DEV/.env")"
  [ -n "$ADMIN_TOKEN" ]
}

# cpcurl ARGS...: curl over PQ TLS to the dev stack (OpenSSL >= 3.5 offers X25519MLKEM768),
# pinned to the dev root CA. Prints the body; use -w for the status.
cpcurl() { curl -sS -m "${CURL_TIMEOUT:-10}" --cacert "$CA" --curves X25519MLKEM768 "$@"; }

# code URL [ARGS...]: HTTP status only ("000" on transport failure).
code() { u="$1"; shift; cpcurl -o /dev/null -w '%{http_code}' "$@" "$u" 2>/dev/null || true; }

# admin_code METHOD PATH [BODY]: status of an admin call with the real token. The header goes
# through stdin (-H @-) so the token never appears in ps.
admin_code() {
  load_token || { echo 000; return; }
  printf 'Authorization: Bearer %s\n' "$ADMIN_TOKEN" |
    cpcurl -o /dev/null -w '%{http_code}' -X "$1" -H @- ${3:+-H 'Content-Type: application/json' --data-raw "$3"} "$CP_URL/v1/admin$2" 2>/dev/null || true
}
# admin_get PATH: body of an admin GET.
admin_get() {
  load_token || return 1
  printf 'Authorization: Bearer %s\n' "$ADMIN_TOKEN" | cpcurl -H @- "$CP_URL/v1/admin$1"
}

dc() { docker compose --project-directory "$DEV" -f "$DEV/docker-compose.yml" -p opensase "$@"; }
cexec() { dc --profile e2e exec -T client "$@"; }
running() { [ -n "$(dc ps -q --status running "$1" 2>/dev/null)" ]; }

# mode PATH: octal permission bits ("" if missing).
mode() { stat -c '%a' "$1" 2>/dev/null || true; }

RUN_ID="${RUN_ID:-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')}"
