#!/bin/sh
# Areas 1 and 4 (black box, curl): admin token, routes without client certificates, the
# unauthenticated surface and HTTP-level input handling. Certificate role isolation,
# revocation and renewal attacks need crafted certificates: Go package (SEC-AUTH-0xx).
set -u
. "$(dirname "$0")/lib.sh"

if ! load_token; then
  skip SEC-AUTH-101 "admin API: no/wrong token -> 401" "no deploy/dev/.env"
  exit 0
fi

# Admin API: no token and a wrong token -> 401; the real token -> 200 (control).
no="$(code "$CP_URL/v1/admin/tenants")"
wrong="$(printf 'Authorization: Bearer %s\n' "not-the-admin-token-000000" | code "$CP_URL/v1/admin/tenants" -H @-)"
ok="$(admin_code GET /tenants)"
if [ "$ok" != 200 ]; then
  skip SEC-AUTH-101 "admin API: no/wrong token -> 401" "control with the real token got $ok"
elif [ "$no" = 401 ] && [ "$wrong" = 401 ]; then
  pass SEC-AUTH-101 "admin API: no/wrong token -> 401"
else
  fail SEC-AUTH-101 "admin API: no/wrong token -> 401" "no token $no, wrong token $wrong"
fi

# Every mTLS route without a client certificate -> 401 (the TLS layer lets the browser in,
# so the route must refuse).
bad=""
for r in "GET /v1/snapshot" "GET /v1/self/rules" "PUT /v1/self/rules" "POST /v1/renew" "POST /v1/decide" \
  "POST /v1/flows" "GET /v1/connector/config" "POST /v1/connector/renew" "GET /v1/edge/peers" "POST /v1/edge/sessions"; do
  m="${r% *}"; p="${r#* }"
  c="$(code "$CP_URL$p" -X "$m" -H 'Content-Type: application/json' --data-raw '{}')"
  [ "$c" = 401 ] || bad="$bad $m $p=$c;"
done
[ -z "$bad" ] && pass SEC-AUTH-102 "mTLS routes without a client certificate -> 401" ||
  fail SEC-AUTH-102 "mTLS routes without a client certificate -> 401" "$bad"

# The Edge session channel requires the certificate at the TLS layer.
c="$(code "$EDGE_URL/v1/session" -X POST --data-raw '{}')"
case "$c" in
  000 | 401 | 403) pass SEC-AUTH-103 "Edge /v1/session without a client certificate refused" ;;
  *) fail SEC-AUTH-103 "Edge /v1/session without a client certificate refused" "HTTP $c" ;;
esac

# Unauthenticated surface: /v1/pki/ca carries public material only (no private key, no
# token, no provisioning key).
body="$(cpcurl "$CP_URL/v1/pki/ca" 2>/dev/null || true)"
if [ -z "$body" ]; then
  skip SEC-AUTH-104 "public /v1/pki/ca exposes no secrets" "no response"
elif printf '%s' "$body" | grep -qiE 'PRIVATE KEY|osk_|osc_' || printf '%s' "$body" | grep -qF "$ADMIN_TOKEN"; then
  fail SEC-AUTH-104 "public /v1/pki/ca exposes no secrets" "secret material in the response"
else
  pass SEC-AUTH-104 "public /v1/pki/ca exposes no secrets"
fi

# Admin portal static files: no path traversal out of the portal directory.
bad=""
for p in "/admin/../../etc/passwd" "/admin/%2e%2e/%2e%2e/%2e%2e/etc/passwd" "/admin/..%2f..%2f..%2fetc%2fpasswd" "/admin/....//....//etc/passwd" "/admin/%2e%2e%5c%2e%2e%5cetc%5cpasswd"; do
  out="$(cpcurl --path-as-is "$CP_URL$p" 2>/dev/null || true)"
  printf '%s' "$out" | grep -q 'root:' && bad="$bad $p"
done
[ -z "$bad" ] && pass SEC-IN-101 "admin portal: no path traversal (../, %2e%2e, %2f, backslash)" ||
  fail SEC-IN-101 "admin portal: no path traversal (../, %2e%2e, %2f, backslash)" "served /etc/passwd for$bad"

# Methods that should not exist: TRACE echo (XST), and unknown methods on admin routes.
t1="$(code "$CP_URL/v1/pki/ca" -X TRACE)"
t2="$(code "$CP_URL/v1/admin/tenants" -X DELETE)"
case "$t1$t2" in
  *200*) fail SEC-IN-103 "TRACE and unknown methods not served" "TRACE $t1, DELETE admin $t2" ;;
  *) pass SEC-IN-103 "TRACE and unknown methods not served" ;;
esac

# Responses carry no-store on API JSON (tokens, keys and policies must not be cached).
h="$(printf 'Authorization: Bearer %s\n' "$ADMIN_TOKEN" | cpcurl -D - -o /dev/null -H @- "$CP_URL/v1/admin/tenants" 2>/dev/null | tr -d '\r')"
if printf '%s' "$h" | grep -qi '^cache-control:.*no-store'; then
  pass SEC-IN-104 "admin API responses are Cache-Control: no-store"
else
  fail SEC-IN-104 "admin API responses are Cache-Control: no-store" "headers: $(printf '%s' "$h" | grep -i cache)"
fi
