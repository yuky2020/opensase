#!/bin/sh
# Bootstrap the OpenSASE dev stack: PKI, admin token, Control Plane + Edge, a tenant, a user,
# a provisioning key, the example policy, and ZTNA (ADR-0013): a Connector "dc1" with
# the private app of apps.example.json, served by the intranet container on the corp network. Idempotent: re-running keeps the PKI and data
# and issues a fresh provisioning key.
#
# Env: TENANT (acme), USER_ID (user-1), USER_EMAIL, EDGE_HOST and CONTROL_HOST (edge and
# controlplane; use 10.0.2.2 for the Android emulator), UPSTREAM_DNS (1.1.1.1:53),
# BROKER_HOST (edge; the Edge broker host Connectors dial).
set -eu
cd "$(dirname "$0")"

TENANT="${TENANT:-acme}"
USER_ID="${USER_ID:-user-1}"
USER_EMAIL="${USER_EMAIL:-user@acme.example}"
EDGE_HOST="${EDGE_HOST:-edge}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }

# .env holds the admin token and the latest provisioning key (never printed);
# provisioning.key holds the key alone for the client container (compose secret).
touch .env provisioning.key connector.key
chmod 600 .env provisioning.key connector.key
mkdir -p connector-state edge-state
chmod 700 connector-state edge-state
if ! grep -q '^OPENSASE_ADMIN_TOKEN=' .env; then
  log "generating admin token"
  printf 'OPENSASE_ADMIN_TOKEN=%s\n' "$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')" >>.env
fi
set_env() { # set_env KEY VALUE
  grep -v "^$1=" .env >.env.tmp || true
  printf '%s=%s\n' "$1" "$2" >>.env.tmp
  mv .env.tmp .env
  chmod 600 .env
}
set_env EDGE_HOST "$EDGE_HOST"
set_env CONTROL_HOST "${CONTROL_HOST:-controlplane}"
set_env OPENSASE_UID "$(id -u)"
set_env OPENSASE_GID "$(id -g)"
[ -n "${UPSTREAM_DNS:-}" ] && set_env UPSTREAM_DNS "$UPSTREAM_DNS"

mkdir -p pki data
log "building images"
docker compose build controlplane edge connector

ctl() { docker compose run --rm --no-deps -T ctl "$@"; }

if [ ! -f pki/root.crt ]; then
  log "generating PKI (edge reachable at $EDGE_HOST)"
  # Distinct SANs per server (security review #1); clients also check the SPIFFE URI.
  DEV_SANS="localhost,127.0.0.1,::1,10.0.2.2"
  ctl pki init -dir /pki -session-url "https://$EDGE_HOST:8443" -wg-endpoint "$EDGE_HOST:51820" -broker-addr "${BROKER_HOST:-edge}:8444" \
    -cp-san "controlplane,$DEV_SANS${CONTROL_HOST:+,$CONTROL_HOST}" \
    -edge-san "edge,$DEV_SANS,$EDGE_HOST"
else
  log "PKI exists, keeping it"
fi

# Edges advertise a broker address to Connectors (ADR-0013). pki init writes edges.json
# without it; add it once, keeping everything else. BROKER_HOST is what connectors dial
# (default: the edge service name, in the Edge cert SANs), independent of EDGE_HOST, which
# devices use (10.0.2.2 for the emulator is not reachable from the connector container).
BROKER_HOST="${BROKER_HOST:-edge}"
if [ -f pki/edges.json ] && ! grep -q '"brokerAddr"' pki/edges.json; then
  log "adding brokerAddr $BROKER_HOST:8444 to pki/edges.json"
  sed 's|^\(\( *\)"id": "edge-1",\)$|\1\n\2"brokerAddr": "'"$BROKER_HOST"':8444",|' pki/edges.json >pki/edges.json.tmp
  grep -q '"brokerAddr"' pki/edges.json.tmp || { echo "bootstrap: could not add brokerAddr to pki/edges.json" >&2; exit 1; }
  mv pki/edges.json.tmp pki/edges.json
  # The Control Plane reads edges.json at startup.
  docker compose ps -q controlplane | grep -q . && docker compose restart controlplane >/dev/null
fi

log "starting controlplane and edge"
docker compose up -d controlplane edge

log "waiting for the Control Plane (PQ TLS handshake)"
i=0
until ctl pq-check >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -ge 30 ] && { docker compose logs --tail 50 controlplane >&2; echo "Control Plane did not come up" >&2; exit 1; }
  sleep 1
done
ctl pq-check

log "registering edge-1, creating tenant $TENANT, user $USER_ID and a provisioning key"
OUT="$(ctl bootstrap -tenant "$TENANT" -user-id "$USER_ID" -email "$USER_EMAIL" -max-uses 10 \
  -control-url "https://${CONTROL_HOST:-controlplane}:9443")"
KEY="$(echo "$OUT" | sed -n 's/^PROVISIONING_KEY=//p')"
set_env OPENSASE_PROVISIONING_KEY "$KEY"
(umask 077 && printf '%s\n' "$KEY" >provisioning.key.tmp && mv provisioning.key.tmp provisioning.key)
unset KEY
set_env OPENSASE_CONTROL_URL "$(echo "$OUT" | sed -n 's/^CONTROL_URL=//p')"
set_env OPENSASE_ENROLL_URI "$(echo "$OUT" | sed -n 's/^ENROLL_URI=//p')"
# Root CA pin for the Connector's first contact (same #sha256= as the device URL).
set_env OPENSASE_ROOT_SHA256 "$(grep '^OPENSASE_CONTROL_URL=' .env | sed -n 's/.*#sha256=//p')"

log "applying policy.example.json"
ctl policy set -tenant "$TENANT" -f /work/policy.example.json

# ZTNA (ADR-0013). A connector provisioning key is single use: a new one is issued only while
# the connector has not enrolled yet (no state); the state directory survives re-runs.
log "publishing private apps (apps.example.json)"
ctl app set -tenant "$TENANT" -file /work/apps.example.json
if [ ! -s connector-state/connector.json ]; then
  log "adding Connector dc1 (group default)"
  rm -f pki/connector.key
  # The key goes only to the 0600 file; never echo it (stdout is often logged).
  ctl connector add -tenant "$TENANT" -name dc1 -key-out /pki/connector.key | grep -v '^PROVISIONING_KEY=' >&2 || true
  [ -s pki/connector.key ] || { echo "bootstrap: opensasectl connector add wrote no key" >&2; exit 1; }
  (umask 077 && cp pki/connector.key connector.key.tmp && mv connector.key.tmp connector.key)
  rm -f pki/connector.key
else
  log "Connector already enrolled, keeping it"
fi
log "starting intranet (corp network only) and connector"
docker compose up -d intranet connector

log "done"
cat >&2 <<EOF

  Control Plane  https://localhost:9443   (CA: deploy/dev/pki/root.crt)
  Edge           https://localhost:8443 , udp/51820, Connector broker tcp/8444
  ZTNA           http://intranet.acme.internal/ via connector (dc1) -> intranet (corp)
  Provisioning key for $USER_ID, pinned control URL (#sha256= of the root CA) and the
  single-string enroll URI (for a QR code) are in deploy/dev/.env:
  OPENSASE_PROVISIONING_KEY, OPENSASE_CONTROL_URL, OPENSASE_ENROLL_URI
  (Android emulator: CONTROL_HOST=10.0.2.2 EDGE_HOST=10.0.2.2 ./bootstrap.sh)

  Next: ./e2e.sh      or   docker compose run --rm ctl flows -tenant $TENANT
EOF
