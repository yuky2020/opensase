#!/bin/bash
set -euo pipefail
umask 077

if [ -z "${OPENSASE_PUBLIC_HOST:-}" ]; then
  echo "quickstart: OPENSASE_PUBLIC_HOST is required (set to the public DNS name or IP of this host)" >&2
  exit 1
fi

HOST="$OPENSASE_PUBLIC_HOST"
TENANT="${OPENSASE_TENANT:-demo}"
USER_ID="${OPENSASE_USER_ID:-demo-user}"
USER_EMAIL="${OPENSASE_USER_EMAIL:-demo@example.invalid}"
UPSTREAM_DNS="${OPENSASE_UPSTREAM_DNS:-1.1.1.1:53}"
CATEGORIES_URL="${CATEGORIES_URL-https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz}"

export EDGE_UID="${EDGE_UID:-1000}"
export EDGE_GID="${EDGE_GID:-1000}"

mkdir -p /data/pki /data/cp /data/edge /data/pki/tenants
# umask 077 makes these 0700: the Control Plane (uid 65532) and the Edge must traverse them.
chmod 0711 /data /data/pki

if [ ! -f /data/pki/root.crt ]; then
  echo "quickstart: generating admin token" >&2
  ADMIN_TOKEN="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
  printf '%s\n' "$ADMIN_TOKEN" > /data/admin-token
  chmod 0600 /data/admin-token

  echo "quickstart: initializing PKI" >&2
  SANS="localhost,127.0.0.1,::1,$HOST"
  if [ -n "${OPENSASE_EXTRA_SANS:-}" ]; then
    SANS="$SANS,$OPENSASE_EXTRA_SANS"
  fi

  /usr/local/bin/opensasectl pki init \
    -dir /data/pki \
    -session-url "https://$HOST:8443" \
    -wg-endpoint "$HOST:51820" \
    -broker-addr "$HOST:8444" \
    -cp-san "$SANS" \
    -edge-san "$SANS"

  if [ -f /data/pki/edges.json ] && ! grep -q '"brokerAddr"' /data/pki/edges.json; then
    sed 's|^\(\( *\)"id": "edge-1",\)$|\1\n\2"brokerAddr": "'"$HOST"':8444",|' /data/pki/edges.json > /data/pki/edges.json.tmp
    grep -q '"brokerAddr"' /data/pki/edges.json.tmp || { echo "quickstart: could not add brokerAddr to edges.json" >&2; exit 1; }
    mv /data/pki/edges.json.tmp /data/pki/edges.json
  fi
else
  if [ ! -f /data/admin-token ]; then
    echo "quickstart: generating admin token" >&2
    ADMIN_TOKEN="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
    printf '%s\n' "$ADMIN_TOKEN" > /data/admin-token
    chmod 0600 /data/admin-token
  fi
fi

ADMIN_TOKEN="$(cat /data/admin-token)"

chown -R 65532:65532 /data/cp
for item in root.crt root.key controlplane.crt controlplane.key snapshot.key edges.json tenants; do
  if [ -e "/data/pki/$item" ]; then
    chown -R 65532:65532 "/data/pki/$item"
  fi
done

chown -R "$EDGE_UID:$EDGE_GID" /data/edge
if [ -e /data/pki/edge ]; then
  chown -R "$EDGE_UID:$EDGE_GID" /data/pki/edge
fi

for keyfile in /data/pki/*.key /data/pki/edge/*.key /data/admin-token; do
  if [ -f "$keyfile" ]; then
    chmod 0600 "$keyfile"
  fi
done
if [ -f /data/quickstart.env ]; then
  chmod 0600 /data/quickstart.env
fi

echo "quickstart: starting Control Plane" >&2
OPENSASE_ADMIN_TOKEN="$ADMIN_TOKEN" setpriv --reuid=65532 --regid=65532 --clear-groups \
  /usr/local/bin/controlplane \
  -listen :9443 \
  -db /data/cp/controlplane.db \
  -pki /data/pki \
  -control-url "https://$HOST:9443" \
  -portal-dir /usr/share/opensase/portal \
  -categories-file /data/cp/categories.tar.gz \
  -categories-url "$CATEGORIES_URL" \
  > /tmp/controlplane.log 2>&1 &
CP_PID=$!

echo "quickstart: waiting for Control Plane (PQ TLS handshake)" >&2
i=0
until /usr/local/bin/opensasectl -url https://localhost:9443 -ca /data/pki/root.crt pq-check >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then
    echo "quickstart: Control Plane did not come up within 60s" >&2
    if [ -f /tmp/controlplane.log ]; then
      tail -n 50 /tmp/controlplane.log >&2
    fi
    exit 1
  fi
  sleep 1
done

if [ ! -f /data/quickstart.env ]; then
  echo "quickstart: bootstrapping initial tenant and user" >&2
  BOOTSTRAP_OUT="$(OPENSASE_URL="https://localhost:9443" OPENSASE_CA="/data/pki/root.crt" OPENSASE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    /usr/local/bin/opensasectl bootstrap \
      -tenant "$TENANT" \
      -user-id "$USER_ID" \
      -email "$USER_EMAIL" \
      -max-uses 10 \
      -control-url "https://$HOST:9443")"

  BOOT_CONTROL_URL="$(printf '%s\n' "$BOOTSTRAP_OUT" | sed -n 's/^CONTROL_URL=//p')"
  BOOT_PROVISIONING_KEY="$(printf '%s\n' "$BOOTSTRAP_OUT" | sed -n 's/^PROVISIONING_KEY=//p')"
  BOOT_ENROLL_URI="$(printf '%s\n' "$BOOTSTRAP_OUT" | sed -n 's/^ENROLL_URI=//p')"

  if [ -z "$BOOT_CONTROL_URL" ] || [ -z "$BOOT_PROVISIONING_KEY" ] || [ -z "$BOOT_ENROLL_URI" ]; then
    echo "quickstart: failed to parse bootstrap output" >&2
    exit 1
  fi

  cat > /data/quickstart.env.tmp <<EOF
CONTROL_URL=$BOOT_CONTROL_URL
ENROLL_URI=$BOOT_ENROLL_URI
PROVISIONING_KEY=$BOOT_PROVISIONING_KEY
TENANT=$TENANT
ADMIN_TOKEN_FILE=/data/admin-token
EOF
  chmod 0600 /data/quickstart.env.tmp
  mv /data/quickstart.env.tmp /data/quickstart.env

  echo "quickstart: applying policy.example.json" >&2
  OPENSASE_URL="https://localhost:9443" OPENSASE_CA="/data/pki/root.crt" OPENSASE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    /usr/local/bin/opensasectl policy set -tenant "$TENANT" -f /usr/share/opensase/policy.example.json
fi

unset ADMIN_TOKEN BOOTSTRAP_OUT BOOT_CONTROL_URL BOOT_PROVISIONING_KEY BOOT_ENROLL_URI

echo "quickstart: starting Edge" >&2
/usr/local/bin/edge-entrypoint.sh \
  -control-url https://localhost:9443 \
  -pki /data/pki/edge \
  -listen :8443 \
  -wg-port 51820 \
  -wg-endpoint "$HOST:51820" \
  -upstream-dns "$UPSTREAM_DNS" \
  -ztna-listen 0.0.0.0:15001 \
  -broker-listen :8444 \
  -state-dir /data/edge \
  -flow-log /data/edge/flows.jsonl &
EDGE_PID=$!

cat <<EOF

================================================================================
OpenSASE Quick Start (Trials and Demos Only)
================================================================================

OpenSASE is ready.

Admin Portal:  https://$HOST:9443/admin/
Tenant:        $TENANT

To retrieve secrets and configuration:
  docker exec <container> cat /data/quickstart.env
  docker exec <container> cat /data/admin-token

To enrol a device:
  CLI:     opensase enroll -control <CONTROL_URL> -key-file <KEY_FILE>
  Android: Scan ENROLL_URI in the Android app.

  (CONTROL_URL, ENROLL_URI and PROVISIONING_KEY are in /data/quickstart.env)

NOTE: This all-in-one setup is for trials and demos only, not for production.
================================================================================

EOF

term_handler() {
  trap - SIGTERM SIGINT
  kill -TERM "$CP_PID" "$EDGE_PID" 2>/dev/null || true
  wait "$CP_PID" 2>/dev/null || true
  wait "$EDGE_PID" 2>/dev/null || true
  exit 0
}

trap term_handler SIGTERM SIGINT

EXIT_CODE=0
wait -n "$CP_PID" "$EDGE_PID" || EXIT_CODE=$?

trap - SIGTERM SIGINT
kill -TERM "$CP_PID" "$EDGE_PID" 2>/dev/null || true
wait "$CP_PID" 2>/dev/null || true
wait "$EDGE_PID" 2>/dev/null || true
exit "$EXIT_CODE"
