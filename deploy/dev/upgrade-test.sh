#!/usr/bin/env bash
# Automated upgrade test from previous release to current build (issue #60).
# Checks that the Control Plane and Edge can be upgraded in place with existing PKI,
# data, tenant policy, and device enrollment preserved, and that an enrolled client
# reconnects without re-enrollment.
set -euo pipefail
cd "$(dirname "$0")"

if [ -z "${OPENSASE_PREV_VERSION:-}" ]; then
  echo "upgrade-test: OPENSASE_PREV_VERSION is required (e.g. 0.2.0)" >&2
  exit 1
fi

TENANT="${TENANT:-acme}"
TUN="${CLIENT_TUN:-osase0}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
ctl() { docker compose run --rm --no-deps -T ctl "$@"; }
cexec() { docker compose --profile e2e exec -T client "$@"; }

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
ko() { FAIL=$((FAIL + 1)); printf '\033[1;31mFAIL\033[0m %s\n' "$*"; }

# 3b. docker compose down and preserve maintainer dev state in bind mounts / state dirs
log "stopping existing dev containers"
docker compose down >/dev/null 2>&1 || true

BACKUP_DIR=".dev-state-backup-$(date +%Y%m%d%H%M%S)-$$"
mkdir -p "$BACKUP_DIR"

for item in pki data connector-state edge-state .env provisioning.key connector.key; do
  if [ -e "$item" ]; then
    mv "$item" "$BACKUP_DIR/"
  fi
done

restore_state() {
  log "cleaning up test containers and restoring dev state"
  docker compose --profile e2e stop >/dev/null 2>&1 || true
  docker compose stop >/dev/null 2>&1 || true
  docker volume rm opensase_clientstate >/dev/null 2>&1 || true
  rm -rf pki data connector-state edge-state .env provisioning.key connector.key
  if [ -d "$BACKUP_DIR" ]; then
    for item in pki data connector-state edge-state .env provisioning.key connector.key; do
      if [ -e "$BACKUP_DIR/$item" ]; then
        mv "$BACKUP_DIR/$item" ./
      fi
    done
    rm -rf "$BACKUP_DIR"
  fi
}
trap restore_state EXIT INT TERM

# Preserve offline category fixture or URL settings if set by runner / maintainer
if [ -f "$BACKUP_DIR/data/categories.tar.gz" ]; then
  mkdir -p data
  cp "$BACKUP_DIR/data/categories.tar.gz" data/categories.tar.gz
fi
if [ -f "$BACKUP_DIR/.env" ] && grep -q '^CATEGORIES_URL=' "$BACKUP_DIR/.env"; then
  printf 'CATEGORIES_URL=\n' >.env
fi

# 3c. Start controlplane and edge from previous release with docker-compose.upgrade.yml override
log "bootstrapping previous release ($OPENSASE_PREV_VERSION)"
export COMPOSE_FILE=docker-compose.yml:docker-compose.upgrade.yml
OPENSASE_SKIP_BUILD=1 ./bootstrap.sh
docker compose -f docker-compose.yml -f docker-compose.upgrade.yml up -d controlplane edge

# 3d. Build only the current client image, start e2e client, wait for connected status, record IDs/hashes
log "building current client image"
docker compose build client

log "starting e2e client"
docker compose --profile e2e rm -sf client >/dev/null 2>&1 || true
docker volume rm opensase_clientstate >/dev/null 2>&1 || true
docker compose --profile e2e up -d client

log "waiting for the tunnel address on $TUN"
i=0
until cexec ip -4 addr show "$TUN" 2>/dev/null | grep -q 'inet 100\.'; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then
    ko "client tunnel did not come up within 60s"
    docker compose --profile e2e logs --tail 80 client edge >&2 || true
    exit 1
  fi
  sleep 1
done
ok "tunnel up: $(cexec ip -4 -o addr show "$TUN" | awk '{print $4}')"
cexec sh -c 'grep -q "^nameserver 100.64.0.1" /etc/resolv.conf || echo "nameserver 100.64.0.1" >/etc/resolv.conf' || true

# Record device id
prev_dev_id="$(docker compose --profile e2e logs client 2>/dev/null | grep -o '"deviceId":"[^"]*"' | tail -1 | cut -d'"' -f4)"
if [ -z "$prev_dev_id" ]; then
  prev_dev_id="$(ctl devices -tenant "$TENANT" 2>/dev/null | awk '$3 == "e2e-client" {print $1; exit}')"
fi
if [ -z "$prev_dev_id" ]; then
  echo "upgrade-test: could not record client device id" >&2
  exit 1
fi
log "recorded client device ID: $prev_dev_id"

# Record ctl policy get hash
prev_policy_hash="$(ctl policy get -tenant "$TENANT" | sha256sum | awk '{print $1}')"
if [ -z "$prev_policy_hash" ]; then
  echo "upgrade-test: could not record policy hash" >&2
  exit 1
fi
log "recorded policy hash: $prev_policy_hash"

# Record root CA fingerprint
if [ -f pki/root.crt ]; then
  prev_root_ca="$(openssl x509 -in pki/root.crt -outform DER | sha256sum | awk '{print $1}')"
else
  prev_root_ca="$(grep '^OPENSASE_ROOT_SHA256=' .env | cut -d= -f2)"
fi
if [ -z "$prev_root_ca" ]; then
  echo "upgrade-test: could not record root CA fingerprint" >&2
  exit 1
fi
log "recorded root CA fingerprint: $prev_root_ca"

# 3e. Upgrade: docker compose build controlplane edge then docker compose up -d controlplane edge with only docker-compose.yml
log "upgrading controlplane and edge to current build"
upgraded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export COMPOSE_FILE=docker-compose.yml
docker compose build controlplane edge
docker compose up -d controlplane edge

log "waiting for Control Plane (PQ TLS handshake)"
i=0
until ctl pq-check >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 30 ]; then
    ko "Control Plane did not come up after upgrade within 30s"
    docker compose logs --tail 50 controlplane >&2 || true
    exit 1
  fi
  sleep 1
done
ctl pq-check

# 3f. Checks
# 1. Control Plane up with the same root CA fingerprint
if [ -f pki/root.crt ]; then
  new_root_ca="$(openssl x509 -in pki/root.crt -outform DER | sha256sum | awk '{print $1}')"
else
  new_root_ca="$(grep '^OPENSASE_ROOT_SHA256=' .env | cut -d= -f2)"
fi
if [ -n "$new_root_ca" ] && [ "$new_root_ca" = "$prev_root_ca" ]; then
  ok "Control Plane up with the same root CA fingerprint ($new_root_ca)"
else
  ko "Control Plane root CA fingerprint changed (was $prev_root_ca, now $new_root_ca)"
fi

# 2. Device ID still listed by ctl devices -tenant <tenant>
if ctl devices -tenant "$TENANT" 2>/dev/null | grep -q "$prev_dev_id"; then
  ok "device id still listed by ctl devices ($prev_dev_id)"
else
  ko "device id $prev_dev_id not listed in ctl devices"
fi

# 3. ctl policy get unchanged
new_policy_hash="$(ctl policy get -tenant "$TENANT" | sha256sum | awk '{print $1}')"
if [ "$new_policy_hash" = "$prev_policy_hash" ]; then
  ok "ctl policy get unchanged"
else
  ko "ctl policy get changed after upgrade"
fi

# 4. The client works again after the upgrade without re-enrolment: only status lines logged
# after the upgrade count, and the tunnel must carry DNS again (the Edge restart drops the
# session, so the client has to notice and set up a new one).
log "waiting up to 180s for the client to work through the upgraded Edge"
reconnected=false
current_dev_id=""
for i in $(seq 1 90); do
  latest_status="$(docker compose --profile e2e logs --since "$upgraded_at" client 2>/dev/null | grep '"state":"connected"' | tail -1 || true)"
  current_dev_id="$(printf '%s' "$latest_status" | grep -o '"deviceId":"[^"]*"' | head -1 | cut -d'"' -f4 || true)"
  if [ "$current_dev_id" = "$prev_dev_id" ] &&
    cexec dig +time=2 +tries=1 @100.64.0.1 example.com 2>/dev/null | grep -q 'status: NOERROR'; then
    reconnected=true
    break
  fi
  sleep 2
done
if [ "$reconnected" = true ]; then
  ok "client works again after about $((i * 2))s, same device id, no re-enrolment ($current_dev_id)"
  ok "DNS query through the tunnel resolves after the upgrade"
else
  ko "client did not work through the upgraded Edge within 180s (last device id: '$current_dev_id')"
  docker compose --profile e2e logs --tail 40 client edge >&2 || true
fi

# 3g. Summary and exit
echo
printf 'upgrade: %d passed, %d failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
  docker compose --profile e2e logs --tail 40 client edge >&2 || true
  exit 1
fi
