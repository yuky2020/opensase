#!/usr/bin/env bash
# End-to-end failover and fail-back test across two Edges (issue #70).
set -euo pipefail
cd "$(dirname "$0")"

TENANT="${TENANT:-acme}"
TUN="${CLIENT_TUN:-osase0}"
PASS=0
FAIL=0

log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
ok() { PASS=$((PASS + 1)); printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
ko() { FAIL=$((FAIL + 1)); printf '\033[1;31mFAIL\033[0m %s\n' "$*"; }
ctl() { docker compose run --rm --no-deps -T ctl "$@"; }
cexec() { docker compose --profile e2e exec -T client "$@"; }

# Preserve maintainer / existing dev state
BACKUP_DIR=""
if [ -d pki ] || [ -d data ] || [ -d edge-state ] || [ -d edge2-state ] || [ -d connector-state ] || [ -f .env ]; then
  BACKUP_DIR="$(mktemp -d -t opensase-failover-backup.XXXXXX)"
  for item in pki data connector-state edge-state edge2-state .env provisioning.key connector.key; do
    if [ -e "$item" ]; then
      cp -a "$item" "$BACKUP_DIR/"
    fi
  done
fi

restore_state() {
  local exit_code=$?
  if [ "$exit_code" -ne 0 ] || [ "$FAIL" -ne 0 ]; then
    log "test failed, dumping compose logs"
    docker compose --profile e2e logs --tail 200 || true
  fi
  log "cleaning up test stack"
  docker compose --profile e2e down -v || true
  if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
    log "restoring pre-test state"
    for item in pki data connector-state edge-state edge2-state .env provisioning.key connector.key; do
      rm -rf "$item"
      if [ -e "$BACKUP_DIR/$item" ]; then
        cp -a "$BACKUP_DIR/$item" ./
      fi
    done
    rm -rf "$BACKUP_DIR"
  fi
  exit "$exit_code"
}
trap restore_state EXIT INT TERM

# Preserve offline category fixture or URL settings if set by runner / maintainer
if [ -n "$BACKUP_DIR" ] && [ -f "$BACKUP_DIR/data/categories.tar.gz" ]; then
  mkdir -p data
  cp "$BACKUP_DIR/data/categories.tar.gz" data/categories.tar.gz
fi
if [ -n "$BACKUP_DIR" ] && [ -f "$BACKUP_DIR/.env" ] && grep -q '^CATEGORIES_URL=' "$BACKUP_DIR/.env"; then
  printf 'CATEGORIES_URL=\n' >.env
fi

export COMPOSE_FILE="docker-compose.yml:docker-compose.failover.yml"

log "bootstrapping dev stack with edge-1 and edge-2"
./bootstrap.sh

# Ensure edge2 is started and registered
docker compose up -d controlplane edge edge2
ctl edge add -id edge-2 >/dev/null 2>&1 || true

# Start e2e client with clean state
log "building and starting the e2e client container"
docker compose --profile e2e build client
docker compose --profile e2e rm -sf client >/dev/null 2>&1 || true
docker volume rm opensase_clientstate >/dev/null 2>&1 || true
docker compose --profile e2e up -d client

log "waiting for the tunnel address on $TUN"
i=0
until cexec ip -4 addr show "$TUN" 2>/dev/null | grep -q 'inet 100\.'; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then
    ko "client tunnel did not come up within 60s"
    exit 1
  fi
  sleep 1
done
ok "tunnel up: $(cexec ip -4 -o addr show "$TUN" | awk '{print $4}')"
cexec sh -c 'grep -q "^nameserver 100.64.0.1" /etc/resolv.conf || echo "nameserver 100.64.0.1" >/etc/resolv.conf' || true

get_client_edge() {
  docker compose --profile e2e logs --tail 30 client 2>/dev/null | grep -o '"edge":"[^"]*"' | tail -1 | cut -d'"' -f4 || true
}

get_tunnel_ip() {
  cexec ip -4 -o addr show "$TUN" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true
}

test_traffic() {
  local target_desc="$1"
  local code=""
  local j
  for j in 1 2 3 4 5; do
    code="$(cexec curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com 2>&1)" && break
    sleep 2
  done
  case "$code" in
    2??|3??)
      ok "traffic works through $target_desc (HTTP $code)"
      return 0
      ;;
    *)
      ko "traffic failed through $target_desc (HTTP $code)"
      return 1
      ;;
  esac
}

# 1. Initial checks: verify client connected to edge-1 and traffic works
log "verifying initial connection to edge-1"
edge_detected=false
current_edge=""
for i in $(seq 1 20); do
  current_edge="$(get_client_edge)"
  if [ "$current_edge" = "edge-1" ]; then
    edge_detected=true
    break
  fi
  sleep 1
done
if [ "$edge_detected" = true ]; then
  ok "client connected to edge-1"
else
  ko "client connected to '$current_edge', expected edge-1"
fi

test_traffic "edge-1"

# 2. Record the client's tunnel address
client_ip="$(get_tunnel_ip)"
if [ -n "$client_ip" ]; then
  ok "recorded client tunnel address: $client_ip"
else
  ko "could not determine client tunnel address"
  exit 1
fi

# Ensure tunnel is idle for probeIdle (10s) before stopping edge-1
log "waiting 10s for tunnel to become idle (exceeding probeIdle)"
sleep 10

# 3. Stop edge-1 and time failover to edge-2
log "stopping edge-1 (docker compose stop edge)"
stop_time="$(date +%s)"
docker compose stop edge

log "waiting up to 30s for client failover to edge-2"
failover_ok=false
failover_sec=0
for i in $(seq 1 30); do
  now="$(date +%s)"
  failover_sec=$((now - stop_time))
  current_edge="$(get_client_edge)"
  if [ "$current_edge" = "edge-2" ]; then
    failover_ok=true
    break
  fi
  sleep 1
done

if [ "$failover_ok" = true ]; then
  ok "failover to edge-2 detected in ${failover_sec}s"
else
  ko "client did not fail over to edge-2 within 30s (last edge: '$current_edge')"
fi

# Print measured failover seconds
printf 'failover measured: %d seconds\n' "$failover_sec"

# Verify tunnel address is unchanged
current_ip="$(get_tunnel_ip)"
if [ -n "$current_ip" ] && [ "$current_ip" = "$client_ip" ]; then
  ok "tunnel address unchanged after failover ($current_ip)"
else
  ko "tunnel address changed after failover (was $client_ip, now $current_ip)"
fi

# Verify traffic works through edge-2
test_traffic "edge-2"

# 4. Start edge-1 again and time fail-back
log "starting edge-1 again (docker compose start edge)"
start_time="$(date +%s)"
docker compose start edge

# Client failbackAfter is 5 minutes (300s). Deadline is failbackAfter + 60s = 360s.
log "waiting up to 360s (failbackAfter 300s + 60s) for fail-back to edge-1"
failback_ok=false
failback_sec=0
for i in $(seq 1 180); do
  now="$(date +%s)"
  failback_sec=$((now - start_time))
  current_edge="$(get_client_edge)"
  if [ "$current_edge" = "edge-1" ]; then
    failback_ok=true
    break
  fi
  if [ "$failback_sec" -ge 360 ]; then
    break
  fi
  sleep 2
done

if [ "$failback_ok" = true ]; then
  ok "fail-back to edge-1 detected in ${failback_sec}s"
else
  ko "client did not fail back to edge-1 within 360s (elapsed ${failback_sec}s, last edge: '$current_edge')"
fi

# Print measured fail-back seconds
printf 'fail-back measured: %d seconds\n' "$failback_sec"

# Verify traffic works through edge-1 after fail-back
test_traffic "edge-1 after fail-back"

# 5. Summary line and exit
echo
printf 'failover: %d passed, %d failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
exit 0
