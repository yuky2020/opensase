#!/bin/sh
# Areas 6 and 7 (black box): container privileges, capabilities and mounts (ADR-0002 /
# review #2) and the file modes of secrets, state and flow logs in deploy/dev.
set -u
. "$(dirname "$0")/lib.sh"

# insp CONTAINER FORMAT
insp() { docker inspect -f "$2" "$1" 2>/dev/null; }
# pstatus CONTAINER FIELD: a field of /proc/<pid>/status of the container's main process.
pstatus() {
  pid="$(insp "$1" '{{.State.Pid}}')"
  [ -n "$pid" ] && [ "$pid" != 0 ] && awk -v f="$2:" '$1 == f {print $2}' "/proc/$pid/status" 2>/dev/null
}
cid() { dc ps -a -q "$1" 2>/dev/null | head -1; }

CP="$(cid controlplane)"
EDGE="$(cid edge)"
CONN="$(cid connector)"
if [ -z "$CP" ] || [ -z "$EDGE" ]; then
  skip SEC-DEP-001 "containers inspected" "controlplane/edge containers not found"
  exit 0
fi

# No container is privileged, on the host network, or mounts the docker socket.
bad=""
for c in $(dc ps -a -q 2>/dev/null); do
  n="$(insp "$c" '{{.Name}}')"
  [ "$(insp "$c" '{{.HostConfig.Privileged}}')" = true ] && bad="$bad $n:privileged"
  [ "$(insp "$c" '{{.HostConfig.NetworkMode}}')" = host ] && bad="$bad $n:host-net"
  [ "$(insp "$c" '{{.HostConfig.PidMode}}')" = host ] && bad="$bad $n:host-pid"
  insp "$c" '{{range .Mounts}}{{.Source}} {{end}}' | grep -q 'docker.sock' && bad="$bad $n:docker.sock"
done
[ -z "$bad" ] && pass SEC-DEP-001 "no privileged/host-network/host-pid container, no docker.sock mount" ||
  fail SEC-DEP-001 "no privileged/host-network/host-pid container, no docker.sock mount" "$bad"

# Edge (review #2): runs as non-root with only NET_ADMIN + NET_BIND_SERVICE effective,
# cap_drop ALL, no-new-privileges, and only pki/edge mounted read-only.
uid="$(pstatus "$EDGE" Uid)"
eff="$(pstatus "$EDGE" CapEff)"
nnp="$(pstatus "$EDGE" NoNewPrivs)"
drop="$(insp "$EDGE" '{{.HostConfig.CapDrop}}')"
pkim="$(insp "$EDGE" '{{range .Mounts}}{{if eq .Destination "/pki"}}{{.Source}}:{{.RW}}{{end}}{{end}}')"
problems=""
[ -n "$uid" ] && [ "$uid" != 0 ] || problems="$problems uid=$uid"
# CapEff bits: NET_BIND_SERVICE (10) + NET_ADMIN (12) = 0x1400.
[ "$eff" = 0000000000001400 ] || problems="$problems CapEff=$eff"
[ "$nnp" = 1 ] || problems="$problems NoNewPrivs=$nnp"
case "$drop" in *ALL*) ;; *) problems="$problems cap_drop=$drop" ;; esac
case "$pkim" in */pki/edge:false) ;; *) problems="$problems pki-mount=$pkim" ;; esac
[ -z "$problems" ] && pass SEC-DEP-002 "edge: uid!=0, CapEff NET_ADMIN+NET_BIND_SERVICE only, no-new-privs, ro pki/edge" ||
  fail SEC-DEP-002 "edge: uid!=0, CapEff NET_ADMIN+NET_BIND_SERVICE only, no-new-privs, ro pki/edge" "$problems"

# Control Plane: non-root, no capabilities at all, no-new-privileges, never the Edge keys;
# CA and snapshot keys mounted read-only.
uid="$(pstatus "$CP" Uid)"
bnd="$(pstatus "$CP" CapBnd)"
nnp="$(pstatus "$CP" NoNewPrivs)"
problems=""
[ -n "$uid" ] && [ "$uid" != 0 ] || problems="$problems uid=$uid"
for m in $(insp "$CP" '{{range .Mounts}}{{.Source}}:{{.RW}} {{end}}'); do
  case "$m" in
    */pki:* | */pki/:* | */pki/edge:* | */pki/edge/*) problems="$problems mounts-edge-keys($m)" ;;
    */root.key:true | */snapshot.key:true | */controlplane.key:true) problems="$problems rw-key($m)" ;;
  esac
done
if [ -n "$problems" ]; then
  fail SEC-DEP-003 "controlplane: non-root, no Edge keys, CA/snapshot keys read-only" "$problems"
else
  pass SEC-DEP-003 "controlplane: non-root, no Edge keys, CA/snapshot keys read-only"
fi
# Least privilege beyond non-root: the CP needs no capability (it binds 9443).
if [ "$bnd" = 0000000000000000 ] && [ "$nnp" = 1 ]; then
  pass SEC-DEP-004 "controlplane: cap_drop ALL and no-new-privileges"
else
  fail SEC-DEP-004 "controlplane: cap_drop ALL and no-new-privileges" "CapBnd=$bnd NoNewPrivs=$nnp (compose sets neither)" ST-08
fi

# Connector (ADR-0013): non-root, cap_drop ALL, read-only root fs, no published port.
if [ -z "$CONN" ]; then
  skip SEC-DEP-005 "connector: non-root, cap_drop ALL, read-only rootfs, no ports" "no connector container"
else
  problems=""
  u="$(insp "$CONN" '{{.Config.User}}')"
  case "$u" in "" | 0 | 0:* | root*) problems="$problems user=$u" ;; esac
  case "$(insp "$CONN" '{{.HostConfig.CapDrop}}')" in *ALL*) ;; *) problems="$problems no-cap-drop" ;; esac
  [ "$(insp "$CONN" '{{.HostConfig.ReadonlyRootfs}}')" = true ] || problems="$problems rw-rootfs"
  [ -z "$(insp "$CONN" '{{range $p, $b := .HostConfig.PortBindings}}{{$p}} {{end}}')" ] || problems="$problems published-ports"
  insp "$CONN" '{{.HostConfig.SecurityOpt}}' | grep -q no-new-privileges || problems="$problems no-nnp"
  [ -z "$problems" ] && pass SEC-DEP-005 "connector: non-root, cap_drop ALL, read-only rootfs, no ports" ||
    fail SEC-DEP-005 "connector: non-root, cap_drop ALL, read-only rootfs, no ports" "$problems"
fi

# Secrets in deploy/dev: 0600 files, 0700 directories.
bad=""
for f in .env provisioning.key connector.key pki/root.key pki/controlplane.key pki/snapshot.key pki/edge/edge.key pki/edge/edge-wg.key; do
  [ -e "$DEV/$f" ] || continue
  m="$(mode "$DEV/$f")"
  [ "$m" = 600 ] || [ "$m" = 400 ] || bad="$bad $f=$m"
done
for d in pki/edge pki/tenants connector-state edge-state; do
  [ -e "$DEV/$d" ] || continue
  m="$(mode "$DEV/$d")"
  [ "$m" = 700 ] || bad="$bad $d/=$m"
done
for k in "$DEV"/pki/tenants/*/ca.key; do
  [ -e "$k" ] || continue
  m="$(mode "$k")"
  [ "$m" = 600 ] || bad="$bad ${k#"$DEV"/}=$m"
done
[ -z "$bad" ] && pass SEC-DEP-010 "deploy/dev secrets 0600, key/state directories 0700" ||
  fail SEC-DEP-010 "deploy/dev secrets 0600, key/state directories 0700" "$bad"

# The Control Plane database holds every tenant's flows (user browsing history), policies,
# devices and provisioning-key hashes: it must not be world-readable.
bad=""
for f in data data/controlplane.db data/controlplane.db-wal data/controlplane.db-shm; do
  [ -e "$DEV/$f" ] || continue
  m="$(mode "$DEV/$f")"
  o="${m#"${m%?}"}" # the "other" permission digit
  [ "$o" = 0 ] || bad="$bad $f=$m"
done
[ -z "$bad" ] && pass SEC-DEP-011 "Control Plane database not world-readable" ||
  fail SEC-DEP-011 "Control Plane database not world-readable" "$bad" ST-09

# Area 6: the Edge state cache and local flow log (ADR-0014) are 0600 in a 0700 directory.
bad=""
for f in edge-state/state.json edge-state/flows.jsonl edge-state/flows.jsonl.1; do
  [ -e "$DEV/$f" ] || continue
  m="$(mode "$DEV/$f")"
  [ "$m" = 600 ] || bad="$bad $f=$m"
done
if [ ! -e "$DEV/edge-state/state.json" ]; then
  skip SEC-OFF-010 "edge state.json / flows.jsonl are 0600" "no edge-state/state.json"
elif [ -z "$bad" ]; then
  pass SEC-OFF-010 "edge state.json / flows.jsonl are 0600"
else
  fail SEC-OFF-010 "edge state.json / flows.jsonl are 0600" "$bad"
fi

# Client state (device key, certificate, snapshot) inside the client container: 0600.
if running client; then
  out="$(cexec sh -c 'for f in /var/lib/opensase-client/*; do stat -c "%a %n" "$f"; done' 2>/dev/null)"
  bad="$(printf '%s\n' "$out" | awk '$1 != "600" {print $2"="$1}' | tr '\n' ' ')"
  [ -z "$bad" ] && pass SEC-OFF-011 "client state files (device key, cert, snapshot) are 0600" ||
    fail SEC-OFF-011 "client state files (device key, cert, snapshot) are 0600" "$bad"
else
  skip SEC-OFF-011 "client state files (device key, cert, snapshot) are 0600" "client not running"
fi
