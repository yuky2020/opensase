#!/bin/sh
# Edge entrypoint. Runs as root with only the capabilities granted by compose
# (NET_ADMIN, NET_BIND_SERVICE, SETUID, SETGID; iptables needs no NET_RAW): installs the kernel firewall for
# the tunnel, then drops to EDGE_UID:EDGE_GID with setpriv, keeping NET_ADMIN (TUN device,
# addresses, WireGuard) and NET_BIND_SERVICE (DNS resolver on :53) as ambient capabilities.
#
# Kernel rules are defence in depth: the Edge filter (internal/edge) already enforces the
# same built-in deny and DNS-bypass rules before tenant policy (security review #3, #6).
set -eu

TUN="${EDGE_TUN:-wg0}"
WAN="${EDGE_WAN:-eth0}"
POOL="100.64.0.0/10"
EDGE_IP="100.64.0.1"
EDGE_IP6="fd7a:5a5e::1"
SYNTH="100.96.0.0/12"                  # synthetic PrivateApp addresses (ADR-0013)
ZTNA_PORT="${EDGE_ZTNA_PORT:-15001}"  # must match -ztna-listen
OCR="${EDGE_OCR:-}"                    # OCR service URL for DLP (ADR-0024); adds -ocr
ICAP="${EDGE_ICAP:-}"                  # ICAP malware service icap://host/service (issue #25); overrides clamd
CLAMD="${EDGE_CLAMD:-}"                # malware scanner host:port (ADR-0020); adds -clamd
INSPECT_PORT="${EDGE_INSPECT_PORT:-}"  # TLS inspection (ADR-0018); empty = off; adds -inspect-listen
ALLOW_PRIVATE="${EDGE_ALLOW_PRIVATE:-0}"
EDGE_UID="${EDGE_UID:-1000}"
EDGE_GID="${EDGE_GID:-1000}"

log() { echo "edge-entrypoint: $*" >&2; }

# Kubernetes has no device mapping: create the TUN device node if the runtime did not
# provide one (needs CAP_MKNOD; the device cgroup of common runtimes allows 10:200).
if [ ! -c /dev/net/tun ]; then
  mkdir -p /dev/net
  if mknod /dev/net/tun c 10 200 2>/dev/null; then
    chmod 0666 /dev/net/tun
    log "created /dev/net/tun"
  else
    log "no /dev/net/tun and mknod failed: map the device or grant CAP_MKNOD"
  fi
fi

# chain IPT NAME: create or flush a custom chain.
chain() { "$1" -N "$2" 2>/dev/null || "$1" -F "$2"; }
# hook IPT PARENT ARGS...: jump from a built-in chain once.
hook() { ipt="$1"; shift; "$ipt" -C "$@" 2>/dev/null || "$ipt" -A "$@"; }

# --- IPv4 ---
iptables -t nat -C POSTROUTING -s "$POOL" -o "$WAN" -j MASQUERADE 2>/dev/null ||
  iptables -t nat -A POSTROUTING -s "$POOL" -o "$WAN" -j MASQUERADE
# Routed Workload Gateway subnets (issue #21, slice B) are private IPv4 ranges only (the
# Control Plane refuses others); their traffic leaves masqueraded like the tunnel pool.
# WireGuard accepts from each peer only the sources in its allowed IPs, so a peer cannot use
# another peer's subnet.
ROUTED="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
for net in $ROUTED; do
  iptables -t nat -C POSTROUTING -s "$net" -o "$WAN" -j MASQUERADE 2>/dev/null ||
    iptables -t nat -A POSTROUTING -s "$net" -o "$WAN" -j MASQUERADE
done
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null ||
  iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# ZTNA (ADR-0013): tunnel TCP to synthetic addresses goes to the broker listener. The Edge
# process checks the same rule at startup (internal/edge redirectZTNA).
iptables -t nat -C PREROUTING -i "$TUN" -d "$SYNTH" -p tcp -j REDIRECT --to-ports "$ZTNA_PORT" 2>/dev/null ||
  iptables -t nat -A PREROUTING -i "$TUN" -d "$SYNTH" -p tcp -j REDIRECT --to-ports "$ZTNA_PORT"

# TLS inspection (ADR-0018, issue #22): tunnel TCP to ports 80/443 jumps to OSASE_INSPECT,
# where the Edge keeps one REDIRECT rule per device whose policy needs inspection. After the
# ZTNA rule, and synthetic addresses are excluded anyway.
if [ -n "$INSPECT_PORT" ]; then
  iptables -t nat -N OSASE_INSPECT 2>/dev/null || iptables -t nat -F OSASE_INSPECT
  # Drop the blanket rule of older versions.
  while iptables -t nat -D PREROUTING -i "$TUN" ! -d "$SYNTH" -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports "$INSPECT_PORT" 2>/dev/null; do :; done
  iptables -t nat -C PREROUTING -i "$TUN" ! -d "$SYNTH" -p tcp -m multiport --dports 80,443 -j OSASE_INSPECT 2>/dev/null ||
    iptables -t nat -A PREROUTING -i "$TUN" ! -d "$SYNTH" -p tcp -m multiport --dports 80,443 -j OSASE_INSPECT
fi

# FORWARD: default drop, explicit accepts.
iptables -P FORWARD DROP
chain iptables OSASE_FWD
hook iptables FORWARD -j OSASE_FWD
iptables -A OSASE_FWD -i "$WAN" -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
for net in 169.254.0.0/16 127.0.0.0/8 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4; do
  iptables -A OSASE_FWD -i "$TUN" -d "$net" -j DROP
done
if [ "$ALLOW_PRIVATE" != 1 ]; then
  for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 198.18.0.0/15; do
    iptables -A OSASE_FWD -i "$TUN" -d "$net" -j DROP
  done
fi
# DNS only through the Edge resolver (INPUT): no third-party DNS or DoT.
for p in udp tcp; do
  iptables -A OSASE_FWD -i "$TUN" -p "$p" --dport 53 -j DROP
  iptables -A OSASE_FWD -i "$TUN" -p "$p" --dport 853 -j DROP
done
iptables -A OSASE_FWD -i "$TUN" -o "$WAN" -s "$POOL" -j ACCEPT
for net in $ROUTED; do
  iptables -A OSASE_FWD -i "$TUN" -o "$WAN" -s "$net" -j ACCEPT
done

# INPUT from the tunnel: only DNS and ping to the Edge tunnel address.
chain iptables OSASE_IN
hook iptables INPUT -i "$TUN" -j OSASE_IN
iptables -A OSASE_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A OSASE_IN -d "$EDGE_IP" -p udp --dport 53 -j ACCEPT
iptables -A OSASE_IN -d "$EDGE_IP" -p tcp --dport 53 -j ACCEPT
iptables -A OSASE_IN -d "$EDGE_IP" -p icmp -j ACCEPT
# Only connections REDIRECTed from the synthetic prefix reach the broker port, never direct ones.
iptables -A OSASE_IN -p tcp --dport "$ZTNA_PORT" -m conntrack --ctstate DNAT --ctorigdst "$SYNTH" -j ACCEPT
if [ -n "$INSPECT_PORT" ]; then
  # Only connections REDIRECTed from ports 80/443, never direct ones to the listener.
  iptables -A OSASE_IN -p tcp --dport "$INSPECT_PORT" -m conntrack --ctstate DNAT --ctorigdstport 80 -j ACCEPT
  iptables -A OSASE_IN -p tcp --dport "$INSPECT_PORT" -m conntrack --ctstate DNAT --ctorigdstport 443 -j ACCEPT
fi
iptables -A OSASE_IN -j DROP

# --- IPv6 (no IPv6 NAT in dev: nothing is forwarded) ---
if ip6tables -L -n >/dev/null 2>&1; then
  ip6tables -P FORWARD DROP
  chain ip6tables OSASE_IN6
  hook ip6tables INPUT -i "$TUN" -j OSASE_IN6
  ip6tables -A OSASE_IN6 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ip6tables -A OSASE_IN6 -d "$EDGE_IP6" -p udp --dport 53 -j ACCEPT
  ip6tables -A OSASE_IN6 -d "$EDGE_IP6" -p tcp --dport 53 -j ACCEPT
  ip6tables -A OSASE_IN6 -d "$EDGE_IP6" -p ipv6-icmp -j ACCEPT
  ip6tables -A OSASE_IN6 -j DROP
else
  log "ip6tables unavailable; IPv6 kernel rules skipped"
fi

log "NAT $POOL -> $WAN, FORWARD default DROP, tunnel INPUT limited to DNS/ICMP and ZTNA $SYNTH -> :$ZTNA_PORT, inspection :${INSPECT_PORT:-off} (allow-private=$ALLOW_PRIVATE)"

set -- /usr/local/bin/edge "$@"
if [ "$ALLOW_PRIVATE" = 1 ]; then
  set -- "$@" -allow-private
fi
if [ -n "$INSPECT_PORT" ]; then
  set -- "$@" -inspect-listen "0.0.0.0:$INSPECT_PORT"
fi
if [ -n "$CLAMD" ]; then
  set -- "$@" -clamd "$CLAMD"
fi
if [ -n "$ICAP" ]; then
  set -- "$@" -icap "$ICAP"
fi
if [ -n "$OCR" ]; then
  set -- "$@" -ocr "$OCR"
fi

if [ "$EDGE_UID" = 0 ]; then
  log "EDGE_UID=0: running the edge as root (not recommended)"
  exec "$@"
fi
log "dropping to uid $EDGE_UID gid $EDGE_GID with ambient NET_ADMIN, NET_BIND_SERVICE"
exec setpriv --reuid="$EDGE_UID" --regid="$EDGE_GID" --clear-groups \
  --inh-caps=-all,+net_admin,+net_bind_service \
  --ambient-caps=-all,+net_admin,+net_bind_service \
  -- "$@"
