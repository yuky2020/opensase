#!/bin/sh
# End-to-end test of the dev stack (run bootstrap.sh first). Starts the headless Linux
# client container, enrolls it, brings up the PQ WireGuard tunnel and checks:
#   1. HTTPS to the internet works through the Edge (NAT),
#   2. a blocklisted domain fails DNS at the Edge resolver,
#   3. TCP port 25 is blocked,
#   4. flows show up in `opensasectl flows` (device and edge records),
#   5. Edge built-in rules: no cloud metadata, no third-party DNS, no DoT (review #3, #6),
#   6. the client renewed its certificate (-renew-now, POST /v1/renew, review #4),
#   7. deployment hardening: Edge runs unprivileged and only sees pki/edge; the Control
#      Plane never mounts Edge keys (review #2),
#   8. ZTNA (ADR-0013): intranet.acme.internal resolves to a synthetic address and is served
#      through the Connector from the corp network, which the Edge cannot reach; a port
#      outside the app fails; after `opensasectl connector revoke` access fails within ~20s.
#      Destructive: the connector stays revoked (re-run bootstrap.sh to add a new one).
#  10. Workload Gateway (ADR-0015): a workload on an internal subnet, with no Client, reaches the
#      internet and the private app only through the gateway; policy and DNS policy apply;
#      forwarded traffic cannot bypass the tunnel.
#  11. Web and SaaS control (ADR-0017): a blocked SaaS app fails DNS, and connecting to it by
#      address (curl --connect-to, no DNS) is reset by the Edge on its TLS SNI, while the
#      same request naming the address's own host completes.
#  12. TLS inspection (ADR-0018): with web.inspect on, HTTPS is served with a certificate from
#      the tenant's inspection root (trusted only with that root), a URL rule blocks one path
#      with 403, a DLP rule refuses an upload with a card number (ADR-0019), the EICAR test
#      file is refused by the ClamAV scan (ADR-0020), a bypassed
#      domain keeps the server's own certificate; then the example
#      policy is restored.
#  13. Web categories (ADR-0022): with "gambling" blocked, a UT1 gambling domain fails DNS at
#      the Edge and is reset by SNI; the block is recorded; then the policy is restored.
#   9. Private Edge offline operation (ADR-0014): with the Control Plane stopped, the Edge
#      restarts from its state cache, the client reconnects, policy is still enforced, and
#      flows land in the Edge's local flow log.
set -eu
cd "$(dirname "$0")"
[ -f .env ] || { echo "e2e: run ./bootstrap.sh first" >&2; exit 1; }
TENANT="${TENANT:-acme}"
TUN="${CLIENT_TUN:-osase0}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
ctl() { docker compose run --rm --no-deps -T ctl "$@"; }
cexec() { docker compose --profile e2e exec -T client "$@"; }

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
ko() { FAIL=$((FAIL + 1)); printf '\033[1;31mFAIL\033[0m %s\n' "$*"; }

log "building and starting a fresh client (new enrollment)"
docker compose --profile e2e build client
docker compose --profile e2e rm -sf client >/dev/null 2>&1 || true
docker volume rm opensase_clientstate >/dev/null 2>&1 || true
docker compose --profile e2e up -d client
# Malware scanner (ADR-0020): it loads its signatures while the other sections run.
docker compose --profile av up -d clamav >/dev/null 2>&1 || true
docker compose --profile av up -d --build ocr >/dev/null 2>&1 || true

log "waiting for the tunnel address on $TUN"
i=0
until cexec ip -4 addr show "$TUN" 2>/dev/null | grep -q 'inet 100\.'; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then
    ko "tunnel did not come up within 60s"
    docker compose --profile e2e logs --tail 80 client edge >&2
    exit 1
  fi
  sleep 1
done
ok "tunnel up: $(cexec ip -4 -o addr show "$TUN" | awk '{print $4}')"
cexec sh -c 'grep -q "^nameserver 100.64.0.1" /etc/resolv.conf || echo "nameserver 100.64.0.1" >/etc/resolv.conf'

if cexec ip route get 1.1.1.1 | grep -q "dev $TUN"; then ok "internet routes via $TUN"; else ko "internet not routed via $TUN: $(cexec ip route get 1.1.1.1)"; fi

# 1. HTTPS through the Edge. Retry: the first SYN of a new flow can race the first handshake.
code=""
for _ in 1 2 3 4 5; do
  code="$(cexec curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com 2>&1)" && break
  sleep 2
done
case "$code" in
  2??|3??) ok "curl https://example.com -> HTTP $code" ;;
  *) ko "curl https://example.com: $code" ;;
esac

# 2. DNS policy: blocklisted names fail, other names resolve (Edge resolver and system resolver).
if cexec dig +time=5 +tries=1 @100.64.0.1 ads.doubleclick.net A | grep -q 'status: NXDOMAIN'; then
  ok "Edge resolver: ads.doubleclick.net -> NXDOMAIN"
else
  ko "Edge resolver did not block ads.doubleclick.net: $(cexec dig +time=5 +tries=1 @100.64.0.1 ads.doubleclick.net A 2>&1 | grep -E 'status|ANSWER' | head -2)"
fi
if out="$(cexec nslookup ads.doubleclick.net 2>&1)"; then
  ko "system resolver resolved ads.doubleclick.net: $out"
else
  ok "system resolver: ads.doubleclick.net fails"
fi
if [ -n "$(cexec dig +short +time=5 +tries=1 @100.64.0.1 example.com A 2>/dev/null)" ]; then
  ok "Edge resolver: example.com resolves"
else
  ko "Edge resolver failed for example.com"
fi

# 3. Port 25 is blocked (RST from the client firewall or the Edge).
if out="$(cexec nc -z -w 5 smtp.gmail.com 25 2>&1)"; then
  ko "TCP 25 to smtp.gmail.com connected: $out"
else
  ok "TCP 25 blocked ($out)"
fi
# Control: another port to the same host works, so the failure above is policy.
if cexec nc -z -w 5 smtp.gmail.com 587 >/dev/null 2>&1; then ok "control: TCP 587 to smtp.gmail.com connects"; else ko "control: TCP 587 to smtp.gmail.com failed"; fi

# 5. Built-in Edge rules (before any policy; the client firewall may block some first).
if out="$(cexec curl -sS -m 5 -o /dev/null http://169.254.169.254/latest/meta-data/ 2>&1)"; then
  ko "cloud metadata 169.254.169.254 reachable: $out"
else
  ok "cloud metadata 169.254.169.254 unreachable"
fi
if [ -n "$(cexec dig +short +time=3 +tries=1 @8.8.8.8 example.com A 2>/dev/null | grep -E '^[0-9.]+$')" ]; then
  ko "third-party DNS (dig @8.8.8.8) answered"
else
  ok "third-party DNS (dig @8.8.8.8 example.com) fails"
fi
if out="$(cexec nc -z -w 5 1.1.1.1 853 2>&1)"; then
  ko "DoT to 1.1.1.1:853 connected: $out"
else
  ok "DoT to 1.1.1.1:853 blocked"
fi

# 10. Workload Gateway (ADR-0015).
wexec() { docker compose --profile e2e exec -T workload "$@"; }
log "workload gateway: starting the gateway and a workload on the vpc subnet"
docker compose --profile e2e rm -sf gateway workload >/dev/null 2>&1 || true
docker volume rm opensase_gatewaystate >/dev/null 2>&1 || true
docker compose --profile e2e up -d gateway workload >/dev/null 2>&1
i=0
until docker compose --profile e2e logs gateway 2>/dev/null | grep -q 'workload gateway active'; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then break; fi
  sleep 1
done
if [ "$i" -lt 60 ]; then ok "gateway tunnel up and forwarding 10.30.0.0/24"; else ko "gateway not active"; docker compose --profile e2e logs --tail 30 gateway >&2; fi
wexec sh -c 'ip route replace default via 10.30.0.2 && echo "nameserver 1.1.1.1" >/etc/resolv.conf'
code=""
for _ in 1 2 3 4 5; do
  code="$(wexec curl -sS -m 15 -o /dev/null -w '%{http_code}' https://example.com 2>/dev/null)" && break
  sleep 2
done
case "$code" in
  2??|3??) ok "workload: curl https://example.com -> HTTP $code through the gateway" ;;
  *) ko "workload: HTTPS through the gateway failed: $code" ;;
esac
# DNS to 1.1.1.1 is diverted to the Edge resolver: DNS policy applies to the workload.
if wexec dig +short +time=3 +tries=1 ads.doubleclick.net | grep -q .; then ko "workload: blocklisted name resolved"; else ok "workload: ads.doubleclick.net blocked (DNS diverted to the Edge)"; fi
if wexec nc -z -w 5 smtp.gmail.com 25 >/dev/null 2>&1; then ko "workload: TCP 25 connected"; else ok "workload: TCP 25 blocked"; fi
i=0
until body="$(wexec wget -qO- -T 5 http://intranet.acme.internal/ 2>/dev/null)" && echo "$body" | grep -q 'hello from intranet'; do
  i=$((i + 1))
  [ "$i" -ge 10 ] && break
  sleep 2
done
if echo "${body:-}" | grep -q 'hello from intranet'; then ok "workload: private app via gateway + connector (ZTNA)"; else ko "workload: private app unreachable"; fi
# Fail closed: the Control Plane is reachable from the gateway outside the tunnel (bypass
# route), but forwarded workload traffic may only leave through the tunnel.
cpip="$(docker compose --profile e2e exec -T gateway getent hosts controlplane | awk '{print $1; exit}')"
if [ -n "$cpip" ] && wexec nc -z -w 4 "$cpip" 9443 >/dev/null 2>&1; then ko "workload reached $cpip outside the tunnel"; else ok "workload cannot bypass the tunnel (direct $cpip:9443 dropped)"; fi
docker compose --profile e2e rm -sf gateway workload >/dev/null 2>&1 || true

# 8. ZTNA private access through the Connector (ADR-0013).
log "ZTNA: waiting for the Connector broker link"
i=0
until docker compose logs connector 2>/dev/null | grep -q '"broker link up"'; do
  i=$((i + 1))
  if [ "$i" -ge 40 ]; then
    ko "connector: no broker link within 40s"
    docker compose logs --tail 30 connector >&2 || true
    break
  fi
  sleep 1
done
[ "$i" -lt 40 ] && ok "connector: PQ broker link to the Edge is up"
synth="$(cexec dig +short +time=5 +tries=1 @100.64.0.1 intranet.acme.internal A 2>/dev/null | head -1)"
case "$synth" in
  100.9[6-9].* | 100.10[0-9].* | 100.11[01].*) ok "intranet.acme.internal -> synthetic $synth (100.96.0.0/12)" ;;
  *) ko "intranet.acme.internal did not resolve to a synthetic address: '$synth'" ;;
esac
aaaa="$(cexec dig +time=5 +tries=1 @100.64.0.1 intranet.acme.internal AAAA 2>/dev/null)"
if echo "$aaaa" | grep -q 'status: NOERROR' && echo "$aaaa" | grep -q 'ANSWER: 0'; then
  ok "intranet.acme.internal AAAA -> empty NOERROR"
else
  ko "AAAA for the private app: $(echo "$aaaa" | grep -E 'status|ANSWER' | head -2)"
fi
if docker compose exec -T edge wget -qO- -T 3 http://intranet.acme.internal/ >/dev/null 2>&1; then
  ko "the Edge itself reaches the intranet (corp must be isolated)"
else
  ok "the Edge cannot reach the intranet directly (only the connector can)"
fi
body=""
for _ in 1 2 3 4 5; do
  body="$(cexec wget -qO- -T 10 http://intranet.acme.internal/ 2>&1)" && break
  sleep 2
done
if [ "$body" = "hello from intranet" ]; then
  ok "wget http://intranet.acme.internal/ -> '$body' (via connector)"
else
  ko "wget http://intranet.acme.internal/: $body"
fi
if out="$(cexec wget -qO- -T 5 http://intranet.acme.internal:81/ 2>&1)"; then
  ko "port 81 (not in the app) reachable: $out"
else
  ok "port 81 not in the app: refused"
fi
i=0
while :; do
  flows="$(ctl flows -tenant "$TENANT" -limit 500 -json 2>/dev/null || true)"
  echo "$flows" | grep -q '"ruleId": "ztna:intranet"' && break
  i=$((i + 1))
  [ "$i" -ge 10 ] && break
  sleep 3
done
if echo "$flows" | grep -q '"ruleId": "ztna:intranet"'; then ok "ztna flow recorded (layer ztna, rule ztna:intranet)"; else ko "no ztna:intranet flow record"; fi

CID="$(sed -n 's/.*"connectorId": *"\([^"]*\)".*/\1/p' connector-state/connector.json 2>/dev/null)"
if [ -z "$CID" ]; then
  ko "no enrolled connector id in connector-state/connector.json"
else
  log "ZTNA: revoking connector $CID"
  if ctl connector revoke -tenant "$TENANT" -id "$CID"; then
    i=0
    while cexec wget -qO- -T 3 http://intranet.acme.internal/ >/dev/null 2>&1; do
      i=$((i + 1))
      [ "$i" -ge 20 ] && break
      sleep 1
    done
    if [ "$i" -lt 20 ]; then ok "access fails ${i}s after connector revoke"; else ko "private app still reachable 20s after revoke"; fi
  else
    ko "opensasectl connector revoke failed"
  fi
  # The revoked identity is useless: drop it so bootstrap.sh adds a fresh connector.
  docker compose stop connector >/dev/null 2>&1 || true
  rm -f connector-state/connector.json connector-state/connector.pem connector-state/root.pem
fi

# 6. Certificate renewal at startup (-renew-now).
if docker compose logs controlplane 2>/dev/null | grep -q '"device certificate renewed"'; then
  ok "device certificate renewed via POST /v1/renew"
else
  ko "no certificate renewal logged by the Control Plane"
fi

# 7. Deployment hardening.
uid="$(docker compose exec -T edge awk '/^Uid:/ {print $2}' /proc/1/status 2>/dev/null || true)"
if [ -n "$uid" ] && [ "$uid" != 0 ]; then ok "edge runs as uid $uid"; else ko "edge runs as root (uid '$uid')"; fi
# As the Edge user: the 0700 directory is not readable by the capability-less container root.
files="$(docker compose exec -T -u "$(id -u):$(id -g)" edge ls /pki 2>/dev/null | tr '\n' ' ')"
if [ "$files" = "edge-wg.key edge.crt edge.key root.crt " ]; then ok "edge sees only its PKI files"; else ko "edge /pki: $files"; fi
# The Control Plane needs root.key, tenant CA keys and snapshot.key, but never the Edge keys:
# neither the whole pki directory nor pki/edge (or anything in it) may be mounted.
bad=""
for src in $(docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$(docker compose ps -q controlplane)"); do
  case "$src" in
    */pki | */pki/ | */pki/edge | */pki/edge/*) bad="$bad $src" ;;
  esac
done
if [ -z "$bad" ]; then ok "control plane does not mount edge keys (pki/edge)"; else ko "control plane mounts edge material:$bad"; fi

# 11. Web and SaaS control (ADR-0017). pastebin is blocked by the example policy's SaaS section.
if out="$(cexec nslookup pastebin.com 2>&1)"; then
  ko "blocked SaaS app pastebin.com resolved: $out"
else
  ok "SaaS block: pastebin.com fails DNS"
fi
# Bypass DNS: connect to example.com's address but name pastebin.com in the SNI. -k so that a
# certificate mismatch is not mistaken for the block: only an Edge reset gives HTTP 000.
sni_code() { cexec curl -sk -m 15 -o /dev/null -w '%{http_code}' --connect-to "$1:443:example.com:443" "https://$1/" 2>/dev/null || true; }
code="$(sni_code pastebin.com)"
if [ "$code" = 000 ]; then ok "SaaS block by SNI: TLS to pastebin.com over example.com's address reset"; else ko "SNI pastebin.com not blocked: HTTP $code"; fi
code="$(sni_code example.com)"
case "$code" in
  000) ko "control: the same request shape with SNI example.com failed" ;;
  *) ok "control: same request shape with SNI example.com completes (HTTP $code)" ;;
esac

# 12. TLS inspection (ADR-0018): turn it on for the tenant, with one URL rule and one bypass.
log "inspection: enabling web.inspect for $TENANT"
ctl inspection-ca -tenant "$TENANT" >.e2e-inspect.crt
cexec sh -c 'cat >/tmp/inspect.crt' <.e2e-inspect.crt
jq '.web = {inspect: true, bypass: ["example.org"], rules: [{id: "e2e-no-blocked", domains: ["example.com"], pathPrefixes: ["/blocked"], action: "block"}], dlp: [{id: "e2e-pci", detectors: ["credit-card"], action: "block"}], malware: {uploads: true, downloads: true}}' \
  policy.example.json >.e2e-policy-web.json
ctl policy set -tenant "$TENANT" -f /work/.e2e-policy-web.json
issuer=""
i=0
while :; do
  issuer="$(cexec curl -sv -m 15 --cacert /tmp/inspect.crt -o /dev/null https://example.com/ 2>&1 | sed -n 's/.*issuer: *//p' | head -1)"
  case "$issuer" in *"web inspection $TENANT"*) break ;; esac
  i=$((i + 1))
  [ "$i" -ge 15 ] && break
  sleep 2
done
case "$issuer" in
  *"web inspection $TENANT"*) ok "inspected: example.com served by the Edge with the tenant inspection root ($issuer)" ;;
  *) ko "example.com not inspected (issuer '$issuer')" ;;
esac
code="$(cexec curl -s -m 15 --cacert /tmp/inspect.crt -o /dev/null -w '%{http_code}' https://example.com/ 2>/dev/null || true)"
case "$code" in 2??|3??|404) ok "inspected request proxied to the real server (HTTP $code)" ;; *) ko "inspected request: HTTP $code" ;; esac
# HTTP/2 on the inspected path (ADR-0023): negotiated with the device, rules still apply.
v="$(cexec curl -s -m 15 --http2 --cacert /tmp/inspect.crt -o /dev/null -w '%{http_version} %{http_code}' https://example.com/ 2>/dev/null || true)"
case "$v" in "2 "2??|"2 "3??) ok "inspected HTTP/2: $v" ;; *) ko "inspected HTTP/2 not negotiated: '$v'" ;; esac
v="$(cexec curl -s -m 15 --http2 --cacert /tmp/inspect.crt -o /dev/null -w '%{http_version} %{http_code}' https://example.com/blocked 2>/dev/null || true)"
if [ "$v" = "2 403" ]; then ok "URL rule over HTTP/2: 403"; else ko "URL rule over HTTP/2: '$v'"; fi
code="$(cexec curl -s -m 15 --cacert /tmp/inspect.crt -o /dev/null -w '%{http_code}' https://example.com/x/../Blocked/page 2>/dev/null || true)"
if [ "$code" = 403 ]; then ok "URL rule: /blocked (normalized, any case) refused with 403"; else ko "URL rule not applied: HTTP $code"; fi
if cexec curl -s -m 15 -o /dev/null https://example.com/ 2>/dev/null; then
  ko "interception certificate accepted without the inspection root"
else
  ok "without the inspection root the device refuses the interception certificate"
fi
issuer="$(cexec curl -sv -m 15 -o /dev/null https://example.org/ 2>&1 | sed -n 's/.*issuer: *//p' | head -1)"
case "$issuer" in
  "") ko "bypassed example.org failed" ;;
  *"web inspection"*) ko "bypassed example.org was intercepted" ;;
  *) ok "bypass: example.org keeps its own certificate ($issuer)" ;;
esac
# DLP (ADR-0019): an upload with a card number is refused, a clean one reaches the server.
code="$(cexec curl -s -m 15 --cacert /tmp/inspect.crt -o /dev/null -w '%{http_code}' --data 'note=pay with 4111 1111 1111 1111' https://example.com/ 2>/dev/null || true)"
if [ "$code" = 403 ]; then ok "DLP: upload with a card number refused with 403"; else ko "DLP card upload: HTTP $code"; fi
code="$(cexec curl -s -m 15 --cacert /tmp/inspect.crt -o /dev/null -w '%{http_code}' --data 'note=hello' https://example.com/ 2>/dev/null || true)"
case "$code" in 000 | 403) ko "DLP: clean upload refused or failed (HTTP $code)" ;; *) ok "DLP: clean upload reaches the server (HTTP $code)" ;; esac
# DLP on images and legacy Office (ADR-0024): the card number drawn in a PNG (read by the OCR
# service) and stored in a legacy .doc.
for f in card.png card.doc; do
  docker compose --profile e2e cp "../../test/security/fixtures/$f" "client:/tmp/$f" >/dev/null 2>&1
  out="$(cexec curl -s -m 60 --cacert /tmp/inspect.crt -F "file=@/tmp/$f" https://example.com/ 2>/dev/null || true)"
  case "$out" in *"rule dlp:e2e-pci)"*) ok "DLP: $f with a card number refused (text read, not unscanned)" ;; *) ko "DLP: $f not refused by dlp:e2e-pci" ;; esac
done
# Malware (ADR-0020): the EICAR test file, assembled here, is refused as an upload.
i=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose --profile av ps -q clamav)" 2>/dev/null)" = healthy ]; do
  i=$((i + 1))
  [ "$i" -ge 60 ] && break
  sleep 5
done
if [ "$i" -ge 60 ]; then
  ko "malware: clamav not healthy within 5 minutes"
else
  eicar='X5O!P%@AP[4\PZX54(P^)7CC)7}$'"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*"
  code="$(cexec curl -s -m 30 --cacert /tmp/inspect.crt -o /dev/null -w '%{http_code}' --data-binary "$eicar" https://example.com/ 2>/dev/null || true)"
  if [ "$code" = 403 ]; then ok "malware: EICAR upload refused by the ClamAV scan"; else ko "malware: EICAR upload: HTTP $code"; fi
fi
i=0
while :; do
  f="$(ctl flows -tenant "$TENANT" -limit 500 -json 2>/dev/null || true)"
  echo "$f" | grep -q '"ruleId": "url:e2e-no-blocked"' && echo "$f" | grep -q '"ruleId": "dlp:e2e-pci"' && break
  i=$((i + 1))
  [ "$i" -ge 10 ] && break
  sleep 3
done
if [ "$i" -lt 10 ]; then ok "URL and DLP blocks recorded (rules url:e2e-no-blocked, dlp:e2e-pci)"; else ko "no url:e2e-no-blocked or dlp:e2e-pci flow record"; fi
ctl policy set -tenant "$TENANT" -f /work/policy.example.json
rm -f .e2e-policy-web.json .e2e-inspect.crt
# Wait until the Edge enforces the restored policy (and caches it, for the offline section):
# example.com verifies again with the system roots.
i=0
until cexec curl -s -m 10 -o /dev/null https://example.com/ 2>/dev/null; do
  i=$((i + 1))
  [ "$i" -ge 20 ] && break
  sleep 2
done
if [ "$i" -lt 20 ]; then ok "inspection off again after the policy is restored"; else ko "inspection still on 40s after the policy was restored"; fi
sleep 2 # the state cache is written right after the sync

# 13. Web categories (ADR-0022): the UT1 list on the Control Plane, "gambling" blocked.
log "categories: waiting for the Control Plane's category list"
i=0
until ctl categories -json 2>/dev/null | grep -q '"version": "[0-9a-f]'; do
  i=$((i + 1))
  [ "$i" -ge 60 ] && break
  sleep 5
done
if [ "$i" -ge 60 ]; then
  ko "categories: no list loaded on the Control Plane within 5 minutes"
else
  ok "categories: $(ctl categories 2>/dev/null | head -1)"
  jq '.categories = ["gambling"]' policy.example.json >.e2e-policy-cat.json
  ctl policy set -tenant "$TENANT" -f /work/.e2e-policy-cat.json
  i=0
  until cexec dig +time=3 +tries=1 @100.64.0.1 www.0-casino.info A 2>/dev/null | grep -q 'status: NXDOMAIN'; do
    i=$((i + 1))
    [ "$i" -ge 30 ] && break
    sleep 2
  done
  if [ "$i" -lt 30 ]; then ok "categories: www.0-casino.info (UT1 gambling) -> NXDOMAIN at the Edge resolver"; else ko "categories: gambling name not blocked by DNS"; fi
  code="$(sni_code 0-casino.info)"
  if [ "$code" = 000 ]; then ok "categories: TLS to 0-casino.info over example.com's address reset (SNI)"; else ko "categories: SNI not blocked: HTTP $code"; fi
  if cexec dig +time=3 +tries=1 @100.64.0.1 example.com A 2>/dev/null | grep -q 'status: NOERROR'; then ok "categories: control example.com resolves"; else ko "categories: control example.com does not resolve"; fi
  i=0
  until ctl flows -tenant "$TENANT" -limit 500 -json 2>/dev/null | grep -q '"ruleId": "cat:gambling"'; do
    i=$((i + 1))
    [ "$i" -ge 10 ] && break
    sleep 3
  done
  if [ "$i" -lt 10 ]; then ok "categories: blocks recorded (rule cat:gambling)"; else ko "categories: no cat:gambling flow record"; fi
  ctl policy set -tenant "$TENANT" -f /work/policy.example.json
  rm -f .e2e-policy-cat.json
fi

# 4. Flows: device records, Edge records and the port-25 block. Edge flows are reported when
# they close (plus a few seconds of batching), so poll.
log "waiting for flow records"
i=0
while :; do
  flows="$(ctl flows -tenant "$TENANT" -limit 500 -json 2>/dev/null || true)"
  has_edge=no; has_dev=no; has_smtp=no; has_builtin=no; has_saas=no
  echo "$flows" | grep -q '"ruleId": "saas:pastebin"' && has_saas=yes
  echo "$flows" | grep -q '"ruleId": "builtin-' && has_builtin=yes
  echo "$flows" | grep -q '"where": "edge"' && has_edge=yes
  echo "$flows" | grep -q '"where": "device"' && has_dev=yes
  echo "$flows" | grep -q '"ruleId": "block-smtp"' && has_smtp=yes
  [ "$has_edge$has_dev$has_smtp$has_saas" = yesyesyesyes ] && break
  i=$((i + 1))
  [ "$i" -ge 20 ] && break
  sleep 3
done
[ "$has_edge" = yes ] && ok "edge flow records present" || ko "no edge flow records"
[ "$has_dev" = yes ] && ok "device flow records present" || ko "no device flow records"
[ "$has_smtp" = yes ] && ok "port 25 block recorded (rule block-smtp)" || ko "no block-smtp flow record"
[ "$has_saas" = yes ] && ok "SNI block recorded (layer web, rule saas:pastebin)" || ko "no saas:pastebin web record"
# Informational: the client firewall may already block these before they reach the Edge.
[ "$has_builtin" = yes ] && echo "info: Edge builtin-deny / builtin-dns-bypass records present" || echo "info: no Edge builtin-* records (blocked on the device first?)"
ctl flows -tenant "$TENANT" -limit 15 || true

# 9. Private Edge offline operation (ADR-0014). Last: it stops the Control Plane.
log "offline: stopping the control plane and restarting the edge from its state cache"
docker compose stop controlplane >/dev/null 2>&1
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker compose restart edge >/dev/null 2>&1
i=0
until docker compose logs --since "$since" edge 2>/dev/null | grep -q '"msg":"edge ready"'; do
  i=$((i + 1))
  [ "$i" -ge 30 ] && break
  sleep 1
done
if docker compose logs --since "$since" edge 2>/dev/null | grep -q 'enforcing cached state'; then
  ok "edge started from its state cache with the control plane down"
else
  ko "edge did not start from its state cache"
  docker compose logs --tail 20 edge >&2
fi
# The restarted Edge has no WireGuard peers: restart the client to set up a new session
# (otherwise it notices the stale handshake within its 3-minute liveness timeout).
docker compose --profile e2e restart client >/dev/null 2>&1
i=0
until cexec ip -4 addr show "$TUN" 2>/dev/null | grep -q 'inet 100\.'; do
  i=$((i + 1))
  [ "$i" -ge 60 ] && break
  sleep 1
done
cexec sh -c 'grep -q "^nameserver 100.64.0.1" /etc/resolv.conf || echo "nameserver 100.64.0.1" >/etc/resolv.conf' || true
code=""
for _ in 1 2 3 4 5 6; do
  code="$(cexec curl -sS -m 15 -o /dev/null -w '%{http_code}' https://example.com 2>/dev/null)" && break
  sleep 3
done
case "$code" in
  2??|3??) ok "offline: curl https://example.com -> HTTP $code via the cached edge" ;;
  *) ko "offline: HTTPS through the edge failed: $code"; docker compose --profile e2e logs --tail 30 client edge >&2 ;;
esac
if cexec nc -z -w 5 smtp.gmail.com 25 >/dev/null 2>&1; then ko "offline: TCP 25 connected (policy lost)"; else ok "offline: TCP 25 still blocked"; fi
i=0
until [ -s edge-state/flows.jsonl ] && grep -q '"where":"edge"' edge-state/flows.jsonl; do
  i=$((i + 1))
  [ "$i" -ge 20 ] && break
  sleep 2
done
if [ -s edge-state/flows.jsonl ] && grep -q '"where":"edge"' edge-state/flows.jsonl; then
  ok "edge local flow log has records ($(wc -l <edge-state/flows.jsonl) lines)"
else
  ko "edge local flow log empty"
fi
log "offline: restarting the control plane"
docker compose up -d --wait controlplane >/dev/null 2>&1 || docker compose up -d controlplane >/dev/null 2>&1

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[1;32me2e: %d passed\033[0m\n' "$PASS"
else
  printf '\033[1;31me2e: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
  docker compose --profile e2e logs --tail 40 client edge >&2
  exit 1
fi
