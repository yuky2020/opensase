#!/bin/sh
# Area 5 (black box, through the real client container): the OpenSASE Linux client plus the
# Edge together. The Go harness (SEC-DP-0xx) attacks the Edge alone with raw packets in a
# hostile WireGuard tunnel; these checks confirm the same with the product client.
# Outbound probes go only to the e2e test hosts (example.com, smtp.gmail.com, public DNS).
set -u
. "$(dirname "$0")/lib.sh"
TUN="${CLIENT_TUN:-osase0}"

if ! running client || ! cexec ip -4 addr show "$TUN" 2>/dev/null | grep -q 'inet 100\.'; then
  skip SEC-DP-100 "client container tunnel up" "client not running or no tunnel (run deploy/dev/e2e.sh first)"
  exit 0
fi
# Control: the tunnel carries traffic and the Edge resolver answers.
if [ -z "$(cexec dig +short +time=5 +tries=1 @100.64.0.1 example.com A 2>/dev/null)" ]; then
  skip SEC-DP-100 "client container tunnel up" "Edge resolver does not answer through the tunnel"
  exit 0
fi
pass SEC-DP-100 "control: client container tunnel up, Edge resolver answers"

# Cloud metadata and link-local.
if cexec curl -sS -m 5 -o /dev/null http://169.254.169.254/latest/meta-data/ 2>/dev/null; then
  fail SEC-DP-101 "client: cloud metadata 169.254.169.254 unreachable" "HTTP answer"
else
  pass SEC-DP-101 "client: cloud metadata 169.254.169.254 unreachable"
fi

# DNS bypass: third-party resolver (udp, tcp), DoT, DoH by IP and by name.
bad=""
[ -n "$(cexec dig +short +time=3 +tries=1 @8.8.8.8 example.com A 2>/dev/null | grep -E '^[0-9.]+$')" ] && bad="$bad udp@8.8.8.8"
[ -n "$(cexec dig +tcp +short +time=3 +tries=1 @1.1.1.1 example.com A 2>/dev/null | grep -E '^[0-9.]+$')" ] && bad="$bad tcp@1.1.1.1"
cexec nc -z -w 4 1.1.1.1 853 >/dev/null 2>&1 && bad="$bad dot@1.1.1.1"
cexec curl -sS -m 6 -o /dev/null -H 'accept: application/dns-json' 'https://1.1.1.1/dns-query?name=example.com' 2>/dev/null && bad="$bad doh@1.1.1.1"
cexec curl -sS -m 6 -o /dev/null --resolve dns.google:443:8.8.8.8 'https://dns.google/resolve?name=example.com' 2>/dev/null && bad="$bad doh@dns.google"
cexec curl -sS -m 6 -o /dev/null -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name=example.com' 2>/dev/null && bad="$bad doh@cloudflare-dns.com"
[ -z "$bad" ] && pass SEC-DP-102 "client: third-party DNS, DoT and DoH blocked" ||
  fail SEC-DP-102 "client: third-party DNS, DoT and DoH blocked" "reachable:$bad"

# IPv6 leak: v6 must go into the tunnel (or nowhere), never out of the physical interface.
r6="$(cexec ip -6 route get 2001:4860:4860::8888 2>&1 || true)"
case "$r6" in
  *"dev $TUN"* | *unreachable* | *"Network is unreachable"* | *prohibit*)
    if cexec curl -6 -sS -m 6 -o /dev/null https://example.com 2>/dev/null; then
      fail SEC-DP-103 "client: no IPv6 leak outside the tunnel" "curl -6 https://example.com succeeded (route: $r6)"
    else
      pass SEC-DP-103 "client: no IPv6 leak outside the tunnel"
    fi ;;
  *) fail SEC-DP-103 "client: no IPv6 leak outside the tunnel" "v6 route bypasses $TUN: $r6" ;;
esac

# Port policy: tcp/25 blocked, 587 control.
if ! cexec nc -z -w 5 smtp.gmail.com 587 >/dev/null 2>&1; then
  skip SEC-DP-104 "client: tcp/25 blocked by tenant policy" "control smtp.gmail.com:587 failed (no internet?)"
elif cexec nc -z -w 5 smtp.gmail.com 25 >/dev/null 2>&1; then
  fail SEC-DP-104 "client: tcp/25 blocked by tenant policy" "smtp.gmail.com:25 connected"
else
  pass SEC-DP-104 "client: tcp/25 blocked by tenant policy"
fi

# ZTNA synthetic range: an address that maps to no app is refused.
if cexec nc -z -w 4 100.111.250.250 80 >/dev/null 2>&1; then
  fail SEC-DP-105 "client: ZTNA unmapped synthetic address refused" "100.111.250.250:80 connected"
else
  pass SEC-DP-105 "client: ZTNA unmapped synthetic address refused"
fi

# A port outside the private app is refused; control: the app's own port works (needs the
# Connector, so this is skipped after e2e.sh revoked it until bootstrap.sh re-adds one).
synth="$(cexec dig +short +time=4 +tries=1 @100.64.0.1 intranet.acme.internal A 2>/dev/null | head -1)"
if [ -z "$synth" ] || ! cexec wget -qO- -T 6 "http://$synth/" 2>/dev/null | grep -q .; then
  skip SEC-DP-107 "client: ZTNA port outside the app (81) refused" "control: intranet:80 not served (connector down?)"
elif cexec sh -c "printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 4 $synth 81" 2>/dev/null | grep -q .; then
  fail SEC-DP-107 "client: ZTNA port outside the app (81) refused" "$synth:81 answered"
else
  pass SEC-DP-107 "client: ZTNA port outside the app (81) refused"
fi

# The Edge's tunnel address serves only DNS/ICMP: its HTTPS and broker ports are closed.
bad=""
for p in 8443 8444 15001 15002; do cexec nc -z -w 3 100.64.0.1 "$p" >/dev/null 2>&1 && bad="$bad $p"; done
[ -z "$bad" ] && pass SEC-DP-106 "client: Edge tunnel address 100.64.0.1 exposes only DNS/ICMP" ||
  fail SEC-DP-106 "client: Edge tunnel address 100.64.0.1 exposes only DNS/ICMP" "open:$bad"

# Web and SaaS control (ADR-0017). The bootstrap policy blocks the SaaS app "pastebin"; DNS for
# it fails, so these checks try to reach it without DNS, by example.com's address, and expect
# the Edge to reset the flow on the hostname it reads from the TLS SNI or HTTP Host.
# -k: a certificate mismatch must not be mistaken for the block; only a reset gives HTTP 000.
https_via() { cexec curl -sk -m 12 -o /dev/null -w '%{http_code}' --connect-to "$1:443:example.com:443" "https://$1/" 2>/dev/null || true; }
http_host() { cexec curl -s -m 12 -o /dev/null -w '%{http_code}' -H "Host: $1" http://example.com/ 2>/dev/null || true; }
if [ "$(https_via example.com)" = 000 ]; then
  skip SEC-DP-110 "client: blocked SaaS app unreachable by address (TLS SNI)" "control: https://example.com via --connect-to failed"
else
  bad=""
  for h in pastebin.com www.pastebin.com PASTEBIN.COM; do
    c="$(https_via "$h")"
    [ "$c" = 000 ] || bad="$bad $h=$c"
  done
  [ -z "$bad" ] && pass SEC-DP-110 "client: blocked SaaS app unreachable by address (TLS SNI, subdomain, case)" ||
    fail SEC-DP-110 "client: blocked SaaS app unreachable by address (TLS SNI, subdomain, case)" "answered:$bad"
fi
if [ "$(http_host example.com)" = 000 ]; then
  skip SEC-DP-111 "client: blocked SaaS app unreachable by address (HTTP Host)" "control: http://example.com failed"
else
  c="$(http_host pastebin.com)"
  [ "$c" = 000 ] && pass SEC-DP-111 "client: blocked SaaS app unreachable by address (HTTP Host)" ||
    fail SEC-DP-111 "client: blocked SaaS app unreachable by address (HTTP Host)" "HTTP $c"
fi
# DNS-blocklisted names are enforced the same way (DNS policy applied to the SNI).
c="$(https_via ads.doubleclick.net)"
[ "$c" = 000 ] && pass SEC-DP-112 "client: DNS-blocklisted name unreachable by address (TLS SNI)" ||
  fail SEC-DP-112 "client: DNS-blocklisted name unreachable by address (TLS SNI)" "HTTP $c"

# TLS inspection (ADR-0018). Turns web.inspect on for the dev tenant with one URL rule, attacks
# the inspected path from the client, then restores the policy. Needs EDGE_INSPECT_PORT on the
# Edge (the dev default) and jq.
T="${SECTEST_TENANT:-acme}"
orig="$(admin_get "/tenants/$T/policy" 2>/dev/null || true)"
if ! command -v jq >/dev/null 2>&1 || [ -z "$orig" ]; then
  skip SEC-DP-120 "inspection: requests must match the connection's host" "no jq or no admin access"
  exit 0
fi
admin_get "/tenants/$T/inspection-ca" 2>/dev/null | cexec sh -c 'cat >/tmp/sec-inspect.crt'
web="$(printf '%s' "$orig" | jq -c '.web = {inspect: true, rules: [{id: "sec-blocked", domains: ["example.com"], pathPrefixes: ["/blocked"], action: "block"}], dlp: [{id: "sec-pci", detectors: ["credit-card", "iban"], action: "block", blockUnscanned: true}], malware: {uploads: true, downloads: true}}')"
if [ "$(admin_code PUT "/tenants/$T/policy" "$web")" != 204 ]; then
  skip SEC-DP-120 "inspection: requests must match the connection's host" "could not enable inspection"
  exit 0
fi
ins() { cexec curl -s -m 12 --cacert /tmp/sec-inspect.crt -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || true; }
i=0
until cexec curl -sv -m 12 --cacert /tmp/sec-inspect.crt -o /dev/null https://example.com/ 2>&1 | grep -q "issuer:.*web inspection"; do
  i=$((i + 1))
  [ "$i" -ge 15 ] && break
  sleep 2
done
if [ "$i" -ge 15 ]; then
  skip SEC-DP-120 "inspection: requests must match the connection's host" "inspection did not take effect (EDGE_INSPECT_PORT unset?)"
else
  # Domain fronting: an inspected connection opened for an allowed name carries a request for
  # a blocked SaaS app.
  c="$(ins -H 'Host: pastebin.com' https://example.com/)"
  [ "$c" = 421 ] && pass SEC-DP-120 "inspection: a request for another host on an inspected connection is refused" ||
    fail SEC-DP-120 "inspection: a request for another host on an inspected connection is refused" "HTTP $c"
  # Path rule evasion: case, duplicate slashes, dot segments, percent-encoding.
  bad=""
  for p in /blocked /BLOCKED/x //blocked /x/../blocked /./blocked /%62locked /blocked%2fx; do
    c="$(ins --path-as-is "https://example.com$p")"
    [ "$c" = 403 ] || bad="$bad $p=$c"
  done
  c="$(ins https://example.com/)"
  case "$c" in 2??|3??|404) ;; *) bad="$bad control:/=$c" ;; esac
  [ -z "$bad" ] && pass SEC-DP-121 "inspection: URL rule holds against path encoding tricks" ||
    fail SEC-DP-121 "inspection: URL rule holds against path encoding tricks" "not refused:$bad"
  # DLP evasion (ADR-0019): the same card number in shapes an exfiltrating client might use.
  bad=""
  card="4111 1111 1111 1111"
  for shape in form json multipart chunked gzip iban; do
    case "$shape" in
      form) c="$(ins --data-urlencode "x=$card" https://example.com/)" ;;
      json) c="$(ins -H 'Content-Type: application/json' --data "{\"pan\":\"4111-1111-1111-1111\"}" https://example.com/)" ;;
      multipart) c="$(ins -F "file=$card;filename=a.txt" https://example.com/)" ;;
      chunked) c="$(ins -H 'Transfer-Encoding: chunked' --data "$card" https://example.com/)" ;;
      gzip) c="$(cexec sh -c 'printf "4111111111111111" | gzip | curl -s -m 12 --cacert /tmp/sec-inspect.crt -o /dev/null -w "%{http_code}" -H "Content-Encoding: gzip" --data-binary @- https://example.com/' 2>/dev/null || true)" ;;
      iban) c="$(ins --data 'iban=IT60 X054 2811 1010 0000 0123 456' https://example.com/)" ;;
    esac
    [ "$c" = 403 ] || bad="$bad $shape=$c"
  done
  c="$(ins --data 'x=hello' https://example.com/)"
  case "$c" in 403 | 000) bad="$bad control:clean=$c" ;; esac
  [ -z "$bad" ] && pass SEC-DP-123 "inspection: DLP catches a card number in every upload encoding" ||
    fail SEC-DP-123 "inspection: DLP catches a card number in every upload encoding" "not refused:$bad"
  # DLP inside documents (ADR-0021): Word, PDF and a nested ZIP, each with the test card.
  # The block page must name the matching rule, not ":unscanned": the text was really read.
  bad=""
  for f in card.docx card.pdf card-nested.zip; do
    dc cp "$(dirname "$0")/fixtures/$f" "client:/tmp/$f" >/dev/null 2>&1 || { bad="$bad $f=copy"; continue; }
    cexec curl -s -m 15 --cacert /tmp/sec-inspect.crt -F "file=@/tmp/$f" https://example.com/ 2>/dev/null | grep -q "rule dlp:sec-pci)" || bad="$bad $f"
  done
  [ -z "$bad" ] && pass SEC-DP-125 "inspection: DLP reads inside Word, PDF and nested ZIP uploads" ||
    fail SEC-DP-125 "inspection: DLP reads inside Word, PDF and nested ZIP uploads" "not caught:$bad"
  # Malware evasion (ADR-0020): the EICAR test file inside a multipart upload and gzip-compressed.
  if [ "$(docker inspect -f '{{.State.Health.Status}}' "$(dc --profile av ps -q clamav 2>/dev/null)" 2>/dev/null)" != healthy ]; then
    skip SEC-DP-124 "inspection: malware scan catches EICAR in multipart and gzip uploads" "clamav not running (docker compose --profile av up -d clamav)"
  else
    bad=""
    cexec sh -c 'printf "%s%s" "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$" "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" >/tmp/sec-eicar.txt'
    # The block page must name the malware scan: the DLP rule above also blocks gzip bodies.
    cexec curl -s -m 30 --cacert /tmp/sec-inspect.crt -F 'file=@/tmp/sec-eicar.txt' https://example.com/ 2>/dev/null | grep -q "malware scan" || bad="$bad multipart"
    cexec sh -c 'gzip -c /tmp/sec-eicar.txt | curl -s -m 30 --cacert /tmp/sec-inspect.crt -H "Content-Encoding: gzip" --data-binary @- https://example.com/' 2>/dev/null | grep -q "malware scan" || bad="$bad gzip"
    [ -z "$bad" ] && pass SEC-DP-124 "inspection: malware scan catches EICAR in multipart and gzip uploads" ||
      fail SEC-DP-124 "inspection: malware scan catches EICAR in multipart and gzip uploads" "not refused:$bad"
  fi
  # The Edge must not hide a bad server certificate: an SNI the server has no certificate for.
  c="$(ins --connect-to untrusted.opensase.test:443:example.com:443 https://untrusted.opensase.test/)"
  [ "$c" = 502 ] && pass SEC-DP-122 "inspection: upstream certificate is verified (no silent MITM of a bad server)" ||
    fail SEC-DP-122 "inspection: upstream certificate is verified (no silent MITM of a bad server)" "HTTP $c"
fi
admin_code PUT "/tenants/$T/policy" "$orig" >/dev/null

