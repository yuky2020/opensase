#!/bin/sh
# Area 3 (black box): classic TLS refused on every listener, checked with openssl s_client
# and opensasectl pq-check. Crafted certificates, SPIFFE and ALPN checks are in the Go
# package (SEC-TLS-0xx).
set -u
. "$(dirname "$0")/lib.sh"

# sclient ADDR ARGS...: handshake summary (Negotiated group / alerts).
sclient() { a="$1"; shift; echo | timeout 10 openssl s_client -connect "$a" -CAfile "$CA" -servername localhost "$@" 2>&1; }

if ! openssl list -kem-algorithms 2>/dev/null | grep -q X25519MLKEM768; then
  skip SEC-TLS-101 "openssl s_client: classic groups refused on 9443/8443/8444" "openssl without X25519MLKEM768"
else
  # Each listener: the hybrid group negotiates (control), classic groups and TLS 1.2 do not.
  bad=""
  for a in localhost:9443 localhost:8443 localhost:8444; do
    out="$(sclient "$a" -groups X25519MLKEM768)"
    echo "$out" | grep -q 'Negotiated TLS1.3 group: X25519MLKEM768' || bad="$bad control($a)"
    for g in X25519 P-256 P-384 X448 ffdhe2048; do
      # A classic handshake "succeeds" only if a group gets negotiated.
      sclient "$a" -groups "$g" | grep -q "Negotiated TLS1.3 group: $g" && bad="$bad $a:$g"
    done
    sclient "$a" -tls1_2 | grep -qE 'Cipher is [A-Z]' && bad="$bad $a:TLS1.2"
  done
  if [ -z "$bad" ]; then
    pass SEC-TLS-101 "openssl s_client: classic groups and TLS 1.2 refused on 9443/8443/8444"
  else
    fail SEC-TLS-101 "openssl s_client: classic groups and TLS 1.2 refused on 9443/8443/8444" "accepted:$bad"
  fi
fi

# Same through curl: a classic-only client gets no HTTP response at all.
c="$(code "$CP_URL/v1/pki/ca" --curves X25519)"
c2="$(code "$CP_URL/v1/pki/ca")"
if [ "$c2" != 200 ]; then
  skip SEC-TLS-102 "curl with X25519 only gets no response from the CP" "control (PQ curl) got $c2"
elif [ "$c" = 000 ]; then
  pass SEC-TLS-102 "curl with X25519 only gets no response from the CP"
else
  fail SEC-TLS-102 "curl with X25519 only gets no response from the CP" "HTTP $c"
fi

# The product's own check (Control Plane and Edge listeners).
if out="$(dc run --rm --no-deps -T ctl pq-check 2>&1)"; then
  pass SEC-TLS-103 "opensasectl pq-check: Control Plane negotiates X25519MLKEM768"
else
  fail SEC-TLS-103 "opensasectl pq-check: Control Plane negotiates X25519MLKEM768" "$out"
fi
