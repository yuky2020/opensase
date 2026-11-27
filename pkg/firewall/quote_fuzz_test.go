package firewall

import "testing"

// FuzzWalkQuotedIPv6 checks that walking the extension headers of a quoted IPv6 packet
// (an ICMPv6 error's payload, attacker-controlled) never panics and never returns a
// transport slice outside the quote.
func FuzzWalkQuotedIPv6(f *testing.F) {
	hdr := make([]byte, 48)
	hdr[0] = 0x60
	hdr[6] = 6 // TCP
	f.Add(hdr)
	ext := make([]byte, 56)
	ext[0] = 0x60
	ext[6] = ipv6HopByHop
	ext[40] = 17 // UDP after one 8-byte hop-by-hop header
	f.Add(ext)
	f.Fuzz(func(t *testing.T, q []byte) {
		proto, l4, ok := walkQuotedIPv6(q)
		if !ok {
			return
		}
		if len(l4) > len(q)-40 {
			t.Fatalf("transport slice longer than the payload: %d > %d", len(l4), len(q)-40)
		}
		switch proto {
		case ipv6HopByHop, ipv6Routing, ipv6DestOpts, ipv6Fragment:
			t.Fatalf("returned an extension header as transport protocol %d", proto)
		}
	})
}
