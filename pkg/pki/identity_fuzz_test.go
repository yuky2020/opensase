package pki

import (
	"testing"
)

func formatIdentityURI(id Identity) string {
	switch id.Kind {
	case PeerDevice:
		return DeviceURI(id.TenantID, id.DeviceID).String()
	case PeerConnector:
		return ConnectorURI(id.TenantID, id.ConnectorID).String()
	case PeerEdge:
		return EdgeURI(id.EdgeID).String()
	case PeerControlPlane:
		return ControlPlaneURI().String()
	default:
		return ""
	}
}

func FuzzParseURI(f *testing.F) {
	f.Add("spiffe://opensase/tenant/t/device/d")
	f.Add("spiffe://opensase/tenant/acme/connector/dc1")
	f.Add("spiffe://opensase/edge/edge-1")
	f.Add("spiffe://opensase/controlplane")
	f.Add("spiffe://other/edge/e1")
	f.Add("spiffe://opensase/tenant/t")
	f.Add("spiffe://opensase/tenant/t/device/d/x")
	f.Add("spiffe://opensase/tenant/../device/d")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		id, err := ParseURI(raw)
		if err != nil {
			return
		}
		formatted := formatIdentityURI(id)
		if formatted == "" {
			t.Fatalf("formatIdentityURI(%+v) returned empty string", id)
		}
		id2, err2 := ParseURI(formatted)
		if err2 != nil {
			t.Fatalf("ParseURI(%q) failed after round-trip: %v", formatted, err2)
		}
		if id2 != id {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", id2, id)
		}
	})
}

func FuzzParseSANs(f *testing.F) {
	f.Add("localhost, 127.0.0.1, ::1, example.com")
	f.Add("10.0.2.2, 192.168.1.1, ::ffff:192.0.2.1")
	f.Add("")
	f.Add(",,,")
	f.Add("  foo.bar.internal  ,  2001:db8::1  ")

	f.Fuzz(func(t *testing.T, list string) {
		dns, ips := ParseSANs(list)
		for _, d := range dns {
			if d == "" {
				t.Fatal("empty DNS name returned")
			}
		}
		for _, ip := range ips {
			if ip == nil {
				t.Fatal("nil IP returned")
			}
		}
	})
}
