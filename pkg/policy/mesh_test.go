package policy

import (
	"errors"
	"testing"
)

func TestCompileMeshValidation(t *testing.T) {
	tests := []struct {
		name  string
		grant MeshGrant
		field string // expected ValidationError.Field; "" = valid
	}{
		{"any proto", MeshGrant{RuleID: "any", FromAll: true}, ""},
		{"tcp", MeshGrant{RuleID: "ssh", FromUsers: []string{"u1"}, Protocol: "tcp", Ports: []PortRange{{From: 22}}}, ""},
		{"udp", MeshGrant{RuleID: "dns", FromDevices: []string{"d1"}, Protocol: "udp", Ports: []PortRange{{From: 53}}}, ""},
		{"icmp", MeshGrant{RuleID: "ping", FromAll: true, Protocol: "icmp"}, ""},
		{"icmpv6", MeshGrant{RuleID: "ping6", FromAll: true, Protocol: "icmpv6"}, ""},
		{"bad proto", MeshGrant{RuleID: "bad", FromAll: true, Protocol: "sctp"}, "meshInbound[0].protocol"},
		{"uppercase proto", MeshGrant{RuleID: "upper", FromAll: true, Protocol: "ICMPv6"}, "meshInbound[0].protocol"},
		{"no selector", MeshGrant{RuleID: "none", Protocol: "icmpv6"}, "meshInbound[0]"},
		{"port zero", MeshGrant{RuleID: "p0", FromAll: true, Protocol: "tcp", Ports: []PortRange{{From: 0}}}, "meshInbound[0].ports"},
		{"port reversed", MeshGrant{RuleID: "prev", FromAll: true, Protocol: "tcp", Ports: []PortRange{{From: 80, To: 22}}}, "meshInbound[0].ports"},
		{"no rule id", MeshGrant{FromAll: true, Protocol: "icmpv6"}, "meshInbound[0].ruleId"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := baseSnapshot()
			s.MeshInbound = []MeshGrant{tt.grant}
			c, err := Compile(s)
			if tt.field == "" {
				if err != nil {
					t.Fatalf("Compile: unexpected error: %v", err)
				}
				if !c.HasMesh() {
					t.Fatal("HasMesh() = false, want true")
				}
				return
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("want ValidationError for %s, got %v", tt.field, err)
			}
			if ve.Field != tt.field {
				t.Fatalf("field = %q, want %q (%v)", ve.Field, tt.field, err)
			}
		})
	}
}

func TestMeshAllowsICMPv6(t *testing.T) {
	tests := []struct {
		name       string
		grants     []MeshGrant
		fromUser   string
		fromDevice string
		proto      string
		port       uint16
		wantRule   string
		wantOK     bool
	}{
		{
			name:       "icmp grant allows icmp",
			grants:     []MeshGrant{{RuleID: "ping", FromAll: true, Protocol: "icmp"}},
			fromUser:   "u1",
			fromDevice: "d1",
			proto:      "icmp",
			wantRule:   "mesh:ping",
			wantOK:     true,
		},
		{
			name:       "icmp grant allows icmpv6",
			grants:     []MeshGrant{{RuleID: "ping", FromAll: true, Protocol: "icmp"}},
			fromUser:   "u1",
			fromDevice: "d1",
			proto:      "icmpv6",
			wantRule:   "mesh:ping",
			wantOK:     true,
		},
		{
			name:       "icmp grant rejects tcp",
			grants:     []MeshGrant{{RuleID: "ping", FromAll: true, Protocol: "icmp"}},
			fromUser:   "u1",
			fromDevice: "d1",
			proto:      "tcp",
			port:       80,
		},
		{
			name:       "icmpv6 grant allows icmpv6",
			grants:     []MeshGrant{{RuleID: "ping6", FromAll: true, Protocol: "icmpv6"}},
			fromUser:   "u1",
			fromDevice: "d1",
			proto:      "icmpv6",
			wantRule:   "mesh:ping6",
			wantOK:     true,
		},
		{
			name:       "icmpv6 grant rejects icmp",
			grants:     []MeshGrant{{RuleID: "ping6", FromAll: true, Protocol: "icmpv6"}},
			fromUser:   "u1",
			fromDevice: "d1",
			proto:      "icmp",
		},
		{
			name:       "icmpv6 grant rejects udp",
			grants:     []MeshGrant{{RuleID: "ping6", FromAll: true, Protocol: "icmpv6"}},
			fromUser:   "u1",
			fromDevice: "d1",
			proto:      "udp",
			port:       53,
		},
		{
			name:       "any proto with ports skips port check for icmp",
			grants:     []MeshGrant{{RuleID: "ssh", FromAll: true, Ports: []PortRange{{From: 22}}}},
			fromUser:   "u1",
			fromDevice: "d1",
			proto:      "icmp",
			wantRule:   "mesh:ssh",
			wantOK:     true,
		},
		{
			name:       "any proto with ports skips port check for icmpv6",
			grants:     []MeshGrant{{RuleID: "ssh", FromAll: true, Ports: []PortRange{{From: 22}}}},
			fromUser:   "u1",
			fromDevice: "d1",
			proto:      "icmpv6",
			wantRule:   "mesh:ssh",
			wantOK:     true,
		},
		{
			name:       "any proto with ports still checks tcp port",
			grants:     []MeshGrant{{RuleID: "ssh", FromAll: true, Ports: []PortRange{{From: 22}}}},
			fromUser:   "u1",
			fromDevice: "d1",
			proto:      "tcp",
			port:       80,
		},
		{
			name:       "icmpv6 grant with ports skips port check",
			grants:     []MeshGrant{{RuleID: "ping6-ports", FromAll: true, Protocol: "icmpv6", Ports: []PortRange{{From: 443}}}},
			fromUser:   "u1",
			fromDevice: "d1",
			proto:      "icmpv6",
			wantRule:   "mesh:ping6-ports",
			wantOK:     true,
		},
		{
			name:       "tcp grant rejects icmpv6",
			grants:     []MeshGrant{{RuleID: "ssh", FromAll: true, Protocol: "tcp", Ports: []PortRange{{From: 22}}}},
			fromUser:   "u1",
			fromDevice: "d1",
			proto:      "icmpv6",
		},
		{
			name:       "icmpv6 grant enforces user selector allow",
			grants:     []MeshGrant{{RuleID: "admin-ping6", FromUsers: []string{"alice"}, Protocol: "icmpv6"}},
			fromUser:   "alice",
			fromDevice: "d1",
			proto:      "icmpv6",
			wantRule:   "mesh:admin-ping6",
			wantOK:     true,
		},
		{
			name:       "icmpv6 grant enforces user selector deny",
			grants:     []MeshGrant{{RuleID: "admin-ping6", FromUsers: []string{"alice"}, Protocol: "icmpv6"}},
			fromUser:   "bob",
			fromDevice: "d1",
			proto:      "icmpv6",
		},
		{
			name:       "icmpv6 grant enforces device selector allow",
			grants:     []MeshGrant{{RuleID: "dev-ping6", FromDevices: []string{"d1"}, Protocol: "icmpv6"}},
			fromUser:   "bob",
			fromDevice: "d1",
			proto:      "icmpv6",
			wantRule:   "mesh:dev-ping6",
			wantOK:     true,
		},
		{
			name:       "icmpv6 grant enforces device selector deny",
			grants:     []MeshGrant{{RuleID: "dev-ping6", FromDevices: []string{"d1"}, Protocol: "icmpv6"}},
			fromUser:   "bob",
			fromDevice: "d2",
			proto:      "icmpv6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := baseSnapshot()
			s.MeshInbound = tt.grants
			c := mustCompile(t, s)
			gotRule, gotOK := c.MeshAllows(tt.fromUser, tt.fromDevice, tt.proto, tt.port)
			if gotRule != tt.wantRule || gotOK != tt.wantOK {
				t.Fatalf("MeshAllows(%q, %q, %q, %d) = (%q, %v), want (%q, %v)",
					tt.fromUser, tt.fromDevice, tt.proto, tt.port, gotRule, gotOK, tt.wantRule, tt.wantOK)
			}
		})
	}
}
