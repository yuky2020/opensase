package controlplane

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

func TestCompileDecideIPv6Normalization(t *testing.T) {
	t.Run("invalid cidrs rejected", func(t *testing.T) {
		tests := []struct {
			name  string
			cidrs []string
			field string
		}{
			{"zoned bare ipv6", []string{"fe80::1%eth0"}, "decideBlockCidrs[0]"},
			{"zoned ipv6 prefix", []string{"fe80::1%eth0/64"}, "decideBlockCidrs[0]"},
			{"v4-mapped shorter than /96", []string{"::ffff:10.0.0.0/80"}, "decideBlockCidrs[0]"},
			{"v4-mapped /95", []string{"::ffff:0:0/95"}, "decideBlockCidrs[0]"},
			{"invalid ipv4 prefix len", []string{"10.0.0.0/33"}, "decideBlockCidrs[0]"},
			{"second entry zoned", []string{"2001:db8::/32", "fe80::1%lo"}, "decideBlockCidrs[1]"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := compileDecide(api.TenantPolicy{
					DecideBlockCIDRs: tt.cidrs,
					DecideDefault:    policy.ActionAllow,
				})
				var ve *policy.ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("compileDecide(%v) err = %v, want ValidationError", tt.cidrs, err)
				}
				if ve.Field != tt.field {
					t.Fatalf("field = %q, want %q (%v)", ve.Field, tt.field, err)
				}
			})
		}
	})

	t.Run("normalized cidrs match flows", func(t *testing.T) {
		type probe struct {
			dstIP      string
			wantAction policy.Action
			wantRule   string
		}
		tests := []struct {
			name       string
			cidr       string
			wantPrefix string
			probes     []probe
		}{
			{
				name:       "v4-mapped /128",
				cidr:       "::ffff:203.0.113.66/128",
				wantPrefix: "203.0.113.66/32",
				probes: []probe{
					{"203.0.113.66", policy.ActionBlock, "decide:cidr"},
					{"::ffff:203.0.113.66", policy.ActionBlock, "decide:cidr"},
					{"203.0.113.67", policy.ActionAllow, "decide:default"},
				},
			},
			{
				name:       "v4-mapped /120 masks host bits",
				cidr:       "::ffff:203.0.113.5/120",
				wantPrefix: "203.0.113.0/24",
				probes: []probe{
					{"203.0.113.99", policy.ActionBlock, "decide:cidr"},
					{"203.0.114.1", policy.ActionAllow, "decide:default"},
				},
			},
			{
				name:       "bare v4-mapped ipv6",
				cidr:       "::ffff:198.51.100.7",
				wantPrefix: "198.51.100.7/32",
				probes: []probe{
					{"198.51.100.7", policy.ActionBlock, "decide:cidr"},
					{"::ffff:198.51.100.7", policy.ActionBlock, "decide:cidr"},
					{"198.51.100.8", policy.ActionAllow, "decide:default"},
				},
			},
			{
				name:       "v4-mapped /96 matches ipv4 only",
				cidr:       "::ffff:0.0.0.0/96",
				wantPrefix: "0.0.0.0/0",
				probes: []probe{
					{"192.0.2.1", policy.ActionBlock, "decide:cidr"},
					{"2001:db8::1", policy.ActionAllow, "decide:default"},
				},
			},
			{
				name:       "ipv6 cidr masks host bits",
				cidr:       "2001:db8:dead::1/48",
				wantPrefix: "2001:db8:dead::/48",
				probes: []probe{
					{"2001:db8:dead::beef", policy.ActionBlock, "decide:cidr"},
					{"2001:db8:beef::1", policy.ActionAllow, "decide:default"},
				},
			},
			{
				name:       "bare ipv6",
				cidr:       "2001:db8::1",
				wantPrefix: "2001:db8::1/128",
				probes: []probe{
					{"2001:db8::1", policy.ActionBlock, "decide:cidr"},
					{"2001:db8::2", policy.ActionAllow, "decide:default"},
				},
			},
			{
				name:       "ipv4 cidr unchanged",
				cidr:       "203.0.113.66/32",
				wantPrefix: "203.0.113.66/32",
				probes: []probe{
					{"203.0.113.66", policy.ActionBlock, "decide:cidr"},
					{"::ffff:203.0.113.66", policy.ActionBlock, "decide:cidr"},
					{"203.0.113.67", policy.ActionAllow, "decide:default"},
				},
			},
			{
				name:       "bare ipv4 unchanged",
				cidr:       "203.0.113.10",
				wantPrefix: "203.0.113.10/32",
				probes: []probe{
					{"203.0.113.10", policy.ActionBlock, "decide:cidr"},
					{"203.0.113.11", policy.ActionAllow, "decide:default"},
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				de, err := compileDecide(api.TenantPolicy{
					DecideBlockCIDRs: []string{tt.cidr},
					DecideDefault:    policy.ActionAllow,
				})
				if err != nil {
					t.Fatalf("compileDecide(%q): %v", tt.cidr, err)
				}
				wantP := netip.MustParsePrefix(tt.wantPrefix)
				if len(de.cidrs) != 1 || de.cidrs[0] != wantP {
					t.Fatalf("cidrs = %v, want [%v]", de.cidrs, wantP)
				}
				for _, p := range tt.probes {
					d := de.cloudDecide(policy.Flow{Protocol: "tcp", DstIP: p.dstIP, DstPort: 443})
					if d.Action != p.wantAction || d.RuleID != p.wantRule || d.Layer != policy.LayerCloud {
						t.Errorf("cloudDecide(%q) = %+v, want action=%s rule=%q layer=%s",
							p.dstIP, d, p.wantAction, p.wantRule, policy.LayerCloud)
					}
				}
			})
		}
	})
}

func TestValidateTenantPolicyMeshICMPv6(t *testing.T) {
	tp := api.TenantPolicy{
		DefaultAction: policy.ActionAllow,
		Mesh: api.MeshPolicy{
			Rules: []api.MeshRule{
				{
					ID:       "ping6",
					From:     api.MeshSelector{All: true},
					To:       api.MeshSelector{All: true},
					Protocol: "icmpv6",
				},
			},
		},
	}
	if err := validateTenantPolicy(tp); err != nil {
		t.Fatalf("validateTenantPolicy with icmpv6 mesh rule: %v", err)
	}
}
