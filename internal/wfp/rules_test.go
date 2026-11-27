//go:build windows

package wfp

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

type capturedCondition struct {
	fieldKey  windows.GUID
	matchType wtFwpMatchType
	dataType  wtFwpDataType
	u8        uint8
	u16       uint16
	u32       uint32
	u64       uint64
	addr16    [16]byte
	prefix6   netip.Prefix
}

type capturedFilter struct {
	name        string
	description string
	providerKey windows.GUID
	subLayerKey windows.GUID
	layerKey    windows.GUID
	weightType  wtFwpDataType
	weight      uint8
	flags       wtFwpmFilterFlags
	action      wtFwpActionType
	conditions  []capturedCondition
}

type filterRecorder struct {
	filters []capturedFilter
	failAt  int // 1-based call index to fail; 0 never fails
	calls   int
	failErr error
}

func (r *filterRecorder) add(_ uintptr, f *wtFwpmFilter0, _ uintptr, id *uint64) error {
	r.calls++
	if r.failAt > 0 && r.calls == r.failAt {
		if r.failErr != nil {
			return r.failErr
		}
		return errors.New("simulated fwpmFilterAdd0 failure")
	}
	if id != nil {
		*id = uint64(r.calls)
	}
	cf := capturedFilter{
		subLayerKey: f.subLayerKey,
		layerKey:    f.layerKey,
		weightType:  f.weight._type,
		weight:      uint8(f.weight.value),
		flags:       f.flags,
		action:      f.action._type,
	}
	if f.displayData.name != nil {
		cf.name = windows.UTF16PtrToString(f.displayData.name)
	}
	if f.displayData.description != nil {
		cf.description = windows.UTF16PtrToString(f.displayData.description)
	}
	if f.providerKey != nil {
		cf.providerKey = *f.providerKey
	}
	if f.numFilterConditions > 0 && f.filterCondition != nil {
		rawConds := unsafe.Slice(f.filterCondition, int(f.numFilterConditions))
		cf.conditions = make([]capturedCondition, len(rawConds))
		for i := range rawConds {
			c := rawConds[i]
			cc := capturedCondition{
				fieldKey:  c.fieldKey,
				matchType: c.matchType,
				dataType:  c.conditionValue._type,
			}
			switch c.conditionValue._type {
			case cFWP_UINT8:
				cc.u8 = uint8(c.conditionValue.value)
			case cFWP_UINT16:
				cc.u16 = uint16(c.conditionValue.value)
			case cFWP_UINT32:
				cc.u32 = uint32(c.conditionValue.value)
			case cFWP_UINT64:
				p := *(**uint64)(unsafe.Pointer(&c.conditionValue.value))
				cc.u64 = *p
			case cFWP_BYTE_ARRAY16_TYPE:
				p := *(**wtFwpByteArray16)(unsafe.Pointer(&c.conditionValue.value))
				cc.addr16 = p.byteArray16
			case cFWP_V6_ADDR_MASK:
				p := *(**wtFwpV6AddrAndMask)(unsafe.Pointer(&c.conditionValue.value))
				cc.prefix6 = netip.PrefixFrom(netip.AddrFrom16(p.addr), int(p.prefixLength))
			}
			cf.conditions[i] = cc
		}
	}
	r.filters = append(r.filters, cf)
	return nil
}

func testBaseObjects() *baseObjects {
	return &baseObjects{
		provider: openSASEProviderGUID,
		filters:  openSASESublayerGUID,
	}
}

func v4Uint32(s string) uint32 {
	a := netip.MustParseAddr(s)
	return binary.BigEndian.Uint32(a.AsSlice())
}

func v6Array(s string) [16]byte {
	return netip.MustParseAddr(s).As16()
}

func checkFilterMeta(t *testing.T, bo *baseObjects, cf capturedFilter, wantLayer windows.GUID, wantAction wtFwpActionType, wantWeight uint8) {
	t.Helper()
	if cf.providerKey != bo.provider {
		t.Errorf("filter %q providerKey = %v, want %v", cf.name, cf.providerKey, bo.provider)
	}
	if cf.subLayerKey != bo.filters {
		t.Errorf("filter %q subLayerKey = %v, want %v", cf.name, cf.subLayerKey, bo.filters)
	}
	if cf.layerKey != wantLayer {
		t.Errorf("filter %q layerKey = %v, want %v", cf.name, cf.layerKey, wantLayer)
	}
	if cf.action != wantAction {
		t.Errorf("filter %q action = %#x, want %#x", cf.name, cf.action, wantAction)
	}
	if cf.weightType != cFWP_UINT8 || cf.weight != wantWeight {
		t.Errorf("filter %q weight = (type=%d, val=%d), want (type=%d, val=%d)", cf.name, cf.weightType, cf.weight, cFWP_UINT8, wantWeight)
	}
}

func checkCondition(t *testing.T, filterName string, idx int, got, want capturedCondition) {
	t.Helper()
	if got != want {
		t.Errorf("filter %q condition[%d]:\ngot:  %+v\nwant: %+v", filterName, idx, got, want)
	}
}

func TestPermitBypass(t *testing.T) {
	bo := testBaseObjects()
	const weight uint8 = 14

	type wantBypassFilter struct {
		layer windows.GUID
		cond  capturedCondition
	}

	tests := []struct {
		name      string
		addresses []netip.Addr
		want      []wantBypassFilter
	}{
		{
			name:      "empty address list adds no filters",
			addresses: nil,
		},
		{
			name:      "ipv4 bypass emits connect and recv-accept v4 permits",
			addresses: []netip.Addr{netip.MustParseAddr("198.51.100.10")},
			want: []wantBypassFilter{
				{
					layer: cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
					cond: capturedCondition{
						fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
						matchType: cFWP_MATCH_EQUAL,
						dataType:  cFWP_UINT32,
						u32:       v4Uint32("198.51.100.10"),
					},
				},
				{
					layer: cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
					cond: capturedCondition{
						fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
						matchType: cFWP_MATCH_EQUAL,
						dataType:  cFWP_UINT32,
						u32:       v4Uint32("198.51.100.10"),
					},
				},
			},
		},
		{
			name:      "ipv6 bypass emits connect and recv-accept v6 permits with 16-byte address",
			addresses: []netip.Addr{netip.MustParseAddr("2001:db8::10")},
			want: []wantBypassFilter{
				{
					layer: cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
					cond: capturedCondition{
						fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
						matchType: cFWP_MATCH_EQUAL,
						dataType:  cFWP_BYTE_ARRAY16_TYPE,
						addr16:    v6Array("2001:db8::10"),
					},
				},
				{
					layer: cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
					cond: capturedCondition{
						fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
						matchType: cFWP_MATCH_EQUAL,
						dataType:  cFWP_BYTE_ARRAY16_TYPE,
						addr16:    v6Array("2001:db8::10"),
					},
				},
			},
		},
		{
			name: "mixed v4 and v6 deduplicates mapped, zoned and invalid addresses",
			addresses: []netip.Addr{
				{},
				netip.MustParseAddr("198.51.100.10"),
				netip.MustParseAddr("::ffff:198.51.100.10"),
				netip.MustParseAddr("2001:db8::10%eth0"),
				netip.MustParseAddr("2001:db8::10"),
			},
			want: []wantBypassFilter{
				{
					layer: cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
					cond: capturedCondition{
						fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
						matchType: cFWP_MATCH_EQUAL,
						dataType:  cFWP_UINT32,
						u32:       v4Uint32("198.51.100.10"),
					},
				},
				{
					layer: cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
					cond: capturedCondition{
						fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
						matchType: cFWP_MATCH_EQUAL,
						dataType:  cFWP_UINT32,
						u32:       v4Uint32("198.51.100.10"),
					},
				},
				{
					layer: cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
					cond: capturedCondition{
						fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
						matchType: cFWP_MATCH_EQUAL,
						dataType:  cFWP_BYTE_ARRAY16_TYPE,
						addr16:    v6Array("2001:db8::10"),
					},
				},
				{
					layer: cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
					cond: capturedCondition{
						fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
						matchType: cFWP_MATCH_EQUAL,
						dataType:  cFWP_BYTE_ARRAY16_TYPE,
						addr16:    v6Array("2001:db8::10"),
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var rec filterRecorder
			if err := permitBypassWith(tc.addresses, 0, bo, weight, rec.add); err != nil {
				t.Fatalf("permitBypassWith() error = %v", err)
			}
			if len(rec.filters) != len(tc.want) {
				t.Fatalf("got %d filters, want %d", len(rec.filters), len(tc.want))
			}
			for i, w := range tc.want {
				got := rec.filters[i]
				checkFilterMeta(t, bo, got, w.layer, cFWP_ACTION_PERMIT, weight)
				if len(got.conditions) != 1 {
					t.Fatalf("filter %d (%q) got %d conditions, want 1", i, got.name, len(got.conditions))
				}
				checkCondition(t, got.name, 0, got.conditions[0], w.cond)
			}
		})
	}

	t.Run("propagates filter add error", func(t *testing.T) {
		rec := filterRecorder{failAt: 2}
		err := permitBypassWith([]netip.Addr{netip.MustParseAddr("2001:db8::10")}, 0, bo, weight, rec.add)
		if err == nil {
			t.Fatal("expected error from failing filterAdder, got nil")
		}
	})
}

func TestBlockDNS(t *testing.T) {
	bo := testBaseObjects()
	const (
		tunLUID     uint64 = 0x0006000000000001
		weightAllow uint8  = 15
		weightDeny  uint8  = 14
	)

	baseDNSConds := []capturedCondition{
		{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
			matchType: cFWP_MATCH_EQUAL,
			dataType:  cFWP_UINT16,
			u16:       53,
		},
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			dataType:  cFWP_UINT8,
			u8:        uint8(cIPPROTO_UDP),
		},
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			dataType:  cFWP_UINT8,
			u8:        uint8(cIPPROTO_TCP),
		},
	}

	nonTunCond := capturedCondition{
		fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
		matchType: cFWP_MATCH_NOT_EQUAL,
		dataType:  cFWP_UINT64,
		u64:       tunLUID,
	}
	tunCond := capturedCondition{
		fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
		matchType: cFWP_MATCH_EQUAL,
		dataType:  cFWP_UINT64,
		u64:       tunLUID,
	}

	denyLayers := []windows.GUID{
		cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
		cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
		cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
	}

	tests := []struct {
		name        string
		except      []netip.Addr
		tunLUID     uint64
		weightAllow uint8
		weightDeny  uint8
		wantErr     bool
		wantV4Allow []uint32
		wantV6Allow [][16]byte
	}{
		{
			name:        "dual-stack tunnel DNS scoped to tunLUID",
			except:      []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:5a5e::1")},
			tunLUID:     tunLUID,
			weightAllow: weightAllow,
			weightDeny:  weightDeny,
			wantV4Allow: []uint32{v4Uint32("100.64.0.1")},
			wantV6Allow: [][16]byte{v6Array("fd7a:5a5e::1")},
		},
		{
			name:        "ipv4-only tunnel DNS still blocks physical ipv6 DNS and omits v6 allow filters",
			except:      []netip.Addr{netip.MustParseAddr("100.64.0.1")},
			tunLUID:     tunLUID,
			weightAllow: weightAllow,
			weightDeny:  weightDeny,
			wantV4Allow: []uint32{v4Uint32("100.64.0.1")},
		},
		{
			name:        "ipv6-only tunnel DNS still blocks physical ipv4 DNS and omits v4 allow filters",
			except:      []netip.Addr{netip.MustParseAddr("fd7a:5a5e::1")},
			tunLUID:     tunLUID,
			weightAllow: weightAllow,
			weightDeny:  weightDeny,
			wantV6Allow: [][16]byte{v6Array("fd7a:5a5e::1")},
		},
		{
			name: "mapped, zoned, duplicate and invalid DNS addresses are normalized",
			except: []netip.Addr{
				{},
				netip.MustParseAddr("100.64.0.1"),
				netip.MustParseAddr("::ffff:100.64.0.1"),
				netip.MustParseAddr("fd7a:5a5e::1%eth0"),
				netip.MustParseAddr("fd7a:5a5e::1"),
				netip.MustParseAddr("fd7a:5a5e::2"),
			},
			tunLUID:     tunLUID,
			weightAllow: weightAllow,
			weightDeny:  weightDeny,
			wantV4Allow: []uint32{v4Uint32("100.64.0.1")},
			wantV6Allow: [][16]byte{v6Array("fd7a:5a5e::1"), v6Array("fd7a:5a5e::2")},
		},
		{
			name:        "zero tunLUID leaves deny and allow filters unscoped by interface",
			except:      []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:5a5e::1")},
			tunLUID:     0,
			weightAllow: weightAllow,
			weightDeny:  weightDeny,
			wantV4Allow: []uint32{v4Uint32("100.64.0.1")},
			wantV6Allow: [][16]byte{v6Array("fd7a:5a5e::1")},
		},
		{
			name:        "equal allow and deny weights rejected",
			except:      []netip.Addr{netip.MustParseAddr("100.64.0.1")},
			tunLUID:     tunLUID,
			weightAllow: 14,
			weightDeny:  14,
			wantErr:     true,
		},
		{
			name:        "deny weight greater than allow weight rejected",
			except:      []netip.Addr{netip.MustParseAddr("100.64.0.1")},
			tunLUID:     tunLUID,
			weightAllow: 13,
			weightDeny:  14,
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var rec filterRecorder
			err := blockDNSWith(tc.except, tc.tunLUID, 0, bo, tc.weightAllow, tc.weightDeny, rec.add)
			if (err != nil) != tc.wantErr {
				t.Fatalf("blockDNSWith() err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				if len(rec.filters) != 0 {
					t.Errorf("expected 0 filters on error, got %d", len(rec.filters))
				}
				return
			}

			wantTotal := len(denyLayers)
			if len(tc.wantV4Allow) > 0 {
				wantTotal += 2
			}
			if len(tc.wantV6Allow) > 0 {
				wantTotal += 2
			}
			if len(rec.filters) != wantTotal {
				t.Fatalf("got %d filters, want %d", len(rec.filters), wantTotal)
			}

			wantDenyConds := append([]capturedCondition(nil), baseDNSConds...)
			if tc.tunLUID != 0 {
				wantDenyConds = append(wantDenyConds, nonTunCond)
			}
			idx := 0
			for _, layer := range denyLayers {
				got := rec.filters[idx]
				idx++
				checkFilterMeta(t, bo, got, layer, cFWP_ACTION_BLOCK, tc.weightDeny)
				if len(got.conditions) != len(wantDenyConds) {
					t.Fatalf("deny filter %q got %d conditions, want %d", got.name, len(got.conditions), len(wantDenyConds))
				}
				for ci, wc := range wantDenyConds {
					checkCondition(t, got.name, ci, got.conditions[ci], wc)
				}
			}

			if len(tc.wantV4Allow) > 0 {
				wantConds := append([]capturedCondition(nil), baseDNSConds...)
				if tc.tunLUID != 0 {
					wantConds = append(wantConds, tunCond)
				}
				for _, ip4 := range tc.wantV4Allow {
					wantConds = append(wantConds, capturedCondition{
						fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
						matchType: cFWP_MATCH_EQUAL,
						dataType:  cFWP_UINT32,
						u32:       ip4,
					})
				}
				for _, layer := range []windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V4, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4} {
					got := rec.filters[idx]
					idx++
					checkFilterMeta(t, bo, got, layer, cFWP_ACTION_PERMIT, tc.weightAllow)
					if len(got.conditions) != len(wantConds) {
						t.Fatalf("allow v4 filter %q got %d conditions, want %d", got.name, len(got.conditions), len(wantConds))
					}
					for ci, wc := range wantConds {
						checkCondition(t, got.name, ci, got.conditions[ci], wc)
					}
				}
			}

			if len(tc.wantV6Allow) > 0 {
				wantConds := append([]capturedCondition(nil), baseDNSConds...)
				if tc.tunLUID != 0 {
					wantConds = append(wantConds, tunCond)
				}
				for _, ip6 := range tc.wantV6Allow {
					wantConds = append(wantConds, capturedCondition{
						fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
						matchType: cFWP_MATCH_EQUAL,
						dataType:  cFWP_BYTE_ARRAY16_TYPE,
						addr16:    ip6,
					})
				}
				for _, layer := range []windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V6, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6} {
					got := rec.filters[idx]
					idx++
					checkFilterMeta(t, bo, got, layer, cFWP_ACTION_PERMIT, tc.weightAllow)
					if len(got.conditions) != len(wantConds) {
						t.Fatalf("allow v6 filter %q got %d conditions, want %d", got.name, len(got.conditions), len(wantConds))
					}
					for ci, wc := range wantConds {
						checkCondition(t, got.name, ci, got.conditions[ci], wc)
					}
				}
			}
		})
	}

	t.Run("propagates filter add error", func(t *testing.T) {
		rec := filterRecorder{failAt: 3}
		err := blockDNSWith([]netip.Addr{netip.MustParseAddr("fd7a:5a5e::1")}, tunLUID, 0, bo, weightAllow, weightDeny, rec.add)
		if err == nil {
			t.Fatal("expected error from failing filterAdder, got nil")
		}
	})
}

func TestPermitDHCPIPv6(t *testing.T) {
	bo := testBaseObjects()
	const weight uint8 = 12

	var rec filterRecorder
	if err := permitDHCPIPv6With(0, bo, weight, rec.add); err != nil {
		t.Fatalf("permitDHCPIPv6With() error = %v", err)
	}
	if len(rec.filters) != 2 {
		t.Fatalf("got %d filters, want 2", len(rec.filters))
	}

	fe80 := netip.MustParsePrefix("fe80::/10")
	tests := []struct {
		name      string
		idx       int
		wantLayer windows.GUID
		wantConds []capturedCondition
	}{
		{
			name:      "outbound DHCPv6 multicast from link-local port 546 to 547",
			idx:       0,
			wantLayer: cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
			wantConds: []capturedCondition{
				{
					fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
					matchType: cFWP_MATCH_EQUAL,
					dataType:  cFWP_UINT8,
					u8:        uint8(cIPPROTO_UDP),
				},
				{
					fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
					matchType: cFWP_MATCH_EQUAL,
					dataType:  cFWP_BYTE_ARRAY16_TYPE,
					addr16:    v6Array("ff02::1:2"),
				},
				{
					fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
					matchType: cFWP_MATCH_EQUAL,
					dataType:  cFWP_BYTE_ARRAY16_TYPE,
					addr16:    v6Array("ff05::1:3"),
				},
				{
					fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
					matchType: cFWP_MATCH_EQUAL,
					dataType:  cFWP_UINT16,
					u16:       547,
				},
				{
					fieldKey:  cFWPM_CONDITION_IP_LOCAL_ADDRESS,
					matchType: cFWP_MATCH_EQUAL,
					dataType:  cFWP_V6_ADDR_MASK,
					prefix6:   fe80,
				},
				{
					fieldKey:  cFWPM_CONDITION_IP_LOCAL_PORT,
					matchType: cFWP_MATCH_EQUAL,
					dataType:  cFWP_UINT16,
					u16:       546,
				},
			},
		},
		{
			name:      "inbound DHCPv6 response from link-local port 547 to link-local port 546",
			idx:       1,
			wantLayer: cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
			wantConds: []capturedCondition{
				{
					fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
					matchType: cFWP_MATCH_EQUAL,
					dataType:  cFWP_UINT8,
					u8:        uint8(cIPPROTO_UDP),
				},
				{
					fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
					matchType: cFWP_MATCH_EQUAL,
					dataType:  cFWP_V6_ADDR_MASK,
					prefix6:   fe80,
				},
				{
					fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
					matchType: cFWP_MATCH_EQUAL,
					dataType:  cFWP_UINT16,
					u16:       547,
				},
				{
					fieldKey:  cFWPM_CONDITION_IP_LOCAL_ADDRESS,
					matchType: cFWP_MATCH_EQUAL,
					dataType:  cFWP_V6_ADDR_MASK,
					prefix6:   fe80,
				},
				{
					fieldKey:  cFWPM_CONDITION_IP_LOCAL_PORT,
					matchType: cFWP_MATCH_EQUAL,
					dataType:  cFWP_UINT16,
					u16:       546,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rec.filters[tc.idx]
			checkFilterMeta(t, bo, got, tc.wantLayer, cFWP_ACTION_PERMIT, weight)
			if len(got.conditions) != len(tc.wantConds) {
				t.Fatalf("got %d conditions, want %d", len(got.conditions), len(tc.wantConds))
			}
			for i, wc := range tc.wantConds {
				checkCondition(t, got.name, i, got.conditions[i], wc)
			}
		})
	}
}

func TestPermitNDP(t *testing.T) {
	bo := testBaseObjects()
	const weight uint8 = 12

	var rec filterRecorder
	if err := permitNdpWith(0, bo, weight, rec.add); err != nil {
		t.Fatalf("permitNdpWith() error = %v", err)
	}

	icmpConds := func(icmpType uint16, extra ...capturedCondition) []capturedCondition {
		conds := []capturedCondition{
			{
				fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
				matchType: cFWP_MATCH_EQUAL,
				dataType:  cFWP_UINT8,
				u8:        uint8(cIPPROTO_ICMPV6),
			},
			{
				fieldKey:  cFWPM_CONDITION_ICMP_TYPE,
				matchType: cFWP_MATCH_EQUAL,
				dataType:  cFWP_UINT16,
				u16:       icmpType,
			},
			{
				fieldKey:  cFWPM_CONDITION_ICMP_CODE,
				matchType: cFWP_MATCH_EQUAL,
				dataType:  cFWP_UINT16,
				u16:       0,
			},
		}
		return append(conds, extra...)
	}

	fe80 := netip.MustParsePrefix("fe80::/10")
	tests := []struct {
		name      string
		layer     windows.GUID
		wantConds []capturedCondition
	}{
		{
			name:  "router solicitation 133 outbound to ff02::2",
			layer: cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
			wantConds: icmpConds(133, capturedCondition{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType: cFWP_MATCH_EQUAL,
				dataType:  cFWP_BYTE_ARRAY16_TYPE,
				addr16:    v6Array("ff02::2"),
			}),
		},
		{
			name:  "router advertisement 134 inbound from fe80::/10",
			layer: cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
			wantConds: icmpConds(134, capturedCondition{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType: cFWP_MATCH_EQUAL,
				dataType:  cFWP_V6_ADDR_MASK,
				prefix6:   fe80,
			}),
		},
		{
			name:      "neighbor solicitation 135 outbound",
			layer:     cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
			wantConds: icmpConds(135),
		},
		{
			name:      "neighbor solicitation 135 inbound",
			layer:     cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
			wantConds: icmpConds(135),
		},
		{
			name:      "neighbor advertisement 136 outbound",
			layer:     cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
			wantConds: icmpConds(136),
		},
		{
			name:      "neighbor advertisement 136 inbound",
			layer:     cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
			wantConds: icmpConds(136),
		},
		{
			name:  "redirect 137 inbound from fe80::/10",
			layer: cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
			wantConds: icmpConds(137, capturedCondition{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType: cFWP_MATCH_EQUAL,
				dataType:  cFWP_V6_ADDR_MASK,
				prefix6:   fe80,
			}),
		},
	}

	if len(rec.filters) != len(tests) {
		t.Fatalf("got %d filters, want %d", len(rec.filters), len(tests))
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rec.filters[i]
			checkFilterMeta(t, bo, got, tc.layer, cFWP_ACTION_PERMIT, weight)
			if len(got.conditions) != len(tc.wantConds) {
				t.Fatalf("got %d conditions, want %d", len(got.conditions), len(tc.wantConds))
			}
			for ci, wc := range tc.wantConds {
				checkCondition(t, got.name, ci, got.conditions[ci], wc)
			}
		})
	}
}

func TestBlockAll(t *testing.T) {
	bo := testBaseObjects()
	const weight uint8 = 0

	var rec filterRecorder
	if err := blockAllWith(0, bo, weight, rec.add); err != nil {
		t.Fatalf("blockAllWith() error = %v", err)
	}

	wantLayers := []struct {
		name  string
		layer windows.GUID
	}{
		{name: "outbound ipv4", layer: cFWPM_LAYER_ALE_AUTH_CONNECT_V4},
		{name: "inbound ipv4", layer: cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4},
		{name: "outbound ipv6", layer: cFWPM_LAYER_ALE_AUTH_CONNECT_V6},
		{name: "inbound ipv6", layer: cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6},
	}

	if len(rec.filters) != len(wantLayers) {
		t.Fatalf("got %d filters, want %d", len(rec.filters), len(wantLayers))
	}
	for i, tc := range wantLayers {
		t.Run(tc.name, func(t *testing.T) {
			got := rec.filters[i]
			checkFilterMeta(t, bo, got, tc.layer, cFWP_ACTION_BLOCK, weight)
			if len(got.conditions) != 0 {
				t.Errorf("catch-all block filter %q got %d conditions, want 0", got.name, len(got.conditions))
			}
		})
	}
}

func TestPermitTunInterface(t *testing.T) {
	bo := testBaseObjects()
	const (
		tunLUID uint64 = 0x0006000000000042
		weight  uint8  = 12
	)

	var rec filterRecorder
	if err := permitTunInterfaceWith(0, bo, weight, tunLUID, rec.add); err != nil {
		t.Fatalf("permitTunInterfaceWith() error = %v", err)
	}

	wantLayers := []struct {
		name  string
		layer windows.GUID
	}{
		{name: "outbound ipv4", layer: cFWPM_LAYER_ALE_AUTH_CONNECT_V4},
		{name: "inbound ipv4", layer: cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4},
		{name: "outbound ipv6", layer: cFWPM_LAYER_ALE_AUTH_CONNECT_V6},
		{name: "inbound ipv6", layer: cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6},
	}

	wantCond := capturedCondition{
		fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
		matchType: cFWP_MATCH_EQUAL,
		dataType:  cFWP_UINT64,
		u64:       tunLUID,
	}

	if len(rec.filters) != len(wantLayers) {
		t.Fatalf("got %d filters, want %d", len(rec.filters), len(wantLayers))
	}
	for i, tc := range wantLayers {
		t.Run(tc.name, func(t *testing.T) {
			got := rec.filters[i]
			checkFilterMeta(t, bo, got, tc.layer, cFWP_ACTION_PERMIT, weight)
			if len(got.conditions) != 1 {
				t.Fatalf("filter %q got %d conditions, want 1", got.name, len(got.conditions))
			}
			checkCondition(t, got.name, 0, got.conditions[0], wantCond)
		})
	}
}

// testPacket models the ALE attributes evaluated by the generated WFP filters.
// For ICMPv6 packets, localPort holds ICMP type and remotePort holds ICMP code
// because WFP shares the IP_LOCAL_PORT / IP_REMOTE_PORT condition GUIDs.
type testPacket struct {
	layer      windows.GUID
	localLUID  uint64
	proto      uint8
	localAddr  netip.Addr
	localPort  uint16
	remoteAddr netip.Addr
	remotePort uint16
	flags      uint32
}

func matchCondition(c capturedCondition, p testPacket) bool {
	switch c.fieldKey {
	case cFWPM_CONDITION_IP_LOCAL_INTERFACE:
		if c.dataType != cFWP_UINT64 {
			return false
		}
		switch c.matchType {
		case cFWP_MATCH_EQUAL:
			return p.localLUID == c.u64
		case cFWP_MATCH_NOT_EQUAL:
			return p.localLUID != c.u64
		}
	case cFWPM_CONDITION_IP_PROTOCOL:
		return c.matchType == cFWP_MATCH_EQUAL && c.dataType == cFWP_UINT8 && p.proto == c.u8
	case cFWPM_CONDITION_IP_LOCAL_PORT:
		return c.matchType == cFWP_MATCH_EQUAL && c.dataType == cFWP_UINT16 && p.localPort == c.u16
	case cFWPM_CONDITION_IP_REMOTE_PORT:
		return c.matchType == cFWP_MATCH_EQUAL && c.dataType == cFWP_UINT16 && p.remotePort == c.u16
	case cFWPM_CONDITION_IP_REMOTE_ADDRESS:
		if c.matchType != cFWP_MATCH_EQUAL {
			return false
		}
		switch c.dataType {
		case cFWP_UINT32:
			return p.remoteAddr.Is4() && binary.BigEndian.Uint32(p.remoteAddr.AsSlice()) == c.u32
		case cFWP_BYTE_ARRAY16_TYPE:
			return p.remoteAddr.Is6() && p.remoteAddr.As16() == c.addr16
		case cFWP_V6_ADDR_MASK:
			return p.remoteAddr.Is6() && c.prefix6.Contains(p.remoteAddr)
		}
	case cFWPM_CONDITION_IP_LOCAL_ADDRESS:
		if c.matchType == cFWP_MATCH_EQUAL && c.dataType == cFWP_V6_ADDR_MASK {
			return p.localAddr.Is6() && c.prefix6.Contains(p.localAddr)
		}
	case cFWPM_CONDITION_FLAGS:
		return c.matchType == cFWP_MATCH_FLAGS_ALL_SET && c.dataType == cFWP_UINT32 && (p.flags&c.u32) == c.u32
	}
	return false
}

// evalFilters evaluates captured filters in a single sublayer using WFP rules:
// repeated conditions with the same fieldKey are ORed, distinct fieldKeys are
// ANDed, and the highest-weight matching filter decides the action.
func evalFilters(filters []capturedFilter, p testPacket) (action wtFwpActionType, weight uint8, matched bool) {
	for _, f := range filters {
		if f.layerKey != p.layer {
			continue
		}
		byField := make(map[windows.GUID]bool)
		for _, c := range f.conditions {
			if matchCondition(c, p) {
				byField[c.fieldKey] = true
			} else if _, exists := byField[c.fieldKey]; !exists {
				byField[c.fieldKey] = false
			}
		}
		allMatch := true
		for _, ok := range byField {
			if !ok {
				allMatch = false
				break
			}
		}
		if !allMatch {
			continue
		}
		if !matched || f.weight > weight {
			action = f.action
			weight = f.weight
			matched = true
		}
	}
	return action, weight, matched
}

func TestBlockDNSAllowsTunRedirectBlocksPhysical(t *testing.T) {
	bo := testBaseObjects()
	const (
		tunLUID      uint64 = 0x0006000000000001
		physLUID     uint64 = 0x0006000000000002
		loopbackLUID uint64 = 0x0018000000000001
	)

	var rec filterRecorder
	bypass := []netip.Addr{
		netip.MustParseAddr("198.51.100.10"),
		netip.MustParseAddr("2001:db8::10"),
	}
	dnsServers := []netip.Addr{
		netip.MustParseAddr("100.64.0.1"),
		netip.MustParseAddr("fd7a:5a5e::1"),
	}
	if err := permitBypassWith(bypass, 0, bo, 14, rec.add); err != nil {
		t.Fatalf("permitBypassWith: %v", err)
	}
	if err := blockDNSWith(dnsServers, tunLUID, 0, bo, 15, 14, rec.add); err != nil {
		t.Fatalf("blockDNSWith: %v", err)
	}
	if err := permitLoopbackWith(0, bo, 13, rec.add); err != nil {
		t.Fatalf("permitLoopbackWith: %v", err)
	}
	if err := permitTunInterfaceWith(0, bo, 12, tunLUID, rec.add); err != nil {
		t.Fatalf("permitTunInterfaceWith: %v", err)
	}
	if err := permitDHCPIPv6With(0, bo, 12, rec.add); err != nil {
		t.Fatalf("permitDHCPIPv6With: %v", err)
	}
	if err := permitNdpWith(0, bo, 12, rec.add); err != nil {
		t.Fatalf("permitNdpWith: %v", err)
	}
	if err := blockAllWith(0, bo, 0, rec.add); err != nil {
		t.Fatalf("blockAllWith: %v", err)
	}

	tests := []struct {
		name       string
		pkt        testPacket
		wantAction wtFwpActionType
		wantWeight uint8
	}{
		{
			name: "tunnel IPv4 DNS query to Edge resolver permitted at weight 15",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
				localLUID:  tunLUID,
				proto:      uint8(cIPPROTO_UDP),
				remoteAddr: netip.MustParseAddr("100.64.0.1"),
				remotePort: 53,
			},
			wantAction: cFWP_ACTION_PERMIT,
			wantWeight: 15,
		},
		{
			name: "tunnel IPv6 DNS query to Edge resolver permitted at weight 15",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
				localLUID:  tunLUID,
				proto:      uint8(cIPPROTO_UDP),
				remoteAddr: netip.MustParseAddr("fd7a:5a5e::1"),
				remotePort: 53,
			},
			wantAction: cFWP_ACTION_PERMIT,
			wantWeight: 15,
		},
		{
			name: "third-party IPv4 UDP/53 on TUN passes to Edge for dns.redirectQueries",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
				localLUID:  tunLUID,
				proto:      uint8(cIPPROTO_UDP),
				remoteAddr: netip.MustParseAddr("8.8.8.8"),
				remotePort: 53,
			},
			wantAction: cFWP_ACTION_PERMIT,
			wantWeight: 12,
		},
		{
			name: "third-party IPv6 TCP/53 on TUN passes to Edge for dns.redirectQueries",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
				localLUID:  tunLUID,
				proto:      uint8(cIPPROTO_TCP),
				remoteAddr: netip.MustParseAddr("2001:4860:4860::8888"),
				remotePort: 53,
			},
			wantAction: cFWP_ACTION_PERMIT,
			wantWeight: 12,
		},
		{
			name: "inbound redirected IPv6 DNS reply on TUN permitted at weight 12",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
				localLUID:  tunLUID,
				proto:      uint8(cIPPROTO_UDP),
				remoteAddr: netip.MustParseAddr("2001:4860:4860::8888"),
				remotePort: 53,
			},
			wantAction: cFWP_ACTION_PERMIT,
			wantWeight: 12,
		},
		{
			name: "physical IPv4 DNS query to LAN resolver blocked at weight 14",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
				localLUID:  physLUID,
				proto:      uint8(cIPPROTO_UDP),
				remoteAddr: netip.MustParseAddr("192.168.1.1"),
				remotePort: 53,
			},
			wantAction: cFWP_ACTION_BLOCK,
			wantWeight: 14,
		},
		{
			name: "physical IPv6 DNS query to RDNSS link-local resolver blocked at weight 14",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
				localLUID:  physLUID,
				proto:      uint8(cIPPROTO_UDP),
				remoteAddr: netip.MustParseAddr("fe80::1"),
				remotePort: 53,
			},
			wantAction: cFWP_ACTION_BLOCK,
			wantWeight: 14,
		},
		{
			name: "physical IPv6 TCP/53 to third-party resolver blocked at weight 14",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
				localLUID:  physLUID,
				proto:      uint8(cIPPROTO_TCP),
				remoteAddr: netip.MustParseAddr("2001:4860:4860::8888"),
				remotePort: 53,
			},
			wantAction: cFWP_ACTION_BLOCK,
			wantWeight: 14,
		},
		{
			name: "tunnel IPv6 DNS address cannot leak over physical interface",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
				localLUID:  physLUID,
				proto:      uint8(cIPPROTO_UDP),
				remoteAddr: netip.MustParseAddr("fd7a:5a5e::1"),
				remotePort: 53,
			},
			wantAction: cFWP_ACTION_BLOCK,
			wantWeight: 14,
		},
		{
			name: "loopback port 53 remains blocked at weight 14",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
				localLUID:  loopbackLUID,
				proto:      uint8(cIPPROTO_UDP),
				remoteAddr: netip.MustParseAddr("::1"),
				remotePort: 53,
				flags:      uint32(cFWP_CONDITION_FLAG_IS_LOOPBACK),
			},
			wantAction: cFWP_ACTION_BLOCK,
			wantWeight: 14,
		},
		{
			name: "non-DNS IPv6 loopback permitted at weight 13",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
				localLUID:  loopbackLUID,
				proto:      uint8(cIPPROTO_TCP),
				remoteAddr: netip.MustParseAddr("::1"),
				remotePort: 8080,
				flags:      uint32(cFWP_CONDITION_FLAG_IS_LOOPBACK),
			},
			wantAction: cFWP_ACTION_PERMIT,
			wantWeight: 13,
		},
		{
			name: "IPv6 bypass endpoint permitted on physical interface at weight 14",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
				localLUID:  physLUID,
				proto:      uint8(cIPPROTO_UDP),
				remoteAddr: netip.MustParseAddr("2001:db8::10"),
				remotePort: 51820,
			},
			wantAction: cFWP_ACTION_PERMIT,
			wantWeight: 14,
		},
		{
			name: "DHCPv6 outbound request permitted on physical interface at weight 12",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
				localLUID:  physLUID,
				proto:      uint8(cIPPROTO_UDP),
				localAddr:  netip.MustParseAddr("fe80::10"),
				localPort:  546,
				remoteAddr: netip.MustParseAddr("ff02::1:2"),
				remotePort: 547,
			},
			wantAction: cFWP_ACTION_PERMIT,
			wantWeight: 12,
		},
		{
			name: "NDP router solicitation permitted on physical interface at weight 12",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
				localLUID:  physLUID,
				proto:      uint8(cIPPROTO_ICMPV6),
				localPort:  133,
				remoteAddr: netip.MustParseAddr("ff02::2"),
				remotePort: 0,
			},
			wantAction: cFWP_ACTION_PERMIT,
			wantWeight: 12,
		},
		{
			name: "arbitrary IPv6 traffic on physical interface blocked by catch-all at weight 0",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
				localLUID:  physLUID,
				proto:      uint8(cIPPROTO_TCP),
				remoteAddr: netip.MustParseAddr("2001:db8::99"),
				remotePort: 443,
			},
			wantAction: cFWP_ACTION_BLOCK,
			wantWeight: 0,
		},
		{
			name: "arbitrary IPv6 traffic on TUN permitted at weight 12",
			pkt: testPacket{
				layer:      cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
				localLUID:  tunLUID,
				proto:      uint8(cIPPROTO_TCP),
				remoteAddr: netip.MustParseAddr("2001:db8::99"),
				remotePort: 443,
			},
			wantAction: cFWP_ACTION_PERMIT,
			wantWeight: 12,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			action, weight, ok := evalFilters(rec.filters, tc.pkt)
			if !ok {
				t.Fatalf("no filter matched packet %+v", tc.pkt)
			}
			if action != tc.wantAction || weight != tc.wantWeight {
				t.Errorf("evalFilters() = (action=%#x, weight=%d), want (action=%#x, weight=%d)",
					action, weight, tc.wantAction, tc.wantWeight)
			}
		})
	}
}
