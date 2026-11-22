package edge

import "github.com/miekg/dns"

// stripECH removes ECH configurations from HTTPS and SVCB records in Answer and Extra (ADR-0030).
// It returns the number of ECH parameters removed.
func stripECH(m *dns.Msg) int {
	if m == nil {
		return 0
	}
	removed := 0
	for _, rr := range m.Answer {
		removed += stripECHFromRR(rr)
	}
	for _, rr := range m.Extra {
		removed += stripECHFromRR(rr)
	}
	return removed
}

func stripECHFromRR(rr dns.RR) int {
	switch v := rr.(type) {
	case *dns.HTTPS:
		filtered, n := stripECHParams(v.Value)
		if n > 0 {
			v.Value = filtered
		}
		return n
	case *dns.SVCB:
		filtered, n := stripECHParams(v.Value)
		if n > 0 {
			v.Value = filtered
		}
		return n
	default:
		return 0
	}
}

func stripECHParams(params []dns.SVCBKeyValue) ([]dns.SVCBKeyValue, int) {
	hasECH := false
	for _, p := range params {
		if p != nil && (p.Key() == dns.SVCB_ECHCONFIG || isECHConfig(p)) {
			hasECH = true
			break
		}
	}
	if !hasECH {
		return params, 0
	}
	out := make([]dns.SVCBKeyValue, 0, len(params))
	removed := 0
	for _, p := range params {
		if p != nil && (p.Key() == dns.SVCB_ECHCONFIG || isECHConfig(p)) {
			removed++
			continue
		}
		out = append(out, p)
	}
	return out, removed
}

func isECHConfig(p dns.SVCBKeyValue) bool {
	_, ok := p.(*dns.SVCBECHConfig)
	return ok
}
