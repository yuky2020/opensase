package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Internal DNS (issue #62): names the Edge resolver answers itself (DNSPolicy.Zone for device
// names, DNSPolicy.Records) and zones it forwards to other resolvers (DNSPolicy.Forwarders).

// DNS record types the Edge answers.
const (
	RecordA     = "A"
	RecordAAAA  = "AAAA"
	RecordCNAME = "CNAME"
	RecordTXT   = "TXT"
)

const (
	maxDNSRecords    = 2000
	maxForwarders    = 32
	defaultRecordTTL = 300
)

// CompiledRecord is one validated DNSRecord.
type CompiledRecord struct {
	Type  string
	Addr  netip.Addr // A, AAAA
	Value string     // CNAME target (normalized) or TXT text
	TTL   uint32
}

// CompiledForwarder is one validated DNSForwarder.
type CompiledForwarder struct {
	Zone    string           // normalized, no trailing dot
	Servers []netip.AddrPort // port 53 when the policy gives none
}

func normName(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }

func compileInternalDNS(c *Compiled, d *DNSPolicy) error {
	if d.Zone != "" {
		z := normName(d.Zone)
		if err := validName(z); err != nil || !strings.Contains(z, ".") {
			return verr("dns.zone", "invalid zone %q", d.Zone)
		}
		c.zone = z
	}
	if len(d.Records) > maxDNSRecords {
		return verr("dns.records", "at most %d records", maxDNSRecords)
	}
	c.records = map[string][]CompiledRecord{}
	for i, r := range d.Records {
		field := fmt.Sprintf("dns.records[%d]", i)
		name := normName(r.Name)
		if validName(name) != nil {
			return verr(field+".name", "invalid name %q", r.Name)
		}
		cr := CompiledRecord{Type: strings.ToUpper(r.Type), TTL: defaultRecordTTL}
		if r.TTL > 0 {
			cr.TTL = uint32(min(r.TTL, 86400)) //nolint:gosec // G115: bounded above
		}
		switch cr.Type {
		case RecordA, RecordAAAA:
			a, err := netip.ParseAddr(r.Value)
			if err != nil || (cr.Type == RecordA) != a.Is4() {
				return verr(field+".value", "%s record needs an IPv%s address", cr.Type, map[bool]string{true: "4", false: "6"}[cr.Type == RecordA])
			}
			cr.Addr = a
		case RecordCNAME:
			cr.Value = normName(r.Value)
			if validName(cr.Value) != nil {
				return verr(field+".value", "invalid CNAME target %q", r.Value)
			}
			if len(c.records[name]) > 0 {
				return verr(field, "a CNAME cannot share its name with other records")
			}
		case RecordTXT:
			if len(r.Value) > 255 {
				return verr(field+".value", "TXT value longer than 255 bytes")
			}
			cr.Value = r.Value
		default:
			return verr(field+".type", "type must be A, AAAA, CNAME or TXT")
		}
		if prev := c.records[name]; len(prev) > 0 && prev[0].Type == RecordCNAME {
			return verr(field, "a CNAME cannot share its name with other records")
		}
		c.records[name] = append(c.records[name], cr)
	}
	if len(d.Forwarders) > maxForwarders {
		return verr("dns.forwarders", "at most %d forwarders", maxForwarders)
	}
	for i, f := range d.Forwarders {
		field := fmt.Sprintf("dns.forwarders[%d]", i)
		cf := CompiledForwarder{Zone: normName(f.Zone)}
		if validName(cf.Zone) != nil {
			return verr(field+".zone", "invalid zone %q", f.Zone)
		}
		if len(f.Servers) == 0 || len(f.Servers) > 4 {
			return verr(field+".servers", "1 to 4 servers")
		}
		for _, sv := range f.Servers {
			ap, err := netip.ParseAddrPort(sv)
			if err != nil {
				a, aerr := netip.ParseAddr(sv)
				if aerr != nil {
					return verr(field+".servers", "invalid server %q (IP or IP:port)", sv)
				}
				ap = netip.AddrPortFrom(a, 53)
			}
			cf.Servers = append(cf.Servers, ap)
		}
		c.forwarders = append(c.forwarders, cf)
	}
	// Longest zone first, so the most specific forwarder wins.
	slices.SortStableFunc(c.forwarders, func(a, b CompiledForwarder) int { return len(b.Zone) - len(a.Zone) })
	c.logQueries = d.LogQueries
	return nil
}

// Zone is the internal zone of device names ("" if none).
func (c *Compiled) Zone() string { return c.zone }

// Records returns the records for name (normalized), if any.
func (c *Compiled) Records(name string) []CompiledRecord { return c.records[name] }

// Forwarder returns the most specific forwarder whose zone is name or a parent of it.
func (c *Compiled) Forwarder(name string) (CompiledForwarder, bool) {
	for _, f := range c.forwarders {
		if name == f.Zone || strings.HasSuffix(name, "."+f.Zone) {
			return f, true
		}
	}
	return CompiledForwarder{}, false
}

// LogQueries reports whether allowed DNS queries are recorded as flows.
func (c *Compiled) LogQueries() bool { return c.logQueries }
