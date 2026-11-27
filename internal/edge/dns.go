package edge

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/safesearch"
)

// resolver is the Edge DNS resolver on the tunnel addresses. It applies the querying
// device's DNS policy (EvaluateDNS), forwards allowed queries upstream, blocks answers whose
// CNAME chain hits a blocked name, and snoops A/AAAA answers for domain rules.
type resolver struct {
	e        *Edge
	upstream string
	udp      *dns.Client
	tcp      *dns.Client
}

func newResolver(e *Edge, upstream string) *resolver {
	return &resolver{
		e:        e,
		upstream: upstream,
		udp:      &dns.Client{Net: "udp", Timeout: 4 * time.Second, UDPSize: dns.DefaultMsgSize},
		tcp:      &dns.Client{Net: "tcp", Timeout: 4 * time.Second},
	}
}

func remoteAddr(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.AddrPort().Addr().Unmap()
	case *net.TCPAddr:
		return v.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

// dnsLocal returns the destination IP and transport protocol of a DNS query from the
// listener's local address, falling back to EdgeIPv4 and "udp".
func dnsLocal(a net.Addr) (dstIP, proto string) {
	proto = "udp"
	if _, ok := a.(*net.TCPAddr); ok {
		proto = "tcp"
	}
	dst := remoteAddr(a)
	if !dst.IsValid() || dst.IsUnspecified() {
		dst = EdgeIPv4
	}
	return dst.String(), proto
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// ServeDNS implements dns.Handler.
func (rs *resolver) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	defer w.Close()
	rs.e.obs.dnsQueries.Inc()
	client := remoteAddr(w.RemoteAddr())
	d := rs.e.reg.byTunnelIP(client)
	var c *policy.Compiled
	if d != nil {
		c = d.compiled.Load()
	}
	if c == nil || len(req.Question) != 1 || req.Opcode != dns.OpcodeQuery {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	name := normalize(q.Name)
	// Internal names (issue #62): device names in the tenant zone and the tenant's records
	// are answered here and never forwarded.
	if rs.answerInternal(w, req, c, d, name, q) {
		return
	}
	if blocked, list := c.EvaluateDNS(name); blocked {
		rs.block(w, req, c, d, client, name, "dns:"+list, q)
		return
	}
	// SafeSearch (ADR-0025): covered names resolve to the provider's safe hostname.
	if c.SafeSearch() {
		if target, ok := safesearch.Target(name); ok {
			sctx, cancel := context.WithTimeout(rs.e.ctx, 5*time.Second)
			defer cancel()
			rs.safeAnswer(sctx, w, req, d.id, name, target, q)
			return
		}
	}
	// Web categories (ADR-0022), unless the tenant allowed the name explicitly.
	if cat, ok := rs.e.category(c, name); ok {
		rs.block(w, req, c, d, client, name, "cat:"+cat, q)
		return
	}
	// Private app names (ADR-0013) are answered here and never forwarded upstream.
	if v := d.ztna.Load(); v != nil {
		if _, ok := v.app(name); ok {
			rs.synthesize(w, req, d.id, v.tenant, name, q)
			return
		}
	}

	ctx, cancel := context.WithTimeout(rs.e.ctx, 5*time.Second)
	defer cancel()
	servers := []string{rs.upstream}
	if f, ok := c.Forwarder(name); ok { // conditional forwarding (issue #62)
		servers = servers[:0]
		for _, sv := range f.Servers {
			servers = append(servers, sv.String())
		}
	}
	var resp *dns.Msg
	var err error
	for _, server := range servers {
		resp, _, err = rs.udp.ExchangeContext(ctx, req, server)
		if err == nil && resp.Truncated {
			resp, _, err = rs.tcp.ExchangeContext(ctx, req, server)
		}
		if err == nil && resp != nil {
			break
		}
	}
	if err != nil || resp == nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	// CNAME cloaking: a permitted name that aliases a blocked one is blocked too.
	for _, rr := range resp.Answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			target := normalize(cn.Target)
			if blocked, list := c.EvaluateDNS(target); blocked {
				rs.block(w, req, c, d, client, name, "dns:"+list, q)
				return
			}
			if cat, ok := rs.e.category(c, target); ok {
				rs.block(w, req, c, d, client, name, "cat:"+cat, q)
				return
			}
		}
	}
	now := time.Now()
	for _, rr := range resp.Answer {
		var ip netip.Addr
		switch v := rr.(type) {
		case *dns.A:
			ip, _ = netip.AddrFromSlice(v.A.To4())
		case *dns.AAAA:
			ip, _ = netip.AddrFromSlice(v.AAAA)
			ip = ip.Unmap()
		default:
			continue
		}
		if ip.IsValid() {
			rs.e.snoop.add(d.id, ip, name, time.Duration(rr.Header().Ttl)*time.Second, now)
		}
	}
	if c.BlockECH() {
		stripECH(resp)
	}
	if c.LogQueries() {
		dst, proto := dnsLocal(w.LocalAddr())
		rs.e.flows.add(api.FlowRecord{
			Start: now, End: now, Where: "edge", DeviceID: d.id,
			Flow:     policy.Flow{Protocol: proto, SrcIP: client.String(), DstIP: dst, DstPort: 53, Domain: name},
			Decision: policy.Decision{Action: policy.ActionAllow, RuleID: "dns:query", Layer: "dns", Log: true},
		})
	}
	resp.Id = req.Id
	_ = w.WriteMsg(resp)
}

// answerInternal answers device names in the tenant zone and the tenant's records (issue
// #62). It reports whether it answered.
func (rs *resolver) answerInternal(w dns.ResponseWriter, req *dns.Msg, c *policy.Compiled, d *device, name string, q dns.Question) bool {
	if z := c.Zone(); z != "" && (name == z || strings.HasSuffix(name, "."+z)) && len(c.Records(name)) == 0 {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative, m.RecursionAvailable = true, true
		var target *device
		if label := strings.TrimSuffix(strings.TrimSuffix(name, z), "."); label != "" {
			target = rs.e.reg.byDNSName(d.tenantID, label)
		}
		if target == nil {
			if name != z {
				m.SetRcode(req, dns.RcodeNameError)
			}
			_ = w.WriteMsg(m)
			return true
		}
		rs.e.reg.mu.Lock()
		ip4, ip6, has := target.ip4, target.ip6, target.offset != 0
		rs.e.reg.mu.Unlock()
		if has && q.Qclass == dns.ClassINET {
			hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 60}
			switch q.Qtype {
			case dns.TypeA:
				hdr.Rrtype = dns.TypeA
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip4.AsSlice()})
			case dns.TypeAAAA:
				if rs.e.ipv6 {
					hdr.Rrtype = dns.TypeAAAA
					m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip6.AsSlice()})
				}
			}
		}
		_ = w.WriteMsg(m)
		return true
	}
	recs := c.Records(name)
	if len(recs) == 0 {
		return false
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative, m.RecursionAvailable = true, true
	for _, r := range recs {
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: r.TTL}
		switch {
		case r.Type == policy.RecordCNAME:
			hdr.Rrtype = dns.TypeCNAME
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(r.Value)})
			// Follow one internal CNAME level; other targets the client resolves itself.
			for _, t := range c.Records(r.Value) {
				th := dns.RR_Header{Name: dns.Fqdn(r.Value), Class: dns.ClassINET, Ttl: t.TTL}
				switch {
				case t.Type == policy.RecordA && q.Qtype == dns.TypeA:
					th.Rrtype = dns.TypeA
					m.Answer = append(m.Answer, &dns.A{Hdr: th, A: t.Addr.AsSlice()})
				case t.Type == policy.RecordAAAA && q.Qtype == dns.TypeAAAA:
					th.Rrtype = dns.TypeAAAA
					m.Answer = append(m.Answer, &dns.AAAA{Hdr: th, AAAA: t.Addr.AsSlice()})
				}
			}
		case r.Type == policy.RecordA && q.Qtype == dns.TypeA:
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: r.Addr.AsSlice()})
		case r.Type == policy.RecordAAAA && q.Qtype == dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: r.Addr.AsSlice()})
		case r.Type == policy.RecordTXT && q.Qtype == dns.TypeTXT:
			hdr.Rrtype = dns.TypeTXT
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{r.Value}})
		}
	}
	_ = w.WriteMsg(m)
	return true
}

// synthesize answers a private app name: A with the sticky synthetic address of
// (tenant, name), TTL synthTTL; every other type (AAAA included) with an empty NOERROR.
func (rs *resolver) synthesize(w dns.ResponseWriter, req *dns.Msg, deviceID, tenant, name string, q dns.Question) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = true
	if q.Qtype == dns.TypeA && q.Qclass == dns.ClassINET {
		now := time.Now()
		ip, err := rs.e.synth.assign(tenant, name, now)
		if err != nil {
			rs.e.log.Warn("synthetic address not assigned", "tenant", tenant, "name", name, "err", err)
			m.SetRcode(req, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
			return
		}
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: synthTTL},
			A:   ip.AsSlice(),
		})
		rs.e.snoop.add(deviceID, ip, name, synthTTL*time.Second, now)
	}
	_ = w.WriteMsg(m)
}

func (rs *resolver) block(w dns.ResponseWriter, req *dns.Msg, c *policy.Compiled, d *device, client netip.Addr, name, rule string, q dns.Question) {
	m := new(dns.Msg)
	if c.BlockResponse() == "zero" {
		m.SetReply(req)
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 60}
		switch q.Qtype {
		case dns.TypeA:
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IPv4zero})
		case dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IPv6zero})
		}
	} else {
		m.SetRcode(req, dns.RcodeNameError)
	}
	// Record before answering, so the record exists once the client has its answer.
	now := time.Now()
	dst, proto := dnsLocal(w.LocalAddr())
	rs.e.flows.add(api.FlowRecord{
		Start: now, End: now, Where: "edge", DeviceID: d.id,
		Flow:     policy.Flow{Protocol: proto, SrcIP: client.String(), DstIP: dst, DstPort: 53, Domain: name},
		Decision: policy.Decision{Action: policy.ActionBlock, RuleID: rule, Layer: "dns", Log: true},
	})
	_ = w.WriteMsg(m)
}

// serveDNS runs UDP and TCP listeners on addr until ctx is done.
func (rs *resolver) serveDNS(ctx context.Context, addr string) error {
	errc := make(chan error, 2)
	var servers []*dns.Server
	for _, network := range []string{"udp", "tcp"} {
		started := make(chan struct{})
		srv := &dns.Server{Addr: addr, Net: network, Handler: rs, NotifyStartedFunc: func() { close(started) }, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
		servers = append(servers, srv)
		go func() { errc <- srv.ListenAndServe() }()
		select {
		case <-started:
		case err := <-errc:
			for _, s := range servers[:len(servers)-1] {
				_ = s.Shutdown()
			}
			return err
		}
	}
	rs.e.log.Info("dns resolver listening", "addr", addr, "upstream", rs.upstream)
	go func() {
		<-ctx.Done()
		for _, s := range servers {
			_ = s.Shutdown()
		}
	}()
	return nil
}
