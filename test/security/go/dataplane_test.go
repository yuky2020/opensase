package securitytest

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/yuky2020/opensase/pkg/packet"
)

var syntheticPrefix = netip.MustParsePrefix("100.96.0.0/12")

// containerAddrs returns the IPv4 addresses and gateways of a docker container.
func containerAddrs(name string) []netip.Addr {
	out, err := exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.Gateway}} {{end}}", name).Output() //nolint:gosec // G204: fixed docker CLI, test-controlled name
	if err != nil {
		return nil
	}
	var as []netip.Addr
	for _, s := range strings.Fields(string(out)) {
		if a, err := netip.ParseAddr(s); err == nil {
			as = append(as, a)
		}
	}
	return as
}

// edgeCanReachIPv6 reports whether the dev Edge container itself has IPv6 WAN connectivity
// to target, distinguishing missing host IPv6 WAN from broken Edge IPv6 forwarding.
func edgeCanReachIPv6(target netip.AddrPort) bool {
	return exec.Command("docker", "exec", "opensase-edge-1", "nc", "-z", "-w", "4", target.Addr().String(), fmt.Sprint(target.Port())).Run() == nil //nolint:gosec // G204: fixed docker CLI, parsed AddrPort
}

// refusedByEdge requires an explicit RST (the Edge filter's rejection). A SYN-ACK means
// the attack got through; silence is inconclusive (could be a dead target).
func refusedByEdge(res tcpResult, what string) error {
	switch res {
	case rst:
		return nil
	case synAck:
		return fmt.Errorf("%s: SYN-ACK (reachable through the tunnel)", what)
	}
	return fmt.Errorf("%s: no answer (want an RST from the Edge filter)", what)
}

func TestDataPlane(t *testing.T) {
	f := stack(t)
	a1, err := f.openTunnel(f.devA1)
	if err != nil {
		check(t, "SEC-DP-000", "raw WireGuard tunnel to the Edge (harness)", "", func(*testing.T) error { return skipf("%v", err) })
		return
	}
	defer a1.close()
	edgeIP := netip.MustParseAddr(edgeTunIP)

	// Positive controls. Without them a "refused" result could be a dead tunnel.
	var web netip.Addr
	check(t, "SEC-DP-000", "control: tunnel up, Edge DNS answers, example.com:443 reachable", "", func(t *testing.T) error {
		ips := a1.resolve4("example.com")
		if len(ips) == 0 {
			return skipf("Edge resolver gave no A record for example.com (no internet?)")
		}
		web = ips[0]
		if r := a1.probe(netip.AddrPortFrom(web, 443), netip.Addr{}, nil, 5*time.Second); r != synAck {
			web = netip.Addr{}
			return skipf("example.com:443 via the tunnel: %s (no internet?)", r)
		}
		return nil
	})
	needWeb := func() error {
		if !web.IsValid() {
			return skipf("needs internet through the Edge (SEC-DP-000)")
		}
		return nil
	}

	// Built-in deny: cloud metadata / link-local, loopback, this-network, multicast.
	check(t, "SEC-DP-001", "built-in deny: metadata, link-local, loopback, 0/8, multicast (RST from Edge)", "", func(t *testing.T) error {
		var errs []error
		for _, d := range []string{"169.254.169.254:80", "169.254.1.1:443", "127.0.0.1:8443", "127.0.0.1:9443", "0.0.0.1:80", "224.0.0.1:80", "240.0.0.1:80"} {
			if err := refusedByEdge(a1.probe(netip.MustParseAddrPort(d), netip.Addr{}, nil, 3*time.Second), d); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})

	// The Edge's own addresses, the Control Plane and the docker networks behind them.
	check(t, "SEC-DP-002", "Edge host, Control Plane and docker/private ranges unreachable from the tunnel", "", func(t *testing.T) error {
		targets := []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:80"), netip.MustParseAddrPort("192.168.1.1:80"), netip.MustParseAddrPort("172.17.0.1:80")}
		for _, a := range containerAddrs("opensase-edge-1") {
			targets = append(targets, netip.AddrPortFrom(a, 8443), netip.AddrPortFrom(a, 8444))
		}
		for _, a := range containerAddrs("opensase-controlplane-1") {
			targets = append(targets, netip.AddrPortFrom(a, 9443))
		}
		if len(targets) < 6 {
			return skipf("docker inspect gave no container addresses")
		}
		var errs []error
		for _, d := range targets {
			if err := refusedByEdge(a1.probe(d, netip.Addr{}, nil, 3*time.Second), d.String()); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})

	// The Edge's tunnel address serves only DNS (and ping): its HTTPS, broker and ZTNA
	// listener ports are refused.
	check(t, "SEC-DP-003", "Edge tunnel address: only DNS/ICMP (8443, 8444, 15001, 22 refused)", "", func(t *testing.T) error {
		var errs []error
		for _, p := range []uint16{8443, 8444, 15001, 22, 80} {
			if err := refusedByEdge(a1.probe(netip.AddrPortFrom(edgeIP, p), netip.Addr{}, nil, 3*time.Second), fmt.Sprintf("%s:%d", edgeIP, p)); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})

	// DNS bypass: third-party DNS over UDP/TCP, DoT, DoH by IP and by snooped name.
	check(t, "SEC-DP-004", "DNS bypass blocked: third-party DNS (udp/tcp), DoT, DoH", "", func(t *testing.T) error {
		if a1.dnsQuery(edgeIP, "example.com", dns.TypeA) == nil {
			return skipf("control: Edge resolver did not answer")
		}
		var errs []error
		for _, s := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"} {
			if r := a1.dnsQuery(netip.MustParseAddr(s), "example.com", dns.TypeA); r != nil {
				errs = append(errs, fmt.Errorf("udp DNS to %s answered", s))
			}
		}
		for _, d := range []string{"8.8.8.8:53", "1.1.1.1:853", "9.9.9.9:853", "1.1.1.1:443", "8.8.8.8:443"} {
			if err := refusedByEdge(a1.probe(netip.MustParseAddrPort(d), netip.Addr{}, nil, 3*time.Second), d); err != nil {
				errs = append(errs, err)
			}
		}
		// DoH by name: resolve through the Edge (it snoops the answer), then HTTPS to it.
		for _, n := range []string{"cloudflare-dns.com", "dns.quad9.net"} {
			ips := a1.resolve4(n)
			if len(ips) == 0 {
				continue
			}
			if err := refusedByEdge(a1.probe(netip.AddrPortFrom(ips[0], 443), netip.Addr{}, nil, 3*time.Second), n+" "+ips[0].String()+":443"); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})

	// Tenant port policy is enforced at the Edge too (not only on the device).
	check(t, "SEC-DP-005", "tenant port policy (block tcp/25) enforced at the Edge; 587 control", "", func(t *testing.T) error {
		if err := needWeb(); err != nil {
			return err
		}
		ips := a1.resolve4("smtp.gmail.com")
		if len(ips) == 0 {
			return skipf("no A record for smtp.gmail.com")
		}
		if r := a1.probe(netip.AddrPortFrom(ips[0], 587), netip.Addr{}, nil, 5*time.Second); r != synAck {
			return skipf("control: smtp.gmail.com:587 -> %s", r)
		}
		return refusedByEdge(a1.probe(netip.AddrPortFrom(ips[0], 25), netip.Addr{}, nil, 5*time.Second), "smtp.gmail.com:25")
	})

	// Mid-stream segments without conntrack state are dropped (a stray ACK forwarded to
	// a real server would be answered with an RST by that server).
	check(t, "SEC-DP-006", "TCP segments without a SYN (no conntrack state) are dropped", "", func(t *testing.T) error {
		if err := needWeb(); err != nil {
			return err
		}
		dst := netip.AddrPortFrom(web, 443)
		for _, fl := range []uint8{packet.FlagACK, packet.FlagACK | packet.FlagPSH, packet.FlagFIN | packet.FlagACK} {
			sp := netip.AddrPortFrom(a1.ip4, ephemeral())
			a1.send(tcpSeg(sp, dst, fl, 5000, 7000))
			if p := a1.wait(3*time.Second, func(p *packet.Packet) bool { return p.Protocol == packet.ProtoTCP && p.DstPort == sp.Port() }); p != nil {
				return fmt.Errorf("stateless segment flags %#x forwarded (reply flags %#x)", fl, p.TCPFlags)
			}
		}
		return nil
	})

	// Spoofed sources: tunnel A1 sends with the tunnel address of A2 (same tenant) and of
	// B1 (other tenant). WireGuard cryptokey routing must drop them: the victim tunnel must
	// not receive the SYN-ACK. Control: the victim's own SYN is answered.
	check(t, "SEC-DP-007", "spoofed source IPs inside the tunnel are dropped (cryptokey routing)", "", func(t *testing.T) error {
		if err := needWeb(); err != nil {
			return err
		}
		a2, err := f.openTunnel(f.devA2)
		if err != nil {
			return skipf("second tunnel: %v", err)
		}
		defer a2.close()
		b1, err := f.openTunnel(f.devB1)
		if err != nil {
			return skipf("tenant B tunnel: %v", err)
		}
		defer b1.close()
		dst := netip.AddrPortFrom(web, 443)
		if r := a2.probe(dst, netip.Addr{}, nil, 5*time.Second); r != synAck {
			return skipf("control: victim tunnel own SYN -> %s", r)
		}
		var errs []error
		for name, v := range map[string]*tunnel{"same tenant": a2, "other tenant": b1} {
			if r := a1.probe(dst, v.ip4, v, 4*time.Second); r != none {
				errs = append(errs, fmt.Errorf("SYN spoofed as %s tunnel IP %s: victim received %s", name, v.ip4, r))
			}
		}
		// Off-pool source: nothing may come back on the attacker tunnel either.
		if r := a1.probe(dst, netip.MustParseAddr("203.0.113.5"), nil, 3*time.Second); r != none {
			errs = append(errs, fmt.Errorf("off-pool source 203.0.113.5: %s", r))
		}
		// Device to device: no tunnel-to-tunnel traffic at all.
		sp := netip.AddrPortFrom(a1.ip4, ephemeral())
		a1.send(tcpSeg(sp, netip.AddrPortFrom(b1.ip4, 22), packet.FlagSYN, 1, 0))
		if p := b1.wait(3*time.Second, func(p *packet.Packet) bool { return p.SrcPort == sp.Port() }); p != nil {
			errs = append(errs, errors.New("device-to-device SYN delivered across tenants"))
		}
		a1.send(icmpEcho(a1.ip4, b1.ip4, 0x5ed))
		if p := b1.wait(3*time.Second, func(p *packet.Packet) bool { return p.Protocol == packet.ProtoICMP }); p != nil {
			errs = append(errs, errors.New("device-to-device ping delivered"))
		}
		return errors.Join(errs...)
	})

	// ZTNA synthetic range (ADR-0013): unmapped addresses and other tenants' apps refused.
	check(t, "SEC-DP-008", "ZTNA: unmapped synthetic address, UDP, and other tenant's app refused", "", func(t *testing.T) error {
		mine := a1.resolve4(f.appA)
		if len(mine) == 0 || !syntheticPrefix.Contains(mine[0]) {
			return skipf("control: own private app %s -> %s (want synthetic)", f.appA, addrsString(mine))
		}
		b1, err := f.openTunnel(f.devB1)
		if err != nil {
			return skipf("tenant B tunnel: %v", err)
		}
		defer b1.close()
		var errs []error
		if got := b1.resolve4(f.appA); len(got) > 0 && syntheticPrefix.Contains(got[0]) {
			errs = append(errs, fmt.Errorf("tenant B device got a synthetic address for tenant A's app: %s", addrsString(got)))
		}
		if err := refusedByEdge(b1.probe(netip.AddrPortFrom(mine[0], 80), netip.Addr{}, nil, 3*time.Second), "tenant B to tenant A's synthetic "+mine[0].String()); err != nil {
			errs = append(errs, err)
		}
		unmapped := netip.MustParseAddr("100.111.250.250")
		if err := refusedByEdge(a1.probe(netip.AddrPortFrom(unmapped, 80), netip.Addr{}, nil, 3*time.Second), "unmapped synthetic"); err != nil {
			errs = append(errs, err)
		}
		// UDP to a synthetic address is never brokered.
		sp := netip.AddrPortFrom(a1.ip4, ephemeral())
		a1.send(udpDgram(sp, netip.AddrPortFrom(mine[0], 80), []byte("x")))
		if p := a1.wait(2*time.Second, func(p *packet.Packet) bool { return p.Protocol == packet.ProtoUDP && p.DstPort == sp.Port() }); p != nil {
			errs = append(errs, errors.New("UDP to a synthetic address got a UDP answer"))
		}
		return errors.Join(errs...)
	})

	// IPv6 through the tunnel (issue #74): denied ranges, NAT64, DNS/DoT/DoH bypass and
	// tenant policy are refused with RST; allowed global IPv6 is forwarded when the Edge
	// host has IPv6 WAN.
	check(t, "SEC-DP-009", "IPv6: denied ranges, NAT64, DNS/DoT/DoH bypass and tcp/25 refused; global v6 forwarded", "", func(t *testing.T) error {
		if !a1.ip6.IsValid() {
			return skipf("no tunnel IPv6 address")
		}
		pingOK := false
		for i := 0; i < 2 && !pingOK; i++ {
			pingOK = a1.ping6()
		}
		if !pingOK {
			return fmt.Errorf("control: ICMPv6 echo to Edge %s failed", edgeTunIP6)
		}
		var errs []error
		// Loopback, link-local, ULA, NAT64 (RFC 6052 / RFC 8215), discard-only (RFC 6666),
		// benchmarking (RFC 5180), and Edge non-DNS ports must all be refused with RST.
		denied := []string{
			"[::1]:8443",
			"[fe80::1]:80",
			"[fd00::1]:80",
			"[fd7a:5a5e::1]:8443",
			"[fd7a:5a5e::1]:8444",
			"[fd7a:5a5e::1]:15001",
			"[64:ff9b::a9fe:a9fe]:80",
			"[64:ff9b:1::a9fe:a9fe]:80",
			"[100::1]:80",
			"[2001:2::1]:80",
		}
		for _, d := range denied {
			if err := refusedByEdge(a1.probe(netip.MustParseAddrPort(d), netip.Addr{}, nil, 3*time.Second), d); err != nil {
				errs = append(errs, err)
			}
		}
		// Third-party IPv6 DNS (UDP/TCP), DoT (853) and built-in IPv6 DoH endpoints (443).
		for _, s := range []string{"2001:4860:4860::8888", "2606:4700:4700::1111", "2620:fe::fe"} {
			if r := a1.dnsQuery(netip.MustParseAddr(s), "example.com", dns.TypeAAAA); r != nil {
				errs = append(errs, fmt.Errorf("IPv6 udp DNS to %s answered", s))
			}
		}
		dnsBypass := []string{
			"[2001:4860:4860::8888]:53",
			"[2001:4860:4860::8888]:853",
			"[2001:4860:4860::8888]:443",
			"[2606:4700:4700::1111]:53",
			"[2606:4700:4700::1111]:853",
			"[2606:4700:4700::1111]:443",
			"[2620:fe::fe]:443",
		}
		for _, d := range dnsBypass {
			if err := refusedByEdge(a1.probe(netip.MustParseAddrPort(d), netip.Addr{}, nil, 3*time.Second), d); err != nil {
				errs = append(errs, err)
			}
		}
		// Resolve example.com AAAA via the Edge IPv6 resolver and check tenant policy
		// (block tcp/25) plus global IPv6 HTTPS egress.
		ips := a1.resolve6("example.com")
		smtpDst := netip.MustParseAddrPort("[2001:db8::1]:25")
		if len(ips) > 0 {
			smtpDst = netip.AddrPortFrom(ips[0], 25)
		}
		if err := refusedByEdge(a1.probe(smtpDst, netip.Addr{}, nil, 4*time.Second), "IPv6 tcp/25 "+smtpDst.String()); err != nil {
			errs = append(errs, err)
		}
		if len(ips) == 0 {
			if web.IsValid() {
				errs = append(errs, errors.New("Edge IPv6 resolver gave no AAAA record for example.com"))
			}
		} else {
			target := netip.AddrPortFrom(ips[0], 443)
			switch res := a1.probe(target, netip.Addr{}, nil, 5*time.Second); res {
			case synAck:
			case rst:
				errs = append(errs, fmt.Errorf("allowed global IPv6 %s refused with RST by Edge", target))
			default:
				if edgeCanReachIPv6(target) {
					errs = append(errs, fmt.Errorf("allowed global IPv6 %s: %s (Edge has IPv6 WAN)", target, res))
				} else {
					t.Logf("global IPv6 %s: %s and Edge container has no IPv6 WAN; skipping SYN-ACK check", target, res)
				}
			}
		}
		return errors.Join(errs...)
	})
}
