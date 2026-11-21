package edge

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/yuky2020/opensase/pkg/packet"
	"github.com/yuky2020/opensase/pkg/peek"
	"github.com/yuky2020/opensase/pkg/policy"
)

// Web control (ADR-0017). The Edge reads the hostname a TCP flow is really for (TLS SNI or
// HTTP Host) from the first bytes the client sends, without decrypting anything, and
// re-applies policy to it:
//   - the built-in Edge rules (for example the DoH resolvers);
//   - the DNS policy, including SaaS app blocklists, so names the client never resolved
//     through the Edge (hard-coded addresses, stale caches) are still enforced;
//   - firewall domain rules, so a flow allowed for one name cannot carry another one.
//
// The segments are forwarded while the message is incomplete. The decision is taken on the
// segment that completes it, before that segment is forwarded, so a blocked server never
// receives a complete ClientHello or request head.

// LayerWeb is the decision layer of flows blocked on their hostname.
const LayerWeb = "web"

// hostPeek reassembles the start of the client's byte stream of one flow.
type hostPeek struct {
	mu   sync.Mutex
	buf  []byte
	next uint32 // next expected client sequence number
	done bool
}

// newHostPeek starts tracking at the SYN p (whose payload, with TCP Fast Open, is kept).
func newHostPeek(p *packet.Packet) *hostPeek {
	return &hostPeek{next: p.Seq + 1 + uint32(len(p.Payload)), buf: append([]byte(nil), p.Payload...)}
}

// add appends the new bytes of segment p. It returns false if p starts beyond the bytes seen
// so far: such a segment is dropped until the missing ones are retransmitted, because the
// message must be read in order before any of it completes at the server.
func (h *hostPeek) add(p *packet.Packet) bool {
	switch d := int32(p.Seq - h.next); {
	case d > 0:
		return false
	case d < 0: // retransmission, possibly carrying new bytes after the known ones
		skip := int(-d)
		if skip >= len(p.Payload) {
			return true
		}
		h.buf = append(h.buf, p.Payload[skip:]...)
		h.next += uint32(len(p.Payload) - skip)
	default:
		h.buf = append(h.buf, p.Payload...)
		h.next += uint32(len(p.Payload))
	}
	return true
}

// inspect feeds an outbound segment of cn to its hostPeek. It returns false when the
// segment must not be forwarded: out of order while peeking, or the flow was just blocked
// (then the device has been sent a reset).
func (f *Filter) inspect(cn *conn, c *policy.Compiled, p *packet.Packet, pkt []byte, dst netip.Addr, now time.Time) bool {
	h := cn.peek
	h.mu.Lock()
	if h.done {
		h.mu.Unlock()
		return true
	}
	if !h.add(p) {
		h.mu.Unlock()
		return false
	}
	host, _, r := peek.Host(h.buf)
	if r == peek.NeedMore {
		h.mu.Unlock()
		return true
	}
	h.done, h.buf = true, nil
	h.mu.Unlock()
	if r != peek.Found || host == "" {
		return true // not TLS or HTTP, or no name: the decision on the address stands
	}
	cn.mu.Lock()
	cn.flow.Domain = host
	flow := cn.flow
	cn.mu.Unlock()
	dec, block := f.hostDecision(c, flow, dst)
	if !block {
		return true
	}
	cn.mu.Lock()
	cn.decision = dec
	cn.mu.Unlock()
	cn.blocked.Store(true)
	f.e.flows.add(cn.record(now))
	f.reject(p, pkt)
	return false
}

// hostDecision re-applies policy to flow, whose Domain is now the hostname seen on the wire.
// Only blocks matter: an "ask" or "allow" here leaves the flow as it was decided.
func (f *Filter) hostDecision(c *policy.Compiled, flow policy.Flow, dst netip.Addr) (policy.Decision, bool) {
	if d, builtin := f.e.guard.check(dst, flow); builtin && d.Action != policy.ActionAllow {
		return d, true
	}
	if blocked, list := c.EvaluateDNS(flow.Domain); blocked {
		rule := list
		if !strings.HasPrefix(list, "saas:") {
			rule = "dns:" + list
		}
		return policy.Decision{Action: policy.ActionBlock, RuleID: rule, Layer: LayerWeb, Log: true}, true
	}
	if d := c.Evaluate(flow, true); d.Action == policy.ActionBlock {
		rule := d.Layer
		if d.RuleID != "" {
			rule += ":" + d.RuleID
		}
		return policy.Decision{Action: policy.ActionBlock, RuleID: rule, Layer: LayerWeb, Log: true}, true
	}
	return policy.Decision{}, false
}
