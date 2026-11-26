package policy

import (
	"fmt"
	"slices"
)

type compiledGrant struct {
	ruleID  string
	all     bool
	users   []string
	devices []string
	proto   string
	ports   []PortRange
}

func compileMesh(c *Compiled, grants []MeshGrant) error {
	for i, g := range grants {
		field := fmt.Sprintf("meshInbound[%d]", i)
		switch g.Protocol {
		case "", "tcp", "udp", "icmp":
		default:
			return verr(field+".protocol", "protocol must be tcp, udp, icmp or empty")
		}
		if !g.FromAll && len(g.FromUsers) == 0 && len(g.FromDevices) == 0 {
			return verr(field, "a grant needs fromAll, fromUsers or fromDevices")
		}
		for _, pr := range g.Ports {
			if pr.From == 0 || (pr.To != 0 && pr.To < pr.From) {
				return verr(field+".ports", "invalid port range %d-%d", pr.From, pr.To)
			}
		}
		if g.RuleID == "" {
			return verr(field+".ruleId", "rule ID required")
		}
		c.mesh = append(c.mesh, compiledGrant{ruleID: "mesh:" + g.RuleID, all: g.FromAll, users: g.FromUsers, devices: g.FromDevices, proto: g.Protocol, ports: g.Ports})
	}
	return nil
}

// MeshAllows reports whether a flow from device fromDevice of user fromUser (same tenant)
// may reach this device, and the rule that allows it (ADR-0034).
func (c *Compiled) MeshAllows(fromUser, fromDevice, proto string, port uint16) (string, bool) {
	for _, g := range c.mesh {
		if g.proto != "" && g.proto != proto {
			continue
		}
		if !g.all && !slices.Contains(g.users, fromUser) && !slices.Contains(g.devices, fromDevice) {
			continue
		}
		if len(g.ports) > 0 && proto != "icmp" {
			ok := false
			for _, pr := range g.ports {
				to := pr.To
				if to == 0 {
					to = pr.From
				}
				if port >= pr.From && port <= to {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		return g.ruleID, true
	}
	return "", false
}

// UserID is the user the snapshot belongs to.
func (c *Compiled) UserID() string { return c.userID }

// HasMesh reports whether some device may open flows to this one (ADR-0034).
func (c *Compiled) HasMesh() bool { return len(c.mesh) > 0 }
