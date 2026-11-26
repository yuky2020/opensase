package controlplane

import (
	"strings"

	"github.com/yuky2020/opensase/pkg/store"
)

// deviceDNSNames gives every device "<device>.<user>" built from its name and user ID, unique
// in its tenant (issue #62); a clash gets the start of the device ID appended. Devices are in
// a stable order (ActiveSnapshots sorts by ID), so names do not move between calls.
func deviceDNSNames(act []store.ActiveSnapshot) map[string]string {
	out := make(map[string]string, len(act))
	used := map[string]bool{} // tenant + "/" + name
	for _, a := range act {
		d := a.Device
		name := dnsLabel(d.Name, d.ID) + "." + dnsLabel(d.UserID, "user")
		if used[d.TenantID+"/"+name] {
			name = dnsLabel(d.Name, d.ID) + "-" + dnsLabel(d.ID, "x")[:min(6, len(dnsLabel(d.ID, "x")))] + "." + dnsLabel(d.UserID, "user")
		}
		used[d.TenantID+"/"+name] = true
		out[d.ID] = name
	}
	return out
}

// dnsLabel turns s into a DNS label: lower case, [a-z0-9-], at most 40 characters, no leading
// or trailing hyphen; fallback if nothing is left.
func dnsLabel(s, fallback string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0:
			b.WriteByte('-')
		}
		if b.Len() >= 40 {
			break
		}
	}
	l := strings.Trim(b.String(), "-")
	for strings.Contains(l, "--") {
		l = strings.ReplaceAll(l, "--", "-")
	}
	if l == "" {
		if fallback == "" {
			return "x"
		}
		return dnsLabel(fallback, "x")
	}
	return l
}
