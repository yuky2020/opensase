package securitytest

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
)

// TestZZEnrollRateLimit runs last (file order): it exhausts this host's enrollment budget
// for one minute. Fixtures and other checks that enroll later wait out Retry-After (do).
func TestZZEnrollRateLimit(t *testing.T) {
	f := stack(t)

	// Enrollment brute force: wrong provisioning keys in a burst must hit 429 with
	// Retry-After within the per-IP budget (30 failed attempts/minute; earlier checks may
	// already have used part of it, so the first 429 must come at attempt <= 31).
	check(t, "SEC-IN-008", "enroll / connector-enroll brute force is rate-limited (429 + Retry-After)", "", func(t *testing.T) error {
		csr := csrPEM(newKey())
		c := f.anon()
		noRetry := map[string]string{hdrNoRetry: "1"}
		for i := range 60 {
			u, b := "/v1/enroll", any(api.EnrollRequest{ProvisioningKey: fmt.Sprintf("osk_sectestbrute%04d", i), DeviceName: "x", Platform: "linux", CSRPEM: csr})
			if i%2 == 1 {
				u, b = "/v1/connector/enroll", api.ConnectorEnrollRequest{ProvisioningKey: fmt.Sprintf("osc_sectestbrute%04d", i), CSRPEM: csr}
			}
			r := do(c, "POST", f.cpURL+u, b, noRetry)
			switch r.code {
			case http.StatusForbidden:
				continue
			case http.StatusTooManyRequests:
				if r.hdr.Get("Retry-After") == "" {
					return fmt.Errorf("429 without Retry-After after %d attempts", i)
				}
				if i > 31 {
					return fmt.Errorf("first 429 only after %d failed attempts (limit 30)", i)
				}
				return nil
			default:
				return fmt.Errorf("attempt %d: unexpected %s", i, r)
			}
		}
		return fmt.Errorf("60 wrong keys in a burst, no 429: online guessing is unthrottled (%v)", time.Now().Format(time.TimeOnly))
	})
}
