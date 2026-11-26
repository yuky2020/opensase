package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
	"github.com/yuky2020/opensase/pkg/store"
)

func boolPtr(b bool) *bool { return &b }

func (e *env) enrollWithPosture(key, platform string, p *api.Posture) (*http.Response, []byte, *api.EnrollResponse, *tls.Certificate) {
	e.t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	resp, b := e.do(e.admin, "POST", "/v1/enroll", api.EnrollRequest{
		ProvisioningKey: key,
		DeviceName:      "test-device",
		Platform:        platform,
		CSRPEM:          string(csr),
		Posture:         p,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		return resp, b, nil, nil
	}
	var er api.EnrollResponse
	if err := json.Unmarshal(b, &er); err != nil {
		e.t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	cert, err := tls.X509KeyPair([]byte(er.CertificatePEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
	if err != nil {
		e.t.Fatal(err)
	}
	return resp, b, &er, &cert
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0.0", "1.0", 0},
		{"1.2.3", "1.2.3", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3", "v1.2.3", 0},
		{"v1.2.3", "v1.2.3", 0},
		{"1.2", "1.2.0.0", 0},
		{"1.2.1", "1.2.0", 1},
		{"1.2.0", "1.2.1", -1},
		{"1.10.0", "1.2.0", 1},
		{"1.2.0", "1.10.0", -1},
		{"2.0.0", "1.99.99", 1},
		{"1.99.99", "2.0.0", -1},
		{"1.2.beta", "1.2.0", 0},
		{"1.2.1", "1.2.beta", 1},
		{"v2", "1.9.9.9", 1},
		{"0.0.1", "0.0.0", 1},
		{"0.0.0", "0.0.1", -1},
		{"", "", 0},
		{"v", "", 0},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s vs %s", tc.a, tc.b), func(t *testing.T) {
			got := compareVersions(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestPostureFailing(t *testing.T) {
	tests := []struct {
		name   string
		policy api.PosturePolicy
		report *api.Posture
		want   []string
	}{
		{
			name: "nil report with all checks set",
			policy: api.PosturePolicy{
				MinOSVersion:     map[string]string{"android": "14.0"},
				MinClientVersion: "1.0.0",
				Require:          []string{"managed", "firewall", "screenLock", "diskEncryption"},
			},
			report: nil,
			want:   []string{"osVersion", "clientVersion", "diskEncryption", "screenLock", "firewall", "managed"},
		},
		{
			name:   "nil report with empty policy",
			policy: api.PosturePolicy{},
			report: nil,
			want:   nil,
		},
		{
			name: "compliant android device",
			policy: api.PosturePolicy{
				MinOSVersion:     map[string]string{"android": "14.0"},
				MinClientVersion: "1.0.0",
				Require:          []string{"diskEncryption", "screenLock", "managed", "firewall"},
			},
			report: &api.Posture{
				OS:            "android",
				OSVersion:     "14.1.0",
				ClientVersion: "1.0.0",
				DiskEncrypted: boolPtr(true),
				ScreenLock:    boolPtr(true),
				Managed:       boolPtr(true),
				Firewall:      boolPtr(false), // firewall ignored on android
			},
			want: nil,
		},
		{
			name: "failing osVersion",
			policy: api.PosturePolicy{
				MinOSVersion: map[string]string{"android": "14.0"},
			},
			report: &api.Posture{
				OS:        "android",
				OSVersion: "13.9.0",
			},
			want: []string{"osVersion"},
		},
		{
			name: "failing clientVersion",
			policy: api.PosturePolicy{
				MinClientVersion: "1.2.0",
			},
			report: &api.Posture{
				OS:            "android",
				ClientVersion: "1.1.9",
			},
			want: []string{"clientVersion"},
		},
		{
			name: "unlisted OS platform in minOsVersion passes osVersion check",
			policy: api.PosturePolicy{
				MinOSVersion: map[string]string{"android": "14.0"},
			},
			report: &api.Posture{
				OS:        "linux",
				OSVersion: "6.1.0",
			},
			want: nil,
		},
		{
			name: "windows firewall required and failing",
			policy: api.PosturePolicy{
				Require: []string{"firewall"},
			},
			report: &api.Posture{
				OS:       "windows",
				Firewall: boolPtr(false),
			},
			want: []string{"firewall"},
		},
		{
			name: "windows firewall required and passing",
			policy: api.PosturePolicy{
				Require: []string{"firewall"},
			},
			report: &api.Posture{
				OS:       "windows",
				Firewall: boolPtr(true),
			},
			want: nil,
		},
		{
			name: "nil pointers for required checks fail",
			policy: api.PosturePolicy{
				Require: []string{"diskEncryption", "screenLock", "managed"},
			},
			report: &api.Posture{
				OS: "linux",
			},
			want: []string{"diskEncryption", "screenLock", "managed"},
		},
		{
			name: "fixed order check names",
			policy: api.PosturePolicy{
				MinOSVersion:     map[string]string{"windows": "11.0"},
				MinClientVersion: "2.0.0",
				Require:          []string{"managed", "firewall", "screenLock", "diskEncryption"},
			},
			report: &api.Posture{
				OS:            "windows",
				OSVersion:     "10.0",
				ClientVersion: "1.0",
				DiskEncrypted: boolPtr(false),
				ScreenLock:    boolPtr(false),
				Firewall:      boolPtr(false),
				Managed:       boolPtr(false),
			},
			want: []string{"osVersion", "clientVersion", "diskEncryption", "screenLock", "firewall", "managed"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := postureFailing(tc.policy, tc.report)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("postureFailing = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidatePosturePolicy(t *testing.T) {
	tests := []struct {
		name    string
		policy  api.PosturePolicy
		wantErr bool
		field   string
	}{
		{
			name: "valid full policy",
			policy: api.PosturePolicy{
				MinOSVersion: map[string]string{
					"android": "14.0",
					"windows": "11.0.22621",
					"linux":   "6.1",
					"macos":   "14.5",
					"ios":     "17.5",
				},
				MinClientVersion:   "1.0.0",
				Require:            []string{"diskEncryption", "screenLock", "firewall", "managed"},
				RemediationDomains: []string{"help.example.com", "*.remediation.org"},
			},
			wantErr: false,
		},
		{
			name: "unknown require name",
			policy: api.PosturePolicy{
				Require: []string{"antivirus"},
			},
			wantErr: true,
			field:   "posture.require[0]",
		},
		{
			name: "duplicate require name",
			policy: api.PosturePolicy{
				Require: []string{"diskEncryption", "diskEncryption"},
			},
			wantErr: true,
			field:   "posture.require[1]",
		},
		{
			name: "unknown platform key in minOsVersion",
			policy: api.PosturePolicy{
				MinOSVersion: map[string]string{"freebsd": "14.0"},
			},
			wantErr: true,
			field:   "posture.minOsVersion[freebsd]",
		},
		{
			name: "invalid version format in minOsVersion",
			policy: api.PosturePolicy{
				MinOSVersion: map[string]string{"android": "14.0.0.0.0"},
			},
			wantErr: true,
			field:   "posture.minOsVersion[android]",
		},
		{
			name: "invalid version format in minClientVersion",
			policy: api.PosturePolicy{
				MinClientVersion: "bad-version",
			},
			wantErr: true,
			field:   "posture.minClientVersion",
		},
		{
			name: "invalid remediation domain",
			policy: api.PosturePolicy{
				RemediationDomains: []string{"bad domain name"},
			},
			wantErr: true,
			field:   "posture.remediationDomains[0]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePosturePolicy(tc.policy)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validatePosturePolicy err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && tc.field != "" {
				var ve *policy.ValidationError
				if !strings.Contains(err.Error(), tc.field) && (ve == nil || ve.Field != tc.field) {
					t.Errorf("error %v does not mention field %q", err, tc.field)
				}
			}
		})
	}
}

func TestPostureEnrollment(t *testing.T) {
	e := newEnv(t)
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "acme", Name: "Acme"}, 201)
	e.adminDo("POST", "/v1/admin/tenants/acme/users", api.AdminUser{ID: "u1", Email: "u1@acme"}, 201)

	// Set posture requirements on tenant policy
	tp := examplePolicy()
	tp.Posture = api.PosturePolicy{
		MinOSVersion:     map[string]string{"android": "14.0"},
		MinClientVersion: "1.2.0",
		Require:          []string{"diskEncryption"},
	}
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", tp, 204)

	mintKey := func() string {
		var pk api.ProvisioningKey
		_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u1", MaxUses: 1}, 201), &pk)
		return pk.Key
	}

	// 1. Refused below min OS version
	key1 := mintKey()
	resp1, b1, _, _ := e.enrollWithPosture(key1, "android", &api.Posture{
		OS:            "android",
		OSVersion:     "13.5",
		ClientVersion: "1.2.0",
	})
	if resp1.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d: %s", resp1.StatusCode, b1)
	}
	wantMsg := "posture: OS version below the minimum 14.0"
	if !strings.Contains(string(b1), wantMsg) {
		t.Fatalf("body %q does not contain %q", b1, wantMsg)
	}

	// The provisioning key was NOT consumed by the rejected attempt
	respRetry, _, _, _ := e.enrollWithPosture(key1, "android", &api.Posture{
		OS:            "android",
		OSVersion:     "14.0",
		ClientVersion: "1.2.0",
		DiskEncrypted: boolPtr(true),
	})
	if respRetry.StatusCode != http.StatusOK {
		t.Fatalf("provisioning key should still be usable, got %d", respRetry.StatusCode)
	}

	// 2. Refused below min client version
	key2 := mintKey()
	resp2, b2, _, _ := e.enrollWithPosture(key2, "android", &api.Posture{
		OS:            "android",
		OSVersion:     "14.0",
		ClientVersion: "1.1.0",
	})
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d: %s", resp2.StatusCode, b2)
	}
	wantClientMsg := "posture: client version below the minimum 1.2.0"
	if !strings.Contains(string(b2), wantClientMsg) {
		t.Fatalf("body %q does not contain %q", b2, wantClientMsg)
	}

	// 3. Accepted above minimums and initial posture is stored
	key3 := mintKey()
	resp3, _, er3, _ := e.enrollWithPosture(key3, "android", &api.Posture{
		OS:            "android",
		OSVersion:     "14.2",
		ClientVersion: "1.2.1",
		DiskEncrypted: boolPtr(true),
	})
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp3.StatusCode)
	}

	// Verify posture was stored
	dpRaw := e.adminDo("GET", "/v1/admin/tenants/acme/devices/"+er3.DeviceID+"/posture", nil, 200)
	var dp api.DevicePosture
	if err := json.Unmarshal(dpRaw, &dp); err != nil {
		t.Fatal(err)
	}
	if dp.ReportedAt.IsZero() {
		t.Fatalf("unexpected stored posture: %+v", dp)
	}
	if len(dp.Failing) != 0 {
		t.Fatalf("expected 0 failing checks, got %v", dp.Failing)
	}

	// 4. Older client without Posture proceeds normally
	key4 := mintKey()
	resp4, _, er4, _ := e.enrollWithPosture(key4, "android", nil)
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("older client without posture should succeed, got %d", resp4.StatusCode)
	}
	// Initial posture was not stored for older client
	e.adminDo("GET", "/v1/admin/tenants/acme/devices/"+er4.DeviceID+"/posture", nil, 404)
}

func TestRestrictedSnapshotAndRestoration(t *testing.T) {
	e := newEnvCfg(t, func(c *Config) {
		c.ControlURL = "https://cp.example.com:9443"
	})
	e.setupTenant(1)

	// Set tenant policy with restrict enabled, requiring diskEncryption and remediation domain
	tp := examplePolicy()
	tp.Posture = api.PosturePolicy{
		Require:            []string{"diskEncryption"},
		Restrict:           true,
		RemediationDomains: []string{"help.example.com"},
	}
	tp.PrivateApps = []api.TenantPrivateApp{
		{
			PrivateApp: policy.PrivateApp{ID: "app-internal", Name: "app-internal", Domains: []string{"app.internal"}, Ports: []policy.PortRange{{From: 8080}}, ConnectorGroup: "default"},
		},
	}
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", tp, 204)

	// Enroll compliant device
	var pk api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u1", MaxUses: 1}, 201), &pk)
	resp, _, _, cert := e.enrollWithPosture(pk.Key, "android", &api.Posture{
		OS:            "android",
		OSVersion:     "14.0",
		ClientVersion: "1.0",
		DiskEncrypted: boolPtr(true),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll: %d", resp.StatusCode)
	}

	dev := e.client(cert)

	// 1. Initial snapshot is normal (compliant)
	respSnap, bodySnap := e.do(dev, "GET", "/v1/snapshot", nil, nil)
	if respSnap.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/snapshot: %d %s", respSnap.StatusCode, bodySnap)
	}
	var envl policy.Envelope
	_ = json.Unmarshal(bodySnap, &envl)
	snap1, err := policy.Verify(&envl, e.keys)
	if err != nil {
		t.Fatal(err)
	}
	if snap1.Firewall.DefaultAction != policy.ActionAllow {
		t.Fatalf("expected default allow, got %s", snap1.Firewall.DefaultAction)
	}
	if len(snap1.PostureFailing) != 0 {
		t.Fatalf("expected empty PostureFailing, got %v", snap1.PostureFailing)
	}
	if len(snap1.PrivateApps) != 1 {
		t.Fatalf("expected 1 private app, got %d", len(snap1.PrivateApps))
	}

	// 2. Posture update reporting failing check -> restricted snapshot
	failingReport := api.Posture{
		OS:            "android",
		OSVersion:     "14.0",
		ClientVersion: "1.0",
		DiskEncrypted: boolPtr(false),
	}
	respPost, bodyPost := e.do(dev, "POST", "/v1/posture", failingReport, nil)
	if respPost.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /v1/posture: status %d %s", respPost.StatusCode, bodyPost)
	}

	// Fetch new snapshot
	respSnap2, bodySnap2 := e.do(dev, "GET", "/v1/snapshot", nil, nil)
	if respSnap2.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/snapshot after failure: %d", respSnap2.StatusCode)
	}
	_ = json.Unmarshal(bodySnap2, &envl)
	snap2, err := policy.Verify(&envl, e.keys)
	if err != nil {
		t.Fatal(err)
	}
	if snap2.Version <= snap1.Version {
		t.Fatalf("snapshot version did not increment: %d -> %d", snap1.Version, snap2.Version)
	}
	if snap2.Firewall.DefaultAction != policy.ActionBlock {
		t.Fatalf("restricted snapshot should have ActionBlock, got %s", snap2.Firewall.DefaultAction)
	}
	if !reflect.DeepEqual(snap2.PostureFailing, []string{"diskEncryption"}) {
		t.Fatalf("PostureFailing = %v, want [diskEncryption]", snap2.PostureFailing)
	}
	if len(snap2.PrivateApps) != 0 {
		t.Fatalf("restricted snapshot must carry no private apps, got %d", len(snap2.PrivateApps))
	}

	// Check allowed rules in restricted snapshot:
	// - DNS to tunnel resolver addresses (port 53)
	// - TCP 443 to Control Plane
	// - Remediation domains
	hasDNS := false
	hasCP := false
	hasRemediation := false
	for _, r := range snap2.Firewall.Rules {
		if r.Action != policy.ActionAllow {
			t.Errorf("restricted rule action %s want allow", r.Action)
		}
		if r.ID == "posture:dns" {
			hasDNS = true
		}
		if r.ID == "posture:controlplane" {
			hasCP = true
		}
		if r.ID == "posture:remediation" {
			hasRemediation = true
			if len(r.Match.Domains) != 1 || r.Match.Domains[0] != "help.example.com" {
				t.Errorf("unexpected remediation domains match: %+v", r.Match)
			}
		}
	}
	if !hasDNS || !hasCP || !hasRemediation {
		t.Fatalf("restricted rules missing: dns=%v, cp=%v, rem=%v", hasDNS, hasCP, hasRemediation)
	}

	// 3. Posture update restoring compliance -> normal snapshot restored with new version
	passingReport := api.Posture{
		OS:            "android",
		OSVersion:     "14.0",
		ClientVersion: "1.0",
		DiskEncrypted: boolPtr(true),
	}
	respPost3, _ := e.do(dev, "POST", "/v1/posture", passingReport, nil)
	if respPost3.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /v1/posture: %d", respPost3.StatusCode)
	}

	_, bodySnap3 := e.do(dev, "GET", "/v1/snapshot", nil, nil)
	_ = json.Unmarshal(bodySnap3, &envl)
	snap3, err := policy.Verify(&envl, e.keys)
	if err != nil {
		t.Fatal(err)
	}
	if snap3.Version <= snap2.Version {
		t.Fatalf("snapshot version did not increment: %d -> %d", snap2.Version, snap3.Version)
	}
	if snap3.Firewall.DefaultAction != policy.ActionAllow {
		t.Fatalf("expected ActionAllow restored, got %s", snap3.Firewall.DefaultAction)
	}
	if len(snap3.PostureFailing) != 0 {
		t.Fatalf("expected empty PostureFailing, got %v", snap3.PostureFailing)
	}
	if len(snap3.PrivateApps) != 1 {
		t.Fatalf("expected private app restored, got %d", len(snap3.PrivateApps))
	}
}

func TestRuleAndPrivateAppPostureCondition(t *testing.T) {
	e := newEnv(t)
	e.setupTenant(1)

	// Policy without restrict, but with posture conditions on rules and private apps
	tp := examplePolicy()
	tp.Posture = api.PosturePolicy{
		Require: []string{"diskEncryption"},
	}
	tp.Rules = append(tp.Rules,
		policy.Rule{
			ID:       "rule-comp",
			Priority: 100,
			Action:   policy.ActionBlock,
			Posture:  policy.PostureCompliant,
			Match:    policy.Match{CIDRs: []string{"10.0.1.0/24"}},
		},
		policy.Rule{
			ID:       "rule-noncomp",
			Priority: 101,
			Action:   policy.ActionBlock,
			Posture:  policy.PostureNoncompliant,
			Match:    policy.Match{CIDRs: []string{"10.0.2.0/24"}},
		},
	)
	tp.PrivateApps = []api.TenantPrivateApp{
		{
			PrivateApp: policy.PrivateApp{ID: "app-comp", Name: "app-comp", Domains: []string{"comp.internal"}, Ports: []policy.PortRange{{From: 80}}, ConnectorGroup: "default"},
			Posture:    policy.PostureCompliant,
		},
		{
			PrivateApp: policy.PrivateApp{ID: "app-noncomp", Name: "app-noncomp", Domains: []string{"noncomp.internal"}, Ports: []policy.PortRange{{From: 80}}, ConnectorGroup: "default"},
			Posture:    policy.PostureNoncompliant,
		},
	}
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", tp, 204)

	var pk api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u1", MaxUses: 1}, 201), &pk)
	_, _, er, cert := e.enrollWithPosture(pk.Key, "android", &api.Posture{
		OS:            "android",
		OSVersion:     "14.0",
		ClientVersion: "1.0",
		DiskEncrypted: boolPtr(true),
	})
	dev := e.client(cert)

	findRule := func(snap *policy.Snapshot, id string) (policy.Rule, bool) {
		for _, r := range snap.Firewall.Rules {
			if r.ID == id {
				return r, true
			}
		}
		return policy.Rule{}, false
	}
	hasApp := func(snap *policy.Snapshot, id string) bool {
		for _, a := range snap.PrivateApps {
			if a.ID == id {
				return true
			}
		}
		return false
	}

	// 1. Compliant snapshot
	_, bodySnap1 := e.do(dev, "GET", "/v1/snapshot", nil, nil)
	var envl policy.Envelope
	_ = json.Unmarshal(bodySnap1, &envl)
	snap1, _ := policy.Verify(&envl, e.keys)

	rComp, foundComp := findRule(snap1, "rule-comp")
	if !foundComp {
		t.Fatal("expected rule-comp in compliant snapshot")
	}
	if rComp.Posture != "" {
		t.Fatalf("Rule.Posture must be cleared in compiled snapshot, got %q", rComp.Posture)
	}
	if _, foundNoncomp := findRule(snap1, "rule-noncomp"); foundNoncomp {
		t.Fatal("rule-noncomp should not be present in compliant snapshot")
	}
	if !hasApp(snap1, "app-comp") || hasApp(snap1, "app-noncomp") {
		t.Fatalf("unexpected apps in compliant snapshot: %+v", snap1.PrivateApps)
	}

	// 2. Report noncompliant
	respPost, _ := e.do(dev, "POST", "/v1/posture", api.Posture{
		OS:            "android",
		OSVersion:     "14.0",
		ClientVersion: "1.0",
		DiskEncrypted: boolPtr(false),
	}, nil)
	if respPost.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /v1/posture: %d", respPost.StatusCode)
	}

	_, bodySnap2 := e.do(dev, "GET", "/v1/snapshot", nil, nil)
	_ = json.Unmarshal(bodySnap2, &envl)
	snap2, _ := policy.Verify(&envl, e.keys)

	rNoncomp, foundNoncomp2 := findRule(snap2, "rule-noncomp")
	if !foundNoncomp2 {
		t.Fatal("expected rule-noncomp in noncompliant snapshot")
	}
	if rNoncomp.Posture != "" {
		t.Fatalf("Rule.Posture must be cleared in compiled snapshot, got %q", rNoncomp.Posture)
	}
	if _, foundComp2 := findRule(snap2, "rule-comp"); foundComp2 {
		t.Fatal("rule-comp should not be present in noncompliant snapshot")
	}
	if !hasApp(snap2, "app-noncomp") || hasApp(snap2, "app-comp") {
		t.Fatalf("unexpected apps in noncompliant snapshot: %+v", snap2.PrivateApps)
	}
	_ = er
}

func TestGracePeriod(t *testing.T) {
	e := newEnv(t)
	e.setupTenant(1)

	tp := examplePolicy()
	tp.Posture = api.PosturePolicy{
		Require: []string{"diskEncryption"},
	}
	tp.Rules = append(tp.Rules, policy.Rule{
		ID:       "rule-comp",
		Priority: 100,
		Action:   policy.ActionBlock,
		Posture:  policy.PostureCompliant,
		Match:    policy.Match{CIDRs: []string{"10.0.1.0/24"}},
	})
	e.adminDo("PUT", "/v1/admin/tenants/acme/policy", tp, 204)

	// Enroll without initial posture report (older client)
	var pk api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u1", MaxUses: 1}, 201), &pk)
	_, _, er, cert := e.enrollWithPosture(pk.Key, "android", nil)
	dev := e.client(cert)

	// 1. Within 10 minutes of enrolment: treated as compliant
	_, bodySnap1 := e.do(dev, "GET", "/v1/snapshot", nil, nil)
	var envl policy.Envelope
	_ = json.Unmarshal(bodySnap1, &envl)
	snap1, err := policy.Verify(&envl, e.keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap1.PostureFailing) != 0 {
		t.Fatalf("expected grace period compliant, got failing %v", snap1.PostureFailing)
	}
	found := false
	for _, r := range snap1.Firewall.Rules {
		if r.ID == "rule-comp" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected compliant rule to be present during grace period")
	}

	// 2. Age the device past the 10 minute grace period
	past := time.Now().Add(-15 * time.Minute)
	d, err := e.s.cfg.Store.GetDevice(t.Context(), er.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	d.CreatedAt = past
	// Recompile device snapshot
	if _, err := e.s.compileDevices(t.Context(), "acme", []store.Device{d}); err != nil {
		t.Fatal(err)
	}

	_, bodySnap2 := e.do(dev, "GET", "/v1/snapshot", nil, nil)
	_ = json.Unmarshal(bodySnap2, &envl)
	snap2, err := policy.Verify(&envl, e.keys)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snap2.PostureFailing, []string{"diskEncryption"}) {
		t.Fatalf("expected diskEncryption failure after grace period, got %v", snap2.PostureFailing)
	}
	for _, r := range snap2.Firewall.Rules {
		if r.ID == "rule-comp" {
			t.Fatal("compliant rule should not be present after grace period expired without report")
		}
	}
}

func TestPostureEndpointAuthAndIsolation(t *testing.T) {
	e := newEnv(t)
	e.setupTenant(1) // tenant acme
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "beta", Name: "Beta"}, 201)

	var pk api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u1", MaxUses: 1}, 201), &pk)
	_, _, er, cert := e.enrollWithPosture(pk.Key, "android", &api.Posture{
		OS:            "android",
		OSVersion:     "14.0",
		ClientVersion: "1.0",
		DiskEncrypted: boolPtr(true),
	})
	dev := e.client(cert)

	// Mint token for beta
	var cBeta api.AdminTokenCreated
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/beta/admin-tokens", api.AdminTokenRequest{Name: "b", Role: "admin"}, 201), &cBeta)

	// 1. Beta admin gets 404 on Acme's device posture
	respCross, _ := e.do(e.admin, "GET", "/v1/admin/tenants/acme/devices/"+er.DeviceID+"/posture", nil, map[string]string{
		"Authorization": "Bearer " + cBeta.Token,
	})
	if respCross.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-tenant read: expected 404, got %d", respCross.StatusCode)
	}

	// 2. Unknown device gets 404
	respGhost, _ := e.do(e.admin, "GET", "/v1/admin/tenants/acme/devices/ghost-device/posture", nil, map[string]string{
		"Authorization": "Bearer " + testToken,
	})
	if respGhost.StatusCode != http.StatusNotFound {
		t.Fatalf("ghost device: expected 404, got %d", respGhost.StatusCode)
	}

	// 3. Super admin or acme admin gets 200 with api.DevicePosture
	respAcme, bodyAcme := e.do(e.admin, "GET", "/v1/admin/tenants/acme/devices/"+er.DeviceID+"/posture", nil, map[string]string{
		"Authorization": "Bearer " + testToken,
	})
	if respAcme.StatusCode != http.StatusOK {
		t.Fatalf("acme posture read: %d %s", respAcme.StatusCode, bodyAcme)
	}
	var dp api.DevicePosture
	if err := json.Unmarshal(bodyAcme, &dp); err != nil {
		t.Fatal(err)
	}
	if dp.ReportedAt.IsZero() || dp.OS != "android" {
		t.Fatalf("unexpected posture: %+v", dp)
	}

	// 4. Device without report gets 404 with "no posture report"
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/acme/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u1", MaxUses: 1}, 201), &pk)
	_, _, erNoReport, _ := e.enrollWithPosture(pk.Key, "android", nil)
	respNoRep, bodyNoRep := e.do(e.admin, "GET", "/v1/admin/tenants/acme/devices/"+erNoReport.DeviceID+"/posture", nil, map[string]string{
		"Authorization": "Bearer " + testToken,
	})
	if respNoRep.StatusCode != http.StatusNotFound || !strings.Contains(string(bodyNoRep), "no posture report") {
		t.Fatalf("expected 404 no posture report, got %d %s", respNoRep.StatusCode, bodyNoRep)
	}

	// 5. POST /v1/posture requires device certificate
	respNoCert, _ := e.do(e.admin, "POST", "/v1/posture", api.Posture{OS: "android"}, nil)
	if respNoCert.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /v1/posture without cert: expected 401, got %d", respNoCert.StatusCode)
	}

	// 6. Body size limit (16 KiB)
	hugePayload := api.Posture{
		OS:        "android",
		OSVersion: strings.Repeat("A", 17*1024),
	}
	respHuge, _ := e.do(dev, "POST", "/v1/posture", hugePayload, nil)
	if respHuge.StatusCode != http.StatusBadRequest {
		t.Fatalf("huge payload: expected 400, got %d", respHuge.StatusCode)
	}

	// 7. Reject strings longer than 64 bytes
	longStringPayload := api.Posture{
		OS:        "android",
		OSVersion: strings.Repeat("x", 65),
	}
	respLong, _ := e.do(dev, "POST", "/v1/posture", longStringPayload, nil)
	if respLong.StatusCode != http.StatusBadRequest {
		t.Fatalf("string > 64 bytes: expected 400, got %d", respLong.StatusCode)
	}
}
