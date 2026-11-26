package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/yuky2020/opensase/pkg/api"
	"github.com/yuky2020/opensase/pkg/policy"
)

func TestExperienceAggregates(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(1)
	er, devCert := e.enroll(key)
	dev := e.client(&devCert)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)

	now := time.Now().UTC().Truncate(time.Second)
	probes := []api.ExperienceSample{
		{At: now.Add(-50 * time.Minute), EdgeID: "edge-1", RTTms: 10, LossPct: 0, DNSms: 5, Network: "wifi"},
		{At: now.Add(-40 * time.Minute), EdgeID: "edge-1", RTTms: 20, LossPct: 10, DNSms: 15, Network: "cellular"},
		{At: now.Add(-30 * time.Minute), EdgeID: "edge-1", RTTms: 30, LossPct: 20, DNSms: 25, Network: "ethernet"},
		{At: now.Add(-20 * time.Minute), EdgeID: "edge-1", RTTms: 40, LossPct: 10, DNSms: 0, Network: "roaming"},
		{At: now.Add(-10 * time.Minute), EdgeID: "edge-1", RTTms: 50, LossPct: 10, DNSms: 0, Network: "unknown"},
	}

	batch := api.FlowBatch{
		Records: []api.FlowRecord{
			{Start: now.Add(-50 * time.Minute), Where: "device", DeviceID: er.DeviceID, Flow: policy.Flow{Protocol: "tcp", DstIP: "1.1.1.1", DstPort: 443}},
		},
		Probes: probes,
	}
	resp, body := e.do(dev, "POST", "/v1/flows", batch, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /v1/flows: status %d %s", resp.StatusCode, body)
	}

	raw := e.adminDo("GET", "/v1/admin/tenants/acme/experience", nil, http.StatusOK)
	var sums []api.ExperienceSummary
	if err := json.Unmarshal(raw, &sums); err != nil {
		t.Fatalf("unmarshal experience summaries: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("got %d summaries, want 1", len(sums))
	}
	s := sums[0]
	if s.DeviceID != er.DeviceID {
		t.Errorf("DeviceID = %q, want %q", s.DeviceID, er.DeviceID)
	}
	if s.EdgeID != "edge-1" {
		t.Errorf("EdgeID = %q, want %q", s.EdgeID, "edge-1")
	}
	if s.Samples != 5 {
		t.Errorf("Samples = %d, want 5", s.Samples)
	}
	if s.RTTp50 != 30 {
		t.Errorf("RTTp50 = %v, want 30", s.RTTp50)
	}
	if s.RTTp95 != 50 {
		t.Errorf("RTTp95 = %v, want 50", s.RTTp95)
	}
	if s.LossPct != 10 {
		t.Errorf("LossPct = %v, want 10", s.LossPct)
	}
	if s.DNSp50 != 15 {
		t.Errorf("DNSp50 = %v, want 15", s.DNSp50)
	}
	if !s.Last.Equal(probes[4].At) {
		t.Errorf("Last = %v, want %v", s.Last, probes[4].At)
	}

	// Filter by device and since.
	sinceURL := fmt.Sprintf("/v1/admin/tenants/acme/experience?since=%d&device=%s", now.Add(-25*time.Minute).Unix(), er.DeviceID)
	rawFiltered := e.adminDo("GET", sinceURL, nil, http.StatusOK)
	var filtered []api.ExperienceSummary
	if err := json.Unmarshal(rawFiltered, &filtered); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}
	if len(filtered) != 1 || filtered[0].Samples != 2 {
		t.Fatalf("filtered summaries %+v", filtered)
	}

	// Filter by non-existent device returns empty array.
	rawEmpty := e.adminDo("GET", "/v1/admin/tenants/acme/experience?device=ghost", nil, http.StatusOK)
	var empty []api.ExperienceSummary
	if err := json.Unmarshal(rawEmpty, &empty); err != nil {
		t.Fatalf("unmarshal empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected 0 summaries for ghost device, got %d", len(empty))
	}
}

func TestExperienceValidationAndDrops(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(1)
	_, devCert := e.enroll(key)
	dev := e.client(&devCert)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)

	now := time.Now().UTC().Truncate(time.Second)

	// Invalid samples that must be dropped.
	invalidProbes := []api.ExperienceSample{
		{At: now, EdgeID: "unknown-edge", RTTms: 10, LossPct: 0, DNSms: 5},
		{At: now, EdgeID: "edge-1", RTTms: -1, LossPct: 0, DNSms: 5},
		{At: now, EdgeID: "edge-1", RTTms: 60001, LossPct: 0, DNSms: 5},
		{At: now, EdgeID: "edge-1", RTTms: 10, LossPct: -1, DNSms: 5},
		{At: now, EdgeID: "edge-1", RTTms: 10, LossPct: 101, DNSms: 5},
		{At: now, EdgeID: "edge-1", RTTms: 10, LossPct: 0, DNSms: -1},
		{At: now, EdgeID: "edge-1", RTTms: 10, LossPct: 0, DNSms: 60001},
		{At: now, EdgeID: "edge-1", RTTms: 10, LossPct: 0, DNSms: 5, Network: "invalid-net"},
		{At: now.Add(-25 * time.Hour), EdgeID: "edge-1", RTTms: 10, LossPct: 0, DNSms: 5},
		{At: now.Add(10 * time.Minute), EdgeID: "edge-1", RTTms: 10, LossPct: 0, DNSms: 5},
	}

	batch := api.FlowBatch{Probes: invalidProbes}
	resp, body := e.do(dev, "POST", "/v1/flows", batch, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /v1/flows with invalid probes: %d %s", resp.StatusCode, body)
	}

	raw := e.adminDo("GET", "/v1/admin/tenants/acme/experience", nil, http.StatusOK)
	var sums []api.ExperienceSummary
	_ = json.Unmarshal(raw, &sums)
	if len(sums) != 0 {
		t.Fatalf("expected all invalid probes dropped, got %+v", sums)
	}

	// At most 60 probes per batch: send 70 valid probes.
	manyProbes := make([]api.ExperienceSample, 70)
	for i := range manyProbes {
		manyProbes[i] = api.ExperienceSample{
			At:      now.Add(-time.Duration(i) * time.Minute),
			EdgeID:  "edge-1",
			RTTms:   20,
			LossPct: 0,
			DNSms:   10,
		}
	}
	resp, body = e.do(dev, "POST", "/v1/flows", api.FlowBatch{Probes: manyProbes}, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /v1/flows with 70 probes: %d %s", resp.StatusCode, body)
	}

	raw = e.adminDo("GET", "/v1/admin/tenants/acme/experience", nil, http.StatusOK)
	sums = nil
	_ = json.Unmarshal(raw, &sums)
	if len(sums) != 1 || sums[0].Samples != 60 {
		t.Fatalf("expected 60 probes capped, got %+v", sums)
	}
}

func TestExperienceEdgeCertIgnored(t *testing.T) {
	e := newEnv(t)
	key := e.setupTenant(1)
	er, _ := e.enroll(key)
	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)

	ec := e.edgeCert()
	edge := e.client(&ec)

	// Report live session so the Edge can report flows for this device.
	if resp, _ := e.do(edge, "POST", "/v1/edge/sessions", EdgeSessions{DeviceIDs: []string{er.DeviceID}}, nil); resp.StatusCode != 204 {
		t.Fatalf("edge sessions: %d", resp.StatusCode)
	}

	now := time.Now().UTC().Truncate(time.Second)
	batch := api.FlowBatch{
		Records: []api.FlowRecord{{Start: now, DeviceID: er.DeviceID}},
		Probes: []api.ExperienceSample{
			{At: now, EdgeID: "edge-1", RTTms: 25, LossPct: 0, DNSms: 10},
		},
	}
	resp, body := e.do(edge, "POST", "/v1/flows", batch, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("edge flows: %d %s", resp.StatusCode, body)
	}

	raw := e.adminDo("GET", "/v1/admin/tenants/acme/experience", nil, http.StatusOK)
	var sums []api.ExperienceSummary
	_ = json.Unmarshal(raw, &sums)
	if len(sums) != 0 {
		t.Fatalf("expected probes from edge cert to be ignored, got %+v", sums)
	}
}

func TestExperienceTenantIsolation(t *testing.T) {
	e := newEnv(t)
	keyAcme := e.setupTenant(1) // creates "acme"
	erAcme, certAcme := e.enroll(keyAcme)
	devAcme := e.client(&certAcme)

	// Create second tenant "beta" and enroll device.
	e.adminDo("POST", "/v1/admin/tenants", api.AdminTenant{ID: "beta", Name: "Beta"}, 201)
	e.adminDo("POST", "/v1/admin/tenants/beta/users", api.AdminUser{ID: "u-beta", Email: "u@beta"}, 201)
	var pk api.ProvisioningKey
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/beta/provisioning-keys", api.ProvisioningKeyRequest{UserID: "u-beta", MaxUses: 1}, 201), &pk)
	erBeta, certBeta := e.enroll(pk.Key)
	devBeta := e.client(&certBeta)

	e.adminDo("POST", "/v1/admin/edges", AdminEdge{ID: "edge-1"}, 201)

	now := time.Now().UTC().Truncate(time.Second)
	// Acme device posts probe.
	e.do(devAcme, "POST", "/v1/flows", api.FlowBatch{
		Probes: []api.ExperienceSample{{At: now, EdgeID: "edge-1", RTTms: 15, LossPct: 0, DNSms: 5}},
	}, nil)

	// Beta device posts probe.
	e.do(devBeta, "POST", "/v1/flows", api.FlowBatch{
		Probes: []api.ExperienceSample{{At: now, EdgeID: "edge-1", RTTms: 80, LossPct: 5, DNSms: 20}},
	}, nil)

	// Mint tenant admin token for beta.
	var c api.AdminTokenCreated
	_ = json.Unmarshal(e.adminDo("POST", "/v1/admin/tenants/beta/admin-tokens", api.AdminTokenRequest{Name: "beta-admin", Role: api.TenantRoleAdmin}, 201), &c)
	betaTok := c.Token

	// Acme admin query sees only acme device.
	rawAcme := e.adminDo("GET", "/v1/admin/tenants/acme/experience", nil, http.StatusOK)
	var sumsAcme []api.ExperienceSummary
	_ = json.Unmarshal(rawAcme, &sumsAcme)
	if len(sumsAcme) != 1 || sumsAcme[0].DeviceID != erAcme.DeviceID || sumsAcme[0].RTTp50 != 15 {
		t.Fatalf("acme experience: %+v", sumsAcme)
	}

	// Beta admin query sees only beta device.
	respBeta, bodyBeta := e.do(e.admin, "GET", "/v1/admin/tenants/beta/experience", nil, map[string]string{"Authorization": "Bearer " + betaTok})
	if respBeta.StatusCode != http.StatusOK {
		t.Fatalf("beta admin GET /experience: %d %s", respBeta.StatusCode, bodyBeta)
	}
	var sumsBeta []api.ExperienceSummary
	_ = json.Unmarshal(bodyBeta, &sumsBeta)
	if len(sumsBeta) != 1 || sumsBeta[0].DeviceID != erBeta.DeviceID || sumsBeta[0].RTTp50 != 80 {
		t.Fatalf("beta experience: %+v", sumsBeta)
	}

	// Beta admin cannot read Acme's experience endpoint (must be 404).
	respCross, _ := e.do(e.admin, "GET", "/v1/admin/tenants/acme/experience", nil, map[string]string{"Authorization": "Bearer " + betaTok})
	if respCross.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-tenant read: got %d, want 404", respCross.StatusCode)
	}
}
