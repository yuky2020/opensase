package policy

import (
	"encoding/json"
	"testing"
)

func FuzzCompileSnapshot(f *testing.F) {
	const exampleSnapshotJSON = `{
  "schemaVersion": 1,
  "tenantId": "acme",
  "deviceId": "dev-1",
  "firewall": {
    "defaultAction": "allow",
    "allowUserRules": true,
    "lockdown": false,
    "rules": [
      {
        "id": "block-smtp",
        "priority": 10,
        "action": "block",
        "log": true,
        "description": "No direct SMTP from devices (spam/exfiltration)",
        "match": { "protocols": ["tcp"], "ports": [{ "from": 25 }] }
      },
      {
        "id": "block-tracker-domains",
        "priority": 20,
        "action": "block",
        "log": true,
        "description": "Flows to IPs learned from tracker lookups (DNS snooping)",
        "match": { "domains": ["*.doubleclick.net"] }
      },
      {
        "id": "ask-test-net-3",
        "priority": 30,
        "action": "ask",
        "log": true,
        "description": "TEST-NET-3 is decided by the cloud (POST /v1/decide)",
        "match": { "cidrs": ["203.0.113.0/24"] }
      }
    ],
    "apps": {}
  },
  "dns": {
    "blockResponse": "nxdomain",
    "blocklists": [
      {
        "id": "ads",
        "name": "Advertising",
        "category": "ads",
        "domains": ["*.doubleclick.net", "*.googlesyndication.com"]
      }
    ],
    "allowDomains": [],
    "blockDomains": ["blocked.opensase.test"]
  }
}`
	f.Add([]byte(exampleSnapshotJSON))

	prec, _ := json.Marshal(precedenceSnapshot())
	f.Add(prec)

	const rawPolicyExampleJSON = `{
  "defaultAction": "allow",
  "allowUserRules": true,
  "lockdown": false,
  "rules": [
    {
      "id": "block-smtp",
      "priority": 10,
      "action": "block",
      "log": true,
      "description": "No direct SMTP from devices (spam/exfiltration)",
      "match": { "protocols": ["tcp"], "ports": [{ "from": 25 }] }
    }
  ],
  "apps": {}
}`
	f.Add([]byte(rawPolicyExampleJSON))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var s Snapshot
		if err := json.Unmarshal(data, &s); err != nil {
			return
		}
		c, err := Compile(&s)
		if err != nil {
			return
		}
		if c == nil {
			t.Fatal("Compile succeeded but returned nil")
		}
	})
}
