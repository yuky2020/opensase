import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:opensase_admin/src/api/admin_models.dart';
import 'package:opensase_admin/src/api/json.dart';

/// Sample JSON written by hand from the Go struct tags in pkg/api/types.go and
/// pkg/policy/types.go, with every field set (so omitempty does not drop anything).
const tenantPolicyJson = '''
{
  "defaultAction": "block",
  "allowUserRules": true,
  "lockdown": false,
  "rules": [
    {
      "id": "allow-web",
      "source": "tenant",
      "priority": 10,
      "action": "allow",
      "match": {
        "apps": ["com.android.chrome"],
        "networks": ["wifi", "cellular"],
        "protocols": ["tcp"],
        "cidrs": ["10.0.0.0/8", "fd00::/8"],
        "ports": [{"from": 443, "to": 0}, {"from": 8000, "to": 8080}],
        "domains": ["example.com", "*.example.org"]
      },
      "log": true,
      "description": "web"
    }
  ],
  "apps": {
    "com.whatsapp": {"wifi": "allow", "cellular": "block", "roaming": "ask"}
  },
  "dns": {
    "blockResponse": "nxdomain",
    "blocklists": [{"id": "ads", "name": "Ads", "category": "ads", "domains": ["ads.example.com"]}],
    "allowDomains": ["good.example.com"],
    "blockDomains": ["bad.example.com"]
  },
  "privateApps": [
    {
      "id": "intranet",
      "name": "Intranet",
      "domains": ["intranet.acme.internal"],
      "ports": [{"from": 443, "to": 0}],
      "connectorGroup": "dc1",
      "users": ["alice@acme.test"]
    }
  ],
  "saas": {"blockApps": ["dropbox"], "blockCategories": ["ai-assistant"], "allowApps": ["claude"]},
  "web": {
    "inspect": true,
    "bypass": ["*.bank.example"],
    "rules": [
      {"id": "no-admin", "domains": ["app.example"], "action": "block", "pathPrefixes": ["/admin"], "methods": ["POST"]},
      {"id": "all", "domains": ["*.example"], "action": "allow"}
    ],
    "headers": [{"domains": ["*.saas.example"], "name": "X-Allowed-Tenant", "value": "acme"}],
    "malware": {"uploads": true, "downloads": true, "blockUnscanned": true},
    "dlp": [
      {"id": "pci", "action": "block", "detectors": ["credit-card", "iban"], "datasets": ["customers"], "blockUnscanned": true, "downloads": true},
      {"id": "words", "action": "allow", "domains": ["*.share.example"], "patterns": ["project +falcon"], "minMatches": 3}
    ]
  },
  "categories": ["adult", "gambling"],
  "safeSearch": true,
  "decideBlockDomains": ["*.casino.example"],
  "decideBlockCidrs": ["203.0.113.0/24"],
  "decideDefault": "allow"
}
''';

void roundTrip<T>(String name, String src, T Function(Json) from, Json Function(T) to) {
  test('$name round trip', () {
    final j = jsonDecode(src) as Json;
    final back = jsonDecode(jsonEncode(to(from(j))));
    expect(back, equals(j));
  });
}

void main() {
  roundTrip('AdminTenant', '{"id":"acme","name":"Acme"}', AdminTenant.fromJson, (v) => v.toJson());
  roundTrip(
    'AdminIdentity',
    '{"role":"tenant","tenantId":"acme","tokenId":"t1","tenantRole":"viewer"}',
    AdminIdentity.fromJson,
    (v) => v.toJson(),
  );
  roundTrip('AdminIdentity super', '{"role":"super"}', AdminIdentity.fromJson, (v) => v.toJson());
  roundTrip(
    'AdminToken',
    '{"id":"t1","tenantId":"acme","name":"ops","createdAt":"2026-11-20T10:00:00Z","expiresAt":"2027-02-18T10:00:00Z","revoked":false,"lastUsed":"2026-11-21T08:30:00Z","role":"policy-editor"}',
    AdminToken.fromJson,
    (v) => v.toJson(),
  );
  roundTrip(
    'AuditEntry',
    '{"id":7,"at":"2026-11-21T10:00:00Z","actor":"token:t1","tenantId":"acme","method":"PUT","path":"/v1/admin/tenants/acme/policy","status":204}',
    AuditEntry.fromJson,
    (v) => v.toJson(),
  );
  roundTrip(
    'SaasApp',
    '{"id":"dropbox","name":"Dropbox","category":"file-sharing","domains":["dropbox.com"]}',
    SaasApp.fromJson,
    (v) => v.toJson(),
  );
  test('SaasPolicy.blocks and empty policy omits saas', () {
    final p = SaasPolicy(blockApps: ['dropbox'], blockCategories: ['ai-assistant'], allowApps: ['claude']);
    expect(p.blocks('dropbox', 'file-sharing'), isTrue);
    expect(p.blocks('box', 'file-sharing'), isFalse);
    expect(p.blocks('chatgpt', 'ai-assistant'), isTrue);
    expect(p.blocks('claude', 'ai-assistant'), isFalse);
    expect(TenantPolicy().toJson().containsKey('saas'), isFalse);
    expect(TenantPolicy().toJson().containsKey('web'), isFalse);
  });
  roundTrip('AdminUser', '{"id":"u1","email":"a@b.c","name":"A"}', AdminUser.fromJson, (v) => v.toJson());
  roundTrip(
    'ProvisioningKeyRequest',
    '{"userId":"u1","maxUses":3,"validForSeconds":3600}',
    ProvisioningKeyRequest.fromJson,
    (v) => v.toJson(),
  );
  roundTrip(
    'ProvisioningKey',
    '{"key":"pk_abc","userId":"u1","expiresAt":"2026-11-21T10:00:00.123456Z"}',
    ProvisioningKey.fromJson,
    (v) => v.toJson(),
  );
  roundTrip('TenantPolicy', tenantPolicyJson, TenantPolicy.fromJson, (v) => v.toJson());
  roundTrip(
    'FlowBatch',
    '''{"records":[{"start":"2026-11-20T10:00:00Z","end":"2026-11-20T10:00:05.5Z",
      "flow":{"app":"com.android.chrome","uid":10123,"network":"wifi","protocol":"tcp","dstIp":"93.184.216.34","dstPort":443,"domain":"example.com"},
      "decision":{"action":"block","ruleId":"dns:ads","layer":"dns","log":true},
      "bytesOut":100,"bytesIn":2000,"where":"edge","deviceId":"d1","saasApp":"github","categories":["code-hosting"]}]}''',
    FlowBatch.fromJson,
    (v) => v.toJson(),
  );
  roundTrip(
    'AdminEdge',
    '{"id":"edge-1","revoked":true,"createdAt":"2026-11-20T09:00:00Z"}',
    AdminEdge.fromJson,
    (v) => v.toJson(),
  );
  roundTrip(
    'AdminEdge (Private Edge)',
    '{"id":"site-1","tenantId":"acme","revoked":false,"createdAt":"2026-11-20T09:00:00Z"}',
    AdminEdge.fromJson,
    (v) => v.toJson(),
  );
  roundTrip(
    'AdminDevice',
    '{"id":"d1","userId":"u1","name":"Pixel","platform":"android","revoked":false,"createdAt":"2026-11-20T09:00:00Z"}',
    AdminDevice.fromJson,
    (v) => v.toJson(),
  );
  roundTrip(
    'AdminConnectorRequest',
    '{"name":"dc1-a","group":"dc1"}',
    AdminConnectorRequest.fromJson,
    (v) => v.toJson(),
  );
  roundTrip(
    'AdminConnectorCreated',
    '''{"connector":{"id":"c1","tenantId":"acme","name":"dc1-a","group":"dc1","revoked":false,
      "createdAt":"2026-11-20T09:00:00Z","lastSeen":"2026-11-20T09:59:00Z"},"provisioningKey":"ck_xyz"}''',
    AdminConnectorCreated.fromJson,
    (v) => v.toJson(),
  );

  group('Go encoding details', () {
    test('omitempty fields are dropped and nil slices accepted', () {
      final p = TenantPolicy.fromJson(
        jsonDecode('{"defaultAction":"","rules":null,"apps":null,"dns":{"blockResponse":"","blocklists":null}}')
            as Json,
      );
      expect(p.rules, isEmpty);
      final j = p.toJson();
      expect(j.containsKey('privateApps'), isFalse);
      expect(j.containsKey('decideBlockDomains'), isFalse);
      expect(j['decideDefault'], '');
      expect((j['dns'] as Json).containsKey('allowDomains'), isFalse);
      expect(j['rules'], isEmpty);
    });

    test('rule without description and empty match', () {
      final r = TenantPolicy.fromJson(
        jsonDecode('{"rules":[{"id":"r","source":"tenant","priority":1,"action":"block","match":{},"log":false}]}')
            as Json,
      ).rules.single;
      expect(r.toJson(), {'id': 'r', 'source': 'tenant', 'priority': 1, 'action': 'block', 'match': {}, 'log': false});
    });

    test('zero time is null and written back as Go zero time', () {
      final c = AdminConnectorCreated.fromJson(
        jsonDecode('{"connector":{"id":"c","lastSeen":"0001-01-01T00:00:00Z"},"provisioningKey":"k"}') as Json,
      ).connector;
      expect(c.lastSeen, isNull);
      expect(c.isOnline(DateTime.now()), isFalse);
      expect(c.toJson()['lastSeen'], goZeroTime);
    });

    test('times with offsets are normalised to UTC', () {
      final e = AdminEdge.fromJson({'id': 'e', 'createdAt': '2026-11-20T10:00:00+01:00'});
      expect(goTime(e.createdAt), '2026-11-20T09:00:00Z');
    });

    test('wrong types are rejected', () {
      expect(() => TenantPolicy.fromJson({'lockdown': 'yes'}), throwsFormatException);
      expect(() => TenantPolicy.fromJson({'rules': {}}), throwsFormatException);
    });

    test('connector online window is 2 minutes', () {
      final now = DateTime.utc(2026, 11, 20, 10);
      final c = AdminConnector(id: 'c', lastSeen: now.subtract(const Duration(seconds: 119)));
      expect(c.isOnline(now), isTrue);
      c.lastSeen = now.subtract(const Duration(minutes: 3));
      expect(c.isOnline(now), isFalse);
      c
        ..lastSeen = now
        ..revoked = true;
      expect(c.isOnline(now), isFalse);
    });

    test('TenantOidc fromJson and toJson never stores client secret', () {
      final json = {
        'issuer': 'https://idp.example.com',
        'clientId': 'client-1',
        'hasSecret': true,
        'groupRoles': {'admins': 'admin', 'viewers': 'viewer'},
        'redirectUrl': 'https://cp.test/callback',
      };
      final o = TenantOidc.fromJson(json);
      expect(o.issuer, 'https://idp.example.com');
      expect(o.clientId, 'client-1');
      expect(o.hasSecret, isTrue);
      expect(o.groupRoles, {'admins': 'admin', 'viewers': 'viewer'});
      expect(o.redirectUrl, 'https://cp.test/callback');

      // toJson without secret
      final out = o.toJson();
      expect(out.containsKey('clientSecret'), isFalse);
      expect(out['issuer'], 'https://idp.example.com');

      // toJson with secret for saving
      final outWithSecret = o.toJson(clientSecret: 'my-secret');
      expect(outWithSecret['clientSecret'], 'my-secret');
    });
  });
}
