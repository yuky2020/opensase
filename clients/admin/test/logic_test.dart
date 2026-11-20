import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:opensase_admin/src/api/admin_api.dart';
import 'package:opensase_admin/src/api/admin_models.dart';
import 'package:opensase_admin/src/api/policy_models.dart';
import 'package:opensase_admin/src/data/enroll_link.dart';
import 'package:opensase_admin/src/data/flow_stats.dart';
import 'package:opensase_admin/src/data/parsers.dart';
import 'package:opensase_admin/src/data/validation.dart';

void main() {
  group('parsers', () {
    test('ports', () {
      expect(parsePorts('443, 8000-8080\n53'), [
        PortRange(from: 443),
        PortRange(from: 8000, to: 8080),
        PortRange(from: 53),
      ]);
      expect(formatPorts(parsePorts('443,8000-8080')), '443, 8000-8080');
      for (final bad in ['0', '70000', '90-80', 'http']) {
        expect(() => parsePorts(bad), throwsFormatException, reason: bad);
      }
    });
    test('domains and cidrs', () {
      expect(domainError('*.example.com'), isNull);
      expect(domainError('Example.COM.'), isNull);
      expect(domainError('-bad.com'), isNotNull);
      expect(domainError('a..b'), isNotNull);
      expect(cidrError('10.0.0.0/8'), isNull);
      expect(cidrError('fd00::/8'), isNull);
      expect(cidrError('1.2.3.4'), isNull);
      expect(cidrError('10.0.0.0/33'), isNotNull);
      expect(cidrError('nope'), isNotNull);
    });
    test('ids follow pki.ValidID', () {
      expect(validId('edge-eu.1_a'), isTrue);
      expect(validId('-x'), isFalse);
      expect(validId('..'), isFalse);
      expect(validId(''), isFalse);
    });
  });

  group('validation', () {
    test('valid policy has no issues', () {
      final p = TenantPolicy(
        defaultAction: 'block',
        rules: [
          Rule(
            id: 'r1',
            action: 'allow',
            match: Match(domains: ['example.com']),
          ),
        ],
        privateApps: [
          TenantPrivateApp(
            id: 'app',
            domains: ['intranet.acme.internal'],
            ports: [PortRange(from: 443)],
            connectorGroup: 'default',
          ),
        ],
      );
      expect(validateTenantPolicy(p), isEmpty);
    });
    test('reports server-style field paths', () {
      final p = TenantPolicy(
        defaultAction: 'deny',
        decideDefault: 'ask',
        rules: [
          Rule(
            id: 'r',
            action: 'allow',
            match: Match(cidrs: ['x'], ports: [PortRange(from: 90, to: 80)]),
          ),
          Rule(id: 'r', source: 'user'),
        ],
        dns: DnsPolicy(
          blockResponse: 'refused',
          blocklists: [
            Blocklist(domains: ['ok.com']),
          ],
        ),
        privateApps: [TenantPrivateApp(id: '')],
      );
      final fields = validateTenantPolicy(p).map((i) => i.field).toList();
      expect(
        fields,
        containsAll([
          'defaultAction',
          'decideDefault',
          'rules[0].match.cidrs[0]',
          'rules[0].match.ports[0]',
          'rules[1].id',
          'rules[1].source',
          'dns.blockResponse',
          'dns.blocklists[0].id',
          'privateApps[0].id',
          'privateApps[0].domains',
          'privateApps[0].ports',
        ]),
      );
    });
  });

  group('enroll link', () {
    const pin = '#sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    test('control URL needs https and a pin', () {
      expect(controlUrlError('https://cp.example.com:9443$pin'), isNull);
      expect(controlUrlError('https://cp.example.com:9443'), isNotNull);
      expect(controlUrlError('http://cp.example.com$pin'), isNotNull);
    });
    test('deep link encodes the control URL including the fragment', () {
      final link = enrollLink(controlUrl: 'https://cp.example.com:9443$pin', key: 'pk+1');
      final u = Uri.parse(link);
      expect(u.scheme, 'opensase');
      expect(u.host, 'enroll');
      expect(u.queryParameters['control'], 'https://cp.example.com:9443$pin');
      expect(u.queryParameters['key'], 'pk+1');
      expect(link, contains('%23sha256%3D'));
    });
    test('default control URL is the origin', () {
      expect(defaultControlUrl(Uri.parse('https://cp:9443/admin/#/users')), 'https://cp:9443');
      expect(defaultControlUrl(Uri.parse('file:///x')), '');
    });
  });

  group('flow stats', () {
    final now = DateTime.utc(2026, 11, 20, 12);
    FlowRecord rec(String action, String layer, {int minsAgo = 1, String dev = 'd1', String domain = ''}) => FlowRecord(
      start: now.subtract(Duration(minutes: minsAgo)),
      flow: Flow(protocol: 'tcp', dstIp: '1.2.3.4', dstPort: 443, domain: domain),
      decision: Decision(action: action, layer: layer),
      where: 'device',
      deviceId: dev,
    );
    final flows = [
      rec('block', 'tenant'),
      rec('block', 'dns', minsAgo: 90),
      rec('allow', 'tenant', dev: 'd2', domain: 'example.com'),
      rec('allow', 'default'),
    ];
    test('blocks in the last hour', () => expect(blocksSince(flows, now), 1));
    test('verdicts by layer', () {
      final m = verdictsByLayer(flows);
      expect(m.keys, ['tenant', 'dns', 'default']);
      expect(m['tenant']!.allow, 1);
      expect(m['tenant']!.block, 1);
    });
    test('filters', () {
      expect(filterFlows(flows, const FlowFilter(verdict: 'block')).length, 2);
      expect(filterFlows(flows, const FlowFilter(layer: 'tenant', device: 'd2')).length, 1);
      expect(filterFlows(flows, const FlowFilter(text: 'EXAMPLE')).length, 1);
      expect(filterFlows(flows, const FlowFilter(where: 'edge')), isEmpty);
    });
  });

  group('AdminApi', () {
    test('sends the bearer token to /v1/admin on the portal origin', () async {
      late http.Request seen;
      final api = AdminApi(
        token: 'tok',
        base: Uri.parse('https://cp.example.com:9443/admin/#/policy'),
        client: MockClient((r) async {
          seen = r;
          return http.Response('{"records":[]}', 200);
        }),
      );
      await api.listFlows('acme corp');
      expect(seen.url.toString(), 'https://cp.example.com:9443/v1/admin/tenants/acme%20corp/flows?limit=500');
      expect(seen.headers['Authorization'], 'Bearer tok');
    });
    test('decodes the server error body with the policy field', () async {
      final api = AdminApi(
        token: 't',
        base: Uri.parse('https://cp/admin/'),
        client: MockClient(
          (_) async =>
              http.Response(jsonEncode({'error': 'policy: invalid rules[0].id: empty', 'field': 'rules[0].id'}), 400),
        ),
      );
      try {
        await api.putPolicy('t', TenantPolicy());
        fail('expected ApiException');
      } on ApiException catch (e) {
        expect(e.status, 400);
        expect(e.field, 'rules[0].id');
        expect(e.message, 'policy: invalid rules[0].id: empty');
      }
    });
    test('204 without body', () async {
      final api = AdminApi(
        token: 't',
        base: Uri.parse('https://cp/admin/'),
        client: MockClient((_) async => http.Response('', 204)),
      );
      await api.revokeEdge('e1');
    });
  });
}
