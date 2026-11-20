import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:opensase/src/contracts/api.dart';
import 'package:opensase/src/contracts/policy.dart';
import 'package:opensase/src/data/parsers.dart';

void main() {
  group('status (docs/mobile-client.md)', () {
    test('parses the full documented status', () {
      final s = Parsers.status(
        '{"state":"connected","error":"","enrolled":true,"deviceId":"dev-1","edge":"edge-1",'
        '"network":"wifi","snapshotVersion":7,"stale":false,"pq":true,"kex":"X25519MLKEM768","epoch":3,'
        '"lastHandshake":1763550000,"txBytes":1234,"rxBytes":5678}',
      );
      expect(s.isConnected, isTrue);
      expect(s.pq, isTrue);
      expect(s.kex, 'X25519MLKEM768');
      expect(s.snapshotVersion, 7);
      expect(s.epoch, 3);
      expect(s.lastHandshake, 1763550000);
      expect(s.network, 'wifi');
      expect(s.enrolled, isTrue);
    });

    test('certExpiresAt accepts RFC 3339 text or unix seconds', () {
      expect(Parsers.status('{"certExpiresAt":"2026-12-19T10:00:00Z"}').certExpiresAt, '2026-12-19T10:00:00Z');
      expect(Parsers.status('{"certExpiresAt":1797760800}').certExpiresAt, startsWith('2026-12-'));
      expect(Parsers.status('{}').certExpiresAt, '');
    });

    test('defaults: pq false and stopped on empty or bad JSON', () {
      for (final j in ['', 'null', '{', '[]', '{"state":"connected"}']) {
        final s = Parsers.status(j);
        expect(s.pq, isFalse, reason: j);
      }
      expect(Parsers.status('').state, 'stopped');
    });
  });

  test('flow event example parses, zero end time kept as string', () {
    final r = Parsers.flow(
      '{"start":"2026-11-19T10:00:00Z","end":"0001-01-01T00:00:00Z","flow":{"app":"com.example",'
      '"uid":10123,"network":"wifi","protocol":"tcp","dstIp":"203.0.113.5","dstPort":443,"domain":"www.example.com"},'
      '"decision":{"action":"block","ruleId":"no-social","layer":"tenant","log":false},"bytesOut":0,"bytesIn":0,'
      '"where":"device","deviceId":"dev-1"}',
    )!;
    expect(r.flow.app, 'com.example');
    expect(r.flow.network, NetworkType.wifi);
    expect(r.flow.dstPort, 443);
    expect(r.decision.action, Verdict.block);
    expect(r.decision.layer, 'tenant');
    expect(r.end, startsWith('0001-'));
  });

  test('appStats with DNS counters and unknown owner', () {
    final s = Parsers.appStats(
      '[{"app":"com.example","bytesIn":5678,"bytesOut":1234,"allowed":12,"blocked":3,'
      '"dnsQueries":40,"dnsBlocked":5},{"app":"","allowed":1,"blocked":2,"dnsBlocked":1}]',
    );
    expect(s, hasLength(2));
    expect(s[1].app, '');
    final c = Parsers.counters(s);
    expect(c.allowed, 13);
    expect(c.blocked, 5);
    expect(c.dnsBlocked, 6);
  });

  test('snapshot: Go nil slices/maps (null) and unknown enum values degrade safely', () {
    final snap = Parsers.snapshot(
      jsonEncode({
        'schemaVersion': 1,
        'version': 9,
        'firewall': {
          'defaultAction': 'quarantine', // unknown -> allow
          'allowUserRules': true,
          'lockdown': false,
          'rules': [
            {
              'id': 't-1',
              'source': 'tenant',
              'priority': 1,
              'action': 'block',
              'match': {
                'apps': null,
                'networks': ['wifi', 'satellite'],
                'ports': [
                  {'from': 25, 'to': 0},
                ],
              },
              'log': true,
            },
          ],
          'apps': null,
        },
        'dns': {'blockResponse': 'zero', 'blocklists': null},
      }),
    )!;
    expect(snap.version, 9);
    expect(snap.firewall.defaultAction, Verdict.allow);
    expect(snap.firewall.apps, isEmpty);
    final r = snap.firewall.rules.single;
    expect(r.source, RuleSource.tenant);
    expect(r.match.apps, isEmpty);
    expect(r.match.networks, [NetworkType.wifi, NetworkType.unknown]);
    expect(r.match.ports.single.last, 25);
    expect(snap.dns.blocklists, isEmpty);
    expect(Parsers.snapshot(''), isNull);
  });

  test('UserRules encodes like api.UserRules (omits unset per-network actions)', () {
    const u = UserRules(
      rules: [
        Rule(
          id: 'u-1',
          priority: 100,
          action: Verdict.ask,
          match: Match(domains: ['*.example.com']),
        ),
      ],
      apps: {'com.example': AppPolicy(wifi: Verdict.allow, cellular: Verdict.block)},
    );
    final j = jsonDecode(Parsers.encodeUserRules(u)) as Map<String, dynamic>;
    expect(j['apps'], {
      'com.example': {'wifi': 'allow', 'cellular': 'block'},
    });
    final rule = (j['rules'] as List).single as Map<String, dynamic>;
    expect(rule['source'], 'user');
    expect(rule['action'], 'ask');
    expect(rule.containsKey('description'), isFalse);
    expect((rule['match'] as Map)['domains'], ['*.example.com']);
    // Round trip.
    expect(Parsers.encodeUserRules(Parsers.userRules(jsonEncode(j))), Parsers.encodeUserRules(u));
  });

  test('PortRange.parse', () {
    final cases = {
      '443': '443',
      ' 8000-8100 ': '8000-8100',
      '0': null,
      '70000': null,
      '9-3': null,
      'a': null,
      '1-2-3': null,
    };
    cases.forEach((input, want) => expect(PortRange.parse(input)?.toString(), want, reason: input));
  });
}
