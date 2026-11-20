import 'package:flutter_test/flutter_test.dart';
import 'package:opensase/src/contracts/api.dart';
import 'package:opensase/src/contracts/policy.dart';
import 'package:opensase/src/data/core_state.dart';
import 'package:opensase/src/data/enrollment_code.dart';
import 'package:opensase/src/data/policy_logic.dart';
import 'package:opensase/src/data/rule_draft.dart';
import 'package:opensase/src/engine/fake_engine.dart';

Snapshot snap({bool allowUser = true, bool lockdown = false, Map<String, AppPolicy> apps = const {}}) => Snapshot(
  version: 3,
  firewall: FirewallPolicy(
    allowUserRules: allowUser,
    lockdown: lockdown,
    rules: [...FakeEngine.tenantRules, ...FakeEngine.initialUserRules],
    apps: apps,
  ),
);

void main() {
  group('verdicts', () {
    test('tenant whole-app rule locks every network', () {
      final v = PolicyLogic.verdicts('com.zhiliaoapp.musically', snap(), const UserRules(), const {});
      expect(v.every((x) => x.locked && !x.allowed && x.origin == VerdictOrigin.tenantRule), isTrue);
    });

    test('tenant rule limited to networks locks only those', () {
      final v = PolicyLogic.verdicts('com.facebook.katana', snap(), const UserRules(), const {});
      expect(v.map((x) => x.locked), [false, true, true]);
      expect(v.map((x) => x.allowed), [true, false, false]);
    });

    test('user app policy applies when user rules are allowed', () {
      const user = UserRules(apps: {'a': AppPolicy(cellular: Verdict.block)});
      final v = PolicyLogic.verdicts('a', snap(), user, const {});
      expect(v[1].origin, VerdictOrigin.userApp);
      expect(v[1].allowed, isFalse);
      expect(v[0].origin, VerdictOrigin.defaultAction);
    });

    test('everything locked when the tenant disallows user rules; lockdown blocks', () {
      final v = PolicyLogic.verdicts('a', snap(allowUser: false, lockdown: true), const UserRules(), const {});
      expect(v.every((x) => x.locked && !x.allowed && x.origin == VerdictOrigin.lockdown), isTrue);
    });
  });

  test('no snapshot yet: nothing locked, default allow', () {
    final v = PolicyLogic.verdicts('a', null, const UserRules(), const {});
    expect(v.any((x) => x.locked), isFalse);
    expect(v.every((x) => x.allowed && x.origin == VerdictOrigin.defaultAction), isTrue);
  });

  test('setAppNetwork / setAppAll', () {
    var u = PolicyLogic.setAppNetwork(const UserRules(), 'a', NetworkType.roaming, false);
    expect(u.apps['a']!.roaming, Verdict.block);
    expect(u.apps['a']!.wifi, isNull);
    u = PolicyLogic.setAppAll(u, 'a', true);
    expect([u.apps['a']!.wifi, u.apps['a']!.cellular, u.apps['a']!.roaming], everyElement(Verdict.allow));
  });

  test('moveRule renumbers priorities in the new order', () {
    const u = UserRules(rules: FakeEngine.initialUserRules);
    final m = PolicyLogic.moveRule(u, 2, 0);
    expect(m.rules.map((r) => r.id), ['u-3', 'u-1', 'u-2']);
    expect(m.rules.map((r) => r.priority), [100, 110, 120]);
    expect(PolicyLogic.moveRule(u, 0, 9), same(u));
  });

  test('addDomainRule and deleteRule', () {
    var u = PolicyLogic.addDomainRule(
      const UserRules(rules: FakeEngine.initialUserRules),
      'Tracker.Example.COM.',
      Verdict.block,
    );
    final added = u.rules.last;
    expect(added.match.domains, ['tracker.example.com']);
    expect(added.priority, 130);
    expect(added.id, 'u-4');
    expect(PolicyLogic.domainRules(u).map((r) => r.id), ['u-1', 'u-3', 'u-4']);
    u = PolicyLogic.deleteRule(u, 'u-4');
    expect(u.rules, hasLength(3));
    expect(PolicyLogic.addDomainRule(u, 'not a domain', Verdict.block), same(u));
  });

  test('normalizeDomain', () {
    final cases = {
      'example.com': 'example.com',
      '*.Ads.Example.': '*.ads.example',
      'localhost': null,
      '*.': null,
      'a*b.com': null,
      '-x.com': null,
    };
    cases.forEach((i, want) => expect(PolicyLogic.normalizeDomain(i), want, reason: i));
  });

  test('isValidCidr', () {
    final cases = {
      '10.0.0.0/8': true,
      '192.168.1.1': true,
      'fd00::/8': true,
      '2001:db8::1': true,
      '300.1.1.1': false,
      '10.0.0.0/33': false,
      'x': false,
      '1.2.3/8': false,
    };
    cases.forEach((i, want) => expect(PolicyLogic.isValidCidr(i), want, reason: i));
  });

  group('PolicyState.derive', () {
    test('without a stored layer adopts snapshot apps as user apps', () {
      final p = PolicyState.derive(snap(apps: const {'x': AppPolicy(wifi: Verdict.block)}), null);
      expect(p.user.apps.keys, ['x']);
      expect(p.tenantApps, isEmpty);
      expect(p.user.rules.map((r) => r.id), ['u-1', 'u-2', 'u-3']);
    });

    test('with a stored layer the remaining snapshot apps are tenant-mandated', () {
      final p = PolicyState.derive(
        snap(
          apps: const {
            'x': AppPolicy(wifi: Verdict.block),
            't': AppPolicy(wifi: Verdict.allow),
          },
        ),
        const UserRules(apps: {'x': AppPolicy(wifi: Verdict.block)}),
      );
      expect(p.tenantApps.keys, ['t']);
    });

    test('user rules disallowed: no user apps, all apps tenant', () {
      final p = PolicyState.derive(snap(allowUser: false, apps: const {'t': AppPolicy(wifi: Verdict.allow)}), null);
      expect(p.user.apps, isEmpty);
      expect(p.tenantApps.keys, ['t']);
      expect(p.userLayerEditable, isFalse);
    });
  });

  group('EnrollmentCode', () {
    test('opensase:// link with pin', () {
      final c = EnrollmentCode.parse(
        'opensase://enroll?url=${Uri.encodeComponent('https://cp.example:9443#sha256=ab12')}&key=PK-123&name=Phone',
      )!;
      expect(c.controlUrl, 'https://cp.example:9443#sha256=ab12');
      expect(c.hasPin, isTrue);
      expect(c.provisioningKey, 'PK-123');
      expect(c.deviceName, 'Phone');
    });

    test('deploy/dev OPENSASE_ENROLL_URI format (control=)', () {
      final c = EnrollmentCode.parse(
        'opensase://enroll?control=https%3A%2F%2F10.0.2.2%3A9443%23sha256%3D7c00a6&key=osk_TEST',
      )!;
      expect(c.controlUrl, 'https://10.0.2.2:9443#sha256=7c00a6');
      expect(c.provisioningKey, 'osk_TEST');
      expect(c.hasPin, isTrue);
    });

    test('URL and key separated by whitespace, URL alone, invalid', () {
      expect(EnrollmentCode.parse('https://10.0.2.2:9443#sha256=ff  PK-1\n')!.provisioningKey, 'PK-1');
      expect(EnrollmentCode.parse('https://10.0.2.2:9443')!.provisioningKey, '');
      expect(EnrollmentCode.parse('http://insecure PK'), isNull);
      expect(EnrollmentCode.parse('opensase://enroll?key=x'), isNull);
      expect(EnrollmentCode.parse(''), isNull);
    });
  });

  test('RuleDraft validation and conversion', () {
    expect(const RuleDraft().validate(), {DraftField.empty});
    expect(
      const RuleDraft(cidrs: '10.0.0.0/8, nope', ports: '99999', domains: 'bad domain', priority: 'x').validate(),
      {DraftField.cidrs, DraftField.ports, DraftField.domains, DraftField.priority},
    );
    const d = RuleDraft(
      action: Verdict.allow,
      protocols: {'udp', 'tcp'},
      ports: '53 853-854',
      domains: '*.Corp.Example',
      networks: {NetworkType.roaming},
    );
    expect(d.validate(), isEmpty);
    final r = d.toRule('u-9', 150);
    expect(r.id, 'u-9');
    expect(r.priority, 150);
    expect(r.match.protocols, ['tcp', 'udp']);
    expect(r.match.ports.map((p) => p.toString()), ['53', '853-854']);
    expect(r.match.domains, ['*.corp.example']);
    expect(RuleDraft.from(r).ports, '53, 853-854');
  });
}
