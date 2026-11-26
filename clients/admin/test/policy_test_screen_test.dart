import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase_admin/src/data/session.dart';
import 'package:opensase_admin/src/ui/policy_test_screen.dart';

import 'helpers.dart';

class _SignedIn extends SessionNotifier {
  @override
  String? build() => 'good-token';
}

Future<void> _pump(WidgetTester t, FakeControlPlane cp) async {
  desktopView(t);
  cp.json('GET /v1/admin/tenants', [
    {'id': 'acme', 'name': 'Acme'},
  ]);
  await t.pumpWidget(
    ProviderScope(
      retry: (_, _) => null,
      overrides: [...overridesFor(cp), sessionProvider.overrideWith(_SignedIn.new)],
      child: testApp(const PolicyTestScreen()),
    ),
  );
  await t.pumpAndSettle();
}

void main() {
  testWidgets('the page lists devices', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/devices', [
        {
          'id': 'd1',
          'userId': 'u1',
          'name': 'Laptop Alice',
          'platform': 'linux',
          'revoked': false,
          'createdAt': '2026-11-20T10:00:00Z',
        },
        {
          'id': 'd2',
          'userId': 'u2',
          'name': 'Phone Bob',
          'platform': 'android',
          'revoked': false,
          'createdAt': '2026-11-20T10:00:00Z',
        },
      ])
      ..json('GET /v1/admin/tenants/acme/users', [
        {'id': 'u1', 'email': 'alice@example.com', 'name': 'Alice'},
        {'id': 'u2', 'email': 'bob@example.com', 'name': 'Bob'},
      ]);

    await _pump(t, cp);

    expect(find.byKey(const ValueKey('device_picker')), findsOneWidget);
    await t.tap(find.byKey(const ValueKey('device_picker')));
    await t.pumpAndSettle();

    expect(find.text('Laptop Alice (Alice)'), findsWidgets);
    expect(find.text('Phone Bob (Bob)'), findsWidgets);
  });

  testWidgets('filling the form and pressing Test sends the right JSON body and shows a block result with rule id', (
    t,
  ) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/devices', [
        {
          'id': 'd1',
          'userId': 'u1',
          'name': 'Laptop Alice',
          'platform': 'linux',
          'revoked': false,
          'createdAt': '2026-11-20T10:00:00Z',
        },
      ])
      ..json('GET /v1/admin/tenants/acme/users', [
        {'id': 'u1', 'email': 'alice@example.com', 'name': 'Alice'},
      ])
      ..json('POST /v1/admin/tenants/acme/policy-test', {
        'decision': {
          'action': 'block',
          'ruleId': 'rule-block-malware',
          'layer': 'tenant',
          'log': true,
          'reason': 'blocked by tenant policy',
        },
        'snapshotVersion': 42,
      });

    await _pump(t, cp);

    // Select device
    await t.tap(find.byKey(const ValueKey('device_picker')));
    await t.pumpAndSettle();
    await t.tap(find.text('Laptop Alice (Alice)').last);
    await t.pumpAndSettle();

    // Enter destination IP
    await t.enterText(find.byKey(const ValueKey('dst_ip')), '198.51.100.1');

    // Enter destination port
    await t.enterText(find.byKey(const ValueKey('dst_port')), '80');

    // Enter domain
    await t.enterText(find.byKey(const ValueKey('domain')), 'evil.example.com');

    // Toggle Evaluate as Edge
    await t.tap(find.byKey(const ValueKey('edge_switch')));
    await t.pumpAndSettle();

    // Press Test
    await t.tap(find.byKey(const ValueKey('test_button')));
    await t.pumpAndSettle();

    final req = cp.requests.singleWhere(
      (r) => r.method == 'POST' && r.url.path == '/v1/admin/tenants/acme/policy-test',
    );
    final body = jsonDecode(req.body) as Map<String, dynamic>;
    expect(body['deviceId'], 'd1');
    expect(body['edge'], true);

    final flow = body['flow'] as Map<String, dynamic>;
    expect(flow['protocol'], 'tcp');
    expect(flow['dstIp'], '198.51.100.1');
    expect(flow['dstPort'], 80);
    expect(flow['domain'], 'evil.example.com');

    // Result is displayed
    expect(find.byKey(const ValueKey('result_card')), findsOneWidget);
    expect(find.byKey(const ValueKey('result_action')), findsOneWidget);
    expect(find.text('Block'), findsOneWidget);
    expect(find.text('rule-block-malware'), findsOneWidget);
    expect(find.text('tenant'), findsOneWidget);
    expect(find.text('blocked by tenant policy'), findsOneWidget);
    expect(find.text('42'), findsOneWidget);
  });

  testWidgets('an invalid port shows an error and sends nothing', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/devices', [
        {
          'id': 'd1',
          'userId': 'u1',
          'name': 'Laptop Alice',
          'platform': 'linux',
          'revoked': false,
          'createdAt': '2026-11-20T10:00:00Z',
        },
      ]);

    await _pump(t, cp);

    // Select device
    await t.tap(find.byKey(const ValueKey('device_picker')));
    await t.pumpAndSettle();
    await t.tap(find.text('Laptop Alice (u1)').last);
    await t.pumpAndSettle();

    // Valid IP
    await t.enterText(find.byKey(const ValueKey('dst_ip')), '1.2.3.4');

    // Invalid port > 65535
    await t.enterText(find.byKey(const ValueKey('dst_port')), '70000');

    cp.requests.clear();

    await t.tap(find.byKey(const ValueKey('test_button')));
    await t.pumpAndSettle();

    expect(find.text('Port must be between 0 and 65535'), findsOneWidget);
    expect(cp.requests.where((r) => r.url.path.endsWith('/policy-test')), isEmpty);
  });

  testWidgets('invalid IP shows an error and sends nothing', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/devices', [
        {
          'id': 'd1',
          'userId': 'u1',
          'name': 'Laptop Alice',
          'platform': 'linux',
          'revoked': false,
          'createdAt': '2026-11-20T10:00:00Z',
        },
      ]);

    await _pump(t, cp);

    await t.tap(find.byKey(const ValueKey('device_picker')));
    await t.pumpAndSettle();
    await t.tap(find.text('Laptop Alice (u1)').last);
    await t.pumpAndSettle();

    await t.enterText(find.byKey(const ValueKey('dst_ip')), 'not-an-ip');
    await t.enterText(find.byKey(const ValueKey('dst_port')), '443');

    cp.requests.clear();

    await t.tap(find.byKey(const ValueKey('test_button')));
    await t.pumpAndSettle();

    expect(find.text('Enter a valid IPv4 or IPv6 address'), findsOneWidget);
    expect(cp.requests.where((r) => r.url.path.endsWith('/policy-test')), isEmpty);
  });

  testWidgets('Edge mode disables app package input', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/devices', [
        {
          'id': 'd1',
          'userId': 'u1',
          'name': 'Laptop Alice',
          'platform': 'linux',
          'revoked': false,
          'createdAt': '2026-11-20T10:00:00Z',
        },
      ]);

    await _pump(t, cp);

    final appFieldFinder = find.byKey(const ValueKey('app'));
    expect(t.widget<TextField>(appFieldFinder).enabled, isTrue);

    // Toggle Evaluate as Edge on
    await t.tap(find.byKey(const ValueKey('edge_switch')));
    await t.pumpAndSettle();

    expect(t.widget<TextField>(appFieldFinder).enabled, isFalse);
  });

  testWidgets('API error is displayed when policy-test fails', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/devices', [
        {
          'id': 'd1',
          'userId': 'u1',
          'name': 'Laptop Alice',
          'platform': 'linux',
          'revoked': false,
          'createdAt': '2026-11-20T10:00:00Z',
        },
      ])
      ..json('POST /v1/admin/tenants/acme/policy-test', {'error': 'device has no snapshot yet'}, status: 404);

    await _pump(t, cp);

    await t.tap(find.byKey(const ValueKey('device_picker')));
    await t.pumpAndSettle();
    await t.tap(find.text('Laptop Alice (u1)').last);
    await t.pumpAndSettle();

    await t.enterText(find.byKey(const ValueKey('dst_ip')), '1.2.3.4');
    await t.enterText(find.byKey(const ValueKey('dst_port')), '443');

    await t.tap(find.byKey(const ValueKey('test_button')));
    await t.pumpAndSettle();

    expect(find.byKey(const ValueKey('server_error')), findsOneWidget);
    expect(find.textContaining('device has no snapshot yet'), findsWidgets);
  });
}
