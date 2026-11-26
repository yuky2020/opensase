import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase_admin/src/data/browser_storage.dart';
import 'package:opensase_admin/src/data/providers.dart';
import 'package:opensase_admin/src/data/session.dart';
import 'package:opensase_admin/src/ui/experience_screen.dart';
import 'package:opensase_admin/src/ui/theme.dart';

import 'helpers.dart';

class _SignedIn extends SessionNotifier {
  @override
  String? build() => 'good-token';
}

final _fixedClock = DateTime.utc(2026, 11, 20, 10);

Future<void> _pump(WidgetTester t, FakeControlPlane cp, {KeyValueStore? persistent}) async {
  desktopView(t);
  cp.json('GET /v1/admin/tenants', [
    {'id': 'acme', 'name': 'Acme'},
  ]);
  await t.pumpWidget(
    ProviderScope(
      retry: (_, _) => null,
      overrides: [
        ...overridesFor(cp, persistent: persistent),
        sessionProvider.overrideWith(_SignedIn.new),
        clockProvider.overrideWithValue(() => _fixedClock),
        experienceRefreshPeriodProvider.overrideWithValue(null),
      ],
      child: testApp(const ExperienceScreen()),
    ),
  );
  await t.pumpAndSettle();
}

void main() {
  final sampleDevices = [
    {
      'id': 'dev-alice',
      'userId': 'u1',
      'name': 'Alice Laptop',
      'platform': 'linux',
      'revoked': false,
      'createdAt': '2026-11-20T10:00:00Z',
    },
    {
      'id': 'dev-unnamed',
      'userId': 'u2',
      'name': '',
      'platform': 'android',
      'revoked': false,
      'createdAt': '2026-11-20T10:00:00Z',
    },
  ];

  final sampleExperience = [
    {
      'deviceId': 'dev-alice',
      'edgeId': 'edge-fra',
      'samples': 100,
      'rttP50Ms': 25.0,
      'rttP95Ms': 45.0,
      'lossPct': 1.0,
      'dnsP50Ms': 12.0,
      'last': '2026-11-20T09:30:00Z',
    },
    {
      'deviceId': 'dev-alice',
      'edgeId': 'edge-iad',
      'samples': 80,
      'rttP50Ms': 75.0,
      'rttP95Ms': 160.0,
      'lossPct': 5.0,
      'dnsP50Ms': 28.0,
      'last': '2026-11-20T09:40:00Z',
    },
    {
      'deviceId': 'dev-unnamed',
      'edgeId': 'edge-fra',
      'samples': 250,
      'rttP50Ms': 35.0,
      'rttP95Ms': 55.0,
      'lossPct': 15.0,
      'dnsP50Ms': 10.0,
      'last': '2026-11-20T09:50:00Z',
    },
  ];

  testWidgets('rows render with resolved device names and summary cards', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/devices', sampleDevices)
      ..json('GET /v1/admin/tenants/acme/experience', sampleExperience);

    await _pump(t, cp);

    // Resolved device name for dev-alice
    expect(find.text('Alice Laptop'), findsWidgets);

    // Fallback device ID for dev-unnamed
    expect(find.text('dev-unnamed'), findsOneWidget);

    // Edge identifiers
    expect(find.text('edge-fra'), findsWidgets);
    expect(find.text('edge-iad'), findsOneWidget);

    // Summary cards: devices measured (2), median RTT p50 (35 ms), high loss rows (2)
    expect(find.byKey(const ValueKey('stat_devices_measured')), findsOneWidget);
    expect(find.text('2'), findsWidgets);

    expect(find.byKey(const ValueKey('stat_median_rtt')), findsOneWidget);
    expect(find.text('35 ms'), findsWidgets);

    expect(find.byKey(const ValueKey('stat_high_loss_rows')), findsOneWidget);
  });

  testWidgets('loss and RTT p95 cell colour thresholds', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/devices', sampleDevices)
      ..json('GET /v1/admin/tenants/acme/experience', sampleExperience);

    await _pump(t, cp);

    final context = t.element(find.byType(ExperienceScreen));
    final verdicts = Theme.of(context).extension<VerdictColors>()!;

    // Loss 1.0% (<= 2%): normal (no warning or block colour)
    final lowLoss = t.widget<Text>(find.byKey(const ValueKey('loss_dev-alice_edge-fra')));
    expect(lowLoss.style?.color, isNull);

    // Loss 5.0% (> 2% and <= 10%): warning colour (verdicts.ask)
    final warnLoss = t.widget<Text>(find.byKey(const ValueKey('loss_dev-alice_edge-iad')));
    expect(warnLoss.style?.color, verdicts.ask);

    // Loss 15.0% (> 10%): block colour (verdicts.block)
    final blockLoss = t.widget<Text>(find.byKey(const ValueKey('loss_dev-unnamed_edge-fra')));
    expect(blockLoss.style?.color, verdicts.block);

    // RTT p95 160 ms (> 150 ms): warning colour (verdicts.ask)
    final warnRtt95 = t.widget<Text>(find.byKey(const ValueKey('rtt95_dev-alice_edge-iad')));
    expect(warnRtt95.style?.color, verdicts.ask);

    // RTT p95 45 ms (<= 150 ms): normal
    final normalRtt95 = t.widget<Text>(find.byKey(const ValueKey('rtt95_dev-alice_edge-fra')));
    expect(normalRtt95.style?.color, isNull);
  });

  testWidgets('changing the period requests the right since parameter', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/devices', sampleDevices)
      ..json('GET /v1/admin/tenants/acme/experience', sampleExperience);

    await _pump(t, cp);

    // Default period is 24 hours: 2026-11-20T10:00:00Z - 24h = 2026-11-19T10:00:00Z
    final expected24h = _fixedClock.subtract(const Duration(hours: 24)).millisecondsSinceEpoch ~/ 1000;
    final expReqs1 = cp.requests.where((r) => r.url.path == '/v1/admin/tenants/acme/experience').toList();
    expect(expReqs1, isNotEmpty);
    expect(expReqs1.last.url.queryParameters['since'], '$expected24h');

    // Switch to 1 hour
    await t.tap(find.byKey(const ValueKey('experience_period')));
    await t.pumpAndSettle();
    await t.tap(find.text('1 hour').last);
    await t.pumpAndSettle();

    final expected1h = _fixedClock.subtract(const Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000;
    final expReqs2 = cp.requests.where((r) => r.url.path == '/v1/admin/tenants/acme/experience').toList();
    expect(expReqs2.last.url.queryParameters['since'], '$expected1h');

    // Switch to 7 days
    await t.tap(find.byKey(const ValueKey('experience_period')));
    await t.pumpAndSettle();
    await t.tap(find.text('7 days').last);
    await t.pumpAndSettle();

    final expected7d = _fixedClock.subtract(const Duration(days: 7)).millisecondsSinceEpoch ~/ 1000;
    final expReqs3 = cp.requests.where((r) => r.url.path == '/v1/admin/tenants/acme/experience').toList();
    expect(expReqs3.last.url.queryParameters['since'], '$expected7d');

    // Switch to 30 days
    await t.tap(find.byKey(const ValueKey('experience_period')));
    await t.pumpAndSettle();
    await t.tap(find.text('30 days').last);
    await t.pumpAndSettle();

    final expected30d = _fixedClock.subtract(const Duration(days: 30)).millisecondsSinceEpoch ~/ 1000;
    final expReqs4 = cp.requests.where((r) => r.url.path == '/v1/admin/tenants/acme/experience').toList();
    expect(expReqs4.last.url.queryParameters['since'], '$expected30d');
  });

  testWidgets('the filter hides non-matching rows', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/devices', sampleDevices)
      ..json('GET /v1/admin/tenants/acme/experience', sampleExperience);

    await _pump(t, cp);

    expect(find.text('Alice Laptop'), findsWidgets);
    expect(find.text('dev-unnamed'), findsOneWidget);

    // Filter by 'Alice'
    await t.enterText(find.byKey(const ValueKey('device_filter')), 'Alice');
    await t.pumpAndSettle();

    expect(find.text('Alice Laptop'), findsWidgets);
    expect(find.text('dev-unnamed'), findsNothing);

    // Filter by 'unnamed'
    await t.enterText(find.byKey(const ValueKey('device_filter')), 'unnamed');
    await t.pumpAndSettle();

    expect(find.text('Alice Laptop'), findsNothing);
    expect(find.text('dev-unnamed'), findsOneWidget);

    // Clear filter
    await t.enterText(find.byKey(const ValueKey('device_filter')), '');
    await t.pumpAndSettle();

    expect(find.text('Alice Laptop'), findsWidgets);
    expect(find.text('dev-unnamed'), findsOneWidget);
  });

  testWidgets('refresh button triggers reload', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/devices', sampleDevices)
      ..json('GET /v1/admin/tenants/acme/experience', sampleExperience);

    await _pump(t, cp);

    final initialCount = cp.requests.where((r) => r.url.path == '/v1/admin/tenants/acme/experience').length;

    await t.tap(find.byKey(const ValueKey('experience_refresh')));
    await t.pumpAndSettle();

    final afterCount = cp.requests.where((r) => r.url.path == '/v1/admin/tenants/acme/experience').length;
    expect(afterCount, greaterThan(initialCount));
  });
}
