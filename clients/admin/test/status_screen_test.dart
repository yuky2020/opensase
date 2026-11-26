import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase_admin/src/data/browser_storage.dart';
import 'package:opensase_admin/src/data/providers.dart';
import 'package:opensase_admin/src/data/session.dart';
import 'package:opensase_admin/src/ui/common.dart';
import 'package:opensase_admin/src/ui/status_screen.dart';
import 'package:opensase_admin/src/ui/theme.dart';

import 'helpers.dart';

class _SignedIn extends SessionNotifier {
  @override
  String? build() => 'good-token';
}

Future<void> _pump(WidgetTester t, FakeControlPlane cp, Widget screen, {KeyValueStore? persistent}) async {
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
        // Fix clock at 2026-11-20T10:00:00Z:
        clockProvider.overrideWithValue(() => DateTime.utc(2026, 11, 20, 10)),
        statusRefreshPeriodProvider.overrideWithValue(null),
      ],
      child: testApp(screen),
    ),
  );
  await t.pumpAndSettle();
}

void main() {
  testWidgets('status screen displays deployment health cards for super-admin', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'super'})
      ..json('GET /v1/admin/status', {
        'edges': [
          {'id': 'edge-eu-1', 'region': 'eu-central-1', 'sessions': 5, 'reporting': true},
          {'id': 'edge-us-1', 'region': 'us-east-1', 'sessions': 0, 'reporting': false},
        ],
        'devicesEnrolled': 12,
        'devicesOnline': 5,
        'connectorsTotal': 3,
        'connectorsOnline': 2,
        'certificates': [
          {'name': 'root', 'notAfter': '2036-11-20T10:00:00Z'},
          {'name': 'controlplane', 'notAfter': '2026-11-25T10:00:00Z'}, // 5 days left (< 14 days warning)
        ],
        'auditChain': 'ok',
        'leader': true,
        'categoryListAgeSeconds': 7200,
      });

    await _pump(t, cp, const StatusScreen());

    // Devices & Connectors summary
    expect(find.byKey(const Key('stat_devices')), findsOneWidget);
    expect(find.text('5'), findsNWidgets(2)); // devicesOnline 5 & sessions 5
    expect(find.text('online of 12 enrolled'), findsOneWidget);

    expect(find.byKey(const Key('stat_connectors')), findsOneWidget);
    expect(find.text('2'), findsOneWidget);
    expect(find.text('online of 3 total'), findsOneWidget);

    // Leader
    expect(find.byKey(const Key('stat_leader')), findsOneWidget);
    expect(find.text('Active leader replica'), findsOneWidget);

    // Audit chain
    expect(find.byKey(const Key('stat_audit_chain')), findsOneWidget);
    expect(find.text('OK'), findsWidgets);
    expect(find.text('Intact'), findsOneWidget);

    // Category list age (7200s = 2h 0m)
    expect(find.byKey(const Key('stat_category_list')), findsOneWidget);
    expect(find.text('2h 0m'), findsOneWidget);

    // Edges table
    expect(find.byKey(const Key('status_edges_card')), findsOneWidget);
    expect(find.text('edge-eu-1'), findsOneWidget);
    expect(find.text('eu-central-1'), findsOneWidget);
    expect(find.text('edge-us-1'), findsOneWidget);
    expect(find.text('us-east-1'), findsOneWidget);

    // Reporting chips
    final euReporting = t.widget<StatusChip>(find.byKey(const Key('edge_reporting_edge-eu-1')));
    expect(euReporting.label, 'Yes');
    expect(euReporting.color, VerdictColors.light.allow);

    final usReporting = t.widget<StatusChip>(find.byKey(const Key('edge_reporting_edge-us-1')));
    expect(usReporting.label, 'No');
    expect(usReporting.color, lightScheme.error);

    // Certificates table & expiry warning
    expect(find.byKey(const Key('status_certificates_card')), findsOneWidget);
    expect(find.text('root'), findsOneWidget);
    expect(find.text('controlplane'), findsOneWidget);

    // controlplane cert expires in 5 days (< 14 days), so it gets the warning color
    final cpChip = t.widget<StatusChip>(find.byKey(const Key('cert_chip_controlplane')));
    expect(cpChip.label, '5 days');
    expect(cpChip.color, VerdictColors.light.ask);

    // root cert expires in 10 years, so it gets allow color
    final rootChip = t.widget<StatusChip>(find.byKey(const Key('cert_chip_root')));
    expect(rootChip.label, contains('days'));
    expect(rootChip.color, VerdictColors.light.allow);

    // Refresh button
    final initialCalls = cp.requests.where((r) => r.url.path == '/v1/admin/status').length;
    expect(initialCalls, 1);
    await t.tap(find.byKey(const Key('status_refresh')));
    await t.pumpAndSettle();
    final afterCalls = cp.requests.where((r) => r.url.path == '/v1/admin/status').length;
    expect(afterCalls, 2);
  });

  testWidgets('status screen is hidden for tenant admin', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'tenant', 'tenantId': 'acme', 'tokenId': 't1'});

    await _pump(t, cp, const StatusScreen());

    expect(find.byKey(const Key('status_edges_card')), findsNothing);
    expect(find.byKey(const Key('stat_devices')), findsNothing);
    expect(cp.requests.any((r) => r.url.path == '/v1/admin/status'), isFalse);
  });

  testWidgets('status screen handles broken audit chain and unconfigured category list', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'super'})
      ..json('GET /v1/admin/status', {
        'edges': [],
        'devicesEnrolled': 0,
        'devicesOnline': 0,
        'connectorsTotal': 0,
        'connectorsOnline': 0,
        'certificates': [],
        'auditChain': 'broken',
        'leader': false,
        'categoryListAgeSeconds': -1,
      });

    await _pump(t, cp, const StatusScreen());

    expect(find.text('Broken'), findsWidgets);
    expect(find.text('Verification failed'), findsOneWidget);
    expect(find.text('Not loaded'), findsOneWidget);
    expect(find.text('Follower replica'), findsOneWidget);
  });
}
