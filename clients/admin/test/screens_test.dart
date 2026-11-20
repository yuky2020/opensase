import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase_admin/src/data/browser_storage.dart';
import 'package:opensase_admin/src/data/providers.dart';
import 'package:opensase_admin/src/data/session.dart';
import 'package:opensase_admin/src/ui/infra_screens.dart';
import 'package:opensase_admin/src/ui/users_screen.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'helpers.dart';

class _SignedIn extends SessionNotifier {
  @override
  String? build() => 'good-token';
}

const _pin = '#sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

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
        clockProvider.overrideWithValue(() => DateTime.utc(2026, 11, 20, 10)),
      ],
      child: testApp(screen),
    ),
  );
  await t.pumpAndSettle();
}

void main() {
  testWidgets('provisioning key is shown once with the enroll QR code', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/users', [
        {'id': 'u1', 'email': 'alice@acme.test', 'name': 'Alice'},
      ])
      ..json('POST /v1/admin/tenants/acme/provisioning-keys', {
        'key': 'pk_secret',
        'userId': 'u1',
        'expiresAt': '2026-11-21T10:00:00Z',
      });
    final settings = MemoryStore()..write('opensase.admin.controlUrl', 'https://cp.test:9443$_pin');
    await _pump(t, cp, const UsersScreen(), persistent: settings);
    await t.tap(find.byKey(const Key('provision_u1')));
    await t.pumpAndSettle();
    await t.tap(find.text('Generate'));
    await t.pumpAndSettle();
    expect(find.text('pk_secret'), findsOneWidget);
    final qr = t.widget<QrImageView>(find.byKey(const Key('enroll_qr')));
    expect(qr, isNotNull);
    final link = 'opensase://enroll?control=${Uri.encodeComponent('https://cp.test:9443$_pin')}&key=pk_secret';
    expect(find.text(link), findsOneWidget);
    final req = cp.requests.singleWhere((r) => r.method == 'POST');
    expect(req.body, contains('"userId":"u1"'));
  });

  testWidgets('connectors: online badge and revoke with confirmation', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/connectors', [
        {
          'id': 'c1',
          'tenantId': 'acme',
          'name': 'dc1-a',
          'group': 'dc1',
          'revoked': false,
          'createdAt': '2026-11-20T09:00:00Z',
          'lastSeen': '2026-11-20T09:59:30Z',
        },
        {
          'id': 'c2',
          'tenantId': 'acme',
          'name': 'dc1-b',
          'group': 'dc1',
          'revoked': false,
          'createdAt': '2026-11-20T09:00:00Z',
          'lastSeen': '2026-11-20T09:50:00Z',
        },
      ]);
    cp.routes['POST /v1/admin/tenants/acme/connectors/c2/revoke'] = (_) => http204();
    await _pump(t, cp, const ConnectorsScreen());
    expect(find.text('Online'), findsOneWidget);
    expect(find.text('Offline'), findsOneWidget);
    await t.tap(find.byKey(const Key('revoke_c2')));
    await t.pumpAndSettle();
    expect(find.text('Revoke dc1-b?'), findsOneWidget);
    await t.tap(find.byKey(const Key('confirm_revoke')));
    await t.pumpAndSettle();
    expect(cp.requests.where((r) => r.method == 'POST').single.url.path, '/v1/admin/tenants/acme/connectors/c2/revoke');
  });
}
