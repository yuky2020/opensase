import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:material_ui/material_ui.dart';
import 'package:opensase_admin/src/data/providers.dart';
import 'package:opensase_admin/src/data/session.dart';
import 'package:opensase_admin/src/ui/infra_screens.dart';
import 'package:opensase_admin/src/ui/policy_screen.dart';

import 'helpers.dart';

class _SignedIn extends SessionNotifier {
  @override
  String? build() => 'good-token';
}

Future<void> _pump(WidgetTester t, FakeControlPlane cp, Widget screen) async {
  desktopView(t);
  cp.json('GET /v1/admin/tenants', [
    {'id': 'acme', 'name': 'Acme'},
  ]);
  await t.pumpWidget(
    ProviderScope(
      retry: (_, _) => null,
      overrides: [
        ...overridesFor(cp),
        sessionProvider.overrideWith(_SignedIn.new),
        clockProvider.overrideWithValue(() => DateTime.utc(2026, 11, 20, 10)),
      ],
      child: testApp(screen),
    ),
  );
  await t.pumpAndSettle();
}

void main() {
  testWidgets('device list: posture chip shows compliant, failing and 404, and opens report dialog', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/devices', [
        {'id': 'dev-compliant', 'name': 'Device 1', 'platform': 'android'},
        {'id': 'dev-failing', 'name': 'Device 2', 'platform': 'android'},
        {'id': 'dev-noreport', 'name': 'Device 3', 'platform': 'android'},
      ])
      ..json('GET /v1/admin/tenants/acme/devices/dev-compliant/posture', {
        'os': 'android',
        'osVersion': '14',
        'clientVersion': '1.0.0',
        'diskEncrypted': true,
        'screenLock': true,
        'failing': <String>[],
      })
      ..json('GET /v1/admin/tenants/acme/devices/dev-failing/posture', {
        'os': 'android',
        'osVersion': '12',
        'clientVersion': '1.0.0',
        'diskEncrypted': false,
        'screenLock': false,
        'failing': ['osVersion', 'diskEncryption'],
      });
    // dev-noreport has no route in cp, so FakeControlPlane returns 404

    await _pump(t, cp, const DevicesScreen());

    expect(find.byKey(const ValueKey('posture_chip_dev-compliant')), findsOneWidget);
    expect(find.text('Compliant'), findsOneWidget);

    expect(find.byKey(const ValueKey('posture_chip_dev-failing')), findsOneWidget);
    expect(find.text('2 checks failing'), findsOneWidget);

    expect(find.byKey(const ValueKey('posture_chip_dev-noreport')), findsOneWidget);
    expect(find.text('No report'), findsOneWidget);

    // Tap failing chip to open report dialog
    await t.tap(find.byKey(const ValueKey('posture_chip_dev-failing')));
    await t.pumpAndSettle();

    expect(find.text('Device posture'), findsOneWidget);
    expect(find.text('• osVersion'), findsOneWidget);
    expect(find.text('• diskEncryption'), findsOneWidget);

    await t.tap(find.text('Close'));
    await t.pumpAndSettle();
    expect(find.text('• osVersion'), findsNothing);
  });

  testWidgets('policy screen: saving posture section sends right JSON with If-Match', (t) async {
    http.Request? putReq;
    final cp = FakeControlPlane();
    cp.routes['GET /v1/admin/tenants/acme/policy'] = (req) => http.Response(
      jsonEncode({
        'defaultAction': 'allow',
        'allowUserRules': false,
        'lockdown': false,
        'rules': <dynamic>[],
        'apps': <String, dynamic>{},
        'dns': {'blockResponse': 'nxdomain', 'blocklists': <dynamic>[]},
        'posture': {
          'minOsVersion': {'android': '13'},
          'minClientVersion': '1.0.0',
          'require': ['diskEncryption'],
          'restrict': false,
          'remediationDomains': ['update.example.com'],
        },
      }),
      200,
      headers: {'content-type': 'application/json', 'etag': 'etag-posture-123'},
    );

    cp.routes['PUT /v1/admin/tenants/acme/policy'] = (req) {
      putReq = req;
      return http.Response('', 204, headers: {'etag': 'etag-posture-124'});
    };

    await _pump(t, cp, const PolicyScreen());
    t.view.physicalSize = const Size(1600, 6000); // the posture section is at the bottom
    await t.pumpAndSettle();

    // Verify initial values
    expect(find.byKey(const ValueKey('posture_min_os_android')), findsOneWidget);
    expect(find.byKey(const ValueKey('posture_min_client_version')), findsOneWidget);
    expect(find.byKey(const ValueKey('posture_restrict')), findsOneWidget);
    expect(find.byKey(const ValueKey('remediation_chip_update.example.com')), findsOneWidget);

    // Modify minClientVersion
    await t.enterText(find.byKey(const ValueKey('posture_min_client_version')), '2.0.0');

    // Toggle restrict
    await t.tap(find.byKey(const ValueKey('posture_restrict')));

    // Toggle screenLock in require
    await t.tap(find.byKey(const ValueKey('posture_require_screenLock')));

    // Add remediation domain
    await t.enterText(find.byKey(const ValueKey('remediation_domain_input')), 'help.example.com');
    await t.tap(find.byKey(const ValueKey('remediation_domain_add')));
    await t.pumpAndSettle();

    expect(find.byKey(const ValueKey('remediation_chip_help.example.com')), findsOneWidget);

    // Save policy
    await t.tap(find.byKey(const Key('policy_save')));
    await t.pumpAndSettle();

    expect(putReq, isNotNull);
    expect(putReq!.headers['if-match'], 'etag-posture-123');

    final body = jsonDecode(putReq!.body) as Map<String, dynamic>;
    final posture = body['posture'] as Map<String, dynamic>;

    expect(posture['minClientVersion'], '2.0.0');
    expect(posture['minOsVersion'], {'android': '13'});
    expect(posture['restrict'], true);
    expect(posture['require'], containsAll(['diskEncryption', 'screenLock']));
    expect(posture['remediationDomains'], containsAll(['update.example.com', 'help.example.com']));
  });
}
