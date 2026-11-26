import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:material_ui/material_ui.dart';
import 'package:opensase_admin/src/app.dart';
import 'package:opensase_admin/src/data/browser_storage.dart';
import 'package:opensase_admin/src/data/providers.dart';
import 'package:opensase_admin/src/data/session.dart';
import 'package:opensase_admin/src/ui/onboarding_screen.dart';

import 'helpers.dart';

class _SignedIn extends SessionNotifier {
  @override
  String? build() => 'good-token';
}

Future<void> _pump(
  WidgetTester t,
  FakeControlPlane cp,
  Widget screen, {
  KeyValueStore? tab,
  KeyValueStore? persistent,
}) async {
  desktopView(t);
  await t.pumpWidget(
    ProviderScope(
      retry: (_, _) => null,
      overrides: [
        ...overridesFor(cp, tab: tab, persistent: persistent),
        sessionProvider.overrideWith(_SignedIn.new),
        clockProvider.overrideWithValue(() => DateTime.utc(2026, 11, 20, 10)),
      ],
      child: testApp(screen),
    ),
  );
  await t.pumpAndSettle();
}

void main() {
  final basePolicy = {
    'defaultAction': 'allow',
    'safeSearch': false,
    'categories': <String>[],
    'rules': <Map<String, dynamic>>[],
    'dns': {'redirectQueries': false, 'zone': 'corp.internal'},
    'privateApps': [
      {
        'id': 'app-finance',
        'name': 'Finance App',
        'domains': ['finance.internal'],
        'ports': [
          {'from': 443, 'to': 443},
        ],
        'connectorGroup': 'default',
      },
    ],
    'customLists': <Map<String, dynamic>>[],
    'builtinLists': <String>[],
  };

  testWidgets('the wizard renders all step titles', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'super'})
      ..json('GET /v1/admin/status', {
        'edges': [
          {'id': 'edge-1', 'region': 'eu-west', 'sessions': 2, 'reporting': true},
        ],
        'devicesEnrolled': 0,
        'devicesOnline': 0,
        'connectorsTotal': 0,
        'connectorsOnline': 0,
        'certificates': [
          {'name': 'root-ca', 'notAfter': '2036-11-20T10:00:00Z'},
        ],
        'auditChain': 'ok',
        'leader': true,
        'categoryListAgeSeconds': 3600,
      })
      ..json('GET /v1/admin/tenants', [
        {'id': 'acme', 'name': 'Acme Corp'},
      ])
      ..json('GET /v1/admin/tenants/acme/policy', basePolicy)
      ..json('GET /v1/admin/tenants/acme/oidc', {'error': 'not configured'}, status: 404)
      ..json('GET /v1/admin/blocklists', [
        {'id': 'malware', 'title': 'Malware list', 'url': 'https://example.com/malware.txt', 'licence': 'CC0'},
      ])
      ..json('GET /v1/admin/tenants/acme/connectors', <Map<String, dynamic>>[])
      ..json('GET /v1/admin/tenants/acme/devices', <Map<String, dynamic>>[])
      ..json('GET /v1/admin/tenants/acme/users', <Map<String, dynamic>>[])
      ..json('GET /v1/admin/info', {
        'controlUrl': 'https://cp.test:9443#sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      });

    await _pump(t, cp, const OnboardingScreen());

    expect(find.text('Welcome'), findsWidgets);
    expect(find.text('Organisation'), findsWidgets);
    expect(find.text('Sign-in'), findsWidgets);
    expect(find.text('First policy'), findsWidgets);
    expect(find.text('DNS'), findsWidgets);
    expect(find.text('Private apps'), findsWidgets);
    expect(find.text('Devices'), findsWidgets);
    expect(find.text('Done'), findsWidgets);
  });

  testWidgets(
    'the Recommended template preview contains the malware category and safeSearch true and Apply sends a PUT with If-Match that keeps an existing unrelated field (for example privateApps)',
    (t) async {
      final cp = FakeControlPlane()
        ..json('GET /v1/admin/whoami', {'role': 'tenant', 'tenantId': 'acme'})
        ..json('GET /v1/admin/tenants', [
          {'id': 'acme', 'name': 'Acme Corp'},
        ])
        ..json('GET /v1/admin/tenants/acme/oidc', {'error': 'not configured'}, status: 404)
        ..json('GET /v1/admin/blocklists', [])
        ..json('GET /v1/admin/tenants/acme/connectors', [])
        ..json('GET /v1/admin/tenants/acme/devices', [])
        ..json('GET /v1/admin/tenants/acme/users', [])
        ..json('GET /v1/admin/info', {
          'controlUrl': 'https://cp.test:9443#sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        });

      cp.routes['GET /v1/admin/tenants/acme/policy'] = (_) => http.Response(
        jsonEncode(basePolicy),
        200,
        headers: {'content-type': 'application/json', 'etag': 'etag-policy-999'},
      );
      cp.routes['PUT /v1/admin/tenants/acme/policy'] = (_) =>
          http.Response('', 204, headers: {'etag': 'etag-policy-1000'});

      await _pump(t, cp, const OnboardingScreen());

      // Tap on step 3: First policy
      await t.tap(find.text('First policy').first);
      await t.pumpAndSettle();

      // Check read-only preview
      final previewFinder = find.byKey(const ValueKey('policy_preview_json'));
      expect(previewFinder, findsOneWidget);
      final previewText = t.widget<SelectableText>(previewFinder).data!;

      expect(previewText, contains('"malware"'));
      expect(previewText, contains('"phishing"'));
      expect(previewText, contains('"safeSearch": true'));
      expect(previewText, contains('app-finance'));

      // Apply the template
      await t.tap(find.byKey(const ValueKey('policy_apply_button')));
      await t.pumpAndSettle();

      // Verify the PUT request with If-Match preserving privateApps
      final putReq = cp.requests.singleWhere((r) => r.method == 'PUT' && r.url.path == '/v1/admin/tenants/acme/policy');
      expect(putReq.headers['if-match'], 'etag-policy-999');

      final putBody = jsonDecode(putReq.body) as Map<String, dynamic>;
      expect(putBody['defaultAction'], 'allow');
      expect(putBody['safeSearch'], isTrue);
      expect(putBody['categories'], contains('malware'));
      expect(putBody['categories'], contains('phishing'));
      expect(putBody['privateApps'], isNotEmpty);
      expect(putBody['privateApps'][0]['id'], 'app-finance');
      expect(putBody['privateApps'][0]['name'], 'Finance App');
    },
  );

  testWidgets('the DNS step toggles redirectQueries and saves', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'tenant', 'tenantId': 'acme'})
      ..json('GET /v1/admin/tenants', [
        {'id': 'acme', 'name': 'Acme Corp'},
      ])
      ..json('GET /v1/admin/tenants/acme/oidc', {'error': 'not configured'}, status: 404)
      ..json('GET /v1/admin/blocklists', [
        {'id': 'sec-blocklist', 'title': 'Security Feeds', 'url': 'https://example.com/sec.txt', 'licence': 'MIT'},
      ])
      ..json('GET /v1/admin/tenants/acme/connectors', [])
      ..json('GET /v1/admin/tenants/acme/devices', [])
      ..json('GET /v1/admin/tenants/acme/users', [])
      ..json('GET /v1/admin/info', {
        'controlUrl': 'https://cp.test:9443#sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      });

    cp.routes['GET /v1/admin/tenants/acme/policy'] = (_) => http.Response(
      jsonEncode(basePolicy),
      200,
      headers: {'content-type': 'application/json', 'etag': 'etag-dns-555'},
    );
    cp.routes['PUT /v1/admin/tenants/acme/policy'] = (_) => http.Response('', 204, headers: {'etag': 'etag-dns-556'});

    await _pump(t, cp, const OnboardingScreen());

    // Tap on step 4: DNS
    await t.tap(find.text('DNS').first);
    await t.pumpAndSettle();

    // Toggle redirectQueries
    final switchFinder = find.byKey(const ValueKey('dns_redirect_queries_switch'));
    expect(switchFinder, findsOneWidget);
    await t.tap(switchFinder);
    await t.pumpAndSettle();

    // Tap Save
    await t.tap(find.byKey(const ValueKey('dns_save_button')));
    await t.pumpAndSettle();

    final putReq = cp.requests.singleWhere((r) => r.method == 'PUT' && r.url.path == '/v1/admin/tenants/acme/policy');
    expect(putReq.headers['if-match'], 'etag-dns-555');

    final putBody = jsonDecode(putReq.body) as Map<String, dynamic>;
    expect(putBody['dns']['redirectQueries'], isTrue);
  });

  testWidgets('skipping the Sign-in step moves to First policy', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'tenant', 'tenantId': 'acme'})
      ..json('GET /v1/admin/tenants', [
        {'id': 'acme', 'name': 'Acme Corp'},
      ])
      ..json('GET /v1/admin/tenants/acme/policy', basePolicy)
      ..json('GET /v1/admin/tenants/acme/oidc', {'error': 'not configured'}, status: 404)
      ..json('GET /v1/admin/blocklists', [])
      ..json('GET /v1/admin/tenants/acme/connectors', [])
      ..json('GET /v1/admin/tenants/acme/devices', [])
      ..json('GET /v1/admin/tenants/acme/users', [])
      ..json('GET /v1/admin/info', {
        'controlUrl': 'https://cp.test:9443#sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      });

    await _pump(t, cp, const OnboardingScreen());

    // Tap on step 2: Sign-in
    await t.tap(find.text('Sign-in').first);
    await t.pumpAndSettle();

    // Verify skip button is present
    final skipBtn = find.byKey(const ValueKey('skip_sso_button'));
    expect(skipBtn, findsOneWidget);

    // Tap skip button
    await t.tap(skipBtn);
    await t.pumpAndSettle();

    // Verify we moved to First policy step
    expect(find.byKey(const ValueKey('template_recommended')), findsOneWidget);
    expect(find.byKey(const ValueKey('policy_preview_json')), findsOneWidget);
  });

  testWidgets('shows wizard automatically after sign-in when tenant has no devices and no rules', (t) async {
    final tab = MemoryStore();
    final persistent = MemoryStore();
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'tenant', 'tenantId': 'acme'})
      ..json('GET /v1/admin/tenants', [
        {'id': 'acme', 'name': 'Acme Corp'},
      ])
      ..json('GET /v1/admin/tenants/acme/devices', [])
      ..json('GET /v1/admin/tenants/acme/policy', {'defaultAction': 'allow', 'rules': [], 'dns': {}})
      ..json('GET /v1/admin/tenants/acme/flows', {'records': []})
      ..json('GET /v1/admin/tenants/acme/connectors', [])
      ..json('GET /v1/admin/tenants/acme/oidc', {'error': 'not configured'}, status: 404)
      ..json('GET /v1/admin/blocklists', [])
      ..json('GET /v1/admin/tenants/acme/users', [])
      ..json('GET /v1/admin/info', {
        'controlUrl': 'https://cp.test:9443#sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      });

    tab.write(tokenKey, 'good-token');

    desktopView(t);
    await t.pumpWidget(
      ProviderScope(
        retry: (_, _) => null,
        overrides: [
          ...overridesFor(cp, tab: tab, persistent: persistent),
          clockProvider.overrideWithValue(() => DateTime.utc(2026, 11, 20, 10)),
        ],
        child: const AdminApp(),
      ),
    );
    await t.pumpAndSettle();

    // Verify navigated to onboarding
    expect(tab.read('opensase.admin.onboarding.checked'), '1');
    expect(find.text('Welcome'), findsWidgets);
    expect(find.text('First policy'), findsWidgets);
  });
}
