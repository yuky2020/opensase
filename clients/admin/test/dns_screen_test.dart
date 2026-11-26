import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:material_ui/material_ui.dart';
import 'package:opensase_admin/src/data/browser_storage.dart';
import 'package:opensase_admin/src/data/providers.dart';
import 'package:opensase_admin/src/data/session.dart';
import 'package:opensase_admin/src/ui/dns_screen.dart';

import 'helpers.dart';

class _SignedIn extends SessionNotifier {
  @override
  String? build() => 'good-token';
}

Future<void> _pump(WidgetTester t, FakeControlPlane cp, Widget screen, {KeyValueStore? persistent}) async {
  desktopView(t);
  cp.json('GET /v1/admin/whoami', {'role': 'tenant', 'tenantId': 'acme', 'tokenId': 't1'});
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
  final basePolicy = {
    'defaultAction': 'allow',
    'decideDefault': 'allow',
    'dns': {
      'blockResponse': 'nxdomain',
      'redirectQueries': true,
      'zone': 'corp.internal',
      'records': [
        {'name': 'nas.corp.internal', 'type': 'A', 'value': '10.0.0.5', 'ttl': 300},
      ],
      'forwarders': [
        {
          'zone': 'ad.example.com',
          'servers': ['10.0.0.53', '10.0.0.54'],
        },
      ],
      'allowDomains': ['allow.example.com'],
      'blockDomains': ['block.example.com'],
      'logQueries': true,
    },
    'customLists': [
      {'id': 'corp-bad', 'title': 'Corporate blocklist', 'url': 'https://lists.example.com/hosts.txt'},
    ],
    'builtinLists': ['malware'],
  };

  final blocklistsCatalog = [
    {
      'id': 'malware',
      'title': 'Malware distribution sites',
      'url': 'https://urlhaus.abuse.ch/downloads/hostfile/',
      'licence': 'CC0',
    },
    {'id': 'phishing', 'title': 'Phishing feeds', 'url': 'https://example.com/phishing.txt', 'licence': 'MIT'},
  ];

  testWidgets('the page renders a policy with records, forwarders and lists', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants/acme/policy', basePolicy)
      ..json('GET /v1/admin/blocklists', blocklistsCatalog);

    await _pump(t, cp, const DnsScreen());

    // Internal zone & records
    expect(find.byKey(const ValueKey('dns_zone')), findsOneWidget);
    expect(find.text('nas.corp.internal'), findsOneWidget);
    expect(find.text('10.0.0.5'), findsOneWidget);

    // Forwarders
    expect(find.text('ad.example.com'), findsOneWidget);
    expect(find.text('10.0.0.53, 10.0.0.54'), findsOneWidget);

    // Blocklists
    expect(find.text('Corporate blocklist'), findsOneWidget);
    expect(find.text('corp-bad'), findsOneWidget);
    expect(find.text('Malware distribution sites'), findsOneWidget);

    // Resolver switches
    final redirectSwitch = t.widget<SwitchListTile>(find.byKey(const ValueKey('dns_redirect_queries')));
    expect(redirectSwitch.value, isTrue);

    final logSwitch = t.widget<SwitchListTile>(find.byKey(const ValueKey('dns_log_queries')));
    expect(logSwitch.value, isTrue);

    // Builtin switch
    final malwareSwitch = t.widget<SwitchListTile>(find.byKey(const ValueKey('builtin_switch_malware')));
    expect(malwareSwitch.value, isTrue);

    final phishingSwitch = t.widget<SwitchListTile>(find.byKey(const ValueKey('builtin_switch_phishing')));
    expect(phishingSwitch.value, isFalse);
    await t.scrollUntilVisible(find.text('allow.example.com'), 300, scrollable: find.byType(Scrollable).first);
    // Domain overrides
    expect(find.text('allow.example.com'), findsOneWidget);
    expect(find.text('block.example.com'), findsOneWidget);
  });

  testWidgets('adding a record and saving sends a PUT with If-Match and the new record in dns.records', (t) async {
    Map<String, dynamic>? putBody;
    String? putIfMatch;

    final cp = FakeControlPlane()..json('GET /v1/admin/blocklists', blocklistsCatalog);

    cp.routes['GET /v1/admin/tenants/acme/policy'] = (_) =>
        http.Response(jsonEncode(basePolicy), 200, headers: {'content-type': 'application/json', 'etag': '"etag-abc"'});

    cp.routes['PUT /v1/admin/tenants/acme/policy'] = (r) {
      putBody = jsonDecode(r.body) as Map<String, dynamic>;
      putIfMatch = r.headers['if-match'] ?? r.headers['If-Match'];
      return http204();
    };

    await _pump(t, cp, const DnsScreen());

    // Tap Add Record
    await t.tap(find.byKey(const ValueKey('record_add')));
    await t.pumpAndSettle();

    // Fill form
    await t.enterText(find.byKey(const ValueKey('record_name')), 'wiki.corp.internal');
    await t.enterText(find.byKey(const ValueKey('record_value')), '10.0.0.6');
    await t.enterText(find.byKey(const ValueKey('record_ttl')), '600');

    // Submit dialog
    await t.tap(find.byKey(const ValueKey('record_dialog_submit')));
    await t.pumpAndSettle();

    // Record shows in table
    expect(find.text('wiki.corp.internal'), findsOneWidget);

    // Save policy
    await t.tap(find.byKey(const ValueKey('dns_save')));
    await t.pumpAndSettle();

    expect(putIfMatch, '"etag-abc"');
    expect(putBody, isNotNull);
    final dns = putBody!['dns'] as Map<String, dynamic>;
    final records = dns['records'] as List;
    expect(records.length, 2);
    expect(
      records.any((r) => r['name'] == 'wiki.corp.internal' && r['value'] == '10.0.0.6' && r['ttl'] == 600),
      isTrue,
    );
  });

  testWidgets('toggling a built-in list adds its id to builtinLists', (t) async {
    Map<String, dynamic>? putBody;

    final policyWithoutBuiltin = {...basePolicy, 'builtinLists': <String>[]};

    final cp = FakeControlPlane()..json('GET /v1/admin/blocklists', blocklistsCatalog);

    cp.routes['GET /v1/admin/tenants/acme/policy'] = (_) => http.Response(
      jsonEncode(policyWithoutBuiltin),
      200,
      headers: {'content-type': 'application/json', 'etag': '"etag-toggle"'},
    );

    cp.routes['PUT /v1/admin/tenants/acme/policy'] = (r) {
      putBody = jsonDecode(r.body) as Map<String, dynamic>;
      return http204();
    };

    await _pump(t, cp, const DnsScreen());

    // Toggle malware list
    await t.tap(find.byKey(const ValueKey('builtin_switch_malware')));
    await t.pumpAndSettle();

    // Save policy
    await t.tap(find.byKey(const ValueKey('dns_save')));
    await t.pumpAndSettle();

    expect(putBody, isNotNull);
    final builtin = putBody!['builtinLists'] as List;
    expect(builtin, contains('malware'));
  });

  testWidgets('an invalid A record value shows an error and is not saved', (t) async {
    final cp = FakeControlPlane()..json('GET /v1/admin/blocklists', blocklistsCatalog);

    cp.routes['GET /v1/admin/tenants/acme/policy'] = (_) => http.Response(
      jsonEncode(basePolicy),
      200,
      headers: {'content-type': 'application/json', 'etag': '"etag-test"'},
    );

    await _pump(t, cp, const DnsScreen());

    // Tap Add Record
    await t.tap(find.byKey(const ValueKey('record_add')));
    await t.pumpAndSettle();

    // Fill form with invalid IPv4
    await t.enterText(find.byKey(const ValueKey('record_name')), 'bad.corp.internal');
    await t.enterText(find.byKey(const ValueKey('record_value')), '999.999.999.999');

    // Submit dialog
    await t.tap(find.byKey(const ValueKey('record_dialog_submit')));
    await t.pumpAndSettle();

    // Error is shown in dialog
    expect(find.text('Must be a valid IPv4 address'), findsOneWidget);
    // Dialog is still present
    expect(find.byKey(const ValueKey('record_dialog_submit')), findsOneWidget);

    // Cancel dialog
    await t.tap(find.text('Cancel'));
    await t.pumpAndSettle();

    // Record was not added to table
    expect(find.text('bad.corp.internal'), findsNothing);

    // No PUT request was made
    expect(cp.requests.where((r) => r.method == 'PUT'), isEmpty);
  });
}
