import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase_admin/src/data/browser_storage.dart';
import 'package:opensase_admin/src/data/providers.dart';
import 'package:opensase_admin/src/data/session.dart';
import 'package:opensase_admin/src/ui/admin_tokens_screen.dart';
import 'package:opensase_admin/src/ui/audit_screen.dart';
import 'package:opensase_admin/src/ui/infra_screens.dart';
import 'package:opensase_admin/src/ui/categories_screen.dart';
import 'package:opensase_admin/src/ui/saas_screen.dart';
import 'package:opensase_admin/src/ui/web_screen.dart';
import 'package:opensase_admin/src/ui/tenants_screen.dart';
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

  testWidgets('a tenant admin cannot create tenants; the super-admin can (ST-03)', (t) async {
    final tenantAdmin = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'tenant', 'tenantId': 'acme', 'tokenId': 't1'});
    await _pump(t, tenantAdmin, const TenantsScreen());
    expect(find.byKey(const Key('tenant_create')), findsNothing);

    final superAdmin = FakeControlPlane()..json('GET /v1/admin/whoami', {'role': 'super'});
    await _pump(t, superAdmin, const TenantsScreen());
    expect(find.byKey(const Key('tenant_create')), findsOneWidget);
  });

  testWidgets('admin token is created with its validity and shown once', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'tenant', 'tenantId': 'acme', 'tokenId': 't1'})
      ..json('GET /v1/admin/tenants/acme/admin-tokens', [
        {
          'id': 't1',
          'tenantId': 'acme',
          'name': 'me',
          'createdAt': '2026-11-20T09:00:00Z',
          'expiresAt': '2027-02-18T09:00:00Z',
          'revoked': false,
        },
      ])
      ..json('POST /v1/admin/tenants/acme/admin-tokens', {
        'id': 't2',
        'tenantId': 'acme',
        'name': 'ops',
        'createdAt': '2026-11-20T10:00:00Z',
        'expiresAt': '2026-12-20T10:00:00Z',
        'revoked': false,
        'token': 'osa_secret',
      }, status: 201);
    await _pump(t, cp, const AdminTokensScreen());
    expect(find.text('me (this session)'), findsOneWidget);
    await t.tap(find.byKey(const Key('admin_token_create')));
    await t.pumpAndSettle();
    final fields = find.byType(TextFormField);
    await t.enterText(fields.at(0), 'ops');
    await t.enterText(fields.at(1), 'viewer');
    await t.enterText(fields.at(2), '30');
    await t.tap(find.text('Create'));
    await t.pumpAndSettle();
    expect(find.text('osa_secret'), findsOneWidget);
    final post = cp.requests.lastWhere((r) => r.method == 'POST');
    expect(jsonDecode(post.body), {'name': 'ops', 'validForSeconds': 30 * 86400, 'role': 'viewer'});
  });

  testWidgets('audit shows token names and results', (t) async {
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'super'})
      ..json('GET /v1/admin/audit/verify', {'ok': true, 'entries': 3, 'headId': 3, 'head': 'ab' * 32})
      ..json('GET /v1/admin/tenants/acme/admin-tokens', [
        {
          'id': 't1',
          'tenantId': 'acme',
          'name': 'ops team',
          'createdAt': '2026-11-20T09:00:00Z',
          'expiresAt': '2027-02-18T09:00:00Z',
          'revoked': false,
        },
      ])
      ..json('GET /v1/admin/tenants/acme/audit', [
        {
          'id': 2,
          'at': '2026-11-20T09:30:00Z',
          'actor': 'token:t1',
          'tenantId': 'acme',
          'method': 'PUT',
          'path': '/v1/admin/tenants/acme/policy',
          'status': 204,
        },
        {
          'id': 1,
          'at': '2026-11-20T09:00:00Z',
          'actor': 'super',
          'tenantId': 'acme',
          'method': 'POST',
          'path': '/v1/admin/tenants/acme/admin-tokens',
          'status': 201,
        },
      ]);
    await _pump(t, cp, const AuditScreen());
    expect(find.text('ops team'), findsOneWidget);
    expect(find.text('super-admin'), findsOneWidget);
    expect(find.text('204'), findsOneWidget);
    expect(find.text('/v1/admin/tenants/acme/policy'), findsOneWidget);
    expect(find.byKey(const Key('audit_chain')), findsOneWidget);
    expect(find.textContaining('3 entries verified'), findsOneWidget);
  });

  testWidgets('SaaS: category block with an exemption is saved; discovered apps are shown', (t) async {
    Object? put;
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'super'})
      ..json('GET /v1/admin/tenants/acme/policy', {'defaultAction': 'allow', 'decideDefault': 'allow'})
      ..json('GET /v1/admin/saas/catalog', [
        {
          'id': 'chatgpt',
          'name': 'ChatGPT',
          'category': 'ai-assistant',
          'domains': ['chatgpt.com'],
        },
        {
          'id': 'claude',
          'name': 'Claude',
          'category': 'ai-assistant',
          'domains': ['claude.ai'],
        },
        {
          'id': 'dropbox',
          'name': 'Dropbox',
          'category': 'file-sharing',
          'domains': ['dropbox.com'],
        },
      ])
      ..json('GET /v1/admin/tenants/acme/flows', {
        'records': [
          {
            'start': '2026-11-20T09:00:00Z',
            'flow': {'protocol': 'tcp', 'dstIp': '1.2.3.4', 'dstPort': 443, 'domain': 'www.dropbox.com'},
            'decision': {'action': 'allow', 'layer': 'default'},
            'where': 'edge',
            'saasApp': 'dropbox',
          },
        ],
      });
    cp.routes['PUT /v1/admin/tenants/acme/policy'] = (r) {
      put = jsonDecode(r.body);
      return http204();
    };
    await _pump(t, cp, const SaasScreen());
    expect(find.byKey(const Key('seen_dropbox')), findsOneWidget);
    await t.tap(find.byKey(const Key('saas_cat_ai-assistant')));
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('saas_app_claude'))); // exempt from the category
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('saas_save')));
    await t.pumpAndSettle();
    expect((put! as Map)['saas'], {
      'blockCategories': ['ai-assistant'],
      'allowApps': ['claude'],
    });
  });

  testWidgets('Web inspection: rules and headers are kept, inspection is turned on and saved', (t) async {
    Object? put;
    final web = {
      'bypass': ['*.bank.example'],
      'rules': [
        {
          'id': 'no-admin',
          'domains': ['app.example'],
          'action': 'block',
          'pathPrefixes': ['/admin'],
        },
      ],
      'headers': [
        {
          'domains': ['*.saas.example'],
          'name': 'X-Allowed-Tenant',
          'value': 'acme',
        },
      ],
      'dlp': [
        {
          'id': 'pci',
          'action': 'block',
          'detectors': ['credit-card'],
        },
      ],
    };
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'super'})
      ..json('GET /v1/admin/tenants/acme/policy', {'defaultAction': 'allow', 'decideDefault': 'allow', 'web': web});
    cp.routes['PUT /v1/admin/tenants/acme/policy'] = (r) {
      put = jsonDecode(r.body);
      return http204();
    };
    await _pump(t, cp, const WebScreen());
    expect(find.byKey(const Key('web_rule_no-admin')), findsOneWidget);
    expect(find.text('X-Allowed-Tenant: acme'), findsOneWidget);
    await t.tap(find.byKey(const Key('web_inspect')));
    await t.pumpAndSettle();
    await t.ensureVisible(find.byKey(const Key('web_dlp_unscanned_pci')));
    await t.tap(find.byKey(const Key('web_dlp_unscanned_pci')));
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('web_save')));
    await t.pumpAndSettle();
    expect((put! as Map)['web'], {
      'inspect': true,
      ...web,
      'dlp': [
        {
          'id': 'pci',
          'action': 'block',
          'detectors': ['credit-card'],
          'blockUnscanned': true,
        },
      ],
    });
  });

  testWidgets('Web categories: a category is blocked and saved; allow lists are not offered', (t) async {
    Object? put;
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/whoami', {'role': 'super'})
      ..json('GET /v1/admin/tenants/acme/policy', {
        'defaultAction': 'allow',
        'decideDefault': 'allow',
        'categories': ['adult'],
      })
      ..json('GET /v1/admin/categories', {
        'source': 'UT1 blacklists, Université Toulouse Capitole',
        'licence': 'CC BY-SA 4.0',
        'url': 'https://dsi.ut-capitole.fr/blacklists/',
        'version': 'abc',
        'loadedAt': '2026-11-21T19:00:00Z',
        'categories': [
          {'name': 'adult', 'title': 'Adult (X)', 'type': 'black', 'domains': 4599288},
          {'name': 'gambling', 'title': 'Gambling', 'type': 'black', 'domains': 95194},
          {'name': 'liste_blanche', 'type': 'white', 'domains': 10},
        ],
      });
    cp.routes['PUT /v1/admin/tenants/acme/policy'] = (r) {
      put = jsonDecode(r.body);
      return http204();
    };
    await _pump(t, cp, const CategoriesScreen());
    expect(find.byKey(const Key('cat_liste_blanche')), findsNothing);
    expect(find.byKey(const Key('cat_chip_adult')), findsOneWidget);
    await t.tap(find.byKey(const Key('cat_gambling')));
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('cat_safesearch')));
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('cat_save')));
    await t.pumpAndSettle();
    expect((put! as Map)['categories'], ['adult', 'gambling']);
    expect((put! as Map)['safeSearch'], true);
  });
}
