import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase_admin/src/app.dart';
import 'package:opensase_admin/src/data/browser_nav.dart';
import 'package:opensase_admin/src/data/browser_storage.dart';
import 'package:opensase_admin/src/data/session.dart';

import 'helpers.dart';

class _SpyStore extends MemoryStore {
  final writes = <String, String?>{};
  @override
  void write(String key, String? value) {
    writes[key] = value;
    super.write(key, value);
  }
}

Future<FakeControlPlane> _pumpApp(WidgetTester t, KeyValueStore tab, KeyValueStore persistent) async {
  desktopView(t);
  final cp = FakeControlPlane()
    ..json('GET /v1/admin/tenants', [
      {'id': 'acme', 'name': 'Acme'},
    ])
    ..json('GET /v1/admin/edges', [])
    ..json('GET /v1/admin/tenants/acme/devices', [])
    ..json('GET /v1/admin/tenants/acme/connectors', [])
    ..json('GET /v1/admin/tenants/acme/flows', {'records': []});
  await t.pumpWidget(
    ProviderScope(
      retry: (_, _) => null,
      overrides: overridesFor(cp, tab: tab, persistent: persistent),
      child: const AdminApp(),
    ),
  );
  await t.pumpAndSettle();
  return cp;
}

void main() {
  testWidgets('wrong token shows an error and stays on login', (t) async {
    final tab = _SpyStore();
    await _pumpApp(t, tab, _SpyStore());
    expect(find.byKey(const Key('login_token')), findsOneWidget);
    await t.enterText(find.byKey(const Key('login_token')), 'bad');
    await t.tap(find.byKey(const Key('login_submit')));
    await t.pumpAndSettle();
    expect(find.byKey(const Key('login_error')), findsOneWidget);
    expect(find.textContaining('401'), findsOneWidget);
    expect(tab.writes, isEmpty);
  });

  testWidgets('empty token is refused locally', (t) async {
    final cp = await _pumpApp(t, _SpyStore(), _SpyStore());
    await t.tap(find.byKey(const Key('login_submit')));
    await t.pumpAndSettle();
    expect(find.text('Enter the admin token'), findsOneWidget);
    expect(cp.requests, isEmpty);
  });

  testWidgets('remember for this tab keeps the token in sessionStorage only', (t) async {
    final tab = _SpyStore();
    final persistent = _SpyStore();
    final cp = await _pumpApp(t, tab, persistent);
    await t.enterText(find.byKey(const Key('login_token')), ' good-token ');
    await t.tap(find.byKey(const Key('login_remember')));
    await t.tap(find.byKey(const Key('login_submit')));
    await t.pumpAndSettle();
    expect(find.byKey(const Key('login_token')), findsNothing);
    expect(find.byKey(const Key('stat_devices')), findsOneWidget);
    expect(tab.read(tokenKey), 'good-token');
    expect(persistent.writes.values, isNot(contains('good-token')));
    expect(cp.requests.every((r) => r.headers['Authorization'] == 'Bearer good-token' || r.url.path.isEmpty), isTrue);

    await t.tap(find.byKey(const Key('logout')));
    await t.pumpAndSettle();
    expect(find.byKey(const Key('login_token')), findsOneWidget);
    expect(tab.read(tokenKey), isNull);
  });

  testWidgets('without remember the token stays in memory only', (t) async {
    final tab = _SpyStore();
    final persistent = _SpyStore();
    await _pumpApp(t, tab, persistent);
    await t.enterText(find.byKey(const Key('login_token')), 'good-token');
    await t.tap(find.byKey(const Key('login_submit')));
    await t.pumpAndSettle();
    expect(find.byKey(const Key('stat_devices')), findsOneWidget);
    expect(tab.read(tokenKey), isNull);
    expect(persistent.writes.values, isNot(contains('good-token')));
  });

  testWidgets('a token remembered in the tab skips the login', (t) async {
    final tab = MemoryStore()..write(tokenKey, 'good-token');
    await _pumpApp(t, tab, MemoryStore());
    expect(find.byKey(const Key('login_token')), findsNothing);
    expect(find.byKey(const Key('stat_devices')), findsOneWidget);
  });

  testWidgets('login screen shows organisation sign-in button and builds the right URL for a tenant', (t) async {
    String? navigatedUrl;
    desktopView(t);
    final cp = FakeControlPlane();
    await t.pumpWidget(
      ProviderScope(
        retry: (_, _) => null,
        overrides: [
          ...overridesFor(cp),
          browserNavProvider.overrideWithValue((url) => navigatedUrl = url),
        ],
        child: const AdminApp(),
      ),
    );
    await t.pumpAndSettle();

    expect(find.text('Sign in with your organisation'), findsWidgets);
    expect(find.byKey(const Key('login_oidc_submit')), findsOneWidget);

    // Empty tenant shows error
    await t.tap(find.byKey(const Key('login_oidc_submit')));
    await t.pumpAndSettle();
    expect(find.text('Enter the tenant ID'), findsOneWidget);
    expect(navigatedUrl, isNull);

    // Enter tenant and click submit
    await t.enterText(find.byKey(const Key('login_oidc_tenant')), 'acme');
    await t.tap(find.byKey(const Key('login_oidc_submit')));
    await t.pumpAndSettle();

    expect(navigatedUrl, isNotNull);
    expect(navigatedUrl, 'https://cp.test:9443/v1/auth/oidc/acme/login');
  });

  testWidgets('/oidc-signin route stores the token and shows signed-in UI', (t) async {
    final tab = _SpyStore();
    final persistent = _SpyStore();
    desktopView(t);
    final cp = FakeControlPlane()
      ..json('GET /v1/admin/tenants', [
        {'id': 'acme', 'name': 'Acme'},
      ])
      ..json('GET /v1/admin/edges', [])
      ..json('GET /v1/admin/tenants/acme/devices', [])
      ..json('GET /v1/admin/tenants/acme/connectors', [])
      ..json('GET /v1/admin/tenants/acme/flows', {'records': []});

    await t.pumpWidget(
      ProviderScope(
        retry: (_, _) => null,
        overrides: overridesFor(cp, tab: tab, persistent: persistent),
        child: const AdminApp(),
      ),
    );
    await t.pumpAndSettle();

    expect(find.byKey(const Key('login_token')), findsOneWidget);

    final element = t.element(find.byType(AdminApp));
    final container = ProviderScope.containerOf(element);
    container.read(routerProvider).go('/oidc-signin?token=good-token');
    await t.pumpAndSettle();

    expect(tab.read(tokenKey), 'good-token');
    expect(find.byKey(const Key('stat_devices')), findsOneWidget);
  });

  testWidgets('/oidc-signin route without token goes back to login', (t) async {
    final tab = _SpyStore();
    final persistent = _SpyStore();
    desktopView(t);
    final cp = FakeControlPlane();

    await t.pumpWidget(
      ProviderScope(
        retry: (_, _) => null,
        overrides: overridesFor(cp, tab: tab, persistent: persistent),
        child: const AdminApp(),
      ),
    );
    await t.pumpAndSettle();

    final element = t.element(find.byType(AdminApp));
    final container = ProviderScope.containerOf(element);
    container.read(routerProvider).go('/oidc-signin');
    await t.pumpAndSettle();

    expect(find.byKey(const Key('login_token')), findsOneWidget);
    expect(tab.read(tokenKey), isNull);
  });
}
