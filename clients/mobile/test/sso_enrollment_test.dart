import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase/src/data/core_state.dart';
import 'package:opensase/src/data/sso_pending.dart';
import 'package:opensase/src/data/user_layer_store.dart';
import 'package:opensase/src/engine/fake_engine.dart';
import 'package:opensase/src/l10n/app_localizations.dart';
import 'package:opensase/src/ui/common.dart';
import 'package:opensase/src/ui/onboarding_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

Widget host(FakeEngine e) => ProviderScope(
  overrides: [
    engineProvider.overrideWithValue(e),
    userLayerStoreProvider.overrideWithValue(InMemoryUserLayerStore()),
    pollIntervalProvider.overrideWithValue(null),
  ],
  child: const MaterialApp(
    localizationsDelegates: [AppLocalizations.delegate, ...GlobalMaterialLocalizations.delegates],
    supportedLocales: AppLocalizations.supportedLocales,
    home: OnboardingScreen(),
  ),
);

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    final view = TestWidgetsFlutterBinding.instance.platformDispatcher.implicitView!;
    view.physicalSize = const Size(1080, 2400);
    view.devicePixelRatio = 2.625;
  });

  tearDown(
    () => TestWidgetsFlutterBinding.instance.platformDispatcher.implicitView!
      ..resetPhysicalSize()
      ..resetDevicePixelRatio(),
  );

  group('buildSsoStartUrl', () {
    test('builds the right start URL without fragment and with return_to and state', () {
      const controlUrl = 'https://10.0.2.2:9443#sha256=abcdef123456';
      const tenant = 'acme-corp';
      const state = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

      final startUrl = buildSsoStartUrl(controlUrl, tenant, state);
      final uri = Uri.parse(startUrl);

      expect(uri.scheme, 'https');
      expect(uri.host, '10.0.2.2');
      expect(uri.port, 9443);
      expect(uri.path, '/v1/enroll/oidc/acme-corp/start');
      expect(uri.queryParameters['return_to'], 'opensase://enroll');
      expect(uri.queryParameters['state'], state);
      expect(uri.hasFragment, isFalse);
      expect(startUrl.contains('#'), isFalse);
      expect(startUrl.contains('sha256'), isFalse);
    });

    test('handles trailing slash on control URL and encodes tenant segment', () {
      const controlUrl = 'https://cp.example.com:8443/#sha256=999';
      const tenant = 'tenant-123';
      const state = 'state_val';

      final startUrl = buildSsoStartUrl(controlUrl, tenant, state);
      final uri = Uri.parse(startUrl);

      expect(uri.path, '/v1/enroll/oidc/tenant-123/start');
      expect(uri.hasFragment, isFalse);
    });
  });

  group('SsoPending record in SharedPreferences', () {
    test('generates 32 random bytes hex encoded state (64 characters)', () {
      final s1 = SsoPending.generateState();
      final s2 = SsoPending.generateState();
      expect(s1.length, 64);
      expect(s2.length, 64);
      expect(s1, isNot(equals(s2)));
      expect(RegExp(r'^[0-9a-f]{64}$').hasMatch(s1), isTrue);
    });

    test('stores and loads pending record', () async {
      final now = DateTime.now();
      final pending = SsoPending(
        controlUrl: 'https://cp.example.com#sha256=pin',
        tenantId: 'my-org',
        state: 'secret_state_value',
        createdAt: now,
      );
      await pending.save();

      final loaded = await SsoPending.load();
      expect(loaded, isNotNull);
      expect(loaded!.controlUrl, 'https://cp.example.com#sha256=pin');
      expect(loaded.tenantId, 'my-org');
      expect(loaded.state, 'secret_state_value');
    });

    test('record older than 10 minutes is ignored and removed', () async {
      final old = DateTime.now().subtract(const Duration(minutes: 11));
      final pending = SsoPending(
        controlUrl: 'https://cp.example.com#sha256=pin',
        tenantId: 'my-org',
        state: 'old_state',
        createdAt: old,
      );
      await pending.save();

      final loaded = await SsoPending.load();
      expect(loaded, isNull);

      // Verify it was purged from SharedPreferences
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.containsKey(SsoPending.key), isFalse);
    });

    test('toString does not log state', () {
      final pending = SsoPending(
        controlUrl: 'https://cp.example.com#sha256=pin',
        tenantId: 'my-org',
        state: 'sensitive_state_bytes',
        createdAt: DateTime.now(),
      );
      expect(pending.toString(), isNot(contains('sensitive_state_bytes')));
    });
  });

  group('SSO onboarding form and link handling', () {
    testWidgets('SSO form builds the right start URL and calls openBrowser', (t) async {
      final e = FakeEngine(liveTraffic: false);
      await t.pumpWidget(host(e));
      await t.pumpAndSettle();

      await t.tap(find.byKey(const ValueKey('sso_expand')));
      await t.pumpAndSettle();
      await t.enterText(find.byKey(const ValueKey('sso_url')), 'https://10.0.2.2:9443#sha256=abcdef');
      await t.enterText(find.byKey(const ValueKey('sso_tenant')), 'acme-corp');
      await t.pumpAndSettle();

      await t.tap(find.byKey(const ValueKey('sso_submit')));
      await t.pumpAndSettle();

      expect(e.calls, contains('openBrowser'));
      expect(e.lastOpenedUrl, isNotNull);
      final openedUri = Uri.parse(e.lastOpenedUrl!);

      // check path
      expect(openedUri.path, '/v1/enroll/oidc/acme-corp/start');
      // check return_to
      expect(openedUri.queryParameters['return_to'], 'opensase://enroll');
      // check state
      final state = openedUri.queryParameters['state'];
      expect(state, isNotNull);
      expect(state!.length, 64);
      // check that fragment is not sent
      expect(openedUri.hasFragment, isFalse);
      expect(e.lastOpenedUrl!.contains('#'), isFalse);
      expect(e.lastOpenedUrl!.contains('sha256'), isFalse);

      // check pending record was stored
      final pending = await SsoPending.load();
      expect(pending, isNotNull);
      expect(pending!.controlUrl, 'https://10.0.2.2:9443#sha256=abcdef');
      expect(pending.tenantId, 'acme-corp');
      expect(pending.state, state);
    });

    testWidgets('a result link with matching state enrols with stored control URL and code', (t) async {
      final pending = SsoPending(
        controlUrl: 'https://10.0.2.2:9443#sha256=pin_val',
        tenantId: 'acme-corp',
        state: 'valid_matching_state_123',
        createdAt: DateTime.now(),
      );
      await pending.save();

      final e = FakeEngine(liveTraffic: false);
      await t.pumpWidget(host(e));
      await t.pumpAndSettle();

      // Deliver SSO result link
      e.deliverEnrollLink('opensase://enroll?code=osk_single_use_sso&state=valid_matching_state_123');
      await t.pumpAndSettle();

      expect(e.calls, contains('enroll'));
      // Pending record is deleted after successful enrollment
      final remaining = await SsoPending.load();
      expect(remaining, isNull);
      // No error shown
      expect(find.byType(InfoBanner), findsNothing);
    });

    testWidgets('wrong state does not enrol and shows an error', (t) async {
      final pending = SsoPending(
        controlUrl: 'https://10.0.2.2:9443#sha256=pin_val',
        tenantId: 'acme-corp',
        state: 'correct_state_val',
        createdAt: DateTime.now(),
      );
      await pending.save();

      final e = FakeEngine(liveTraffic: false);
      await t.pumpWidget(host(e));
      await t.pumpAndSettle();

      // Deliver SSO result link with wrong state
      e.deliverEnrollLink('opensase://enroll?code=osk_single_use_sso&state=wrong_mismatched_state');
      await t.pumpAndSettle();

      expect(e.calls, isNot(contains('enroll')));
      expect(find.byType(InfoBanner), findsOneWidget);
      expect(find.textContaining('Single sign-on failed'), findsOneWidget);
    });

    testWidgets('expired record does not enrol and shows an error', (t) async {
      final pending = SsoPending(
        controlUrl: 'https://10.0.2.2:9443#sha256=pin_val',
        tenantId: 'acme-corp',
        state: 'state_for_expired',
        createdAt: DateTime.now().subtract(const Duration(minutes: 11)),
      );
      await pending.save();

      final e = FakeEngine(liveTraffic: false);
      await t.pumpWidget(host(e));
      await t.pumpAndSettle();

      e.deliverEnrollLink('opensase://enroll?code=osk_single_use_sso&state=state_for_expired');
      await t.pumpAndSettle();

      expect(e.calls, isNot(contains('enroll')));
      expect(find.byType(InfoBanner), findsOneWidget);
      expect(find.textContaining('Single sign-on failed'), findsOneWidget);

      final remaining = await SsoPending.load();
      expect(remaining, isNull);
    });

    testWidgets('missing pending record does not enrol and shows an error', (t) async {
      final e = FakeEngine(liveTraffic: false);
      await t.pumpWidget(host(e));
      await t.pumpAndSettle();

      e.deliverEnrollLink('opensase://enroll?code=osk_single_use_sso&state=any_state');
      await t.pumpAndSettle();

      expect(e.calls, isNot(contains('enroll')));
      expect(find.byType(InfoBanner), findsOneWidget);
      expect(find.textContaining('Single sign-on failed'), findsOneWidget);
    });

    testWidgets('launch with SSO link enrols when pending record matches', (t) async {
      final pending = SsoPending(
        controlUrl: 'https://10.0.2.2:9443#sha256=launch_pin',
        tenantId: 'acme-corp',
        state: 'launch_state_456',
        createdAt: DateTime.now(),
      );
      await pending.save();

      final e = FakeEngine(liveTraffic: false)
        ..pendingEnrollLink = 'opensase://enroll?code=osk_launch_code&state=launch_state_456';
      await t.pumpWidget(host(e));
      await t.pumpAndSettle();

      expect(e.calls, contains('enroll'));
      expect(await SsoPending.load(), isNull);
      expect(find.byType(InfoBanner), findsNothing);
    });
  });
}
