import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase/src/data/core_state.dart';
import 'package:opensase/src/data/user_layer_store.dart';
import 'package:opensase/src/engine/fake_engine.dart';
import 'package:opensase/src/l10n/app_localizations.dart';
import 'package:opensase/src/ui/onboarding_screen.dart';

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

String textOf(WidgetTester t, String key) => t.widget<TextField>(find.byKey(ValueKey(key))).controller!.text;

const link = 'opensase://enroll?control=https%3A%2F%2F10.0.2.2%3A9443%23sha256%3Dabcd&key=osk_TEST';

void main() {
  setUp(() {
    final view = TestWidgetsFlutterBinding.instance.platformDispatcher.implicitView!;
    view.physicalSize = const Size(1080, 2400);
    view.devicePixelRatio = 2.625;
  });
  tearDown(
    () => TestWidgetsFlutterBinding.instance.platformDispatcher.implicitView!
      ..resetPhysicalSize()
      ..resetDevicePixelRatio(),
  );

  testWidgets('launch deep link pre-fills the form but does not enroll by itself', (t) async {
    final e = FakeEngine(liveTraffic: false)..pendingEnrollLink = link;
    await t.pumpWidget(host(e));
    await t.pumpAndSettle();
    expect(textOf(t, 'enroll_url'), 'https://10.0.2.2:9443#sha256=abcd');
    expect(textOf(t, 'enroll_key'), 'osk_TEST');
    expect(find.text('Server certificate pinned (sha256)'), findsOneWidget);
    expect(textOf(t, 'enroll_code'), '', reason: 'the code (with the key) is not left on screen');
    expect(find.textContaining('Code applied'), findsOneWidget);
    expect(e.calls, isNot(contains('enroll')));
    await t.tap(find.byKey(const ValueKey('enroll_submit')));
    await t.pumpAndSettle();
    expect(e.calls, contains('enroll'));
    expect(textOf(t, 'enroll_key'), '', reason: 'key cleared after enrolling');
  });

  testWidgets('link received while running; pasted garbage shows an error', (t) async {
    final e = FakeEngine(liveTraffic: false);
    await t.pumpWidget(host(e));
    await t.pumpAndSettle();
    e.deliverEnrollLink(link);
    await t.pumpAndSettle();
    expect(textOf(t, 'enroll_key'), 'osk_TEST');
    await t.enterText(find.byKey(const ValueKey('enroll_code')), 'http://nope');
    await t.pumpAndSettle();
    expect(find.text('Not a valid enrollment code'), findsOneWidget);
  });

  testWidgets('enrollment failure is shown', (t) async {
    final e = FakeEngine(liveTraffic: false);
    await t.pumpWidget(host(e));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const ValueKey('enroll_key')), 'invalid');
    await t.pumpAndSettle();
    await t.tap(find.byKey(const ValueKey('enroll_submit')));
    await t.pumpAndSettle();
    expect(find.textContaining('401'), findsOneWidget);
  });
}
