import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase/src/data/core_state.dart';
import 'package:opensase/src/data/user_layer_store.dart';
import 'package:opensase/src/engine/fake_engine.dart';
import 'package:opensase/src/l10n/app_localizations.dart';
import 'package:opensase/src/ui/home_screen.dart';
import 'package:opensase/src/ui/theme.dart';

void main() {
  testWidgets('connect toggle: quantum badge only when connected with pq', (t) async {
    t.view.physicalSize = const Size(1080, 2400);
    t.view.devicePixelRatio = 2.625;
    addTearDown(t.view.reset);
    final e = FakeEngine(liveTraffic: false, enrolled: true);
    await t.pumpWidget(
      ProviderScope(
        overrides: [
          engineProvider.overrideWithValue(e),
          userLayerStoreProvider.overrideWithValue(InMemoryUserLayerStore()),
          pollIntervalProvider.overrideWithValue(null),
        ],
        child: MaterialApp(
          theme: buildTheme(Brightness.light),
          localizationsDelegates: const [AppLocalizations.delegate, ...GlobalMaterialLocalizations.delegates],
          supportedLocales: AppLocalizations.supportedLocales,
          home: Scaffold(body: HomeScreen(onOpenApp: (_) {})),
        ),
      ),
    );
    await t.pumpAndSettle();
    expect(find.text('Disconnected'), findsOneWidget);
    expect(find.textContaining('Quantum-safe'), findsNothing);
    await t.tap(find.byKey(const Key('connect_toggle')));
    await t.pumpAndSettle();
    expect(e.calls, contains('connect'));
    expect(find.text('Connected'), findsOneWidget);
    expect(find.text('Quantum-safe: X25519MLKEM768'), findsOneWidget);
    expect(find.text('edge-eu-south-1'), findsOneWidget);
    await t.tap(find.byKey(const Key('connect_toggle')));
    await t.pumpAndSettle();
    expect(find.text('Disconnected'), findsOneWidget);
    expect(find.textContaining('Quantum-safe'), findsNothing);
  });

  testWidgets('posture: attention card shows hints for failing checks and is hidden when empty', (t) async {
    t.view.physicalSize = const Size(1080, 2400);
    t.view.devicePixelRatio = 2.625;
    addTearDown(t.view.reset);
    final e = FakeEngine(liveTraffic: false, enrolled: true, postureFailing: ['osVersion', 'screenLock']);
    await t.pumpWidget(
      ProviderScope(
        overrides: [
          engineProvider.overrideWithValue(e),
          userLayerStoreProvider.overrideWithValue(InMemoryUserLayerStore()),
          pollIntervalProvider.overrideWithValue(null),
        ],
        child: MaterialApp(
          theme: buildTheme(Brightness.light),
          localizationsDelegates: const [AppLocalizations.delegate, ...GlobalMaterialLocalizations.delegates],
          supportedLocales: AppLocalizations.supportedLocales,
          home: Scaffold(body: HomeScreen(onOpenApp: (_) {})),
        ),
      ),
    );
    await t.pumpAndSettle();

    expect(find.byKey(const ValueKey('posture_attention_card')), findsOneWidget);
    expect(find.text('Device needs attention'), findsOneWidget);
    expect(find.text('Update Android'), findsOneWidget);
    expect(find.text('Set a screen lock'), findsOneWidget);

    e.postureFailing = [];
    final container = ProviderScope.containerOf(t.element(find.byType(HomeScreen)));
    await container.read(coreProvider.notifier).refreshStatus();
    await t.pumpAndSettle();

    expect(find.byKey(const ValueKey('posture_attention_card')), findsNothing);
    expect(find.text('Device needs attention'), findsNothing);
  });
}
