import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase/src/data/core_state.dart';
import 'package:opensase/src/data/user_layer_store.dart';
import 'package:opensase/src/engine/fake_engine.dart';
import 'package:opensase/src/l10n/app_localizations.dart';
import 'package:opensase/src/ui/apps_screen.dart';
import 'package:opensase/src/ui/theme.dart';

Widget host(FakeEngine e, Widget child, {Locale locale = const Locale('en')}) => ProviderScope(
  overrides: [
    engineProvider.overrideWithValue(e),
    userLayerStoreProvider.overrideWithValue(InMemoryUserLayerStore()),
    pollIntervalProvider.overrideWithValue(null),
  ],
  child: MaterialApp(
    theme: buildTheme(Brightness.light),
    locale: locale,
    localizationsDelegates: const [AppLocalizations.delegate, ...GlobalMaterialLocalizations.delegates],
    supportedLocales: AppLocalizations.supportedLocales,
    home: Scaffold(body: child),
  ),
);

void main() {
  testWidgets('lists apps, shows tenant locks, filters by search, toggles save', (tester) async {
    final e = FakeEngine(liveTraffic: false, enrolled: true);
    String? opened;
    await tester.pumpWidget(host(e, AppsScreen(onOpen: (p) => opened = p)));
    await tester.pumpAndSettle();

    expect(find.text('Chrome'), findsOneWidget);
    expect(find.text('Google Play services'), findsNothing, reason: 'system apps hidden by default');
    expect(find.byKey(const Key('lock_com.zhiliaoapp.musically')), findsOneWidget);
    expect(find.byKey(const Key('lock_com.android.chrome')), findsNothing);

    // Tenant-locked toggle is disabled.
    final locked = tester.widget<IconButton>(find.byKey(const Key('toggle_com.zhiliaoapp.musically_wifi')));
    expect(locked.onPressed, isNull);

    // Toggle WhatsApp on mobile data -> saves the user layer.
    await tester.tap(find.byKey(const Key('toggle_com.whatsapp_cellular')));
    await tester.pumpAndSettle();
    expect(e.calls, contains('setUserRules'));
    final after = tester.widget<IconButton>(find.byKey(const Key('toggle_com.whatsapp_cellular')));
    expect(after.isSelected, isFalse);

    await tester.enterText(find.byKey(const Key('apps_search')), 'spot');
    await tester.pumpAndSettle();
    expect(find.text('Spotify'), findsOneWidget);
    expect(find.text('Chrome'), findsNothing);

    await tester.tap(find.text('Spotify'));
    expect(opened, 'com.spotify.music');
  });

  testWidgets('Italian strings and read-only banner when user rules are not allowed', (tester) async {
    final e = FakeEngine(liveTraffic: false, enrolled: true, allowUserRules: false);
    await tester.pumpWidget(host(e, AppsScreen(onOpen: (_) {}), locale: const Locale('it')));
    await tester.pumpAndSettle();
    expect(find.textContaining('sola lettura'), findsOneWidget);
    expect(find.text('Con Internet'), findsOneWidget);
    final t = tester.widget<IconButton>(find.byKey(const Key('toggle_com.android.chrome_wifi')));
    expect(t.onPressed, isNull);
  });
}
