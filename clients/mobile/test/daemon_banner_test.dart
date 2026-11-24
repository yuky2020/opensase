import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase/src/data/core_state.dart';
import 'package:opensase/src/data/user_layer_store.dart';
import 'package:opensase/src/engine/daemon_engine.dart';
import 'package:opensase/src/engine/daemon_transport.dart';
import 'package:opensase/src/l10n/app_localizations.dart';
import 'package:opensase/src/platform_info.dart';
import 'package:opensase/src/ui/home_screen.dart';
import 'package:opensase/src/ui/onboarding_screen.dart';
import 'package:opensase/src/ui/theme.dart';

class ThrowingTransport implements DaemonTransport {
  @override
  Future<DaemonResponse> request(String method, String path, {String? body}) async {
    throw const SocketException('Connection refused (os error 111)');
  }

  @override
  Stream<String> sse(String path) {
    return Stream<String>.error(const SocketException('Connection refused (os error 111)'));
  }
}

Widget hostWithEngine(DaemonEngine engine, Widget child, {Locale locale = const Locale('en')}) {
  return ProviderScope(
    overrides: [
      engineProvider.overrideWithValue(engine),
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
}

void main() {
  setUp(() {
    isDesktopOverride = true;
  });

  tearDown(() {
    isDesktopOverride = null;
  });

  testWidgets('desktop banner appears on HomeScreen when daemon transport throws', (tester) async {
    final engine = DaemonEngine(ThrowingTransport(), initialBackoff: const Duration(milliseconds: 10));

    await tester.pumpWidget(hostWithEngine(engine, HomeScreen(onOpenApp: (_) {})));
    await tester.pumpAndSettle();

    expect(find.textContaining('The OpenSASE service is not running'), findsOneWidget);
    if (Platform.isWindows) {
      expect(find.textContaining('start the OpenSASE service'), findsOneWidget);
    } else {
      expect(find.textContaining('sudo systemctl start opensased'), findsOneWidget);
    }
  });

  testWidgets('desktop banner appears on OnboardingScreen when daemon transport throws', (tester) async {
    final engine = DaemonEngine(ThrowingTransport(), initialBackoff: const Duration(milliseconds: 10));

    await tester.pumpWidget(hostWithEngine(engine, const OnboardingScreen()));
    await tester.pumpAndSettle();

    expect(find.textContaining('The OpenSASE service is not running'), findsOneWidget);
    if (Platform.isWindows) {
      expect(find.textContaining('start the OpenSASE service'), findsOneWidget);
    } else {
      expect(find.textContaining('sudo systemctl start opensased'), findsOneWidget);
    }
  });

  testWidgets('desktop banner appears in Italian when locale is it', (tester) async {
    final engine = DaemonEngine(ThrowingTransport(), initialBackoff: const Duration(milliseconds: 10));

    await tester.pumpWidget(hostWithEngine(engine, HomeScreen(onOpenApp: (_) {}), locale: const Locale('it')));
    await tester.pumpAndSettle();

    expect(find.textContaining('Il servizio OpenSASE non è in esecuzione'), findsOneWidget);
  });
}
