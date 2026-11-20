import 'dart:convert';

import 'package:flutter_riverpod/misc.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase_admin/src/data/browser_storage.dart';
import 'package:opensase_admin/src/data/session.dart';
import 'package:opensase_admin/src/l10n/app_localizations.dart';
import 'package:opensase_admin/src/ui/theme.dart';

/// A fake Control Plane: routes "METHOD path" to a handler; records requests.
class FakeControlPlane {
  FakeControlPlane({this.token = 'good-token'});

  final String token;
  final requests = <http.Request>[];
  final routes = <String, http.Response Function(http.Request)>{};

  void json(String route, Object body, {int status = 200}) =>
      routes[route] = (_) => http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json'});

  late final client = MockClient((r) async {
    requests.add(r);
    if (r.headers['Authorization'] != 'Bearer $token') {
      return http.Response(jsonEncode({'error': 'unauthorized'}), 401);
    }
    final h = routes['${r.method} ${r.url.path}'];
    return h == null ? http.Response(jsonEncode({'error': 'not found'}), 404) : h(r);
  });
}

List<Override> overridesFor(FakeControlPlane cp, {KeyValueStore? tab, KeyValueStore? persistent}) => [
  httpClientProvider.overrideWithValue(cp.client),
  apiBaseProvider.overrideWithValue(Uri.parse('https://cp.test:9443/admin/')),
  tabStorageProvider.overrideWithValue(tab ?? MemoryStore()),
  persistentStorageProvider.overrideWithValue(persistent ?? MemoryStore()),
];

Widget testApp(Widget home) => MaterialApp(
  theme: buildTheme(Brightness.light),
  localizationsDelegates: const [AppLocalizations.delegate, ...GlobalMaterialLocalizations.delegates],
  supportedLocales: AppLocalizations.supportedLocales,
  locale: const Locale('en'),
  home: Scaffold(body: home),
);

void desktopView(WidgetTester t) {
  t.view.physicalSize = const Size(1600, 1200);
  t.view.devicePixelRatio = 1;
  addTearDown(t.view.reset);
}

http.Response http204() => http.Response('', 204);

http.Response http400(Object body) => http.Response(jsonEncode(body), 400);
