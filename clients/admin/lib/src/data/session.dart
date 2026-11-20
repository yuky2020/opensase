import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:http/http.dart' as http;

import '../api/admin_api.dart';
import 'browser_storage.dart';

/// sessionStorage key for the admin token ("remember for this tab").
const tokenKey = 'opensase.admin.token';

/// Per-tab storage for the token. Overridden in tests.
final tabStorageProvider = Provider<KeyValueStore>((ref) => tabStorage());

/// Persistent storage for non-secret settings. Overridden in tests.
final persistentStorageProvider = Provider<KeyValueStore>((ref) => persistentStorage());

final httpClientProvider = Provider<http.Client>((ref) {
  final c = http.Client();
  ref.onDispose(c.close);
  return c;
});

/// Base URI the API paths are resolved against; null means Uri.base (the portal's own origin).
final apiBaseProvider = Provider<Uri?>((ref) => null);

/// The admin token, held in memory. It is copied to sessionStorage only when the admin
/// ticked "remember for this tab"; it is never written to localStorage.
class SessionNotifier extends Notifier<String?> {
  @override
  String? build() {
    final t = ref.read(tabStorageProvider).read(tokenKey);
    return (t == null || t.isEmpty) ? null : t;
  }

  /// Checks [token] against the Control Plane (GET /v1/admin/tenants) and signs in.
  Future<void> login(String token, {required bool rememberForTab}) async {
    token = token.trim();
    final api = AdminApi(token: token, client: ref.read(httpClientProvider), base: ref.read(apiBaseProvider));
    await api.listTenants();
    ref.read(tabStorageProvider).write(tokenKey, rememberForTab ? token : null);
    state = token;
  }

  void logout() {
    ref.read(tabStorageProvider).write(tokenKey, null);
    state = null;
  }
}

final sessionProvider = NotifierProvider<SessionNotifier, String?>(SessionNotifier.new);

/// The API client for the current session. Throws if signed out (the router prevents that).
final apiProvider = Provider<AdminApi>((ref) {
  final token = ref.watch(sessionProvider);
  if (token == null) throw StateError('not signed in');
  return AdminApi(token: token, client: ref.watch(httpClientProvider), base: ref.watch(apiBaseProvider));
});
