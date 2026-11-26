import 'dart:convert';
import 'dart:math';

import 'package:shared_preferences/shared_preferences.dart';

/// Builds the SSO start URL opened in the system browser.
String buildSsoStartUrl(String controlUrl, String tenant, String state) {
  final uri = Uri.parse(controlUrl).removeFragment();
  final basePath = uri.path.endsWith('/') ? uri.path.substring(0, uri.path.length - 1) : uri.path;
  final encodedTenant = Uri.encodeComponent(tenant);
  final startPath = '$basePath/v1/enroll/oidc/$encodedTenant/start';

  final qp = Map<String, String>.of(uri.queryParameters);
  qp['return_to'] = 'opensase://enroll';
  qp['state'] = state;

  return uri.replace(path: startPath, queryParameters: qp).toString();
}

/// A pending SSO record stored in shared_preferences while the user signs in with
/// their organization's identity provider.
class SsoPending {
  const SsoPending({required this.controlUrl, required this.tenantId, required this.state, required this.createdAt});

  final String controlUrl;
  final String tenantId;
  final String state;
  final DateTime createdAt;

  static const key = 'sso_pending';
  static const ttl = Duration(minutes: 10);

  bool isExpired([DateTime? now]) {
    final current = now ?? DateTime.now();
    return current.difference(createdAt) >= ttl;
  }

  static String generateState() {
    final rng = Random.secure();
    final bytes = List<int>.generate(32, (_) => rng.nextInt(256));
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  Map<String, dynamic> toJson() => {
    'controlUrl': controlUrl,
    'tenantId': tenantId,
    'state': state,
    'createdAt': createdAt.toIso8601String(),
  };

  factory SsoPending.fromJson(Map<String, dynamic> json) => SsoPending(
    controlUrl: json['controlUrl'] as String,
    tenantId: json['tenantId'] as String,
    state: json['state'] as String,
    createdAt: DateTime.parse(json['createdAt'] as String),
  );

  /// Saves this pending SSO record to SharedPreferences.
  Future<void> save([SharedPreferences? prefs]) async {
    final p = prefs ?? await SharedPreferences.getInstance();
    await p.setString(key, jsonEncode(toJson()));
  }

  /// Loads the pending SSO record from SharedPreferences.
  /// If missing or older than 10 minutes, ignores and removes it, returning null.
  static Future<SsoPending?> load({SharedPreferences? prefs, DateTime? now}) async {
    final p = prefs ?? await SharedPreferences.getInstance();
    final raw = p.getString(key);
    if (raw == null || raw.isEmpty) return null;
    try {
      final record = SsoPending.fromJson(jsonDecode(raw) as Map<String, dynamic>);
      if (record.isExpired(now)) {
        await p.remove(key);
        return null;
      }
      return record;
    } catch (_) {
      await p.remove(key);
      return null;
    }
  }

  /// Clears the pending SSO record from SharedPreferences.
  static Future<void> clear([SharedPreferences? prefs]) async {
    final p = prefs ?? await SharedPreferences.getInstance();
    await p.remove(key);
  }

  @override
  String toString() => 'SsoPending(controlUrl: $controlUrl, tenantId: $tenantId)';
}
