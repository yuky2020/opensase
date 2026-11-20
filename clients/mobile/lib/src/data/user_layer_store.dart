import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

import '../contracts/api.dart';

/// Persists the last user layer accepted by the cloud. The snapshot merges tenant and user
/// per-app entries, so the device keeps its own copy to tell them apart.
abstract class UserLayerStore {
  Future<UserRules?> load();
  Future<void> save(UserRules? rules);
}

class InMemoryUserLayerStore implements UserLayerStore {
  InMemoryUserLayerStore([this._value]);
  UserRules? _value;

  @override
  Future<UserRules?> load() async => _value;

  @override
  Future<void> save(UserRules? rules) async => _value = rules;
}

class PrefsUserLayerStore implements UserLayerStore {
  static const _key = 'user_layer_json';

  @override
  Future<UserRules?> load() async {
    final s = (await SharedPreferences.getInstance()).getString(_key);
    if (s == null || s.isEmpty) return null;
    try {
      return UserRules.fromJson(jsonDecode(s) as Map<String, dynamic>);
    } catch (_) {
      return null;
    }
  }

  @override
  Future<void> save(UserRules? rules) async {
    final p = await SharedPreferences.getInstance();
    if (rules == null) {
      await p.remove(_key);
    } else {
      await p.setString(_key, jsonEncode(rules.toJson()));
    }
  }
}
