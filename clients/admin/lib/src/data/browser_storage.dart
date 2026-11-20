/// Browser storage, with an in-memory fallback off the web (tests, VM).
library;

export 'browser_storage_stub.dart' if (dart.library.js_interop) 'browser_storage_web.dart';

/// A minimal key/value store.
abstract class KeyValueStore {
  String? read(String key);
  void write(String key, String? value);
}

class MemoryStore implements KeyValueStore {
  final _m = <String, String>{};

  @override
  String? read(String key) => _m[key];

  @override
  void write(String key, String? value) => value == null ? _m.remove(key) : _m[key] = value;
}
