import 'package:web/web.dart' as web;

import 'browser_storage.dart';

class _WebStore implements KeyValueStore {
  _WebStore(this._s);

  final web.Storage _s;

  @override
  String? read(String key) {
    try {
      return _s.getItem(key);
    } on Object {
      return null; // storage blocked (private mode, policy)
    }
  }

  @override
  void write(String key, String? value) {
    try {
      value == null ? _s.removeItem(key) : _s.setItem(key, value);
    } on Object {
      // storage blocked: keep working in memory only
    }
  }
}

/// window.sessionStorage: cleared when the tab closes. The only place the admin token may persist.
KeyValueStore tabStorage() => _WebStore(web.window.sessionStorage);

/// window.localStorage: non-secret settings only (control URL, last tenant). Never the token.
KeyValueStore persistentStorage() => _WebStore(web.window.localStorage);
