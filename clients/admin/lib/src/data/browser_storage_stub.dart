import 'browser_storage.dart';

/// Per-tab storage (window.sessionStorage on the web).
KeyValueStore tabStorage() => MemoryStore();

/// Persistent, non-secret storage (window.localStorage on the web). Never holds the admin token.
KeyValueStore persistentStorage() => MemoryStore();
