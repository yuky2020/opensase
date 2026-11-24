import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import 'src/app.dart';
import 'src/data/core_state.dart';
import 'src/engine/daemon_engine.dart';
import 'src/engine/daemon_transport.dart';
import 'src/engine/engine.dart';
import 'src/engine/fake_engine.dart';
import 'src/engine/method_channel_engine.dart';

/// `--dart-define=FAKE_ENGINE=true` runs the UI on [FakeEngine] (no native side needed).
const useFakeEngine = bool.fromEnvironment('FAKE_ENGINE');

/// `--dart-define=DAEMON_SOCKET=/path` overrides the default socket path on Linux.
const daemonSocketOverride = String.fromEnvironment('DAEMON_SOCKET');

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final Engine engine;
  if (useFakeEngine) {
    engine = FakeEngine();
  } else if (Platform.isLinux) {
    final socketPath = daemonSocketOverride.isNotEmpty ? daemonSocketOverride : '/run/opensase/opensased.sock';
    engine = DaemonEngine(UnixSocketTransport(socketPath));
  } else if (Platform.isWindows) {
    engine = DaemonEngine(NamedPipeTransport(r'\\.\pipe\opensase'));
  } else {
    engine = MethodChannelEngine();
  }

  runApp(ProviderScope(overrides: [engineProvider.overrideWithValue(engine)], child: const OpenSaseApp()));
}
