import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import 'src/app.dart';
import 'src/data/core_state.dart';
import 'src/engine/engine.dart';
import 'src/engine/fake_engine.dart';
import 'src/engine/method_channel_engine.dart';

/// `--dart-define=FAKE_ENGINE=true` runs the UI on [FakeEngine] (no native side needed).
const useFakeEngine = bool.fromEnvironment('FAKE_ENGINE');

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final Engine engine = useFakeEngine ? FakeEngine() : MethodChannelEngine();
  runApp(ProviderScope(overrides: [engineProvider.overrideWithValue(engine)], child: const OpenSaseApp()));
}
