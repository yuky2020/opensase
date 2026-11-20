import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import 'src/app.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  // No automatic retries: a failed admin call (401, 404, validation) should show at once.
  runApp(ProviderScope(retry: (_, _) => null, child: const AdminApp()));
}
