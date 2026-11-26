/// Browser navigation helper with a stub for off-web (tests, VM).
library;

import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'browser_nav_stub.dart' if (dart.library.js_interop) 'browser_nav_web.dart';

export 'browser_nav_stub.dart' if (dart.library.js_interop) 'browser_nav_web.dart';

typedef BrowserNavigator = void Function(String url);

final browserNavProvider = Provider<BrowserNavigator>((ref) => openUrl);
final browserTabNavProvider = Provider<BrowserNavigator>((ref) => openUrlInNewTab);

String buildOidcLoginUrl(String tenant, {Uri? base}) {
  final b = base ?? Uri.base;
  return b.resolve('/v1/auth/oidc/${Uri.encodeComponent(tenant.trim())}/login').toString();
}
