/// Builds and checks the enrollment deep link of pkg/api/types.go:
/// `opensase://enroll?control=<url-encoded control URL incl. #sha256=>&key=<provisioning key>`.
library;

final _pin = RegExp(r'#sha256=[0-9a-fA-F]{64}$');

/// Returns null if [controlUrl] is an https URL ending in a `#sha256=<64 hex>` pin, else the reason.
String? controlUrlError(String controlUrl) {
  final u = Uri.tryParse(controlUrl);
  if (u == null || u.scheme != 'https' || u.host.isEmpty) return 'must be an https:// URL';
  if (!_pin.hasMatch(controlUrl)) return 'must end with #sha256=<64 hex characters> (root CA pin)';
  return null;
}

String enrollLink({required String controlUrl, required String key}) =>
    'opensase://enroll?control=${Uri.encodeComponent(controlUrl)}&key=${Uri.encodeComponent(key)}';

/// A default control URL: the portal's own origin, which is the Control Plane.
String defaultControlUrl(Uri base) =>
    (base.scheme == 'https' || base.scheme == 'http') && base.host.isNotEmpty ? base.origin : '';
