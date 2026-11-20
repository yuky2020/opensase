/// Parses what the user pastes (or, later, scans) on the enrollment screen.
///
/// Accepted forms:
///  * `opensase://enroll?control=<url-encoded control URL>&key=<provisioning key>[&name=<device>]`
///    (`url=` is accepted as an alias); this is deploy/dev's OPENSASE_ENROLL_URI and the deep link
///  * `<control URL> <provisioning key>` (any whitespace)
///  * `<control URL>` alone
///
/// The control URL may end with `#sha256=<hex>` (pin of the root CA); it is passed to the
/// core unchanged.
class EnrollmentCode {
  const EnrollmentCode({required this.controlUrl, this.provisioningKey = '', this.deviceName = ''});

  final String controlUrl;
  final String provisioningKey;
  final String deviceName;

  bool get hasPin => controlUrl.contains('#sha256=');

  static EnrollmentCode? parse(String input) {
    final s = input.trim();
    if (s.isEmpty) return null;
    if (s.startsWith('opensase://')) {
      final uri = Uri.tryParse(s);
      final url = uri?.queryParameters['control'] ?? uri?.queryParameters['url'];
      if (uri == null || url == null || !url.startsWith('https://')) return null;
      return EnrollmentCode(
        controlUrl: url,
        provisioningKey: uri.queryParameters['key'] ?? '',
        deviceName: uri.queryParameters['name'] ?? '',
      );
    }
    final parts = s.split(RegExp(r'\s+'));
    if (!parts.first.startsWith('https://') || parts.length > 2) return null;
    return EnrollmentCode(controlUrl: parts.first, provisioningKey: parts.length == 2 ? parts[1] : '');
  }
}
