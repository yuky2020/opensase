/// Result of parsing an enrollment deep link or manual entry.
sealed class EnrollmentResult {
  const EnrollmentResult();

  /// Parses a key link, an SSO result link or manual entry.
  static EnrollmentResult? parse(String input) {
    final s = input.trim();
    if (s.startsWith('opensase://')) {
      final uri = Uri.tryParse(s);
      final q = uri?.queryParameters ?? const <String, String>{};
      final code = q['code'] ?? '';
      final state = q['state'] ?? '';
      if (uri != null &&
          uri.host == 'enroll' &&
          !q.containsKey('control') &&
          !q.containsKey('url') &&
          code.isNotEmpty &&
          state.isNotEmpty) {
        return EnrollmentSsoResult(code: code, state: state);
      }
    }
    return EnrollmentCode.parse(s);
  }
}

/// Parses what the user pastes (or, later, scans) on the enrollment screen.
///
/// Accepted forms:
///  * `opensase://enroll?control=<url-encoded control URL>&key=<provisioning key>[&name=<device>]`
///    (`url=` is accepted as an alias); this is deploy/dev's OPENSASE_ENROLL_URI and the deep link
///  * `opensase://enroll?code=<single-use key>&state=<state>` (SSO result link)
///  * `<control URL> <provisioning key>` (any whitespace)
///  * `<control URL>` alone
///
/// The control URL may end with `#sha256=<hex>` (pin of the root CA); it is passed to the
/// core unchanged.
class EnrollmentCode extends EnrollmentResult {
  const EnrollmentCode({required this.controlUrl, this.provisioningKey = '', this.deviceName = ''});

  final String controlUrl;
  final String provisioningKey;
  final String deviceName;

  bool get hasPin => controlUrl.contains('#sha256=');

  /// Parses a key link or manual entry; SSO result links are not codes (see [EnrollmentResult.parse]).
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

  @override
  String toString() => 'EnrollmentCode(controlUrl: $controlUrl, deviceName: $deviceName)';
}

/// Single sign-on result redirect link: `opensase://enroll?code=<code>&state=<state>`.
class EnrollmentSsoResult extends EnrollmentResult {
  const EnrollmentSsoResult({required this.code, required this.state});

  final String code;
  final String state;

  @override
  String toString() => 'EnrollmentSsoResult()';
}
