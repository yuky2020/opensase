import 'package:flutter_test/flutter_test.dart';
import 'package:opensase/src/data/enrollment_code.dart';

void main() {
  group('EnrollmentResult.parse', () {
    test('parses SSO link with code and state', () {
      final res = EnrollmentResult.parse('opensase://enroll?code=osk_single_use_123&state=state_secret_456');
      expect(res, isA<EnrollmentSsoResult>());
      final sso = res as EnrollmentSsoResult;
      expect(sso.code, 'osk_single_use_123');
      expect(sso.state, 'state_secret_456');
      expect(sso.toString(), isNot(contains('osk_single_use_123')));
      expect(sso.toString(), isNot(contains('state_secret_456')));
    });

    test('EnrollmentCode.parse ignores the SSO result link', () {
      expect(EnrollmentCode.parse('opensase://enroll?code=osk_123&state=abc_456'), isNull);
    });

    test('still parses key link with control and key parameters', () {
      final res = EnrollmentResult.parse(
        'opensase://enroll?control=https%3A%2F%2F10.0.2.2%3A9443%23sha256%3Dabcd&key=osk_TEST&name=Device1',
      );
      expect(res, isA<EnrollmentCode>());
      final code = res as EnrollmentCode;
      expect(code.controlUrl, 'https://10.0.2.2:9443#sha256=abcd');
      expect(code.provisioningKey, 'osk_TEST');
      expect(code.deviceName, 'Device1');
      expect(code.hasPin, isTrue);
      expect(code.toString(), isNot(contains('osk_TEST')));
    });

    test('still parses key link with url alias', () {
      final res = EnrollmentResult.parse('opensase://enroll?url=https%3A%2F%2Fexample.com&key=osk_KEY');
      expect(res, isA<EnrollmentCode>());
      final code = res as EnrollmentCode;
      expect(code.controlUrl, 'https://example.com');
      expect(code.provisioningKey, 'osk_KEY');
    });

    test('still parses space-separated control URL and key', () {
      final res = EnrollmentResult.parse('https://example.com:9443#sha256=1111 osk_KEY');
      expect(res, isA<EnrollmentCode>());
      final code = res as EnrollmentCode;
      expect(code.controlUrl, 'https://example.com:9443#sha256=1111');
      expect(code.provisioningKey, 'osk_KEY');
    });

    test('still parses control URL alone', () {
      final res = EnrollmentResult.parse('https://example.com:9443');
      expect(res, isA<EnrollmentCode>());
      final code = res as EnrollmentCode;
      expect(code.controlUrl, 'https://example.com:9443');
      expect(code.provisioningKey, isEmpty);
    });

    test('returns null for invalid inputs', () {
      expect(EnrollmentResult.parse(''), isNull);
      expect(EnrollmentResult.parse('   '), isNull);
      expect(EnrollmentResult.parse('not_a_link'), isNull);
      expect(EnrollmentResult.parse('http://insecure.com'), isNull);
      expect(EnrollmentResult.parse('opensase://enroll'), isNull);
      expect(EnrollmentResult.parse('opensase://enroll?code=only_code'), isNull);
      expect(EnrollmentResult.parse('opensase://enroll?state=only_state'), isNull);
      expect(EnrollmentResult.parse('opensase://other?code=c&state=s'), isNull);
      expect(EnrollmentResult.parse('opensase://enroll?control=http%3A%2F%2Fnot_https&key=k'), isNull);
      expect(EnrollmentResult.parse('https://a https://b https://c'), isNull);
    });
  });
}
