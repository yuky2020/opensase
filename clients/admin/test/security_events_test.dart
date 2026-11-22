import 'package:flutter_test/flutter_test.dart';
import 'package:opensase_admin/src/api/admin_models.dart';
import 'package:opensase_admin/src/api/policy_models.dart';
import 'package:opensase_admin/src/data/security_events.dart';

FlowRecord rec(String rule, {String action = 'block', int minute = 0}) => FlowRecord(
  start: DateTime.utc(2026, 11, 22, 6, minute),
  decision: Decision(action: action, ruleId: rule, layer: 'web'),
);

void main() {
  test('flow records are classified by their rule', () {
    final cases = {
      'dlp:pci': SecurityKind.dlp,
      'dlp:pci:unscanned': SecurityKind.dlp,
      'malware:Eicar-Test-Signature': SecurityKind.malware,
      'url:no-admin': SecurityKind.url,
      'cat:gambling': SecurityKind.category,
      'cat:gambling:url': SecurityKind.category,
      'safesearch:bypass': SecurityKind.safeSearch,
      'saas:pastebin': SecurityKind.saas,
      'dns:saas:pastebin': SecurityKind.saas,
      'web:host-mismatch': SecurityKind.inspection,
    };
    cases.forEach((rule, kind) => expect(securityKind(rec(rule)), kind, reason: rule));
    for (final rule in ['block-smtp', 'dns:ads', '', 'ztna:intranet']) {
      expect(securityKind(rec(rule)), isNull, reason: rule);
    }
  });

  test('events are counted per kind, newest first', () {
    final ev = SecurityEvents([
      rec('dlp:pci', minute: 1),
      rec('block-smtp', minute: 2),
      rec('cat:gambling', minute: 3),
      rec('dlp:mail', action: 'allow', minute: 4),
    ]);
    expect(ev.events.length, 3);
    expect(ev.counts[SecurityKind.dlp], 2);
    expect(ev.events.first.record.decision.ruleId, 'dlp:mail');
  });
}
