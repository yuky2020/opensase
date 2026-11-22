import '../api/admin_models.dart';

/// Kinds of security events derived from flow records (issue #26).
enum SecurityKind { dlp, malware, url, category, safeSearch, saas, inspection }

/// The security event kind of a flow record, or null for an ordinary flow. Records never hold
/// the matched content (ADR-0019), only the rule, the host and the device.
SecurityKind? securityKind(FlowRecord r) {
  final rule = r.decision.ruleId;
  if (rule.startsWith('dlp:')) return SecurityKind.dlp;
  if (rule.startsWith('malware:')) return SecurityKind.malware;
  if (rule.startsWith('url:')) return SecurityKind.url;
  if (rule.startsWith('cat:')) return SecurityKind.category;
  if (rule.startsWith('safesearch:')) return SecurityKind.safeSearch;
  if (rule.startsWith('saas:') || rule.startsWith('dns:saas:')) return SecurityKind.saas;
  if (rule.startsWith('web:')) return SecurityKind.inspection;
  return null;
}

/// The security events of [records], newest first, with counts per kind.
class SecurityEvents {
  SecurityEvents(List<FlowRecord> records) {
    for (final r in records) {
      final k = securityKind(r);
      if (k == null) continue;
      events.add((kind: k, record: r));
      counts[k] = (counts[k] ?? 0) + 1;
    }
    events.sort((a, b) => (b.record.start ?? DateTime(0)).compareTo(a.record.start ?? DateTime(0)));
  }

  final List<({SecurityKind kind, FlowRecord record})> events = [];
  final Map<SecurityKind, int> counts = {};
}
