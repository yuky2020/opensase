import '../api/admin_models.dart';

/// Filters of the Activity screen. Empty string = any.
class FlowFilter {
  const FlowFilter({this.verdict = '', this.layer = '', this.where = '', this.device = '', this.text = ''});

  final String verdict;
  final String layer;
  final String where;
  final String device;
  final String text;

  FlowFilter copyWith({String? verdict, String? layer, String? where, String? device, String? text}) => FlowFilter(
    verdict: verdict ?? this.verdict,
    layer: layer ?? this.layer,
    where: where ?? this.where,
    device: device ?? this.device,
    text: text ?? this.text,
  );

  bool matches(FlowRecord r) {
    if (verdict.isNotEmpty && r.decision.action != verdict) return false;
    if (layer.isNotEmpty && r.decision.layer != layer) return false;
    if (where.isNotEmpty && r.where != where) return false;
    if (device.isNotEmpty && r.deviceId != device) return false;
    if (text.isNotEmpty) {
      final q = text.toLowerCase();
      final f = r.flow;
      final hay = [
        f.domain,
        f.dstIp,
        '${f.dstPort}',
        f.app,
        f.protocol,
        r.decision.ruleId,
        r.deviceId,
      ].join(' ').toLowerCase();
      if (!hay.contains(q)) return false;
    }
    return true;
  }
}

List<FlowRecord> filterFlows(List<FlowRecord> flows, FlowFilter f) => [
  for (final r in flows)
    if (f.matches(r)) r,
];

/// Counts of verdicts per decision layer.
class LayerCounts {
  int allow = 0;
  int block = 0;
  int other = 0;
}

/// Verdict counts by layer, layers in first-seen order.
Map<String, LayerCounts> verdictsByLayer(Iterable<FlowRecord> flows) {
  final out = <String, LayerCounts>{};
  for (final r in flows) {
    final c = out.putIfAbsent(r.decision.layer.isEmpty ? '?' : r.decision.layer, LayerCounts.new);
    switch (r.decision.action) {
      case 'allow':
        c.allow++;
      case 'block':
        c.block++;
      default:
        c.other++;
    }
  }
  return out;
}

/// Blocked flows that started within [window] before [now].
int blocksSince(Iterable<FlowRecord> flows, DateTime now, {Duration window = const Duration(hours: 1)}) {
  final since = now.subtract(window);
  return flows.where((r) => r.decision.action == 'block' && r.start != null && r.start!.isAfter(since)).length;
}
