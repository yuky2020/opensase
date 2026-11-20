import 'dart:convert';

import '../contracts/api.dart';
import '../contracts/engine_types.dart';
import '../contracts/policy.dart';

/// JSON parsing of the engine payloads. A malformed payload degrades to an empty value:
/// the engine stays the source of truth and the UI must not crash on it.
class Parsers {
  Parsers._();

  static T _or<T>(String json, T fallback, T Function(dynamic) parse) {
    if (json.trim().isEmpty || json.trim() == 'null') return fallback;
    try {
      return parse(jsonDecode(json));
    } catch (_) {
      return fallback;
    }
  }

  static EngineStatus status(String json) =>
      _or(json, const EngineStatus(), (j) => EngineStatus.fromJson(j as Map<String, dynamic>));

  static Snapshot? snapshot(String json) =>
      _or<Snapshot?>(json, null, (j) => Snapshot.fromJson(j as Map<String, dynamic>));

  static List<FlowRecord> flows(String json) => _or(
    json,
    const <FlowRecord>[],
    (j) => (j as List).map((e) => FlowRecord.fromJson(e as Map<String, dynamic>)).toList(),
  );

  static FlowRecord? flow(String json) =>
      _or<FlowRecord?>(json, null, (j) => FlowRecord.fromJson(j as Map<String, dynamic>));

  static List<AppStat> appStats(String json) =>
      _or(json, const <AppStat>[], (j) => (j as List).map((e) => AppStat.fromJson(e as Map<String, dynamic>)).toList());

  static UserRules userRules(String json) =>
      _or(json, const UserRules(), (j) => UserRules.fromJson(j as Map<String, dynamic>));

  static Map<String, dynamic> decodeMap(String json) => jsonDecode(json) as Map<String, dynamic>;

  static String encodeUserRules(UserRules r) => jsonEncode(r.toJson());

  /// Today's counters from appStats: flows allowed/blocked and blocked DNS queries.
  static TrafficCounters counters(List<AppStat> stats) => TrafficCounters(
    allowed: stats.fold(0, (a, s) => a + s.allowed),
    blocked: stats.fold(0, (a, s) => a + s.blocked),
    dnsBlocked: stats.fold(0, (a, s) => a + s.dnsBlocked),
  );
}
