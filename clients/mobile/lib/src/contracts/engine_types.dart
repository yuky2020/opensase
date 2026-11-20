import 'package:json_annotation/json_annotation.dart';

part 'engine_types.g.dart';

/// certExpiresAt may arrive as RFC 3339 text or unix seconds: normalise to RFC 3339 ('' if unset).
String _timeFromJson(Object? v) => switch (v) {
  String s => s,
  int n when n > 0 => DateTime.fromMillisecondsSinceEpoch(n * 1000, isUtc: true).toIso8601String(),
  _ => '',
};

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class EngineStatus {
  const EngineStatus({
    this.state = stopped,
    this.edge = '',
    this.snapshotVersion = 0,
    this.stale = false,
    this.pq = false,
    this.kex = '',
    this.error = '',
    this.enrolled = false,
    this.deviceId = '',
    this.network = '',
    this.epoch = 0,
    this.lastHandshake = 0,
    this.txBytes = 0,
    this.rxBytes = 0,
    this.certExpiresAt = '',
  });

  factory EngineStatus.fromJson(Map<String, dynamic> json) => _$EngineStatusFromJson(json);

  static const String connected = 'connected';
  static const String connecting = 'connecting';
  static const String stopped = 'stopped';
  static const String errorState = 'error';

  @JsonKey(defaultValue: 'stopped')
  final String state;

  @JsonKey(defaultValue: '')
  final String edge;

  @JsonKey(defaultValue: 0)
  final int snapshotVersion;

  @JsonKey(defaultValue: false)
  final bool stale;

  @JsonKey(defaultValue: false)
  final bool pq;

  @JsonKey(defaultValue: '')
  final String kex;

  @JsonKey(defaultValue: '')
  final String error;

  @JsonKey(defaultValue: false)
  final bool enrolled;

  @JsonKey(defaultValue: '')
  final String deviceId;

  /// Network type the core is using ("wifi", "cellular", ...).
  @JsonKey(defaultValue: '')
  final String network;

  /// PSK rotation epoch of the current session.
  @JsonKey(defaultValue: 0)
  final int epoch;

  /// WireGuard handshake time (unix seconds), 0 before the first handshake.
  @JsonKey(defaultValue: 0)
  final int lastHandshake;

  @JsonKey(defaultValue: 0)
  final int txBytes;

  @JsonKey(defaultValue: 0)
  final int rxBytes;

  /// Expiry of the device certificate (renewed by the core before it expires).
  @JsonKey(fromJson: _timeFromJson)
  final String certExpiresAt;

  bool get isConnected => state == connected;

  bool get isActive => state == connected || state == connecting;

  Map<String, dynamic> toJson() => _$EngineStatusToJson(this);
}

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class AppStat {
  const AppStat({
    required this.app,
    this.bytesIn = 0,
    this.bytesOut = 0,
    this.allowed = 0,
    this.blocked = 0,
    this.dnsQueries = 0,
    this.dnsBlocked = 0,
  });

  factory AppStat.fromJson(Map<String, dynamic> json) => _$AppStatFromJson(json);

  @JsonKey(defaultValue: '')
  final String app;

  @JsonKey(defaultValue: 0)
  final int bytesIn;

  @JsonKey(defaultValue: 0)
  final int bytesOut;

  @JsonKey(defaultValue: 0)
  final int allowed;

  @JsonKey(defaultValue: 0)
  final int blocked;

  @JsonKey(defaultValue: 0)
  final int dnsQueries;

  @JsonKey(defaultValue: 0)
  final int dnsBlocked;

  Map<String, dynamic> toJson() => _$AppStatToJson(this);
}

/// Today's counters for the Home screen, derived from appStats (not a wire type).
@JsonSerializable(explicitToJson: true, includeIfNull: false)
class TrafficCounters {
  const TrafficCounters({this.allowed = 0, this.blocked = 0, this.dnsBlocked = 0});

  factory TrafficCounters.fromJson(Map<String, dynamic> json) => _$TrafficCountersFromJson(json);

  @JsonKey(defaultValue: 0)
  final int allowed;

  @JsonKey(defaultValue: 0)
  final int blocked;

  @JsonKey(defaultValue: 0)
  final int dnsBlocked;

  Map<String, dynamic> toJson() => _$TrafficCountersToJson(this);
}
