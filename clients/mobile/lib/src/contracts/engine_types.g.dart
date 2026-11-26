// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'engine_types.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

EngineStatus _$EngineStatusFromJson(Map<String, dynamic> json) => EngineStatus(
  state: json['state'] as String? ?? 'stopped',
  edge: json['edge'] as String? ?? '',
  snapshotVersion: (json['snapshotVersion'] as num?)?.toInt() ?? 0,
  stale: json['stale'] as bool? ?? false,
  pq: json['pq'] as bool? ?? false,
  kex: json['kex'] as String? ?? '',
  error: json['error'] as String? ?? '',
  enrolled: json['enrolled'] as bool? ?? false,
  deviceId: json['deviceId'] as String? ?? '',
  network: json['network'] as String? ?? '',
  epoch: (json['epoch'] as num?)?.toInt() ?? 0,
  lastHandshake: (json['lastHandshake'] as num?)?.toInt() ?? 0,
  txBytes: (json['txBytes'] as num?)?.toInt() ?? 0,
  rxBytes: (json['rxBytes'] as num?)?.toInt() ?? 0,
  certExpiresAt: json['certExpiresAt'] == null ? '' : _timeFromJson(json['certExpiresAt']),
  postureFailing: (json['postureFailing'] as List<dynamic>?)?.map((e) => e as String).toList() ?? const [],
);

Map<String, dynamic> _$EngineStatusToJson(EngineStatus instance) => <String, dynamic>{
  'state': instance.state,
  'edge': instance.edge,
  'snapshotVersion': instance.snapshotVersion,
  'stale': instance.stale,
  'pq': instance.pq,
  'kex': instance.kex,
  'error': instance.error,
  'enrolled': instance.enrolled,
  'deviceId': instance.deviceId,
  'network': instance.network,
  'epoch': instance.epoch,
  'lastHandshake': instance.lastHandshake,
  'txBytes': instance.txBytes,
  'rxBytes': instance.rxBytes,
  'certExpiresAt': instance.certExpiresAt,
  'postureFailing': instance.postureFailing,
};

AppStat _$AppStatFromJson(Map<String, dynamic> json) => AppStat(
  app: json['app'] as String? ?? '',
  bytesIn: (json['bytesIn'] as num?)?.toInt() ?? 0,
  bytesOut: (json['bytesOut'] as num?)?.toInt() ?? 0,
  allowed: (json['allowed'] as num?)?.toInt() ?? 0,
  blocked: (json['blocked'] as num?)?.toInt() ?? 0,
  dnsQueries: (json['dnsQueries'] as num?)?.toInt() ?? 0,
  dnsBlocked: (json['dnsBlocked'] as num?)?.toInt() ?? 0,
);

Map<String, dynamic> _$AppStatToJson(AppStat instance) => <String, dynamic>{
  'app': instance.app,
  'bytesIn': instance.bytesIn,
  'bytesOut': instance.bytesOut,
  'allowed': instance.allowed,
  'blocked': instance.blocked,
  'dnsQueries': instance.dnsQueries,
  'dnsBlocked': instance.dnsBlocked,
};

TrafficCounters _$TrafficCountersFromJson(Map<String, dynamic> json) => TrafficCounters(
  allowed: (json['allowed'] as num?)?.toInt() ?? 0,
  blocked: (json['blocked'] as num?)?.toInt() ?? 0,
  dnsBlocked: (json['dnsBlocked'] as num?)?.toInt() ?? 0,
);

Map<String, dynamic> _$TrafficCountersToJson(TrafficCounters instance) => <String, dynamic>{
  'allowed': instance.allowed,
  'blocked': instance.blocked,
  'dnsBlocked': instance.dnsBlocked,
};
