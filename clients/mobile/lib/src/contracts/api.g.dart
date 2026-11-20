// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'api.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

UserRules _$UserRulesFromJson(Map<String, dynamic> json) => UserRules(
  rules: (json['rules'] as List<dynamic>?)?.map((e) => Rule.fromJson(e as Map<String, dynamic>)).toList() ?? [],
  apps:
      (json['apps'] as Map<String, dynamic>?)?.map(
        (k, e) => MapEntry(k, AppPolicy.fromJson(e as Map<String, dynamic>)),
      ) ??
      {},
);

Map<String, dynamic> _$UserRulesToJson(UserRules instance) => <String, dynamic>{
  'rules': instance.rules.map((e) => e.toJson()).toList(),
  'apps': instance.apps.map((k, e) => MapEntry(k, e.toJson())),
};

FlowRecord _$FlowRecordFromJson(Map<String, dynamic> json) => FlowRecord(
  start: json['start'] as String? ?? '',
  end: json['end'] as String? ?? '',
  flow: json['flow'] == null ? const NetFlow() : _flowFromJson(json['flow'] as Map<String, dynamic>?),
  decision: json['decision'] == null ? const Decision() : _decisionFromJson(json['decision'] as Map<String, dynamic>?),
  bytesOut: (json['bytesOut'] as num?)?.toInt() ?? 0,
  bytesIn: (json['bytesIn'] as num?)?.toInt() ?? 0,
  where: json['where'] as String? ?? 'device',
  deviceId: json['deviceId'] as String? ?? '',
);

Map<String, dynamic> _$FlowRecordToJson(FlowRecord instance) => <String, dynamic>{
  'start': instance.start,
  'end': instance.end,
  'flow': instance.flow.toJson(),
  'decision': instance.decision.toJson(),
  'bytesOut': instance.bytesOut,
  'bytesIn': instance.bytesIn,
  'where': instance.where,
  'deviceId': instance.deviceId,
};
