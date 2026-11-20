import 'package:json_annotation/json_annotation.dart';

import 'policy.dart';

part 'api.g.dart';

NetFlow _flowFromJson(Map<String, dynamic>? json) => json == null ? const NetFlow() : NetFlow.fromJson(json);

Decision _decisionFromJson(Map<String, dynamic>? json) => json == null ? const Decision() : Decision.fromJson(json);

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class UserRules {
  const UserRules({this.rules = const [], this.apps = const {}});

  factory UserRules.fromJson(Map<String, dynamic> json) => _$UserRulesFromJson(json);

  @JsonKey(defaultValue: <Rule>[])
  final List<Rule> rules;

  @JsonKey(defaultValue: <String, AppPolicy>{})
  final Map<String, AppPolicy> apps;

  UserRules copyWith({List<Rule>? rules, Map<String, AppPolicy>? apps}) {
    return UserRules(rules: rules ?? this.rules, apps: apps ?? this.apps);
  }

  Map<String, dynamic> toJson() => _$UserRulesToJson(this);
}

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class FlowRecord {
  const FlowRecord({
    this.start = '',
    this.end = '',
    this.flow = const NetFlow(),
    this.decision = const Decision(),
    this.bytesOut = 0,
    this.bytesIn = 0,
    this.where = 'device',
    this.deviceId = '',
  });

  factory FlowRecord.fromJson(Map<String, dynamic> json) => _$FlowRecordFromJson(json);

  @JsonKey(defaultValue: '')
  final String start;

  @JsonKey(defaultValue: '')
  final String end;

  @JsonKey(fromJson: _flowFromJson)
  final NetFlow flow;

  @JsonKey(fromJson: _decisionFromJson)
  final Decision decision;

  @JsonKey(defaultValue: 0)
  final int bytesOut;

  @JsonKey(defaultValue: 0)
  final int bytesIn;

  @JsonKey(defaultValue: 'device')
  final String where;

  @JsonKey(defaultValue: '')
  final String deviceId;

  Map<String, dynamic> toJson() => _$FlowRecordToJson(this);
}
