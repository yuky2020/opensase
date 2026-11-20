// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'policy.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

Snapshot _$SnapshotFromJson(Map<String, dynamic> json) => Snapshot(
  schemaVersion: (json['schemaVersion'] as num?)?.toInt() ?? 1,
  version: (json['version'] as num?)?.toInt() ?? 0,
  tenantId: json['tenantId'] as String? ?? '',
  userId: json['userId'] as String? ?? '',
  deviceId: json['deviceId'] as String? ?? '',
  issuedAt: json['issuedAt'] as String? ?? '',
  expiresAt: json['expiresAt'] as String? ?? '',
  firewall: json['firewall'] == null
      ? const FirewallPolicy()
      : _firewallFromJson(json['firewall'] as Map<String, dynamic>?),
  dns: json['dns'] == null ? const DnsPolicy() : _dnsFromJson(json['dns'] as Map<String, dynamic>?),
);

Map<String, dynamic> _$SnapshotToJson(Snapshot instance) => <String, dynamic>{
  'schemaVersion': instance.schemaVersion,
  'version': instance.version,
  'tenantId': instance.tenantId,
  'userId': instance.userId,
  'deviceId': instance.deviceId,
  'issuedAt': instance.issuedAt,
  'expiresAt': instance.expiresAt,
  'firewall': instance.firewall.toJson(),
  'dns': instance.dns.toJson(),
};

FirewallPolicy _$FirewallPolicyFromJson(Map<String, dynamic> json) => FirewallPolicy(
  defaultAction:
      $enumDecodeNullable(_$VerdictEnumMap, json['defaultAction'], unknownValue: Verdict.allow) ?? Verdict.allow,
  allowUserRules: json['allowUserRules'] as bool? ?? false,
  lockdown: json['lockdown'] as bool? ?? false,
  rules: (json['rules'] as List<dynamic>?)?.map((e) => Rule.fromJson(e as Map<String, dynamic>)).toList() ?? [],
  apps:
      (json['apps'] as Map<String, dynamic>?)?.map(
        (k, e) => MapEntry(k, AppPolicy.fromJson(e as Map<String, dynamic>)),
      ) ??
      {},
);

Map<String, dynamic> _$FirewallPolicyToJson(FirewallPolicy instance) => <String, dynamic>{
  'defaultAction': _$VerdictEnumMap[instance.defaultAction]!,
  'allowUserRules': instance.allowUserRules,
  'lockdown': instance.lockdown,
  'rules': instance.rules.map((e) => e.toJson()).toList(),
  'apps': instance.apps.map((k, e) => MapEntry(k, e.toJson())),
};

const _$VerdictEnumMap = {Verdict.allow: 'allow', Verdict.block: 'block', Verdict.ask: 'ask'};

AppPolicy _$AppPolicyFromJson(Map<String, dynamic> json) => AppPolicy(
  wifi: $enumDecodeNullable(_$VerdictEnumMap, json['wifi'], unknownValue: JsonKey.nullForUndefinedEnumValue),
  cellular: $enumDecodeNullable(_$VerdictEnumMap, json['cellular'], unknownValue: JsonKey.nullForUndefinedEnumValue),
  roaming: $enumDecodeNullable(_$VerdictEnumMap, json['roaming'], unknownValue: JsonKey.nullForUndefinedEnumValue),
);

Map<String, dynamic> _$AppPolicyToJson(AppPolicy instance) => <String, dynamic>{
  'wifi': ?_$VerdictEnumMap[instance.wifi],
  'cellular': ?_$VerdictEnumMap[instance.cellular],
  'roaming': ?_$VerdictEnumMap[instance.roaming],
};

Rule _$RuleFromJson(Map<String, dynamic> json) => Rule(
  id: json['id'] as String? ?? '',
  source: $enumDecodeNullable(_$RuleSourceEnumMap, json['source'], unknownValue: RuleSource.user) ?? RuleSource.user,
  priority: (json['priority'] as num?)?.toInt() ?? 0,
  action: $enumDecodeNullable(_$VerdictEnumMap, json['action'], unknownValue: Verdict.block) ?? Verdict.block,
  match: json['match'] == null ? const Match() : _matchFromJson(json['match'] as Map<String, dynamic>?),
  log: json['log'] as bool? ?? false,
  description: json['description'] as String?,
);

Map<String, dynamic> _$RuleToJson(Rule instance) => <String, dynamic>{
  'id': instance.id,
  'source': _$RuleSourceEnumMap[instance.source]!,
  'priority': instance.priority,
  'action': _$VerdictEnumMap[instance.action]!,
  'match': instance.match.toJson(),
  'log': instance.log,
  'description': ?instance.description,
};

const _$RuleSourceEnumMap = {RuleSource.tenant: 'tenant', RuleSource.user: 'user'};

Match _$MatchFromJson(Map<String, dynamic> json) => Match(
  apps: (json['apps'] as List<dynamic>?)?.map((e) => e as String).toList() ?? [],
  networks:
      (json['networks'] as List<dynamic>?)
          ?.map((e) => $enumDecode(_$NetworkTypeEnumMap, e, unknownValue: NetworkType.unknown))
          .toList() ??
      [],
  protocols: (json['protocols'] as List<dynamic>?)?.map((e) => e as String).toList() ?? [],
  cidrs: (json['cidrs'] as List<dynamic>?)?.map((e) => e as String).toList() ?? [],
  ports: (json['ports'] as List<dynamic>?)?.map((e) => PortRange.fromJson(e as Map<String, dynamic>)).toList() ?? [],
  domains: (json['domains'] as List<dynamic>?)?.map((e) => e as String).toList() ?? [],
);

Map<String, dynamic> _$MatchToJson(Match instance) => <String, dynamic>{
  'apps': instance.apps,
  'networks': instance.networks.map((e) => _$NetworkTypeEnumMap[e]!).toList(),
  'protocols': instance.protocols,
  'cidrs': instance.cidrs,
  'ports': instance.ports.map((e) => e.toJson()).toList(),
  'domains': instance.domains,
};

const _$NetworkTypeEnumMap = {
  NetworkType.wifi: 'wifi',
  NetworkType.cellular: 'cellular',
  NetworkType.roaming: 'roaming',
  NetworkType.ethernet: 'ethernet',
  NetworkType.unknown: 'unknown',
};

PortRange _$PortRangeFromJson(Map<String, dynamic> json) =>
    PortRange(from: (json['from'] as num?)?.toInt() ?? 0, to: (json['to'] as num?)?.toInt() ?? 0);

Map<String, dynamic> _$PortRangeToJson(PortRange instance) => <String, dynamic>{
  'from': instance.from,
  'to': instance.to,
};

DnsPolicy _$DnsPolicyFromJson(Map<String, dynamic> json) => DnsPolicy(
  blockResponse: json['blockResponse'] as String? ?? 'nxdomain',
  blocklists:
      (json['blocklists'] as List<dynamic>?)?.map((e) => Blocklist.fromJson(e as Map<String, dynamic>)).toList() ?? [],
  allowDomains: (json['allowDomains'] as List<dynamic>?)?.map((e) => e as String).toList() ?? [],
  blockDomains: (json['blockDomains'] as List<dynamic>?)?.map((e) => e as String).toList() ?? [],
);

Map<String, dynamic> _$DnsPolicyToJson(DnsPolicy instance) => <String, dynamic>{
  'blockResponse': instance.blockResponse,
  'blocklists': instance.blocklists.map((e) => e.toJson()).toList(),
  'allowDomains': instance.allowDomains,
  'blockDomains': instance.blockDomains,
};

Blocklist _$BlocklistFromJson(Map<String, dynamic> json) => Blocklist(
  id: json['id'] as String? ?? '',
  name: json['name'] as String? ?? '',
  category: json['category'] as String? ?? '',
  domains: (json['domains'] as List<dynamic>?)?.map((e) => e as String).toList() ?? [],
);

Map<String, dynamic> _$BlocklistToJson(Blocklist instance) => <String, dynamic>{
  'id': instance.id,
  'name': instance.name,
  'category': instance.category,
  'domains': instance.domains,
};

NetFlow _$NetFlowFromJson(Map<String, dynamic> json) => NetFlow(
  app: json['app'] as String? ?? '',
  uid: (json['uid'] as num?)?.toInt() ?? 0,
  network:
      $enumDecodeNullable(_$NetworkTypeEnumMap, json['network'], unknownValue: NetworkType.unknown) ??
      NetworkType.unknown,
  protocol: json['protocol'] as String? ?? '',
  dstIp: json['dstIp'] as String? ?? '',
  dstPort: (json['dstPort'] as num?)?.toInt() ?? 0,
  domain: json['domain'] as String? ?? '',
);

Map<String, dynamic> _$NetFlowToJson(NetFlow instance) => <String, dynamic>{
  'app': instance.app,
  'uid': instance.uid,
  'network': _$NetworkTypeEnumMap[instance.network]!,
  'protocol': instance.protocol,
  'dstIp': instance.dstIp,
  'dstPort': instance.dstPort,
  'domain': instance.domain,
};

Decision _$DecisionFromJson(Map<String, dynamic> json) => Decision(
  action: $enumDecodeNullable(_$VerdictEnumMap, json['action'], unknownValue: Verdict.allow) ?? Verdict.allow,
  ruleId: json['ruleId'] as String? ?? '',
  layer: json['layer'] as String? ?? '',
  log: json['log'] as bool? ?? false,
);

Map<String, dynamic> _$DecisionToJson(Decision instance) => <String, dynamic>{
  'action': _$VerdictEnumMap[instance.action]!,
  'ruleId': instance.ruleId,
  'layer': instance.layer,
  'log': instance.log,
};
