import 'package:json_annotation/json_annotation.dart';

part 'policy.g.dart';

enum Verdict {
  @JsonValue('allow')
  allow,
  @JsonValue('block')
  block,
  @JsonValue('ask')
  ask,
}

enum NetworkType {
  @JsonValue('wifi')
  wifi,
  @JsonValue('cellular')
  cellular,
  @JsonValue('roaming')
  roaming,
  @JsonValue('ethernet')
  ethernet,
  @JsonValue('unknown')
  unknown;

  String get wire {
    switch (this) {
      case NetworkType.wifi:
        return 'wifi';
      case NetworkType.cellular:
        return 'cellular';
      case NetworkType.roaming:
        return 'roaming';
      case NetworkType.ethernet:
        return 'ethernet';
      case NetworkType.unknown:
        return 'unknown';
    }
  }

  static NetworkType fromWire(String s) {
    switch (s) {
      case 'wifi':
        return NetworkType.wifi;
      case 'cellular':
        return NetworkType.cellular;
      case 'roaming':
        return NetworkType.roaming;
      case 'ethernet':
        return NetworkType.ethernet;
      default:
        return NetworkType.unknown;
    }
  }
}

enum RuleSource {
  @JsonValue('tenant')
  tenant,
  @JsonValue('user')
  user,
}

FirewallPolicy _firewallFromJson(Map<String, dynamic>? json) =>
    json == null ? const FirewallPolicy() : FirewallPolicy.fromJson(json);

DnsPolicy _dnsFromJson(Map<String, dynamic>? json) => json == null ? const DnsPolicy() : DnsPolicy.fromJson(json);

Match _matchFromJson(Map<String, dynamic>? json) => json == null ? const Match() : Match.fromJson(json);

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class Snapshot {
  const Snapshot({
    this.schemaVersion = 1,
    this.version = 0,
    this.tenantId = '',
    this.userId = '',
    this.deviceId = '',
    this.issuedAt = '',
    this.expiresAt = '',
    this.firewall = const FirewallPolicy(),
    this.dns = const DnsPolicy(),
  });

  factory Snapshot.fromJson(Map<String, dynamic> json) => _$SnapshotFromJson(json);

  @JsonKey(defaultValue: 1)
  final int schemaVersion;

  @JsonKey(defaultValue: 0)
  final int version;

  @JsonKey(defaultValue: '')
  final String tenantId;

  @JsonKey(defaultValue: '')
  final String userId;

  @JsonKey(defaultValue: '')
  final String deviceId;

  @JsonKey(defaultValue: '')
  final String issuedAt;

  @JsonKey(defaultValue: '')
  final String expiresAt;

  @JsonKey(fromJson: _firewallFromJson)
  final FirewallPolicy firewall;

  @JsonKey(fromJson: _dnsFromJson)
  final DnsPolicy dns;

  Map<String, dynamic> toJson() => _$SnapshotToJson(this);
}

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class FirewallPolicy {
  const FirewallPolicy({
    this.defaultAction = Verdict.allow,
    this.allowUserRules = false,
    this.lockdown = false,
    this.rules = const [],
    this.apps = const {},
  });

  factory FirewallPolicy.fromJson(Map<String, dynamic> json) => _$FirewallPolicyFromJson(json);

  @JsonKey(defaultValue: Verdict.allow, unknownEnumValue: Verdict.allow)
  final Verdict defaultAction;

  @JsonKey(defaultValue: false)
  final bool allowUserRules;

  @JsonKey(defaultValue: false)
  final bool lockdown;

  @JsonKey(defaultValue: <Rule>[])
  final List<Rule> rules;

  @JsonKey(defaultValue: <String, AppPolicy>{})
  final Map<String, AppPolicy> apps;

  Map<String, dynamic> toJson() => _$FirewallPolicyToJson(this);
}

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class AppPolicy {
  const AppPolicy({this.wifi, this.cellular, this.roaming});

  factory AppPolicy.fromJson(Map<String, dynamic> json) => _$AppPolicyFromJson(json);

  @JsonKey(unknownEnumValue: JsonKey.nullForUndefinedEnumValue)
  final Verdict? wifi;

  @JsonKey(unknownEnumValue: JsonKey.nullForUndefinedEnumValue)
  final Verdict? cellular;

  @JsonKey(unknownEnumValue: JsonKey.nullForUndefinedEnumValue)
  final Verdict? roaming;

  Verdict? forNetwork(NetworkType n) {
    switch (n) {
      case NetworkType.wifi:
      case NetworkType.ethernet:
        return wifi;
      case NetworkType.cellular:
        return cellular;
      case NetworkType.roaming:
        return roaming;
      case NetworkType.unknown:
        return null;
    }
  }

  AppPolicy withNetwork(NetworkType n, Verdict? v) {
    switch (n) {
      case NetworkType.wifi:
      case NetworkType.ethernet:
        return AppPolicy(wifi: v, cellular: cellular, roaming: roaming);
      case NetworkType.cellular:
        return AppPolicy(wifi: wifi, cellular: v, roaming: roaming);
      case NetworkType.roaming:
        return AppPolicy(wifi: wifi, cellular: cellular, roaming: v);
      case NetworkType.unknown:
        return this;
    }
  }

  bool get isEmpty => wifi == null && cellular == null && roaming == null;

  Map<String, dynamic> toJson() => _$AppPolicyToJson(this);
}

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class Rule {
  const Rule({
    required this.id,
    this.source = RuleSource.user,
    this.priority = 0,
    this.action = Verdict.block,
    this.match = const Match(),
    this.log = false,
    this.description,
  });

  factory Rule.fromJson(Map<String, dynamic> json) => _$RuleFromJson(json);

  @JsonKey(defaultValue: '')
  final String id;

  @JsonKey(defaultValue: RuleSource.user, unknownEnumValue: RuleSource.user)
  final RuleSource source;

  @JsonKey(defaultValue: 0)
  final int priority;

  @JsonKey(defaultValue: Verdict.block, unknownEnumValue: Verdict.block)
  final Verdict action;

  @JsonKey(fromJson: _matchFromJson)
  final Match match;

  @JsonKey(defaultValue: false)
  final bool log;

  final String? description;

  Rule copyWith({
    String? id,
    RuleSource? source,
    int? priority,
    Verdict? action,
    Match? match,
    bool? log,
    String? description,
  }) {
    return Rule(
      id: id ?? this.id,
      source: source ?? this.source,
      priority: priority ?? this.priority,
      action: action ?? this.action,
      match: match ?? this.match,
      log: log ?? this.log,
      description: description ?? this.description,
    );
  }

  Map<String, dynamic> toJson() => _$RuleToJson(this);
}

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class Match {
  const Match({
    this.apps = const [],
    this.networks = const [],
    this.protocols = const [],
    this.cidrs = const [],
    this.ports = const [],
    this.domains = const [],
  });

  factory Match.fromJson(Map<String, dynamic> json) => _$MatchFromJson(json);

  @JsonKey(defaultValue: <String>[])
  final List<String> apps;

  @JsonKey(defaultValue: <NetworkType>[], unknownEnumValue: NetworkType.unknown)
  final List<NetworkType> networks;

  @JsonKey(defaultValue: <String>[])
  final List<String> protocols;

  @JsonKey(defaultValue: <String>[])
  final List<String> cidrs;

  @JsonKey(defaultValue: <PortRange>[])
  final List<PortRange> ports;

  @JsonKey(defaultValue: <String>[])
  final List<String> domains;

  bool get isDomainOnly =>
      domains.isNotEmpty && apps.isEmpty && networks.isEmpty && protocols.isEmpty && cidrs.isEmpty && ports.isEmpty;

  Map<String, dynamic> toJson() => _$MatchToJson(this);
}

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class PortRange {
  const PortRange({required this.from, this.to = 0});

  factory PortRange.fromJson(Map<String, dynamic> json) => _$PortRangeFromJson(json);

  @JsonKey(defaultValue: 0)
  final int from;

  @JsonKey(defaultValue: 0)
  final int to;

  int get last => to == 0 ? from : to;

  @override
  String toString() => last == from ? '$from' : '$from-$last';

  static PortRange? parse(String text) {
    final parts = text.trim().split('-').map((s) => s.trim()).toList();
    if (parts.isEmpty || parts.length > 2) return null;
    final from = int.tryParse(parts[0]);
    if (from == null || from < 1 || from > 65535) return null;
    final int to;
    if (parts.length == 2) {
      final parsedTo = int.tryParse(parts[1]);
      if (parsedTo == null || parsedTo < 0 || parsedTo > 65535) return null;
      to = parsedTo;
    } else {
      to = 0;
    }
    if (to != 0 && to < from) return null;
    return PortRange(from: from, to: to);
  }

  Map<String, dynamic> toJson() => _$PortRangeToJson(this);
}

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class DnsPolicy {
  const DnsPolicy({
    this.blockResponse = 'nxdomain',
    this.blocklists = const [],
    this.allowDomains = const [],
    this.blockDomains = const [],
  });

  factory DnsPolicy.fromJson(Map<String, dynamic> json) => _$DnsPolicyFromJson(json);

  @JsonKey(defaultValue: 'nxdomain')
  final String blockResponse;

  @JsonKey(defaultValue: <Blocklist>[])
  final List<Blocklist> blocklists;

  @JsonKey(defaultValue: <String>[])
  final List<String> allowDomains;

  @JsonKey(defaultValue: <String>[])
  final List<String> blockDomains;

  Map<String, dynamic> toJson() => _$DnsPolicyToJson(this);
}

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class Blocklist {
  const Blocklist({required this.id, this.name = '', this.category = '', this.domains = const []});

  factory Blocklist.fromJson(Map<String, dynamic> json) => _$BlocklistFromJson(json);

  @JsonKey(defaultValue: '')
  final String id;

  @JsonKey(defaultValue: '')
  final String name;

  @JsonKey(defaultValue: '')
  final String category;

  @JsonKey(defaultValue: <String>[])
  final List<String> domains;

  Map<String, dynamic> toJson() => _$BlocklistToJson(this);
}

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class NetFlow {
  const NetFlow({
    this.app = '',
    this.uid = 0,
    this.network = NetworkType.unknown,
    this.protocol = '',
    this.dstIp = '',
    this.dstPort = 0,
    this.domain = '',
  });

  factory NetFlow.fromJson(Map<String, dynamic> json) => _$NetFlowFromJson(json);

  @JsonKey(defaultValue: '')
  final String app;

  @JsonKey(defaultValue: 0)
  final int uid;

  @JsonKey(defaultValue: NetworkType.unknown, unknownEnumValue: NetworkType.unknown)
  final NetworkType network;

  @JsonKey(defaultValue: '')
  final String protocol;

  @JsonKey(defaultValue: '')
  final String dstIp;

  @JsonKey(defaultValue: 0)
  final int dstPort;

  @JsonKey(defaultValue: '')
  final String domain;

  Map<String, dynamic> toJson() => _$NetFlowToJson(this);
}

@JsonSerializable(explicitToJson: true, includeIfNull: false)
class Decision {
  const Decision({this.action = Verdict.allow, this.ruleId = '', this.layer = '', this.log = false});

  factory Decision.fromJson(Map<String, dynamic> json) => _$DecisionFromJson(json);

  @JsonKey(defaultValue: Verdict.allow, unknownEnumValue: Verdict.allow)
  final Verdict action;

  @JsonKey(defaultValue: '')
  final String ruleId;

  @JsonKey(defaultValue: '')
  final String layer;

  @JsonKey(defaultValue: false)
  final bool log;

  Map<String, dynamic> toJson() => _$DecisionToJson(this);
}
