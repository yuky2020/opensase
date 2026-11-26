/// Dart mirror of pkg/policy/types.go (only the types the admin API carries).
/// Field names and omitempty behaviour match the Go struct tags exactly.
library;

import 'json.dart';

/// policy.Action values.
abstract final class Verdicts {
  static const allow = 'allow';
  static const block = 'block';
  static const ask = 'ask';
  static const all = [allow, block, ask];
}

/// policy.NetworkType values.
abstract final class Networks {
  static const all = ['wifi', 'cellular', 'roaming', 'ethernet', 'unknown'];
}

/// Protocols accepted in Match.Protocols by the evaluator.
abstract final class Protocols {
  static const all = ['tcp', 'udp', 'icmp', 'icmpv6'];
}

/// Decision layers, see pkg/api/types.go.
abstract final class Layers {
  static const all = ['tenant', 'user', 'app', 'lockdown', 'ztna', 'default', 'cloud', 'dns'];
}

class PortRange {
  PortRange({required this.from, this.to = 0});

  int from;

  /// Inclusive; 0 means the same as [from].
  int to;

  int get effectiveTo => to == 0 ? from : to;

  factory PortRange.fromJson(Json j) => PortRange(from: integer(j, 'from'), to: integer(j, 'to'));

  Json toJson() => {'from': from, 'to': to};

  @override
  String toString() => effectiveTo == from ? '$from' : '$from-$effectiveTo';

  @override
  bool operator ==(Object other) => other is PortRange && other.from == from && other.to == to;

  @override
  int get hashCode => Object.hash(from, to);
}

class Match {
  Match({
    List<String>? apps,
    List<String>? networks,
    List<String>? protocols,
    List<String>? cidrs,
    List<PortRange>? ports,
    List<String>? domains,
  }) : apps = apps ?? [],
       networks = networks ?? [],
       protocols = protocols ?? [],
       cidrs = cidrs ?? [],
       ports = ports ?? [],
       domains = domains ?? [];

  List<String> apps;
  List<String> networks;
  List<String> protocols;
  List<String> cidrs;
  List<PortRange> ports;
  List<String> domains;

  bool get isEmpty =>
      apps.isEmpty && networks.isEmpty && protocols.isEmpty && cidrs.isEmpty && ports.isEmpty && domains.isEmpty;

  factory Match.fromJson(Json j) => Match(
    apps: strList(j, 'apps'),
    networks: strList(j, 'networks'),
    protocols: strList(j, 'protocols'),
    cidrs: strList(j, 'cidrs'),
    ports: objList(j, 'ports', PortRange.fromJson),
    domains: strList(j, 'domains'),
  );

  Json toJson() {
    final j = <String, dynamic>{};
    putOmit(j, 'apps', apps);
    putOmit(j, 'networks', networks);
    putOmit(j, 'protocols', protocols);
    putOmit(j, 'cidrs', cidrs);
    putOmit(j, 'ports', [for (final p in ports) p.toJson()]);
    putOmit(j, 'domains', domains);
    return j;
  }
}

class Rule {
  Rule({
    this.id = '',
    this.source = 'tenant',
    this.priority = 0,
    this.action = Verdicts.block,
    Match? match,
    this.log = false,
    this.description = '',
    this.posture = '',
    Map<String, dynamic>? extra,
  }) : match = match ?? Match(),
       extra = extra ?? {};

  String id;
  String source;
  int priority;
  String action;
  Match match;
  bool log;
  String description;
  String posture;
  Map<String, dynamic> extra;

  factory Rule.fromJson(Json j) {
    const known = {'id', 'source', 'priority', 'action', 'match', 'log', 'description', 'posture'};
    final extra = <String, dynamic>{
      for (final e in j.entries)
        if (!known.contains(e.key)) e.key: e.value,
    };
    return Rule(
      id: str(j, 'id'),
      source: str(j, 'source'),
      priority: integer(j, 'priority'),
      action: str(j, 'action'),
      match: Match.fromJson(objOrEmpty(j, 'match')),
      log: boolean(j, 'log'),
      description: str(j, 'description'),
      posture: str(j, 'posture'),
      extra: extra,
    );
  }

  Json toJson() {
    final j = Map<String, dynamic>.from(extra);
    j['id'] = id;
    j['source'] = source;
    j['priority'] = priority;
    j['action'] = action;
    j['match'] = match.toJson();
    j['log'] = log;
    putOmit(j, 'description', description);
    putOmit(j, 'posture', posture);
    return j;
  }

  Rule copy() => Rule.fromJson(toJson());
}

class AppPolicy {
  AppPolicy({this.wifi = '', this.cellular = '', this.roaming = ''});

  String wifi;
  String cellular;
  String roaming;

  factory AppPolicy.fromJson(Json j) =>
      AppPolicy(wifi: str(j, 'wifi'), cellular: str(j, 'cellular'), roaming: str(j, 'roaming'));

  Json toJson() {
    final j = <String, dynamic>{};
    putOmit(j, 'wifi', wifi);
    putOmit(j, 'cellular', cellular);
    putOmit(j, 'roaming', roaming);
    return j;
  }
}

class Blocklist {
  Blocklist({this.id = '', this.name = '', this.category = '', List<String>? domains}) : domains = domains ?? [];

  String id;
  String name;
  String category;
  List<String> domains;

  factory Blocklist.fromJson(Json j) =>
      Blocklist(id: str(j, 'id'), name: str(j, 'name'), category: str(j, 'category'), domains: strList(j, 'domains'));

  Json toJson() => {'id': id, 'name': name, 'category': category, 'domains': domains};
}

class DnsRecord {
  DnsRecord({required this.name, required this.type, required this.value, this.ttl = 0});

  String name;

  /// A, AAAA, CNAME, TXT
  String type;
  String value;

  /// Seconds, default 300 (0 in JSON when omitted), at most 86400.
  int ttl;

  factory DnsRecord.fromJson(Json j) =>
      DnsRecord(name: str(j, 'name'), type: str(j, 'type'), value: str(j, 'value'), ttl: integer(j, 'ttl'));

  Json toJson() {
    final j = <String, dynamic>{'name': name, 'type': type, 'value': value};
    putOmit(j, 'ttl', ttl);
    return j;
  }

  DnsRecord copy() => DnsRecord(name: name, type: type, value: value, ttl: ttl);
}

class DnsForwarder {
  DnsForwarder({required this.zone, List<String>? servers}) : servers = servers ?? [];

  String zone;
  List<String> servers;

  factory DnsForwarder.fromJson(Json j) => DnsForwarder(zone: str(j, 'zone'), servers: strList(j, 'servers'));

  Json toJson() => {'zone': zone, 'servers': servers};

  DnsForwarder copy() => DnsForwarder(zone: zone, servers: [...servers]);
}

class DnsPolicy {
  DnsPolicy({
    this.blockResponse = '',
    List<Blocklist>? blocklists,
    List<String>? allowDomains,
    List<String>? blockDomains,
    this.redirectQueries = false,
    this.zone = '',
    List<DnsRecord>? records,
    List<DnsForwarder>? forwarders,
    this.logQueries = false,
  }) : blocklists = blocklists ?? [],
       allowDomains = allowDomains ?? [],
       blockDomains = blockDomains ?? [],
       records = records ?? [],
       forwarders = forwarders ?? [];

  /// "nxdomain" | "zero" ("" means nxdomain).
  String blockResponse;
  List<Blocklist> blocklists;
  List<String> allowDomains;
  List<String> blockDomains;
  bool redirectQueries;
  String zone;
  List<DnsRecord> records;
  List<DnsForwarder> forwarders;
  bool logQueries;

  factory DnsPolicy.fromJson(Json j) => DnsPolicy(
    blockResponse: str(j, 'blockResponse'),
    blocklists: objList(j, 'blocklists', Blocklist.fromJson),
    allowDomains: strList(j, 'allowDomains'),
    blockDomains: strList(j, 'blockDomains'),
    redirectQueries: boolean(j, 'redirectQueries'),
    zone: str(j, 'zone'),
    records: objList(j, 'records', DnsRecord.fromJson),
    forwarders: objList(j, 'forwarders', DnsForwarder.fromJson),
    logQueries: boolean(j, 'logQueries'),
  );

  Json toJson() {
    final j = <String, dynamic>{
      'blockResponse': blockResponse,
      'blocklists': [for (final b in blocklists) b.toJson()],
    };
    putOmit(j, 'allowDomains', allowDomains);
    putOmit(j, 'blockDomains', blockDomains);
    if (redirectQueries) j['redirectQueries'] = true;
    putOmit(j, 'zone', zone);
    putOmit(j, 'records', [for (final r in records) r.toJson()]);
    putOmit(j, 'forwarders', [for (final f in forwarders) f.toJson()]);
    if (logQueries) j['logQueries'] = true;
    return j;
  }

  DnsPolicy copy() => DnsPolicy.fromJson(toJson());
}

/// policy.PrivateApp (ADR-0013).
class PrivateApp {
  PrivateApp({
    this.id = '',
    this.name = '',
    List<String>? domains,
    List<PortRange>? ports,
    this.connectorGroup = '',
    this.posture = '',
    Map<String, dynamic>? extra,
  }) : domains = domains ?? [],
       ports = ports ?? [],
       extra = extra ?? {};

  String id;
  String name;
  List<String> domains;
  List<PortRange> ports;
  String connectorGroup;
  String posture;
  Map<String, dynamic> extra;

  factory PrivateApp.fromJson(Json j) {
    const known = {'id', 'name', 'domains', 'ports', 'connectorGroup', 'posture'};
    final extra = <String, dynamic>{
      for (final e in j.entries)
        if (!known.contains(e.key)) e.key: e.value,
    };
    return PrivateApp(
      id: str(j, 'id'),
      name: str(j, 'name'),
      domains: strList(j, 'domains'),
      ports: objList(j, 'ports', PortRange.fromJson),
      connectorGroup: str(j, 'connectorGroup'),
      posture: str(j, 'posture'),
      extra: extra,
    );
  }

  Json toJson() {
    final j = Map<String, dynamic>.from(extra);
    j['id'] = id;
    j['name'] = name;
    j['domains'] = domains;
    j['ports'] = [for (final p in ports) p.toJson()];
    j['connectorGroup'] = connectorGroup;
    putOmit(j, 'posture', posture);
    return j;
  }
}

class Flow {
  Flow({
    this.app = '',
    this.uid = 0,
    this.network = '',
    this.protocol = '',
    this.dstIp = '',
    this.dstPort = 0,
    this.domain = '',
  });

  String app;
  int uid;
  String network;
  String protocol;
  String dstIp;
  int dstPort;
  String domain;

  factory Flow.fromJson(Json j) => Flow(
    app: str(j, 'app'),
    uid: integer(j, 'uid'),
    network: str(j, 'network'),
    protocol: str(j, 'protocol'),
    dstIp: str(j, 'dstIp'),
    dstPort: integer(j, 'dstPort'),
    domain: str(j, 'domain'),
  );

  Json toJson() {
    final j = <String, dynamic>{};
    putOmit(j, 'app', app);
    putOmit(j, 'uid', uid);
    putOmit(j, 'network', network);
    j['protocol'] = protocol;
    j['dstIp'] = dstIp;
    j['dstPort'] = dstPort;
    putOmit(j, 'domain', domain);
    return j;
  }
}

class Decision {
  Decision({this.action = '', this.ruleId = '', this.layer = '', this.log = false, this.reason = ''});

  String action;
  String ruleId;
  String layer;
  bool log;
  String reason;

  factory Decision.fromJson(Json j) => Decision(
    action: str(j, 'action'),
    ruleId: str(j, 'ruleId'),
    layer: str(j, 'layer'),
    log: boolean(j, 'log'),
    reason: str(j, 'reason'),
  );

  Json toJson() {
    final j = <String, dynamic>{'action': action};
    putOmit(j, 'ruleId', ruleId);
    j['layer'] = layer;
    j['log'] = log;
    putOmit(j, 'reason', reason);
    return j;
  }
}
