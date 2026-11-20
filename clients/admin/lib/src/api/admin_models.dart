/// Dart mirror of the admin wire types in pkg/api/types.go (plus AdminDevice from
/// internal/controlplane). Field names and omitempty behaviour match the Go struct tags.
library;

import 'json.dart';
import 'policy_models.dart';

class AdminTenant {
  AdminTenant({this.id = '', required this.name});

  String id;
  String name;

  factory AdminTenant.fromJson(Json j) => AdminTenant(id: str(j, 'id'), name: str(j, 'name'));

  Json toJson() {
    final j = <String, dynamic>{};
    putOmit(j, 'id', id);
    j['name'] = name;
    return j;
  }
}

class AdminUser {
  AdminUser({this.id = '', required this.email, required this.name});

  String id;
  String email;
  String name;

  factory AdminUser.fromJson(Json j) => AdminUser(id: str(j, 'id'), email: str(j, 'email'), name: str(j, 'name'));

  Json toJson() {
    final j = <String, dynamic>{};
    putOmit(j, 'id', id);
    j['email'] = email;
    j['name'] = name;
    return j;
  }
}

class ProvisioningKeyRequest {
  ProvisioningKeyRequest({required this.userId, this.maxUses = 1, this.validFor = 86400});

  String userId;
  int maxUses;

  /// Seconds.
  int validFor;

  factory ProvisioningKeyRequest.fromJson(Json j) => ProvisioningKeyRequest(
    userId: str(j, 'userId'),
    maxUses: integer(j, 'maxUses'),
    validFor: integer(j, 'validForSeconds'),
  );

  Json toJson() => {'userId': userId, 'maxUses': maxUses, 'validForSeconds': validFor};
}

class ProvisioningKey {
  ProvisioningKey({required this.key, required this.userId, this.expiresAt});

  String key;
  String userId;
  DateTime? expiresAt;

  factory ProvisioningKey.fromJson(Json j) =>
      ProvisioningKey(key: str(j, 'key'), userId: str(j, 'userId'), expiresAt: time(j, 'expiresAt'));

  Json toJson() => {'key': key, 'userId': userId, 'expiresAt': goTime(expiresAt)};
}

/// api.TenantPrivateApp: an embedded policy.PrivateApp (fields flattened) plus Users.
class TenantPrivateApp extends PrivateApp {
  TenantPrivateApp({super.id, super.name, super.domains, super.ports, super.connectorGroup, List<String>? users})
    : users = users ?? [];

  /// User IDs or emails; empty means every user of the tenant.
  List<String> users;

  factory TenantPrivateApp.fromJson(Json j) {
    final p = PrivateApp.fromJson(j);
    return TenantPrivateApp(
      id: p.id,
      name: p.name,
      domains: p.domains,
      ports: p.ports,
      connectorGroup: p.connectorGroup,
      users: strList(j, 'users'),
    );
  }

  @override
  Json toJson() {
    final j = super.toJson();
    putOmit(j, 'users', users);
    return j;
  }

  TenantPrivateApp copy() => TenantPrivateApp.fromJson(toJson());
}

/// api.TenantPolicy: the tenant layer.
class TenantPolicy {
  TenantPolicy({
    this.defaultAction = '',
    this.allowUserRules = false,
    this.lockdown = false,
    List<Rule>? rules,
    Map<String, AppPolicy>? apps,
    DnsPolicy? dns,
    List<TenantPrivateApp>? privateApps,
    List<String>? decideBlockDomains,
    List<String>? decideBlockCidrs,
    this.decideDefault = '',
  }) : rules = rules ?? [],
       apps = apps ?? {},
       dns = dns ?? DnsPolicy(),
       privateApps = privateApps ?? [],
       decideBlockDomains = decideBlockDomains ?? [],
       decideBlockCidrs = decideBlockCidrs ?? [];

  String defaultAction;
  bool allowUserRules;
  bool lockdown;
  List<Rule> rules;

  /// Key: Android package name.
  Map<String, AppPolicy> apps;
  DnsPolicy dns;
  List<TenantPrivateApp> privateApps;
  List<String> decideBlockDomains;
  List<String> decideBlockCidrs;

  /// allow | block ("" means the server default).
  String decideDefault;

  factory TenantPolicy.fromJson(Json j) {
    final apps = objOrEmpty(j, 'apps');
    return TenantPolicy(
      defaultAction: str(j, 'defaultAction'),
      allowUserRules: boolean(j, 'allowUserRules'),
      lockdown: boolean(j, 'lockdown'),
      rules: objList(j, 'rules', Rule.fromJson),
      apps: {for (final e in apps.entries) e.key: AppPolicy.fromJson(obj(e.value, 'apps.${e.key}'))},
      dns: DnsPolicy.fromJson(objOrEmpty(j, 'dns')),
      privateApps: objList(j, 'privateApps', TenantPrivateApp.fromJson),
      decideBlockDomains: strList(j, 'decideBlockDomains'),
      decideBlockCidrs: strList(j, 'decideBlockCidrs'),
      decideDefault: str(j, 'decideDefault'),
    );
  }

  Json toJson() {
    final j = <String, dynamic>{
      'defaultAction': defaultAction,
      'allowUserRules': allowUserRules,
      'lockdown': lockdown,
      'rules': [for (final r in rules) r.toJson()],
      'apps': {for (final e in apps.entries) e.key: e.value.toJson()},
      'dns': dns.toJson(),
    };
    putOmit(j, 'privateApps', [for (final p in privateApps) p.toJson()]);
    putOmit(j, 'decideBlockDomains', decideBlockDomains);
    putOmit(j, 'decideBlockCidrs', decideBlockCidrs);
    j['decideDefault'] = decideDefault;
    return j;
  }

  TenantPolicy copy() => TenantPolicy.fromJson(toJson());
}

class FlowRecord {
  FlowRecord({
    this.start,
    this.end,
    Flow? flow,
    Decision? decision,
    this.bytesOut = 0,
    this.bytesIn = 0,
    this.where = '',
    this.deviceId = '',
  }) : flow = flow ?? Flow(),
       decision = decision ?? Decision();

  DateTime? start;
  DateTime? end;
  Flow flow;
  Decision decision;
  int bytesOut;
  int bytesIn;

  /// "device" | "edge" | "cloud".
  String where;
  String deviceId;

  factory FlowRecord.fromJson(Json j) => FlowRecord(
    start: time(j, 'start'),
    end: time(j, 'end'),
    flow: Flow.fromJson(objOrEmpty(j, 'flow')),
    decision: Decision.fromJson(objOrEmpty(j, 'decision')),
    bytesOut: integer(j, 'bytesOut'),
    bytesIn: integer(j, 'bytesIn'),
    where: str(j, 'where'),
    deviceId: str(j, 'deviceId'),
  );

  Json toJson() {
    final j = <String, dynamic>{
      'start': goTime(start),
      // Go's omitempty never omits a struct, so a zero End is written as the zero time.
      'end': goTime(end),
      'flow': flow.toJson(),
      'decision': decision.toJson(),
      'bytesOut': bytesOut,
      'bytesIn': bytesIn,
      'where': where,
    };
    putOmit(j, 'deviceId', deviceId);
    return j;
  }
}

class FlowBatch {
  FlowBatch({List<FlowRecord>? records}) : records = records ?? [];

  List<FlowRecord> records;

  factory FlowBatch.fromJson(Json j) => FlowBatch(records: objList(j, 'records', FlowRecord.fromJson));

  Json toJson() => {
    'records': [for (final r in records) r.toJson()],
  };
}

class AdminEdge {
  AdminEdge({required this.id, this.revoked = false, this.createdAt});

  String id;
  bool revoked;
  DateTime? createdAt;

  factory AdminEdge.fromJson(Json j) =>
      AdminEdge(id: str(j, 'id'), revoked: boolean(j, 'revoked'), createdAt: time(j, 'createdAt'));

  Json toJson() => {'id': id, 'revoked': revoked, 'createdAt': goTime(createdAt)};
}

/// internal/controlplane.AdminDevice (see the CONTRACT-CHANGE-REQUEST there).
class AdminDevice {
  AdminDevice({
    required this.id,
    this.userId = '',
    this.name = '',
    this.platform = '',
    this.revoked = false,
    this.createdAt,
  });

  String id;
  String userId;
  String name;
  String platform;
  bool revoked;
  DateTime? createdAt;

  factory AdminDevice.fromJson(Json j) => AdminDevice(
    id: str(j, 'id'),
    userId: str(j, 'userId'),
    name: str(j, 'name'),
    platform: str(j, 'platform'),
    revoked: boolean(j, 'revoked'),
    createdAt: time(j, 'createdAt'),
  );

  Json toJson() => {
    'id': id,
    'userId': userId,
    'name': name,
    'platform': platform,
    'revoked': revoked,
    'createdAt': goTime(createdAt),
  };
}

class AdminConnectorRequest {
  AdminConnectorRequest({required this.name, this.group = ''});

  String name;

  /// "" means "default" on the server.
  String group;

  factory AdminConnectorRequest.fromJson(Json j) => AdminConnectorRequest(name: str(j, 'name'), group: str(j, 'group'));

  Json toJson() => {'name': name, 'group': group};
}

class AdminConnector {
  AdminConnector({
    required this.id,
    this.tenantId = '',
    this.name = '',
    this.group = '',
    this.revoked = false,
    this.createdAt,
    this.lastSeen,
  });

  /// A Connector counts as online if an Edge reported it within this window.
  static const onlineWindow = Duration(minutes: 2);

  String id;
  String tenantId;
  String name;
  String group;
  bool revoked;
  DateTime? createdAt;
  DateTime? lastSeen;

  bool isOnline(DateTime now) => !revoked && lastSeen != null && now.difference(lastSeen!) <= onlineWindow;

  factory AdminConnector.fromJson(Json j) => AdminConnector(
    id: str(j, 'id'),
    tenantId: str(j, 'tenantId'),
    name: str(j, 'name'),
    group: str(j, 'group'),
    revoked: boolean(j, 'revoked'),
    createdAt: time(j, 'createdAt'),
    lastSeen: time(j, 'lastSeen'),
  );

  Json toJson() => {
    'id': id,
    'tenantId': tenantId,
    'name': name,
    'group': group,
    'revoked': revoked,
    'createdAt': goTime(createdAt),
    'lastSeen': goTime(lastSeen),
  };
}

class AdminConnectorCreated {
  AdminConnectorCreated({required this.connector, required this.provisioningKey});

  AdminConnector connector;
  String provisioningKey;

  factory AdminConnectorCreated.fromJson(Json j) => AdminConnectorCreated(
    connector: AdminConnector.fromJson(objOrEmpty(j, 'connector')),
    provisioningKey: str(j, 'provisioningKey'),
  );

  Json toJson() => {'connector': connector.toJson(), 'provisioningKey': provisioningKey};
}
