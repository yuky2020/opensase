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
    SaasPolicy? saas,
    WebPolicy? web,
    List<String>? categories,
    this.safeSearch = false,
  }) : saas = saas ?? SaasPolicy(),
       categories = categories ?? [],
       web = web ?? WebPolicy(),
       rules = rules ?? [],
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

  /// SaaS app control (ADR-0017).
  SaasPolicy saas;

  /// TLS inspection and web rules, enforced by the Edge (ADR-0018).
  WebPolicy web;

  /// Web categories to block (ADR-0022), names from the loaded category list.
  List<String> categories;

  /// Force safe search and restricted video modes (ADR-0025).
  bool safeSearch;

  /// The ETag the policy was read at; sent as If-Match when saving. Not part of the JSON.
  String etag = '';

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
      saas: SaasPolicy.fromJson(objOrEmpty(j, 'saas')),
      web: WebPolicy.fromJson(objOrEmpty(j, 'web')),
      categories: strList(j, 'categories'),
      safeSearch: boolean(j, 'safeSearch'),
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
    if (!saas.isEmpty) j['saas'] = saas.toJson();
    if (!web.isEmpty) j['web'] = web.toJson();
    putOmit(j, 'categories', categories);
    if (safeSearch) j['safeSearch'] = true;
    return j;
  }

  TenantPolicy copy() => TenantPolicy.fromJson(toJson())..etag = etag;
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
    this.saasApp = '',
    List<String>? categories,
  }) : flow = flow ?? Flow(),
       decision = decision ?? Decision(),
       categories = categories ?? [];

  DateTime? start;
  DateTime? end;
  Flow flow;
  Decision decision;
  int bytesOut;
  int bytesIn;

  /// "device" | "edge" | "cloud".
  String where;
  String deviceId;

  /// Catalog app of the flow's hostname, set by the Control Plane (ADR-0017).
  String saasApp;

  /// Web categories of the flow's hostname, set by the Control Plane (issue #27).
  List<String> categories;

  factory FlowRecord.fromJson(Json j) => FlowRecord(
    start: time(j, 'start'),
    end: time(j, 'end'),
    flow: Flow.fromJson(objOrEmpty(j, 'flow')),
    decision: Decision.fromJson(objOrEmpty(j, 'decision')),
    bytesOut: integer(j, 'bytesOut'),
    bytesIn: integer(j, 'bytesIn'),
    where: str(j, 'where'),
    deviceId: str(j, 'deviceId'),
    saasApp: str(j, 'saasApp'),
    categories: strList(j, 'categories'),
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
    putOmit(j, 'saasApp', saasApp);
    putOmit(j, 'categories', categories);
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
  AdminEdge({required this.id, this.tenantId = '', this.revoked = false, this.createdAt});

  String id;

  /// Non-empty for a Private Edge bound to that tenant (ADR-0014).
  String tenantId;
  bool revoked;
  DateTime? createdAt;

  factory AdminEdge.fromJson(Json j) => AdminEdge(
    id: str(j, 'id'),
    tenantId: str(j, 'tenantId'),
    revoked: boolean(j, 'revoked'),
    createdAt: time(j, 'createdAt'),
  );

  Json toJson() => {
    'id': id,
    if (tenantId.isNotEmpty) 'tenantId': tenantId,
    'revoked': revoked,
    'createdAt': goTime(createdAt),
  };
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

/// The signed-in admin (GET /v1/admin/whoami). A tenant admin (ST-03) sees only its tenant and
/// cannot create tenants or manage Edges.
class AdminIdentity {
  AdminIdentity({required this.role, this.tenantId = '', this.tokenId = '', this.tenantRole = ''});

  String role;
  String tenantId;
  String tokenId;

  /// admin | policy-editor | viewer for a tenant token (ADR-0027).
  String tenantRole;

  bool get isSuper => role == 'super';

  factory AdminIdentity.fromJson(Json j) => AdminIdentity(
    role: str(j, 'role'),
    tenantId: str(j, 'tenantId'),
    tokenId: str(j, 'tokenId'),
    tenantRole: str(j, 'tenantRole'),
  );

  Json toJson() {
    final j = <String, dynamic>{'role': role};
    putOmit(j, 'tenantId', tenantId);
    putOmit(j, 'tokenId', tokenId);
    putOmit(j, 'tenantRole', tenantRole);
    return j;
  }
}

/// A tenant admin token, without its secret.
class AdminToken {
  AdminToken({
    required this.id,
    required this.tenantId,
    required this.name,
    this.createdAt,
    this.expiresAt,
    this.revoked = false,
    this.lastUsed,
    this.role = 'admin',
  });

  String id;
  String tenantId;
  String name;
  DateTime? createdAt;
  DateTime? expiresAt;
  bool revoked;
  DateTime? lastUsed;

  /// admin | policy-editor | viewer (ADR-0027).
  String role;

  bool isExpired(DateTime now) => expiresAt != null && !now.isBefore(expiresAt!);

  factory AdminToken.fromJson(Json j) => AdminToken(
    id: str(j, 'id'),
    tenantId: str(j, 'tenantId'),
    name: str(j, 'name'),
    createdAt: time(j, 'createdAt'),
    expiresAt: time(j, 'expiresAt'),
    revoked: boolean(j, 'revoked'),
    lastUsed: time(j, 'lastUsed'),
    role: str(j, 'role'),
  );

  Json toJson() {
    final j = <String, dynamic>{
      'id': id,
      'tenantId': tenantId,
      'name': name,
      'createdAt': goTime(createdAt),
      'expiresAt': goTime(expiresAt),
      'revoked': revoked,
      'role': role,
    };
    if (lastUsed != null) j['lastUsed'] = goTime(lastUsed);
    return j;
  }
}

/// The reply to admin token creation; [token] is shown only once.
class AdminTokenCreated {
  AdminTokenCreated({required this.adminToken, required this.token});

  AdminToken adminToken;
  String token;

  factory AdminTokenCreated.fromJson(Json j) =>
      AdminTokenCreated(adminToken: AdminToken.fromJson(j), token: str(j, 'token'));
}

/// One admin write (ADR-0016 audit log).
class AuditEntry {
  AuditEntry({
    required this.id,
    this.at,
    required this.actor,
    this.tenantId = '',
    required this.method,
    required this.path,
    required this.status,
  });

  int id;
  DateTime? at;
  String actor;
  String tenantId;
  String method;
  String path;
  int status;

  bool get ok => status >= 200 && status < 300;

  factory AuditEntry.fromJson(Json j) => AuditEntry(
    id: integer(j, 'id'),
    at: time(j, 'at'),
    actor: str(j, 'actor'),
    tenantId: str(j, 'tenantId'),
    method: str(j, 'method'),
    path: str(j, 'path'),
    status: integer(j, 'status'),
  );

  Json toJson() {
    final j = <String, dynamic>{'id': id, 'at': goTime(at), 'actor': actor};
    putOmit(j, 'tenantId', tenantId);
    j['method'] = method;
    j['path'] = path;
    j['status'] = status;
    return j;
  }
}

/// TenantPolicy.saas: block catalog apps or whole categories (ADR-0017).
class SaasPolicy {
  SaasPolicy({List<String>? blockApps, List<String>? blockCategories, List<String>? allowApps})
    : blockApps = blockApps ?? [],
      blockCategories = blockCategories ?? [],
      allowApps = allowApps ?? [];

  List<String> blockApps;
  List<String> blockCategories;

  /// Exempt from blockCategories (not from blockApps).
  List<String> allowApps;

  bool get isEmpty => blockApps.isEmpty && blockCategories.isEmpty && allowApps.isEmpty;

  /// Whether [app] of [category] is blocked by this policy.
  bool blocks(String app, String category) =>
      blockApps.contains(app) || (blockCategories.contains(category) && !allowApps.contains(app));

  factory SaasPolicy.fromJson(Json j) => SaasPolicy(
    blockApps: strList(j, 'blockApps'),
    blockCategories: strList(j, 'blockCategories'),
    allowApps: strList(j, 'allowApps'),
  );

  Json toJson() {
    final j = <String, dynamic>{};
    putOmit(j, 'blockApps', blockApps);
    putOmit(j, 'blockCategories', blockCategories);
    putOmit(j, 'allowApps', allowApps);
    return j;
  }
}

/// One entry of the built-in SaaS catalog.
class SaasApp {
  SaasApp({required this.id, required this.name, required this.category, List<String>? domains})
    : domains = domains ?? [];

  String id;
  String name;
  String category;
  List<String> domains;

  factory SaasApp.fromJson(Json j) =>
      SaasApp(id: str(j, 'id'), name: str(j, 'name'), category: str(j, 'category'), domains: strList(j, 'domains'));

  Json toJson() => {'id': id, 'name': name, 'category': category, 'domains': domains};
}

/// policy.WebPolicy: TLS inspection, URL rules and injected request headers (ADR-0018).
class WebPolicy {
  WebPolicy({
    this.inspect = false,
    this.blockEch = false,
    List<String>? bypass,
    List<WebRule>? rules,
    List<WebHeader>? headers,
    List<DlpRule>? dlp,
    MalwarePolicy? malware,
  }) : malware = malware ?? MalwarePolicy(),
       bypass = bypass ?? [],
       rules = rules ?? [],
       headers = headers ?? [],
       dlp = dlp ?? [];

  /// Decrypt TLS at the Edge. Without it, rules and headers apply to plain HTTP only.
  bool inspect;

  /// Remove ECH configurations from DNS HTTPS/SVCB answers at the Edge (ADR-0030).
  bool blockEch;

  /// Domains never decrypted (pinned apps, banking, health).
  List<String> bypass;

  /// First match decides; no match allows.
  List<WebRule> rules;
  List<WebHeader> headers;

  /// Request body scanning (ADR-0019).
  List<DlpRule> dlp;

  /// Malware scanning (ADR-0020).
  MalwarePolicy malware;

  bool get isEmpty => !inspect && !blockEch && bypass.isEmpty && rules.isEmpty && headers.isEmpty && dlp.isEmpty && malware.isEmpty;

  factory WebPolicy.fromJson(Json j) => WebPolicy(
    inspect: boolean(j, 'inspect'),
    blockEch: boolean(j, 'blockECH'),
    bypass: strList(j, 'bypass'),
    rules: objList(j, 'rules', WebRule.fromJson),
    headers: objList(j, 'headers', WebHeader.fromJson),
    dlp: objList(j, 'dlp', DlpRule.fromJson),
    malware: MalwarePolicy.fromJson(objOrEmpty(j, 'malware')),
  );

  Json toJson() {
    final j = <String, dynamic>{};
    if (inspect) j['inspect'] = true;
    if (blockEch) j['blockECH'] = true;
    putOmit(j, 'bypass', bypass);
    putOmit(j, 'rules', [for (final r in rules) r.toJson()]);
    putOmit(j, 'headers', [for (final h in headers) h.toJson()]);
    putOmit(j, 'dlp', [for (final d in dlp) d.toJson()]);
    if (!malware.isEmpty) j['malware'] = malware.toJson();
    return j;
  }

  WebPolicy copyWith({
    bool? inspect,
    bool? blockEch,
    List<String>? bypass,
    List<WebRule>? rules,
    List<WebHeader>? headers,
    List<DlpRule>? dlp,
    MalwarePolicy? malware,
  }) => WebPolicy(
    inspect: inspect ?? this.inspect,
    blockEch: blockEch ?? this.blockEch,
    bypass: bypass ?? this.bypass,
    rules: rules ?? this.rules,
    headers: headers ?? this.headers,
    dlp: dlp ?? this.dlp,
    malware: malware ?? this.malware,
  );
}

/// policy.WebRule: matches requests by host, path prefix and method.
class WebRule {
  WebRule({
    required this.id,
    List<String>? domains,
    List<String>? pathPrefixes,
    List<String>? methods,
    this.action = 'block',
  }) : domains = domains ?? [],
       pathPrefixes = pathPrefixes ?? [],
       methods = methods ?? [];

  String id;
  List<String> domains;
  List<String> pathPrefixes;
  List<String> methods;

  /// allow | block.
  String action;

  factory WebRule.fromJson(Json j) => WebRule(
    id: str(j, 'id'),
    domains: strList(j, 'domains'),
    pathPrefixes: strList(j, 'pathPrefixes'),
    methods: strList(j, 'methods'),
    action: str(j, 'action'),
  );

  Json toJson() {
    final j = <String, dynamic>{'id': id, 'domains': domains, 'action': action};
    putOmit(j, 'pathPrefixes', pathPrefixes);
    putOmit(j, 'methods', methods);
    return j;
  }
}

/// policy.WebHeader: a request header the Edge sets for matching hosts.
class WebHeader {
  WebHeader({List<String>? domains, required this.name, required this.value}) : domains = domains ?? [];

  List<String> domains;
  String name;
  String value;

  factory WebHeader.fromJson(Json j) =>
      WebHeader(domains: strList(j, 'domains'), name: str(j, 'name'), value: str(j, 'value'));

  Json toJson() => {'domains': domains, 'name': name, 'value': value};
}

/// policy.DLPRule: sensitive data in request bodies on the inspected path (ADR-0019).
class DlpRule {
  DlpRule({
    required this.id,
    List<String>? domains,
    List<String>? detectors,
    List<String>? patterns,
    this.minMatches = 0,
    this.action = 'block',
    this.blockUnscanned = false,
    this.downloads = false,
    List<String>? datasets,
  }) : domains = domains ?? [],
       datasets = datasets ?? [],
       detectors = detectors ?? [],
       patterns = patterns ?? [];

  /// Built-in detectors of pkg/dlp.
  static const builtinDetectors = ['credit-card', 'iban', 'private-key', 'it-tax-code', 'email'];

  String id;

  /// Empty: every inspected host.
  List<String> domains;
  List<String> detectors;
  List<String> patterns;

  /// 0 means 1.
  int minMatches;

  /// block | allow (record only).
  String action;
  bool blockUnscanned;

  /// Also scan file downloads (ADR-0021).
  bool downloads;

  /// Tenant DLP datasets by name (ADR-0029).
  List<String> datasets;

  factory DlpRule.fromJson(Json j) => DlpRule(
    id: str(j, 'id'),
    domains: strList(j, 'domains'),
    detectors: strList(j, 'detectors'),
    patterns: strList(j, 'patterns'),
    minMatches: integer(j, 'minMatches'),
    action: str(j, 'action'),
    blockUnscanned: boolean(j, 'blockUnscanned'),
    downloads: boolean(j, 'downloads'),
    datasets: strList(j, 'datasets'),
  );

  Json toJson() {
    final j = <String, dynamic>{'id': id, 'action': action};
    putOmit(j, 'domains', domains);
    putOmit(j, 'detectors', detectors);
    putOmit(j, 'patterns', patterns);
    putOmit(j, 'datasets', datasets);
    if (minMatches > 0) j['minMatches'] = minMatches;
    if (blockUnscanned) j['blockUnscanned'] = true;
    if (downloads) j['downloads'] = true;
    return j;
  }
}

/// policy.MalwarePolicy: uploads and file downloads scanned by ClamAV at the Edge (ADR-0020).
class MalwarePolicy {
  MalwarePolicy({this.uploads = false, this.downloads = false, this.blockUnscanned = false});

  bool uploads;
  bool downloads;
  bool blockUnscanned;

  bool get isEmpty => !uploads && !downloads && !blockUnscanned;

  factory MalwarePolicy.fromJson(Json j) => MalwarePolicy(
    uploads: boolean(j, 'uploads'),
    downloads: boolean(j, 'downloads'),
    blockUnscanned: boolean(j, 'blockUnscanned'),
  );

  Json toJson() => {
    if (uploads) 'uploads': true,
    if (downloads) 'downloads': true,
    if (blockUnscanned) 'blockUnscanned': true,
  };
}

/// api.CategoryCatalog: the web category list loaded by the Control Plane (ADR-0022).
class CategoryCatalog {
  CategoryCatalog({
    this.source = '',
    this.licence = '',
    this.url = '',
    this.version = '',
    this.loadedAt,
    List<WebCategory>? categories,
  }) : categories = categories ?? [];

  String source;
  String licence;
  String url;

  /// Empty when no list is loaded.
  String version;
  DateTime? loadedAt;
  List<WebCategory> categories;

  factory CategoryCatalog.fromJson(Json j) => CategoryCatalog(
    source: str(j, 'source'),
    licence: str(j, 'licence'),
    url: str(j, 'url'),
    version: str(j, 'version'),
    loadedAt: time(j, 'loadedAt'),
    categories: objList(j, 'categories', WebCategory.fromJson),
  );
}

class WebCategory {
  WebCategory({
    required this.name,
    this.title = '',
    this.description = '',
    this.type = 'black',
    this.domains = 0,
    this.urls = 0,
    List<String>? aliases,
  }) : aliases = aliases ?? [];

  String name;
  String title;
  String description;

  /// black (can be blocked) | white (allow lists).
  String type;
  int domains;

  /// URL (path) entries, enforced on the inspected path.
  int urls;
  List<String> aliases;

  factory WebCategory.fromJson(Json j) => WebCategory(
    name: str(j, 'name'),
    title: str(j, 'title'),
    description: str(j, 'description'),
    type: str(j, 'type'),
    domains: integer(j, 'domains'),
    urls: integer(j, 'urls'),
    aliases: strList(j, 'aliases'),
  );
}

/// api.AdminInfo (GET /v1/admin/info).
class AdminInfo {
  AdminInfo({this.controlUrl = '', this.rootSha256 = '', this.version = '', List<String>? features})
    : features = features ?? [];

  /// The control URL devices enroll with, including the #sha256= root pin.
  String controlUrl;
  String rootSha256;
  String version;
  List<String> features;

  factory AdminInfo.fromJson(Json j) => AdminInfo(
    controlUrl: str(j, 'controlUrl'),
    rootSha256: str(j, 'rootSha256'),
    version: str(j, 'version'),
    features: strList(j, 'features'),
  );
}

/// api.AuditVerification: the admin audit hash chain check (ADR-0028).
class AuditVerification {
  AuditVerification({
    this.ok = false,
    this.entries = 0,
    this.headId = 0,
    this.head = '',
    this.anchorId = 0,
    this.badId = 0,
    this.reason = '',
  });

  bool ok;
  int entries;
  int headId;
  String head;
  int anchorId;
  int badId;
  String reason;

  factory AuditVerification.fromJson(Json j) => AuditVerification(
    ok: boolean(j, 'ok'),
    entries: integer(j, 'entries'),
    headId: integer(j, 'headId'),
    head: str(j, 'head'),
    anchorId: integer(j, 'anchorId'),
    badId: integer(j, 'badId'),
    reason: str(j, 'reason'),
  );
}
