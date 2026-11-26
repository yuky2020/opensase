import 'dart:convert';

import 'package:http/http.dart' as http;

import 'admin_models.dart';
import 'json.dart';

/// A non-2xx answer from the Control Plane. [field] is the offending policy field of a
/// policy.ValidationError (400 on PUT policy), as sent in the server's error body.
class ApiException implements Exception {
  ApiException(this.status, this.message, {this.field = ''});

  final int status;
  final String message;
  final String field;

  bool get unauthorized => status == 401 || status == 403;

  @override
  String toString() => field.isEmpty ? 'HTTP $status: $message' : 'HTTP $status: $message ($field)';
}

/// Client of the Control Plane admin API (`/v1/admin/...`, Bearer admin token).
///
/// Paths are resolved against [base], which on the web is `Uri.base`, the page the portal
/// was served from: the portal is same-origin with the Control Plane, so no CORS.
class AdminApi {
  AdminApi({required this.token, required this.client, Uri? base}) : base = base ?? Uri.base;

  final String token;
  final Uri base;
  final http.Client client;

  Uri _uri(String path, [Map<String, String>? query]) {
    final u = base.resolve(path);
    return query == null ? u : u.replace(queryParameters: query);
  }

  static String _seg(String s) => Uri.encodeComponent(s);

  Map<String, String> get _headers => {
    'Authorization': 'Bearer $token',
    'Accept': 'application/json',
    'Content-Type': 'application/json',
  };

  Future<Object?> _send(String method, String path, {Object? body, Map<String, String>? query}) async {
    final (v, _) = await _sendH(method, path, body: body, query: query);
    return v;
  }

  /// [_send] that also returns the response headers.
  Future<(Object?, Map<String, String>)> _sendH(
    String method,
    String path, {
    Object? body,
    Map<String, String>? query,
    Map<String, String>? headers,
  }) async {
    final req = http.Request(method, _uri(path, query))..headers.addAll(_headers);
    if (headers != null) req.headers.addAll(headers);
    if (body != null) req.body = jsonEncode(body);
    final resp = await http.Response.fromStream(await client.send(req));
    final text = utf8.decode(resp.bodyBytes, allowMalformed: true);
    if (resp.statusCode < 200 || resp.statusCode > 299) {
      var msg = text.trim();
      var field = '';
      try {
        final j = jsonDecode(text);
        if (j is Map && j['error'] is String) {
          msg = j['error'] as String;
          field = j['field'] is String ? j['field'] as String : '';
        }
      } on FormatException {
        // Plain-text error body.
      }
      if (msg.isEmpty) msg = resp.reasonPhrase ?? 'request failed';
      throw ApiException(resp.statusCode, msg, field: field);
    }
    if (text.trim().isEmpty) return (null, resp.headers);
    return (jsonDecode(text), resp.headers);
  }

  /// GET of a non-JSON body (PEM).
  Future<String> _getText(String path) async {
    final req = http.Request('GET', _uri(path, null))
      ..headers.addAll({..._headers, 'Accept': 'application/x-pem-file'});
    final resp = await http.Response.fromStream(await client.send(req));
    final text = utf8.decode(resp.bodyBytes, allowMalformed: true);
    if (resp.statusCode < 200 || resp.statusCode > 299) {
      var msg = text.trim();
      try {
        final j = jsonDecode(text);
        if (j is Map && j['error'] is String) msg = j['error'] as String;
      } on FormatException {
        // Plain-text error body.
      }
      throw ApiException(resp.statusCode, msg.isEmpty ? (resp.reasonPhrase ?? 'request failed') : msg);
    }
    return text;
  }

  /// The tenant's web inspection root (PEM, ADR-0018), to install on its devices.
  Future<String> inspectionRoot(String tenant) => _getText('/v1/admin/tenants/${_seg(tenant)}/inspection-ca');

  static List<T> _list<T>(Object? v, T Function(Json) f) {
    if (v == null) return <T>[];
    if (v is! List) throw const FormatException('expected a JSON array');
    return [for (final e in v) f(obj(e, 'item'))];
  }

  // --- tenants and users ---

  Future<List<AdminTenant>> listTenants() async => _list(await _send('GET', '/v1/admin/tenants'), AdminTenant.fromJson);

  Future<AdminTenant> createTenant(AdminTenant t) async =>
      AdminTenant.fromJson(obj(await _send('POST', '/v1/admin/tenants', body: t.toJson()), 'tenant'));

  Future<List<AdminUser>> listUsers(String tenant) async =>
      _list(await _send('GET', '/v1/admin/tenants/${_seg(tenant)}/users'), AdminUser.fromJson);

  Future<AdminUser> createUser(String tenant, AdminUser u) async =>
      AdminUser.fromJson(obj(await _send('POST', '/v1/admin/tenants/${_seg(tenant)}/users', body: u.toJson()), 'user'));

  Future<ProvisioningKey> createProvisioningKey(String tenant, ProvisioningKeyRequest r) async =>
      ProvisioningKey.fromJson(
        obj(await _send('POST', '/v1/admin/tenants/${_seg(tenant)}/provisioning-keys', body: r.toJson()), 'key'),
      );

  // --- policy ---

  /// The tenant policy, with the ETag it was read at (issue #19).
  Future<TenantPolicy> getPolicy(String tenant) async {
    final (v, h) = await _sendH('GET', '/v1/admin/tenants/${_seg(tenant)}/policy');
    return TenantPolicy.fromJson(obj(v, 'policy'))..etag = h['etag'] ?? '';
  }

  /// Saves the policy. With [p.etag] set, the server refuses (412) if someone else changed
  /// the policy since it was read.
  Future<void> putPolicy(String tenant, TenantPolicy p) async {
    final (_, h) = await _sendH(
      'PUT',
      '/v1/admin/tenants/${_seg(tenant)}/policy',
      body: p.toJson(),
      headers: p.etag.isEmpty ? null : {'If-Match': p.etag},
    );
    p.etag = h['etag'] ?? '';
  }

  /// Control Plane description: the pinned control URL for enrollment QR codes (issue #19).
  Future<AdminInfo> info() async => AdminInfo.fromJson(obj(await _send('GET', '/v1/admin/info'), 'info'));

  // --- flows ---

  Future<FlowBatch> listFlows(String tenant, {int limit = 500}) async {
    final v = await _send('GET', '/v1/admin/tenants/${_seg(tenant)}/flows', query: {'limit': '$limit'});
    return v == null ? FlowBatch() : FlowBatch.fromJson(obj(v, 'flows'));
  }

  // --- devices ---

  Future<List<AdminDevice>> listDevices(String tenant) async =>
      _list(await _send('GET', '/v1/admin/tenants/${_seg(tenant)}/devices'), AdminDevice.fromJson);

  Future<void> revokeDevice(String tenant, String device) async =>
      _send('POST', '/v1/admin/tenants/${_seg(tenant)}/devices/${_seg(device)}/revoke');

  // --- admin identity and tenant admin tokens (ST-03) ---

  Future<AdminIdentity> whoami() async =>
      AdminIdentity.fromJson(obj(await _send('GET', '/v1/admin/whoami'), 'identity'));

  Future<List<AdminToken>> listAdminTokens(String tenant) async =>
      _list(await _send('GET', '/v1/admin/tenants/${_seg(tenant)}/admin-tokens'), AdminToken.fromJson);

  /// Creates a tenant admin token; [validFor] null means the server default (90 days).
  Future<AdminTokenCreated> createAdminToken(String tenant, String name, {Duration? validFor, String? role}) async =>
      AdminTokenCreated.fromJson(
        obj(
          await _send(
            'POST',
            '/v1/admin/tenants/${_seg(tenant)}/admin-tokens',
            body: {
              'name': name,
              if (validFor != null) 'validForSeconds': validFor.inSeconds,
              if (role != null && role.isNotEmpty) 'role': role,
            },
          ),
          'adminToken',
        ),
      );

  Future<void> revokeAdminToken(String tenant, String id) async =>
      _send('POST', '/v1/admin/tenants/${_seg(tenant)}/admin-tokens/${_seg(id)}/revoke');

  /// Admin writes on [tenant], newest first.
  /// Checks the audit hash chain (super-admin only, ADR-0028).
  Future<AuditVerification> verifyAudit() async =>
      AuditVerification.fromJson(obj(await _send('GET', '/v1/admin/audit/verify'), 'verification'));

  /// The deployment health for the status page (super-admin only, issue #73).
  Future<AdminStatus> status() async => AdminStatus.fromJson(obj(await _send('GET', '/v1/admin/status'), 'status'));

  Future<List<AuditEntry>> listAudit(String tenant, {int limit = 500}) async => _list(
    await _send('GET', '/v1/admin/tenants/${_seg(tenant)}/audit', query: {'limit': '$limit'}),
    AuditEntry.fromJson,
  );

  /// The built-in SaaS catalog (ADR-0017).
  Future<List<SaasApp>> saasCatalog() async => _list(await _send('GET', '/v1/admin/saas/catalog'), SaasApp.fromJson);

  /// The web category list loaded by the Control Plane (ADR-0022).
  Future<CategoryCatalog> categories() async =>
      CategoryCatalog.fromJson(obj(await _send('GET', '/v1/admin/categories'), 'categories'));

  /// The built-in blocklists (issue #63).
  Future<List<BuiltinBlocklist>> blocklists() async =>
      _list(await _send('GET', '/v1/admin/blocklists'), BuiltinBlocklist.fromJson);

  // --- edges ---

  Future<List<AdminEdge>> listEdges() async => _list(await _send('GET', '/v1/admin/edges'), AdminEdge.fromJson);

  Future<void> createEdge(String id, {String tenantId = ''}) async => _send(
    'POST',
    '/v1/admin/edges',
    body: AdminEdge(id: id, tenantId: tenantId).toJson(),
  );

  Future<void> revokeEdge(String id) async => _send('POST', '/v1/admin/edges/${_seg(id)}/revoke');

  // --- Connectors ---

  Future<List<AdminConnector>> listConnectors(String tenant) async =>
      _list(await _send('GET', '/v1/admin/tenants/${_seg(tenant)}/connectors'), AdminConnector.fromJson);

  Future<AdminConnectorCreated> createConnector(String tenant, AdminConnectorRequest r) async =>
      AdminConnectorCreated.fromJson(
        obj(await _send('POST', '/v1/admin/tenants/${_seg(tenant)}/connectors', body: r.toJson()), 'connector'),
      );

  Future<void> revokeConnector(String tenant, String connector) async =>
      _send('POST', '/v1/admin/tenants/${_seg(tenant)}/connectors/${_seg(connector)}/revoke');

  // --- OIDC ---

  Future<TenantOidc?> getTenantOidc(String tenant) async {
    try {
      final v = await _send('GET', '/v1/admin/tenants/${_seg(tenant)}/oidc');
      if (v == null) return null;
      return TenantOidc.fromJson(obj(v, 'oidc'));
    } on ApiException catch (e) {
      if (e.status == 404) return null;
      rethrow;
    }
  }

  Future<TenantOidc> putTenantOidc(String tenant, TenantOidc oidc, {String? clientSecret}) async {
    final v = await _send(
      'PUT',
      '/v1/admin/tenants/${_seg(tenant)}/oidc',
      body: oidc.toJson(clientSecret: clientSecret),
    );
    return TenantOidc.fromJson(obj(v, 'oidc'));
  }

  Future<void> deleteTenantOidc(String tenant) async => _send('DELETE', '/v1/admin/tenants/${_seg(tenant)}/oidc');
}
