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
    final req = http.Request(method, _uri(path, query))..headers.addAll(_headers);
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
    if (text.trim().isEmpty) return null;
    return jsonDecode(text);
  }

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

  Future<TenantPolicy> getPolicy(String tenant) async =>
      TenantPolicy.fromJson(obj(await _send('GET', '/v1/admin/tenants/${_seg(tenant)}/policy'), 'policy'));

  Future<void> putPolicy(String tenant, TenantPolicy p) async =>
      _send('PUT', '/v1/admin/tenants/${_seg(tenant)}/policy', body: p.toJson());

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

  // --- edges ---

  Future<List<AdminEdge>> listEdges() async => _list(await _send('GET', '/v1/admin/edges'), AdminEdge.fromJson);

  Future<void> createEdge(String id) async => _send('POST', '/v1/admin/edges', body: AdminEdge(id: id).toJson());

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
}
