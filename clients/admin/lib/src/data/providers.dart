import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../api/admin_models.dart';
import 'session.dart';

const _controlUrlKey = 'opensase.admin.controlUrl';
const _tenantKey = 'opensase.admin.tenant';

/// Admin settings: the control URL put into enrollment QR codes. Non-secret, so it is kept in
/// localStorage. Defaults to the portal's own origin (the pin still has to be appended).
class ControlUrlNotifier extends Notifier<String> {
  @override
  String build() => ref.read(persistentStorageProvider).read(_controlUrlKey) ?? '';

  void set(String url) {
    url = url.trim();
    ref.read(persistentStorageProvider).write(_controlUrlKey, url.isEmpty ? null : url);
    state = url;
  }
}

final controlUrlProvider = NotifierProvider<ControlUrlNotifier, String>(ControlUrlNotifier.new);

/// The tenant the per-tenant screens show.
class SelectedTenantNotifier extends Notifier<String?> {
  @override
  String? build() => ref.read(persistentStorageProvider).read(_tenantKey);

  void select(String? id) {
    ref.read(persistentStorageProvider).write(_tenantKey, id);
    state = id;
  }
}

final selectedTenantProvider = NotifierProvider<SelectedTenantNotifier, String?>(SelectedTenantNotifier.new);

final tenantsProvider = FutureProvider<List<AdminTenant>>((ref) => ref.watch(apiProvider).listTenants());

/// The selected tenant if it still exists, else the first one.
final currentTenantProvider = Provider<String?>((ref) {
  final tenants = ref.watch(tenantsProvider).value;
  final sel = ref.watch(selectedTenantProvider);
  if (tenants == null) return sel;
  if (tenants.any((t) => t.id == sel)) return sel;
  return tenants.isEmpty ? null : tenants.first.id;
});

final usersProvider = FutureProvider.family<List<AdminUser>, String>((ref, t) => ref.watch(apiProvider).listUsers(t));

final devicesProvider = FutureProvider.family<List<AdminDevice>, String>(
  (ref, t) => ref.watch(apiProvider).listDevices(t),
);

final connectorsProvider = FutureProvider.family<List<AdminConnector>, String>(
  (ref, t) => ref.watch(apiProvider).listConnectors(t),
);

/// Who is signed in: the super-admin or a tenant admin (ST-03).
final identityProvider = FutureProvider<AdminIdentity>((ref) => ref.watch(apiProvider).whoami());

/// True once the Control Plane confirmed the super-admin. False while loading, so
/// super-admin-only UI (tenant creation, Edges) never flashes for a tenant admin.
final isSuperProvider = Provider<bool>((ref) => ref.watch(identityProvider).value?.isSuper ?? false);

final edgesProvider = FutureProvider<List<AdminEdge>>((ref) => ref.watch(apiProvider).listEdges());

final auditProvider = FutureProvider.family<List<AuditEntry>, String>((ref, t) => ref.watch(apiProvider).listAudit(t));

final adminTokensProvider = FutureProvider.family<List<AdminToken>, String>(
  (ref, t) => ref.watch(apiProvider).listAdminTokens(t),
);

/// Number of flow records the Activity and Overview screens fetch.
const flowLimit = 500;

final flowsProvider = FutureProvider.family<List<FlowRecord>, String>(
  (ref, t) async => (await ref.watch(apiProvider).listFlows(t, limit: flowLimit)).records,
);

/// Current time; overridable in tests.
final clockProvider = Provider<DateTime Function()>((ref) => DateTime.now);
