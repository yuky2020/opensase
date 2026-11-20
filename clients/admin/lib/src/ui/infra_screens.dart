import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_models.dart';
import '../data/parsers.dart';
import '../data/providers.dart';
import '../data/session.dart';
import 'common.dart';
import 'fields_dialog.dart';
import 'theme.dart';

/// Connectors of the tenant (ADR-0013).
class ConnectorsScreen extends ConsumerWidget {
  const ConnectorsScreen({super.key});

  Future<void> _create(BuildContext context, WidgetRef ref, String tenant) async {
    final l = context.l10n;
    final v = await showFieldsDialog(
      context,
      title: l.connectorsCreate,
      fields: [
        FieldSpec('name', l.fieldName, validator: (s) => s.isEmpty ? l.fieldRequired : null),
        FieldSpec('group', l.fieldGroup, initial: 'default', hint: l.connectorsGroupHint),
      ],
    );
    if (v == null || !context.mounted) return;
    final created = await runAction(
      context,
      ref,
      () => ref.read(apiProvider).createConnector(tenant, AdminConnectorRequest(name: v['name']!, group: v['group']!)),
    );
    if (created == null || !context.mounted) return;
    ref.invalidate(connectorsProvider(tenant));
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        title: Text(l.connectorsCreated(created.connector.name)),
        content: SizedBox(
          width: 440,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(l.provShownOnce, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
              const SizedBox(height: 12),
              OneTimeSecret(secret: created.provisioningKey),
              const SizedBox(height: 8),
              Text(l.connectorsKeyHelp),
            ],
          ),
        ),
        actions: [FilledButton(onPressed: () => Navigator.pop(ctx), child: Text(l.actionClose))],
      ),
    );
  }

  Future<void> _revoke(BuildContext context, WidgetRef ref, String tenant, AdminConnector c) async {
    final l = context.l10n;
    if (!await confirmRevoke(context, name: c.name.isEmpty ? c.id : c.name, body: l.revokeConfirmConnector)) return;
    if (!context.mounted) return;
    await runAction(context, ref, () => ref.read(apiProvider).revokeConnector(tenant, c.id));
    ref.invalidate(connectorsProvider(tenant));
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    final now = ref.watch(clockProvider)();
    return TenantScoped(
      builder: (tenant) => PageFrame(
        title: l.navConnectors,
        actions: [
          IconButton(
            tooltip: l.actionRefresh,
            onPressed: () => ref.invalidate(connectorsProvider(tenant)),
            icon: const Icon(Icons.refresh),
          ),
          FilledButton.icon(
            key: const Key('connector_create'),
            onPressed: () => _create(context, ref, tenant),
            icon: const Icon(Icons.add),
            label: Text(l.connectorsCreate),
          ),
        ],
        child: AsyncBody(
          value: ref.watch(connectorsProvider(tenant)),
          onRetry: () => ref.invalidate(connectorsProvider(tenant)),
          builder: (list) => list.isEmpty
              ? EmptyState(text: l.emptyNothingHere, icon: Icons.hub_outlined)
              : ScrollTable(
                  columns: [
                    DataColumn(label: Text(l.fieldName)),
                    DataColumn(label: Text(l.fieldGroup)),
                    DataColumn(label: Text(l.fieldLastSeen)),
                    DataColumn(label: Text(l.fieldStatus)),
                    DataColumn(label: Text(l.fieldId)),
                    const DataColumn(label: SizedBox.shrink()),
                  ],
                  rows: [
                    for (final c in list)
                      DataRow(
                        cells: [
                          DataCell(Text(c.name)),
                          DataCell(Text(c.group)),
                          DataCell(Text(formatTime(context, c.lastSeen))),
                          DataCell(
                            c.revoked
                                ? StatusChip(label: l.statusRevoked, color: context.verdicts.block)
                                : c.isOnline(now)
                                ? StatusChip(label: l.statusOnline, color: context.verdicts.allow)
                                : StatusChip(label: l.statusOffline, color: Theme.of(context).colorScheme.outline),
                          ),
                          DataCell(SelectableText(c.id)),
                          DataCell(
                            c.revoked
                                ? const SizedBox.shrink()
                                : TextButton(
                                    key: Key('revoke_${c.id}'),
                                    onPressed: () => _revoke(context, ref, tenant, c),
                                    child: Text(l.actionRevoke),
                                  ),
                          ),
                        ],
                      ),
                  ],
                ),
        ),
      ),
    );
  }
}

/// Enrolled devices (Clients) of the tenant.
class DevicesScreen extends ConsumerWidget {
  const DevicesScreen({super.key});

  Future<void> _revoke(BuildContext context, WidgetRef ref, String tenant, AdminDevice d) async {
    final l = context.l10n;
    if (!await confirmRevoke(context, name: d.name.isEmpty ? d.id : d.name, body: l.revokeConfirmDevice)) return;
    if (!context.mounted) return;
    await runAction(context, ref, () => ref.read(apiProvider).revokeDevice(tenant, d.id));
    ref.invalidate(devicesProvider(tenant));
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    return TenantScoped(
      builder: (tenant) => PageFrame(
        title: l.navDevices,
        actions: [
          IconButton(
            tooltip: l.actionRefresh,
            onPressed: () => ref.invalidate(devicesProvider(tenant)),
            icon: const Icon(Icons.refresh),
          ),
        ],
        child: AsyncBody(
          value: ref.watch(devicesProvider(tenant)),
          onRetry: () => ref.invalidate(devicesProvider(tenant)),
          builder: (list) => list.isEmpty
              ? EmptyState(text: l.emptyNothingHere, icon: Icons.phone_android)
              : ScrollTable(
                  columns: [
                    DataColumn(label: Text(l.fieldName)),
                    DataColumn(label: Text(l.fieldUser)),
                    DataColumn(label: Text(l.fieldPlatform)),
                    DataColumn(label: Text(l.fieldCreated)),
                    DataColumn(label: Text(l.fieldStatus)),
                    DataColumn(label: Text(l.fieldId)),
                    const DataColumn(label: SizedBox.shrink()),
                  ],
                  rows: [
                    for (final d in list)
                      DataRow(
                        cells: [
                          DataCell(Text(d.name)),
                          DataCell(Text(d.userId)),
                          DataCell(Text(d.platform)),
                          DataCell(Text(formatTime(context, d.createdAt))),
                          DataCell(revokedChip(context, d.revoked)),
                          DataCell(SelectableText(d.id)),
                          DataCell(
                            d.revoked
                                ? const SizedBox.shrink()
                                : TextButton(
                                    onPressed: () => _revoke(context, ref, tenant, d),
                                    child: Text(l.actionRevoke),
                                  ),
                          ),
                        ],
                      ),
                  ],
                ),
        ),
      ),
    );
  }
}

/// Edges registered with the Control Plane (global, not per tenant).
class EdgesScreen extends ConsumerWidget {
  const EdgesScreen({super.key});

  Future<void> _create(BuildContext context, WidgetRef ref) async {
    final l = context.l10n;
    final v = await showFieldsDialog(
      context,
      title: l.edgesCreate,
      description: l.edgesCreateHelp,
      fields: [
        FieldSpec('id', l.fieldId, hint: 'edge-eu-south-1', validator: (s) => validId(s) ? null : l.fieldInvalidId),
      ],
    );
    if (v == null || !context.mounted) return;
    await runAction(context, ref, () => ref.read(apiProvider).createEdge(v['id']!));
    ref.invalidate(edgesProvider);
  }

  Future<void> _revoke(BuildContext context, WidgetRef ref, AdminEdge e) async {
    if (!await confirmRevoke(context, name: e.id, body: context.l10n.revokeConfirmEdge)) return;
    if (!context.mounted) return;
    await runAction(context, ref, () => ref.read(apiProvider).revokeEdge(e.id));
    ref.invalidate(edgesProvider);
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    return PageFrame(
      title: l.navEdges,
      actions: [
        IconButton(
          tooltip: l.actionRefresh,
          onPressed: () => ref.invalidate(edgesProvider),
          icon: const Icon(Icons.refresh),
        ),
        FilledButton.icon(
          onPressed: () => _create(context, ref),
          icon: const Icon(Icons.add),
          label: Text(l.edgesCreate),
        ),
      ],
      child: AsyncBody(
        value: ref.watch(edgesProvider),
        onRetry: () => ref.invalidate(edgesProvider),
        builder: (list) => list.isEmpty
            ? EmptyState(text: l.emptyNothingHere, icon: Icons.cell_tower)
            : ScrollTable(
                columns: [
                  DataColumn(label: Text(l.fieldId)),
                  DataColumn(label: Text(l.fieldCreated)),
                  DataColumn(label: Text(l.fieldStatus)),
                  const DataColumn(label: SizedBox.shrink()),
                ],
                rows: [
                  for (final e in list)
                    DataRow(
                      cells: [
                        DataCell(SelectableText(e.id)),
                        DataCell(Text(formatTime(context, e.createdAt))),
                        DataCell(revokedChip(context, e.revoked)),
                        DataCell(
                          e.revoked
                              ? const SizedBox.shrink()
                              : TextButton(onPressed: () => _revoke(context, ref, e), child: Text(l.actionRevoke)),
                        ),
                      ],
                    ),
                ],
              ),
      ),
    );
  }
}
