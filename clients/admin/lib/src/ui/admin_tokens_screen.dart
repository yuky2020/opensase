import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_models.dart';
import '../data/providers.dart';
import '../data/session.dart';
import 'common.dart';
import 'fields_dialog.dart';
import 'theme.dart';

/// Tenant admin tokens (ST-03): credentials that administer the selected tenant only.
class AdminTokensScreen extends ConsumerWidget {
  const AdminTokensScreen({super.key});

  Future<void> _create(BuildContext context, WidgetRef ref, String tenant) async {
    final l = context.l10n;
    final v = await showFieldsDialog(
      context,
      title: l.adminTokensCreate,
      description: l.adminTokensCreateHelp,
      fields: [
        FieldSpec(
          'name',
          l.fieldName,
          hint: l.adminTokensNameHint,
          validator: (s) => s.isEmpty ? l.fieldRequired : null,
        ),
        FieldSpec(
          'days',
          l.adminTokensFieldDays,
          initial: '90',
          helper: l.adminTokensFieldDaysHelp,
          validator: (s) {
            final n = int.tryParse(s);
            return n == null || n < 1 || n > 365 ? l.adminTokensFieldDaysHelp : null;
          },
        ),
      ],
    );
    if (v == null || !context.mounted) return;
    final created = await runAction(
      context,
      ref,
      () => ref.read(apiProvider).createAdminToken(tenant, v['name']!, validFor: Duration(days: int.parse(v['days']!))),
    );
    if (created == null || !context.mounted) return;
    ref.invalidate(adminTokensProvider(tenant));
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        title: Text(l.adminTokensCreated(created.adminToken.name)),
        content: SizedBox(
          width: 440,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(l.adminTokensShownOnce, style: TextStyle(color: Theme.of(ctx).colorScheme.error)),
              const SizedBox(height: 12),
              OneTimeSecret(secret: created.token),
              const SizedBox(height: 8),
              Text(l.adminTokensUseHelp),
            ],
          ),
        ),
        actions: [FilledButton(onPressed: () => Navigator.pop(ctx), child: Text(l.actionClose))],
      ),
    );
  }

  Future<void> _revoke(BuildContext context, WidgetRef ref, String tenant, AdminToken t, bool own) async {
    final l = context.l10n;
    final body = own ? '${l.revokeConfirmAdminToken} ${l.adminTokensRevokeOwn}' : l.revokeConfirmAdminToken;
    if (!await confirmRevoke(context, name: t.name, body: body)) return;
    if (!context.mounted) return;
    await runAction(context, ref, () => ref.read(apiProvider).revokeAdminToken(tenant, t.id));
    ref.invalidate(adminTokensProvider(tenant));
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    final now = ref.watch(clockProvider)();
    final ownId = ref.watch(identityProvider).value?.tokenId ?? '';
    return TenantScoped(
      builder: (tenant) => PageFrame(
        title: l.navAdminTokens,
        actions: [
          IconButton(
            tooltip: l.actionRefresh,
            onPressed: () => ref.invalidate(adminTokensProvider(tenant)),
            icon: const Icon(Icons.refresh),
          ),
          FilledButton.icon(
            key: const Key('admin_token_create'),
            onPressed: () => _create(context, ref, tenant),
            icon: const Icon(Icons.add),
            label: Text(l.adminTokensCreate),
          ),
        ],
        child: AsyncBody(
          value: ref.watch(adminTokensProvider(tenant)),
          onRetry: () => ref.invalidate(adminTokensProvider(tenant)),
          builder: (list) => list.isEmpty
              ? EmptyState(text: l.adminTokensEmpty, icon: Icons.key_outlined)
              : ScrollTable(
                  columns: [
                    DataColumn(label: Text(l.fieldName)),
                    DataColumn(label: Text(l.fieldCreated)),
                    DataColumn(label: Text(l.fieldExpires)),
                    DataColumn(label: Text(l.fieldLastUsed)),
                    DataColumn(label: Text(l.fieldStatus)),
                    const DataColumn(label: SizedBox.shrink()),
                  ],
                  rows: [
                    for (final t in list)
                      DataRow(
                        cells: [
                          DataCell(Text(t.id == ownId ? '${t.name} ${l.adminTokensThisSession}' : t.name)),
                          DataCell(Text(formatTime(context, t.createdAt))),
                          DataCell(Text(formatTime(context, t.expiresAt))),
                          DataCell(Text(formatTime(context, t.lastUsed))),
                          DataCell(
                            t.revoked
                                ? StatusChip(label: l.statusRevoked, color: context.verdicts.block)
                                : t.isExpired(now)
                                ? StatusChip(label: l.statusExpired, color: Theme.of(context).colorScheme.outline)
                                : StatusChip(label: l.statusActive, color: context.verdicts.allow),
                          ),
                          DataCell(
                            t.revoked
                                ? const SizedBox.shrink()
                                : TextButton(
                                    key: Key('revoke_${t.id}'),
                                    onPressed: () => _revoke(context, ref, tenant, t, t.id == ownId),
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
