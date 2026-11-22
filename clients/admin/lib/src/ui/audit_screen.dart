import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_models.dart';
import '../data/providers.dart';
import 'common.dart';
import 'theme.dart';

/// Admin audit log of the tenant (ADR-0016): every admin write, its actor and result.
class AuditScreen extends ConsumerWidget {
  const AuditScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    return TenantScoped(
      builder: (tenant) {
        // Token IDs are shown with their names when the token list is available.
        final names = {
          for (final t in ref.watch(adminTokensProvider(tenant)).value ?? const <AdminToken>[]) t.id: t.name,
        };
        String actor(String a) {
          if (a == 'super') return l.auditActorSuper;
          final id = a.startsWith('token:') ? a.substring(6) : a;
          return names[id] ?? a;
        }

        return PageFrame(
          title: l.navAudit,
          subtitle: l.auditHelp,
          actions: [
            IconButton(
              tooltip: l.actionRefresh,
              onPressed: () {
                ref.invalidate(auditProvider(tenant));
                ref.invalidate(auditVerifyProvider);
              },
              icon: const Icon(Icons.refresh),
            ),
          ],
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (ref.watch(isSuperProvider)) const _ChainStatus(),
              Expanded(
                child: AsyncBody(
                  value: ref.watch(auditProvider(tenant)),
                  onRetry: () => ref.invalidate(auditProvider(tenant)),
                  builder: (list) => list.isEmpty
                      ? EmptyState(text: l.auditEmpty, icon: Icons.history)
                      : ScrollTable(
                          columns: [
                            DataColumn(label: Text(l.fieldTime)),
                            DataColumn(label: Text(l.fieldActor)),
                            DataColumn(label: Text(l.fieldMethod)),
                            DataColumn(label: Text(l.fieldPath)),
                            DataColumn(label: Text(l.fieldResult)),
                          ],
                          rows: [
                            for (final e in list)
                              DataRow(
                                cells: [
                                  DataCell(Text(formatTime(context, e.at))),
                                  DataCell(Tooltip(message: e.actor, child: Text(actor(e.actor)))),
                                  DataCell(Text(e.method)),
                                  DataCell(SelectableText(e.path, style: const TextStyle(fontFamily: 'monospace'))),
                                  DataCell(
                                    StatusChip(
                                      label: '${e.status}',
                                      color: e.ok ? context.verdicts.allow : context.verdicts.block,
                                    ),
                                  ),
                                ],
                              ),
                          ],
                        ),
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

/// The result of the audit hash chain check, for the super-admin (ADR-0028).
class _ChainStatus extends ConsumerWidget {
  const _ChainStatus();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    final v = ref.watch(auditVerifyProvider).value;
    if (v == null) return const SizedBox.shrink();
    final scheme = Theme.of(context).colorScheme;
    return Card(
      key: const Key('audit_chain'),
      margin: const EdgeInsets.only(bottom: 12),
      color: v.ok ? null : scheme.errorContainer,
      child: ListTile(
        leading: Icon(
          v.ok ? Icons.verified_outlined : Icons.gpp_bad_outlined,
          color: v.ok ? context.verdicts.allow : scheme.error,
        ),
        title: Text(v.ok ? l.auditChainOk(v.entries) : l.auditChainBroken(v.badId, v.reason)),
        subtitle: v.ok
            ? SelectableText(l.auditChainHead(v.headId, v.head), style: const TextStyle(fontFamily: 'monospace'))
            : null,
      ),
    );
  }
}
