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
              onPressed: () => ref.invalidate(auditProvider(tenant)),
              icon: const Icon(Icons.refresh),
            ),
          ],
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
        );
      },
    );
  }
}
