import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_models.dart';
import '../data/parsers.dart';
import '../data/providers.dart';
import '../data/session.dart';
import 'common.dart';
import 'fields_dialog.dart';

class TenantsScreen extends ConsumerWidget {
  const TenantsScreen({super.key});

  Future<void> _create(BuildContext context, WidgetRef ref) async {
    final l = context.l10n;
    final v = await showFieldsDialog(
      context,
      title: l.tenantsCreate,
      fields: [
        FieldSpec('name', l.fieldName, validator: (s) => s.isEmpty ? l.fieldRequired : null),
        FieldSpec('id', l.fieldIdOptional, validator: (s) => s.isEmpty || validId(s) ? null : l.fieldInvalidId),
      ],
    );
    if (v == null || !context.mounted) return;
    final t = await runAction(
      context,
      ref,
      () => ref.read(apiProvider).createTenant(AdminTenant(id: v['id']!, name: v['name']!)),
    );
    if (t == null) return;
    ref.invalidate(tenantsProvider);
    ref.read(selectedTenantProvider.notifier).select(t.id);
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    final tenants = ref.watch(tenantsProvider);
    final current = ref.watch(currentTenantProvider);
    return PageFrame(
      title: l.navTenants,
      actions: [
        IconButton(
          tooltip: l.actionRefresh,
          onPressed: () => ref.invalidate(tenantsProvider),
          icon: const Icon(Icons.refresh),
        ),
        FilledButton.icon(
          key: const Key('tenant_create'),
          onPressed: () => _create(context, ref),
          icon: const Icon(Icons.add),
          label: Text(l.tenantsCreate),
        ),
      ],
      child: AsyncBody(
        value: tenants,
        onRetry: () => ref.invalidate(tenantsProvider),
        builder: (list) => list.isEmpty
            ? EmptyState(text: l.emptyNothingHere)
            : ScrollTable(
                columns: [
                  DataColumn(label: Text(l.fieldId)),
                  DataColumn(label: Text(l.fieldName)),
                ],
                rows: [
                  for (final t in list)
                    DataRow(
                      selected: t.id == current,
                      onSelectChanged: (_) => ref.read(selectedTenantProvider.notifier).select(t.id),
                      cells: [DataCell(SelectableText(t.id)), DataCell(Text(t.name))],
                    ),
                ],
              ),
      ),
    );
  }
}
