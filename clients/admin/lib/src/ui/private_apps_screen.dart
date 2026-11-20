import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_api.dart';
import '../api/admin_models.dart';
import '../data/session.dart';
import '../data/validation.dart';
import 'common.dart';
import 'policy_dialogs.dart';
import 'policy_screen.dart';

/// ZTNA private apps (ADR-0013): edits TenantPolicy.privateApps and saves with the policy PUT.
class PrivateAppsScreen extends ConsumerWidget {
  const PrivateAppsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) => TenantScoped(
    builder: (tenant) => AsyncBody(
      value: ref.watch(policyProvider(tenant)),
      onRetry: () => ref.invalidate(policyProvider(tenant)),
      builder: (p) => _PrivateAppsEditor(key: ValueKey('papps-$tenant'), tenant: tenant, initial: p.privateApps),
    ),
  );
}

class _PrivateAppsEditor extends ConsumerStatefulWidget {
  const _PrivateAppsEditor({super.key, required this.tenant, required this.initial});

  final String tenant;
  final List<TenantPrivateApp> initial;

  @override
  ConsumerState<_PrivateAppsEditor> createState() => _PrivateAppsEditorState();
}

class _PrivateAppsEditorState extends ConsumerState<_PrivateAppsEditor> {
  late List<TenantPrivateApp> _apps = [for (final a in widget.initial) a.copy()];
  bool _dirty = false;
  bool _saving = false;
  String? _error;

  @override
  void didUpdateWidget(_PrivateAppsEditor old) {
    super.didUpdateWidget(old);
    if (!_dirty && !identical(old.initial, widget.initial)) _apps = [for (final a in widget.initial) a.copy()];
  }

  Future<void> _edit(int? index) async {
    final out = await showDialog<TenantPrivateApp>(
      context: context,
      builder: (_) => PrivateAppDialog(
        app: index == null ? TenantPrivateApp() : _apps[index],
        isNew: index == null,
        existingIds: {for (final a in _apps) a.id},
      ),
    );
    if (out == null) return;
    setState(() {
      index == null ? _apps.add(out) : _apps[index] = out;
      _dirty = true;
    });
  }

  Future<void> _save() async {
    final issues = validatePrivateApps(_apps);
    if (issues.isNotEmpty) {
      setState(() => _error = '${context.l10n.policyIssues}\n${issues.map((i) => '• $i').join('\n')}');
      return;
    }
    setState(() {
      _saving = true;
      _error = null;
    });
    final api = ref.read(apiProvider);
    try {
      // Re-read the policy so that only privateApps changes, even if it was edited elsewhere.
      final p = await api.getPolicy(widget.tenant);
      p.privateApps = _apps;
      await api.putPolicy(widget.tenant, p);
      if (!mounted) return;
      setState(() => _dirty = false);
      showSnack(context, context.l10n.msgSaved);
      ref.invalidate(policyProvider(widget.tenant));
    } on ApiException catch (e) {
      if (e.status == 401) {
        ref.read(sessionProvider.notifier).logout();
      } else if (mounted) {
        setState(
          () => _error = context.l10n.policyServerError(e.field.isEmpty ? e.message : '${e.field}: ${e.message}'),
        );
      }
    } on Object catch (e) {
      if (mounted) setState(() => _error = context.l10n.policyServerError('$e'));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final scheme = Theme.of(context).colorScheme;
    return PageFrame(
      title: l.navPrivateApps,
      subtitle: l.privateAppsHelp,
      actions: [
        if (_dirty) Chip(label: Text(l.policyUnsaved), avatar: const Icon(Icons.edit_note, size: 18)),
        OutlinedButton.icon(
          onPressed: () => setState(() {
            _apps = [for (final a in widget.initial) a.copy()];
            _dirty = false;
            _error = null;
            ref.invalidate(policyProvider(widget.tenant));
          }),
          icon: const Icon(Icons.restore),
          label: Text(l.actionReload),
        ),
        FilledButton.tonalIcon(
          key: const Key('papp_add'),
          onPressed: () => _edit(null),
          icon: const Icon(Icons.add),
          label: Text(l.privateAppNew),
        ),
        FilledButton.icon(
          key: const Key('papp_save'),
          onPressed: _saving || !_dirty ? null : _save,
          icon: const Icon(Icons.save),
          label: Text(l.actionSave),
        ),
      ],
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (_error != null)
            Container(
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(color: scheme.errorContainer, borderRadius: BorderRadius.circular(12)),
              child: SelectableText(_error!, style: TextStyle(color: scheme.onErrorContainer)),
            ),
          Expanded(
            child: _apps.isEmpty
                ? EmptyState(text: l.emptyNothingHere, icon: Icons.lock_outline)
                : ScrollTable(
                    columns: [
                      DataColumn(label: Text(l.fieldId)),
                      DataColumn(label: Text(l.fieldName)),
                      DataColumn(label: Text(l.matchDomains)),
                      DataColumn(label: Text(l.privateAppPorts)),
                      DataColumn(label: Text(l.privateAppConnectorGroup)),
                      DataColumn(label: Text(l.navUsers)),
                      const DataColumn(label: SizedBox.shrink()),
                    ],
                    rows: [
                      for (final (i, a) in _apps.indexed)
                        DataRow(
                          cells: [
                            DataCell(Text(a.id)),
                            DataCell(Text(a.name)),
                            DataCell(Text(a.domains.join('\n'))),
                            DataCell(Text(a.ports.join(', '))),
                            DataCell(Text(a.connectorGroup)),
                            DataCell(Text(a.users.isEmpty ? l.privateAppEveryone : a.users.join(', '))),
                            DataCell(
                              Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  IconButton(
                                    tooltip: l.actionEdit,
                                    icon: const Icon(Icons.edit),
                                    onPressed: () => _edit(i),
                                  ),
                                  IconButton(
                                    tooltip: l.actionDelete,
                                    icon: const Icon(Icons.delete_outline),
                                    onPressed: () => setState(() {
                                      _apps.removeAt(i);
                                      _dirty = true;
                                    }),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                    ],
                  ),
          ),
        ],
      ),
    );
  }
}
