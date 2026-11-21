import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_api.dart';
import '../api/admin_models.dart';
import '../data/providers.dart';
import '../data/session.dart';
import 'common.dart';
import 'policy_screen.dart';
import 'theme.dart';

/// Web categories (ADR-0022): block whole categories of the public category list (UT1) the
/// Control Plane loaded. Saves TenantPolicy.categories with the policy PUT.
class CategoriesScreen extends ConsumerWidget {
  const CategoriesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) => TenantScoped(
    builder: (tenant) => AsyncBody(
      value: ref.watch(policyProvider(tenant)),
      onRetry: () => ref.invalidate(policyProvider(tenant)),
      builder: (p) => AsyncBody(
        value: ref.watch(categoriesProvider),
        onRetry: () => ref.invalidate(categoriesProvider),
        builder: (cat) =>
            _CategoriesEditor(key: ValueKey('cat-$tenant'), tenant: tenant, initial: p.categories, catalog: cat),
      ),
    ),
  );
}

class _CategoriesEditor extends ConsumerStatefulWidget {
  const _CategoriesEditor({super.key, required this.tenant, required this.initial, required this.catalog});

  final String tenant;
  final List<String> initial;
  final CategoryCatalog catalog;

  @override
  ConsumerState<_CategoriesEditor> createState() => _CategoriesEditorState();
}

class _CategoriesEditorState extends ConsumerState<_CategoriesEditor> {
  late List<String> _blocked = [...widget.initial];
  bool _dirty = false;
  bool _saving = false;
  String? _error;
  String _filter = '';

  @override
  void didUpdateWidget(_CategoriesEditor old) {
    super.didUpdateWidget(old);
    if (!_dirty && !identical(old.initial, widget.initial)) _blocked = [...widget.initial];
  }

  Future<void> _save() async {
    setState(() {
      _saving = true;
      _error = null;
    });
    final api = ref.read(apiProvider);
    try {
      // Re-read the policy so that only the categories change.
      final p = await api.getPolicy(widget.tenant);
      p.categories = [..._blocked]..sort();
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
    final cat = widget.catalog;
    final num = NumberFormat.decimalPattern();
    final shown = [
      for (final c in cat.categories)
        if (c.type != 'white' &&
            (_filter.isEmpty ||
                c.name.contains(_filter) ||
                c.title.toLowerCase().contains(_filter) ||
                c.description.toLowerCase().contains(_filter)))
          c,
    ];
    return PageFrame(
      title: l.navCategories,
      subtitle: l.categoriesHelp,
      actions: [
        if (_dirty) Chip(label: Text(l.policyUnsaved), avatar: const Icon(Icons.edit_note, size: 18)),
        FilledButton.icon(
          key: const Key('cat_save'),
          onPressed: _saving || !_dirty ? null : _save,
          icon: const Icon(Icons.save),
          label: Text(l.actionSave),
        ),
      ],
      child: ListView(
        children: [
          if (_error != null)
            Container(
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(color: scheme.errorContainer, borderRadius: BorderRadius.circular(12)),
              child: SelectableText(_error!, style: TextStyle(color: scheme.onErrorContainer)),
            ),
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: Text(
              cat.version.isEmpty
                  ? l.categoriesNotLoaded
                  : l.categoriesSource(
                      cat.source,
                      cat.licence,
                      cat.loadedAt?.toLocal().toString().substring(0, 16) ?? '',
                    ),
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ),
          if (_blocked.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  for (final n in _blocked)
                    InputChip(
                      key: Key('cat_chip_$n'),
                      label: Text(n),
                      onDeleted: () => setState(() {
                        _blocked.remove(n);
                        _dirty = true;
                      }),
                    ),
                ],
              ),
            ),
          TextField(
            key: const Key('cat_filter'),
            decoration: InputDecoration(prefixIcon: const Icon(Icons.search), hintText: l.categoriesFilter),
            onChanged: (v) => setState(() => _filter = v.trim().toLowerCase()),
          ),
          const SizedBox(height: 8),
          Card(
            child: Column(
              children: [
                for (final c in shown)
                  SwitchListTile(
                    key: Key('cat_${c.name}'),
                    title: Text(c.title.isEmpty ? c.name : '${c.title} · ${c.name}'),
                    subtitle: Text(
                      [
                        if (c.description.isNotEmpty) c.description,
                        l.categoriesDomains(num.format(c.domains)),
                        if (c.urls > 0) l.categoriesUrls(num.format(c.urls)),
                      ].join(' — '),
                    ),
                    secondary: _blocked.contains(c.name)
                        ? StatusChip(label: l.statusBlocked, color: context.verdicts.block)
                        : StatusChip(label: l.statusAllowed, color: context.verdicts.allow),
                    value: _blocked.contains(c.name),
                    onChanged: (v) => setState(() {
                      _blocked.remove(c.name);
                      if (v) _blocked.add(c.name);
                      _dirty = true;
                    }),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
