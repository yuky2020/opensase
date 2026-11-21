import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_api.dart';
import '../api/admin_models.dart';
import '../data/providers.dart';
import '../data/session.dart';
import '../l10n/app_localizations.dart';
import 'common.dart';
import 'policy_screen.dart';
import 'theme.dart';

/// SaaS app control and discovery (ADR-0017): block catalog apps or whole categories, and see
/// which apps the tenant's recent flows used. Saves TenantPolicy.saas with the policy PUT.
class SaasScreen extends ConsumerWidget {
  const SaasScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) => TenantScoped(
    builder: (tenant) => AsyncBody(
      value: ref.watch(policyProvider(tenant)),
      onRetry: () => ref.invalidate(policyProvider(tenant)),
      builder: (p) => AsyncBody(
        value: ref.watch(saasCatalogProvider),
        onRetry: () => ref.invalidate(saasCatalogProvider),
        builder: (catalog) =>
            _SaasEditor(key: ValueKey('saas-$tenant'), tenant: tenant, initial: p.saas, catalog: catalog),
      ),
    ),
  );
}

String saasCategoryLabel(AppLocalizations l, String c) => switch (c) {
  'file-sharing' => l.saasCatFileSharing,
  'webmail' => l.saasCatWebmail,
  'ai-assistant' => l.saasCatAiAssistant,
  'social-media' => l.saasCatSocialMedia,
  'messaging' => l.saasCatMessaging,
  'collaboration' => l.saasCatCollaboration,
  'streaming' => l.saasCatStreaming,
  'code-hosting' => l.saasCatCodeHosting,
  _ => c,
};

class _SaasEditor extends ConsumerStatefulWidget {
  const _SaasEditor({super.key, required this.tenant, required this.initial, required this.catalog});

  final String tenant;
  final SaasPolicy initial;
  final List<SaasApp> catalog;

  @override
  ConsumerState<_SaasEditor> createState() => _SaasEditorState();
}

class _SaasEditorState extends ConsumerState<_SaasEditor> {
  late SaasPolicy _p = _copy(widget.initial);
  bool _dirty = false;
  bool _saving = false;
  String? _error;

  static SaasPolicy _copy(SaasPolicy p) => SaasPolicy.fromJson(p.toJson());

  @override
  void didUpdateWidget(_SaasEditor old) {
    super.didUpdateWidget(old);
    if (!_dirty && !identical(old.initial, widget.initial)) _p = _copy(widget.initial);
  }

  void _setCategory(String cat, bool block) => setState(() {
    _p.blockCategories.remove(cat);
    if (block) _p.blockCategories.add(cat);
    // Exemptions only mean something inside a blocked category.
    if (!block) _p.allowApps.removeWhere((id) => widget.catalog.any((a) => a.id == id && a.category == cat));
    _dirty = true;
  });

  void _setApp(SaasApp a, bool block) => setState(() {
    final catBlocked = _p.blockCategories.contains(a.category);
    _p.blockApps.remove(a.id);
    _p.allowApps.remove(a.id);
    if (block && !catBlocked) _p.blockApps.add(a.id);
    if (!block && catBlocked) _p.allowApps.add(a.id);
    _dirty = true;
  });

  Future<void> _save() async {
    setState(() {
      _saving = true;
      _error = null;
    });
    final api = ref.read(apiProvider);
    try {
      // Re-read the policy so that only the SaaS section changes.
      final p = await api.getPolicy(widget.tenant);
      p.saas = _p;
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
    // Discovery: flows per app in the recent flow records.
    final seen = <String, int>{};
    for (final r in ref.watch(flowsProvider(widget.tenant)).value ?? const <FlowRecord>[]) {
      if (r.saasApp.isNotEmpty) seen[r.saasApp] = (seen[r.saasApp] ?? 0) + 1;
    }
    final cats = <String, List<SaasApp>>{};
    for (final a in widget.catalog) {
      (cats[a.category] ??= []).add(a);
    }
    return PageFrame(
      title: l.navSaas,
      subtitle: l.saasHelp,
      actions: [
        if (_dirty) Chip(label: Text(l.policyUnsaved), avatar: const Icon(Icons.edit_note, size: 18)),
        OutlinedButton.icon(
          onPressed: () => setState(() {
            _p = _copy(widget.initial);
            _dirty = false;
            _error = null;
            ref.invalidate(policyProvider(widget.tenant));
            ref.invalidate(flowsProvider(widget.tenant));
          }),
          icon: const Icon(Icons.restore),
          label: Text(l.actionReload),
        ),
        FilledButton.icon(
          key: const Key('saas_save'),
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
          if (seen.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Wrap(
                spacing: 8,
                runSpacing: 8,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  Text(l.saasDiscovered, style: Theme.of(context).textTheme.titleSmall),
                  for (final e in (seen.entries.toList()..sort((a, b) => b.value.compareTo(a.value))))
                    Chip(
                      key: Key('seen_${e.key}'),
                      label: Text(
                        '${widget.catalog.where((a) => a.id == e.key).firstOrNull?.name ?? e.key} · ${e.value}',
                      ),
                    ),
                ],
              ),
            ),
          for (final cat in cats.keys)
            Card(
              margin: const EdgeInsets.only(bottom: 12),
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    SwitchListTile(
                      key: Key('saas_cat_$cat'),
                      contentPadding: EdgeInsets.zero,
                      title: Text(saasCategoryLabel(l, cat), style: Theme.of(context).textTheme.titleMedium),
                      subtitle: Text(l.saasBlockCategory),
                      value: _p.blockCategories.contains(cat),
                      onChanged: (v) => _setCategory(cat, v),
                    ),
                    for (final a in cats[cat]!)
                      ListTile(
                        dense: true,
                        contentPadding: EdgeInsets.zero,
                        title: Text(a.name),
                        subtitle: Text(a.domains.join(', '), maxLines: 1, overflow: TextOverflow.ellipsis),
                        leading: _p.blocks(a.id, a.category)
                            ? StatusChip(label: l.statusBlocked, color: context.verdicts.block)
                            : StatusChip(label: l.statusAllowed, color: context.verdicts.allow),
                        trailing: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            if (seen[a.id] != null) Text(l.saasSeen(seen[a.id]!)),
                            const SizedBox(width: 8),
                            Switch(
                              key: Key('saas_app_${a.id}'),
                              value: _p.blocks(a.id, a.category),
                              onChanged: (v) => _setApp(a, v),
                            ),
                          ],
                        ),
                      ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}
