import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../contracts/policy.dart';
import '../data/core_state.dart';
import '../data/policy_logic.dart';
import '../data/rule_draft.dart';
import '../platform_info.dart';
import 'common.dart';

class RulesScreen extends ConsumerWidget {
  const RulesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    final policy = ref.watch(coreProvider.select((s) => s.policy));
    final tenant = PolicyLogic.tenantRules(policy.snapshot);
    final user = PolicyLogic.sorted(policy.user.rules);
    final editable = policy.userLayerEditable;
    final notifier = ref.read(coreProvider.notifier);

    Future<void> openEditor([Rule? rule]) async {
      if (!editable) {
        showSaveResult(context, const SaveForbidden());
        return;
      }
      await showModalBottomSheet<void>(
        context: context,
        isScrollControlled: true,
        // Above the shell's bottom navigation bar.
        useRootNavigator: true,
        useSafeArea: true,
        showDragHandle: true,
        builder: (_) => RuleEditor(initial: rule == null ? const RuleDraft() : RuleDraft.from(rule)),
      );
    }

    return Scaffold(
      floatingActionButton: editable
          ? FloatingActionButton.extended(
              key: const Key('rules_add'),
              onPressed: openEditor,
              icon: const Icon(Icons.add),
              label: Text(l.rulesAdd),
            )
          : null,
      body: CustomScrollView(
        slivers: [
          SliverToBoxAdapter(child: SectionHeader(l.rulesTenant, subtitle: l.rulesTenantHint)),
          if (tenant.isEmpty) SliverToBoxAdapter(child: EmptyState(l.emptyNothingHere)),
          SliverList.builder(
            itemCount: tenant.length,
            itemBuilder: (context, i) => Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
              child: Card(
                color: Theme.of(context).colorScheme.surfaceContainerHighest,
                child: ListTile(
                  leading: const Icon(Icons.business),
                  title: _RuleTitle(tenant[i]),
                  subtitle: Text(ruleSummary(context, ref, tenant[i]), maxLines: 2, overflow: TextOverflow.ellipsis),
                  trailing: Tooltip(message: l.companyPolicyLocked, child: const Icon(Icons.lock, size: 18)),
                ),
              ),
            ),
          ),
          SliverToBoxAdapter(child: SectionHeader(l.rulesUser, subtitle: l.rulesUserHint)),
          if (!editable)
            SliverToBoxAdapter(
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: InfoBanner(l.rulesUserDisabled, warning: true),
              ),
            ),
          if (user.isEmpty) SliverToBoxAdapter(child: EmptyState(l.rulesEmptyUser)),
          SliverReorderableList(
            itemCount: user.length,
            onReorderItem: (from, target) async {
              if (target == from) return;
              final r = await notifier.updateUserLayer((u) => PolicyLogic.moveRule(u, from, target));
              if (context.mounted) showSaveResult(context, r, quietOk: true);
            },
            itemBuilder: (context, i) {
              final rule = user[i];
              return Padding(
                key: ValueKey(rule.id),
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                child: Card(
                  child: ListTile(
                    key: Key('user_rule_${rule.id}'),
                    contentPadding: const EdgeInsets.only(left: 4, right: 4),
                    leading: editable
                        ? ReorderableDragStartListener(
                            index: i,
                            child: const Padding(padding: EdgeInsets.all(12), child: Icon(Icons.drag_handle)),
                          )
                        : const Padding(padding: EdgeInsets.all(12), child: Icon(Icons.person_outline)),
                    title: _RuleTitle(rule),
                    subtitle: Text(ruleSummary(context, ref, rule), maxLines: 2, overflow: TextOverflow.ellipsis),
                    onTap: editable ? () => openEditor(rule) : null,
                    trailing: IconButton(
                      icon: const Icon(Icons.delete_outline),
                      tooltip: l.actionDelete,
                      onPressed: !editable
                          ? null
                          : () async {
                              final ok = await showDialog<bool>(
                                context: context,
                                builder: (c) => AlertDialog(
                                  title: Text(l.rulesDeleteConfirm),
                                  content: Text(rule.description ?? rule.id),
                                  actions: [
                                    TextButton(onPressed: () => Navigator.pop(c, false), child: Text(l.actionCancel)),
                                    TextButton(onPressed: () => Navigator.pop(c, true), child: Text(l.actionDelete)),
                                  ],
                                ),
                              );
                              if (ok != true) return;
                              final r = await notifier.updateUserLayer((u) => PolicyLogic.deleteRule(u, rule.id));
                              if (context.mounted) showSaveResult(context, r);
                            },
                    ),
                  ),
                ),
              );
            },
          ),
          const SliverToBoxAdapter(child: SizedBox(height: 96)),
        ],
      ),
    );
  }
}

class _RuleTitle extends StatelessWidget {
  const _RuleTitle(this.rule);
  final Rule rule;

  @override
  Widget build(BuildContext context) => Row(
    children: [
      VerdictChip(rule.action),
      const SizedBox(width: 8),
      Expanded(child: Text(rule.description ?? rule.id, maxLines: 1, overflow: TextOverflow.ellipsis)),
    ],
  );
}

String ruleSummary(BuildContext context, WidgetRef ref, Rule rule) {
  final l = context.l10n;
  final m = rule.match;
  final parts = <String>[
    if (m.protocols.isNotEmpty) m.protocols.map((p) => p.toUpperCase()).join('/'),
    if (m.ports.isNotEmpty) ':${m.ports.join(',')}',
    if (m.cidrs.isNotEmpty) m.cidrs.join(', '),
    if (m.domains.isNotEmpty) m.domains.join(', '),
    if (m.networks.isNotEmpty) m.networks.map((n) => networkLabel(context, n)).join('/'),
    if (m.apps.isNotEmpty) m.apps.map((a) => appLabel(ref, context, a)).join(', '),
  ];
  return [
    l.rulesPriorityShort(rule.priority),
    rule.id,
    parts.isEmpty ? l.rulesAny : parts.join(' · '),
    if (rule.log) l.rulesLogged,
  ].join(' · ');
}

/// Bottom sheet that edits one user rule and saves the whole user layer.
class RuleEditor extends ConsumerStatefulWidget {
  const RuleEditor({super.key, required this.initial});
  final RuleDraft initial;

  @override
  ConsumerState<RuleEditor> createState() => _RuleEditorState();
}

class _RuleEditorState extends ConsumerState<RuleEditor> {
  late RuleDraft _d = widget.initial;
  late final _desc = TextEditingController(text: _d.description);
  late final _cidrs = TextEditingController(text: _d.cidrs);
  late final _ports = TextEditingController(text: _d.ports);
  late final _domains = TextEditingController(text: _d.domains);
  late final _priority = TextEditingController(text: _d.priority);
  Set<DraftField> _errors = {};
  bool _saving = false;

  @override
  void dispose() {
    for (final c in [_desc, _cidrs, _ports, _domains, _priority]) {
      c.dispose();
    }
    super.dispose();
  }

  RuleDraft _current() => RuleDraft(
    id: _d.id,
    action: _d.action,
    description: _desc.text,
    protocols: _d.protocols,
    cidrs: _cidrs.text,
    ports: _ports.text,
    domains: _domains.text,
    networks: _d.networks,
    apps: _d.apps,
    log: _d.log,
    priority: _priority.text,
  );

  void _set(RuleDraft d) => setState(() => _d = d);

  RuleDraft _with({
    Verdict? action,
    Set<String>? protocols,
    Set<NetworkType>? networks,
    List<String>? apps,
    bool? log,
  }) {
    final c = _current();
    return RuleDraft(
      id: c.id,
      action: action ?? c.action,
      description: c.description,
      protocols: protocols ?? c.protocols,
      cidrs: c.cidrs,
      ports: c.ports,
      domains: c.domains,
      networks: networks ?? c.networks,
      apps: apps ?? c.apps,
      log: log ?? c.log,
      priority: c.priority,
    );
  }

  Future<void> _save() async {
    final d = _current();
    final errors = d.validate();
    setState(() => _errors = errors);
    if (errors.isNotEmpty) return;
    setState(() => _saving = true);
    final r = await ref.read(coreProvider.notifier).updateUserLayer((u) {
      final rule = d.toRule(PolicyLogic.newRuleId(u.rules.map((x) => x.id)), PolicyLogic.nextPriority(u));
      return PolicyLogic.upsertRule(u, rule);
    });
    if (!mounted) return;
    setState(() => _saving = false);
    showSaveResult(context, r);
    if (r is SaveOk) Navigator.pop(context);
  }

  Future<void> _pickApps() async {
    final picked = await showDialog<List<String>>(
      context: context,
      builder: (_) => _AppPicker(selected: _d.apps),
    );
    if (picked != null) _set(_with(apps: picked));
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final t = Theme.of(context);
    InputDecoration deco(String label, String hint, DraftField f, String err) => InputDecoration(
      labelText: label,
      helperText: hint,
      errorText: _errors.contains(f) ? err : null,
      border: const OutlineInputBorder(),
    );
    return Padding(
      padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom),
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(20, 0, 20, 24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(_d.id == null ? l.rulesNewTitle : l.rulesEditTitle, style: t.textTheme.titleLarge),
            const SizedBox(height: 16),
            Text(l.rulesFieldAction, style: t.textTheme.labelLarge),
            const SizedBox(height: 8),
            SegmentedButton<Verdict>(
              segments: [for (final v in Verdict.values) ButtonSegment(value: v, label: Text(actionLabel(context, v)))],
              selected: {_d.action},
              onSelectionChanged: (s) => _set(_with(action: s.first)),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _desc,
              decoration: InputDecoration(labelText: l.rulesFieldDescription, border: const OutlineInputBorder()),
            ),
            const SizedBox(height: 16),
            Text(l.rulesFieldProtocols, style: t.textTheme.labelLarge),
            Wrap(
              spacing: 8,
              children: [
                for (final p in RuleDraft.allProtocols)
                  FilterChip(
                    label: Text(p.toUpperCase()),
                    selected: _d.protocols.contains(p),
                    onSelected: (on) =>
                        _set(_with(protocols: on ? {..._d.protocols, p} : ({..._d.protocols}..remove(p)))),
                  ),
              ],
            ),
            const SizedBox(height: 16),
            TextField(
              key: const Key('rule_cidrs'),
              controller: _cidrs,
              decoration: deco(l.rulesFieldCidrs, l.rulesFieldCidrsHint, DraftField.cidrs, l.rulesErrorCidrs),
            ),
            const SizedBox(height: 16),
            TextField(
              key: const Key('rule_ports'),
              controller: _ports,
              decoration: deco(l.rulesFieldPorts, l.rulesFieldPortsHint, DraftField.ports, l.rulesErrorPorts),
            ),
            const SizedBox(height: 16),
            TextField(
              key: const Key('rule_domains'),
              controller: _domains,
              keyboardType: TextInputType.url,
              decoration: deco(l.rulesFieldDomains, l.rulesFieldDomainsHint, DraftField.domains, l.rulesErrorDomains),
            ),
            const SizedBox(height: 16),
            Text(l.rulesFieldNetworks, style: t.textTheme.labelLarge),
            Wrap(
              spacing: 8,
              children: [
                for (final n in RuleDraft.allNetworks)
                  FilterChip(
                    label: Text(networkLabel(context, n)),
                    selected: _d.networks.contains(n),
                    onSelected: (on) => _set(_with(networks: on ? {..._d.networks, n} : ({..._d.networks}..remove(n)))),
                  ),
              ],
            ),
            if (!isDesktop) ...[
              const SizedBox(height: 16),
              Text(l.rulesFieldApps, style: t.textTheme.labelLarge),
              Row(
                children: [
                  Expanded(
                    child: Text(
                      _d.apps.isEmpty ? l.rulesFieldAppsAny : _d.apps.map((a) => appLabel(ref, context, a)).join(', '),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  OutlinedButton(onPressed: _pickApps, child: Text(l.rulesFieldAppsChoose)),
                ],
              ),
            ],
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(l.rulesFieldLog),
              value: _d.log,
              onChanged: (v) => _set(_with(log: v)),
            ),
            TextField(
              controller: _priority,
              keyboardType: TextInputType.number,
              decoration: deco(
                l.rulesFieldPriority,
                l.rulesFieldPriorityHint,
                DraftField.priority,
                l.rulesErrorPriority,
              ),
            ),
            if (_errors.contains(DraftField.empty)) ...[
              const SizedBox(height: 12),
              InfoBanner(l.rulesErrorEmpty, warning: true),
            ],
            const SizedBox(height: 16),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton(onPressed: () => Navigator.pop(context), child: Text(l.actionCancel)),
                const SizedBox(width: 8),
                FilledButton(key: const Key('rule_save'), onPressed: _saving ? null : _save, child: Text(l.actionSave)),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _AppPicker extends ConsumerStatefulWidget {
  const _AppPicker({required this.selected});
  final List<String> selected;

  @override
  ConsumerState<_AppPicker> createState() => _AppPickerState();
}

class _AppPickerState extends ConsumerState<_AppPicker> {
  late final Set<String> _chosen = widget.selected.toSet();
  String _q = '';

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final apps = (ref.watch(installedAppsProvider).value ?? const [])
        .where((a) => a.hasInternet)
        .where((a) => _q.isEmpty || a.label.toLowerCase().contains(_q) || a.packageName.contains(_q))
        .toList();
    return AlertDialog(
      title: Text(l.rulesFieldAppsChoose),
      content: SizedBox(
        width: double.maxFinite,
        height: 420,
        child: Column(
          children: [
            TextField(
              decoration: InputDecoration(hintText: l.appsSearchHint, prefixIcon: const Icon(Icons.search)),
              onChanged: (v) => setState(() => _q = v.trim().toLowerCase()),
            ),
            Expanded(
              child: ListView(
                children: [
                  for (final a in apps)
                    CheckboxListTile(
                      value: _chosen.contains(a.packageName),
                      secondary: AppIcon(a.packageName, size: 28),
                      title: Text(a.label, maxLines: 1, overflow: TextOverflow.ellipsis),
                      onChanged: (on) =>
                          setState(() => on == true ? _chosen.add(a.packageName) : _chosen.remove(a.packageName)),
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(l.actionCancel)),
        TextButton(onPressed: () => Navigator.pop(context, _chosen.toList()..sort()), child: Text(l.actionDone)),
      ],
    );
  }
}
