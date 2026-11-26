import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_api.dart';
import '../api/admin_models.dart';
import '../api/policy_models.dart';
import '../data/policy_editor.dart';
import '../data/session.dart';
import '../data/validation.dart';
import 'common.dart';
import 'policy_dialogs.dart';

final policyProvider = FutureProvider.family<TenantPolicy, String>((ref, t) => ref.watch(apiProvider).getPolicy(t));

class PolicyScreen extends ConsumerWidget {
  const PolicyScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) => TenantScoped(
    builder: (tenant) => AsyncBody(
      value: ref.watch(policyProvider(tenant)),
      onRetry: () => ref.invalidate(policyProvider(tenant)),
      builder: (p) => PolicyEditorView(key: ValueKey('policy-$tenant'), tenant: tenant, initial: p),
    ),
  );
}

/// The policy editor: a form and a raw JSON tab over one [PolicyEditor], plus Save.
class PolicyEditorView extends ConsumerStatefulWidget {
  const PolicyEditorView({super.key, required this.tenant, required this.initial});

  final String tenant;
  final TenantPolicy initial;

  @override
  ConsumerState<PolicyEditorView> createState() => _PolicyEditorViewState();
}

class _PolicyEditorViewState extends ConsumerState<PolicyEditorView> {
  late final PolicyEditor _editor = PolicyEditor(widget.initial);
  List<PolicyIssue> _issues = const [];
  String? _serverError;
  bool _saving = false;

  @override
  void dispose() {
    _editor.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final issues = _editor.validate();
    setState(() {
      _issues = issues;
      _serverError = null;
    });
    if (issues.isNotEmpty) return;
    setState(() => _saving = true);
    try {
      await ref.read(apiProvider).putPolicy(widget.tenant, _editor.policy);
      _editor.markSaved();
      if (mounted) showSnack(context, context.l10n.msgSaved);
    } on ApiException catch (e) {
      if (e.status == 401) {
        ref.read(sessionProvider.notifier).logout();
      } else if (mounted) {
        setState(
          () => _serverError = context.l10n.policyServerError(e.field.isEmpty ? e.message : '${e.field}: ${e.message}'),
        );
      }
    } on Object catch (e) {
      if (mounted) setState(() => _serverError = context.l10n.policyServerError('$e'));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _reload() async {
    final p = await runAction(context, ref, () => ref.read(apiProvider).getPolicy(widget.tenant));
    if (p == null) return;
    _editor.reset(p);
    setState(() {
      _issues = const [];
      _serverError = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final scheme = Theme.of(context).colorScheme;
    return DefaultTabController(
      length: 2,
      child: ListenableBuilder(
        listenable: _editor,
        builder: (context, _) => PageFrame(
          title: l.navPolicy,
          actions: [
            if (_editor.dirty) Chip(label: Text(l.policyUnsaved), avatar: const Icon(Icons.edit_note, size: 18)),
            OutlinedButton.icon(onPressed: _reload, icon: const Icon(Icons.restore), label: Text(l.actionReload)),
            FilledButton.icon(
              key: const Key('policy_save'),
              onPressed: _saving ? null : _save,
              icon: const Icon(Icons.save),
              label: Text(l.actionSave),
            ),
          ],
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (_serverError != null)
                _Banner(key: const Key('policy_server_error'), color: scheme.errorContainer, text: _serverError!),
              if (_issues.isNotEmpty)
                _Banner(
                  key: const Key('policy_issues'),
                  color: scheme.errorContainer,
                  text: '${l.policyIssues}\n${_issues.take(12).map((i) => '• $i').join('\n')}',
                ),
              TabBar(
                tabs: [
                  Tab(key: const Key('tab_form'), text: l.policyTabForm),
                  Tab(key: const Key('tab_json'), text: l.policyTabJson),
                ],
              ),
              Expanded(
                child: TabBarView(
                  children: [
                    PolicyForm(editor: _editor),
                    PolicyJsonTab(editor: _editor),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _Banner extends StatelessWidget {
  const _Banner({super.key, required this.color, required this.text});

  final Color color;
  final String text;

  @override
  Widget build(BuildContext context) => Container(
    margin: const EdgeInsets.only(bottom: 8),
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(12)),
    child: SelectableText(text, style: TextStyle(color: Theme.of(context).colorScheme.onErrorContainer)),
  );
}

/// Raw JSON of the draft. Typing updates the draft when the JSON is valid; form edits
/// replace the text.
class PolicyJsonTab extends StatefulWidget {
  const PolicyJsonTab({super.key, required this.editor});

  final PolicyEditor editor;

  @override
  State<PolicyJsonTab> createState() => _PolicyJsonTabState();
}

class _PolicyJsonTabState extends State<PolicyJsonTab> {
  late final TextEditingController _c = TextEditingController(text: widget.editor.jsonText);
  late int _rev = widget.editor.formRevision;

  @override
  void initState() {
    super.initState();
    widget.editor.addListener(_onEditor);
  }

  void _onEditor() {
    if (widget.editor.formRevision != _rev) {
      _rev = widget.editor.formRevision;
      if (_c.text != widget.editor.jsonText) _c.text = widget.editor.jsonText;
    }
  }

  @override
  void dispose() {
    widget.editor.removeListener(_onEditor);
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final err = widget.editor.jsonError;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 12),
      child: TextField(
        key: const Key('policy_json'),
        controller: _c,
        expands: true,
        maxLines: null,
        minLines: null,
        textAlignVertical: TextAlignVertical.top,
        style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
        decoration: InputDecoration(
          border: const OutlineInputBorder(),
          errorText: err == null ? null : context.l10n.policyJsonInvalid(err),
          errorMaxLines: 3,
        ),
        onChanged: widget.editor.setJson,
      ),
    );
  }
}

/// The form view of the draft. Read-only while the JSON tab holds invalid JSON.
class PolicyForm extends StatelessWidget {
  const PolicyForm({super.key, required this.editor});

  final PolicyEditor editor;

  TenantPolicy get p => editor.policy;

  void _set(void Function() f) {
    f();
    editor.formChanged();
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final on = editor.canEditForm;
    const gap = SizedBox(height: 16);
    return ListView(
      padding: const EdgeInsets.symmetric(vertical: 12),
      children: [
        if (!on)
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: Text(
              l.policyJsonLocked,
              key: const Key('form_locked'),
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ),
        AbsorbPointer(
          absorbing: !on,
          child: Opacity(
            opacity: on ? 1 : 0.5,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _general(context),
                gap,
                _rules(context),
                gap,
                _apps(context),
                gap,
                _dns(context),
                gap,
                _decide(context),
                gap,
                _posture(context),
                gap,
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _general(BuildContext context) {
    final l = context.l10n;
    return SectionCard(
      title: l.policyGeneral,
      children: [
        _ActionSelect(
          key: const Key('default_action'),
          label: l.policyDefaultAction,
          value: p.defaultAction,
          options: const ['', ...Verdicts.all],
          onChanged: (v) => _set(() => p.defaultAction = v),
        ),
        const SizedBox(height: 8),
        SwitchListTile(
          key: const Key('allow_user_rules'),
          contentPadding: EdgeInsets.zero,
          title: Text(l.policyAllowUserRules),
          subtitle: Text(l.policyAllowUserRulesHelp),
          value: p.allowUserRules,
          onChanged: (v) => _set(() => p.allowUserRules = v),
        ),
        SwitchListTile(
          key: const Key('lockdown'),
          contentPadding: EdgeInsets.zero,
          title: Text(l.policyLockdown),
          subtitle: Text(l.policyLockdownHelp),
          value: p.lockdown,
          onChanged: (v) => _set(() => p.lockdown = v),
        ),
      ],
    );
  }

  void _renumber() {
    for (var i = 0; i < p.rules.length; i++) {
      p.rules[i].priority = (i + 1) * 10;
    }
  }

  Future<void> _editRule(BuildContext context, int? index) async {
    final isNew = index == null;
    final maxPrio = p.rules.fold<int>(0, (m, r) => r.priority > m ? r.priority : m);
    final rule = isNew ? Rule(id: 'rule-${p.rules.length + 1}', priority: maxPrio + 10) : p.rules[index];
    final out = await showDialog<Rule>(
      context: context,
      builder: (_) => RuleDialog(rule: rule, isNew: isNew, existingIds: {for (final r in p.rules) r.id}),
    );
    if (out == null) return;
    _set(() {
      isNew ? p.rules.add(out) : p.rules[index] = out;
      // Keep the table in evaluation order (stable for equal priorities).
      final indexed = p.rules.indexed.toList()
        ..sort(
          (a, b) => a.$2.priority != b.$2.priority ? a.$2.priority.compareTo(b.$2.priority) : a.$1.compareTo(b.$1),
        );
      p.rules = [for (final e in indexed) e.$2];
    });
  }

  String _matchSummary(BuildContext context, Match m) {
    final parts = [
      if (m.domains.isNotEmpty) m.domains.join(', '),
      if (m.cidrs.isNotEmpty) m.cidrs.join(', '),
      if (m.ports.isNotEmpty) 'port ${m.ports.join(', ')}',
      if (m.protocols.isNotEmpty) m.protocols.join('/'),
      if (m.networks.isNotEmpty) m.networks.map((n) => networkLabel(context, n)).join('/'),
      if (m.apps.isNotEmpty) m.apps.join(', '),
    ];
    return parts.isEmpty ? context.l10n.ruleMatchAny : parts.join(' · ');
  }

  Widget _rules(BuildContext context) {
    final l = context.l10n;
    return SectionCard(
      title: l.policyRules,
      subtitle: l.policyRulesHelp,
      trailing: FilledButton.tonalIcon(
        key: const Key('rule_add'),
        onPressed: () => _editRule(context, null),
        icon: const Icon(Icons.add),
        label: Text(l.actionAdd),
      ),
      children: [
        if (p.rules.isEmpty)
          Text(l.emptyNothingHere)
        else
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              columnSpacing: 20,
              columns: [
                DataColumn(label: Text(l.rulePriority), numeric: true),
                DataColumn(label: Text(l.fieldId)),
                DataColumn(label: Text(l.ruleAction)),
                DataColumn(label: Text(l.ruleMatch)),
                const DataColumn(label: SizedBox.shrink()),
              ],
              rows: [
                for (final (i, r) in p.rules.indexed)
                  DataRow(
                    cells: [
                      DataCell(Text('${r.priority}')),
                      DataCell(Text(r.description.isEmpty ? r.id : '${r.id}\n${r.description}')),
                      DataCell(
                        StatusChip(label: actionLabel(context, r.action), color: verdictColor(context, r.action)),
                      ),
                      DataCell(
                        ConstrainedBox(
                          constraints: const BoxConstraints(maxWidth: 380),
                          child: Text(_matchSummary(context, r.match), overflow: TextOverflow.ellipsis, maxLines: 2),
                        ),
                      ),
                      DataCell(
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            IconButton(
                              tooltip: l.actionMoveUp,
                              icon: const Icon(Icons.arrow_upward),
                              onPressed: i == 0
                                  ? null
                                  : () => _set(() {
                                      p.rules.insert(i - 1, p.rules.removeAt(i));
                                      _renumber();
                                    }),
                            ),
                            IconButton(
                              tooltip: l.actionMoveDown,
                              icon: const Icon(Icons.arrow_downward),
                              onPressed: i == p.rules.length - 1
                                  ? null
                                  : () => _set(() {
                                      p.rules.insert(i + 1, p.rules.removeAt(i));
                                      _renumber();
                                    }),
                            ),
                            IconButton(
                              tooltip: l.actionEdit,
                              icon: const Icon(Icons.edit),
                              onPressed: () => _editRule(context, i),
                            ),
                            IconButton(
                              tooltip: l.actionDelete,
                              icon: const Icon(Icons.delete_outline),
                              onPressed: () => _set(() => p.rules.removeAt(i)),
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
    );
  }

  Future<void> _editApp(BuildContext context, String? pkg) async {
    final out = await showDialog<(String, AppPolicy)>(
      context: context,
      builder: (_) => AppPolicyDialog(
        package: pkg ?? '',
        policy: pkg == null ? AppPolicy() : p.apps[pkg]!,
        existing: p.apps.keys.toSet(),
      ),
    );
    if (out == null) return;
    _set(() {
      if (pkg != null) p.apps.remove(pkg);
      p.apps[out.$1] = out.$2;
    });
  }

  Widget _apps(BuildContext context) {
    final l = context.l10n;
    final keys = p.apps.keys.toList()..sort();
    Widget verdict(String a) =>
        a.isEmpty ? const Text('—') : StatusChip(label: actionLabel(context, a), color: verdictColor(context, a));
    return SectionCard(
      title: l.policyApps,
      subtitle: l.policyAppsHelp,
      trailing: FilledButton.tonalIcon(
        onPressed: () => _editApp(context, null),
        icon: const Icon(Icons.add),
        label: Text(l.actionAdd),
      ),
      children: [
        if (keys.isEmpty)
          Text(l.emptyNothingHere)
        else
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              columns: [
                DataColumn(label: Text(l.appPackage)),
                DataColumn(label: Text(l.networkWifi)),
                DataColumn(label: Text(l.networkCellular)),
                DataColumn(label: Text(l.networkRoaming)),
                const DataColumn(label: SizedBox.shrink()),
              ],
              rows: [
                for (final k in keys)
                  DataRow(
                    cells: [
                      DataCell(Text(k)),
                      DataCell(verdict(p.apps[k]!.wifi)),
                      DataCell(verdict(p.apps[k]!.cellular)),
                      DataCell(verdict(p.apps[k]!.roaming)),
                      DataCell(
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            IconButton(
                              tooltip: l.actionEdit,
                              icon: const Icon(Icons.edit),
                              onPressed: () => _editApp(context, k),
                            ),
                            IconButton(
                              tooltip: l.actionDelete,
                              icon: const Icon(Icons.delete_outline),
                              onPressed: () => _set(() => p.apps.remove(k)),
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
    );
  }

  Future<void> _editBlocklist(BuildContext context, int? index) async {
    final out = await showDialog<Blocklist>(
      context: context,
      builder: (_) =>
          BlocklistDialog(list: index == null ? Blocklist() : p.dns.blocklists[index], isNew: index == null),
    );
    if (out == null) return;
    _set(() => index == null ? p.dns.blocklists.add(out) : p.dns.blocklists[index] = out);
  }

  Widget _dns(BuildContext context) {
    final l = context.l10n;
    final on = editor.canEditForm;
    return SectionCard(
      title: l.policyDns,
      children: [
        _ActionSelect(
          key: const Key('block_response'),
          label: l.policyBlockResponse,
          value: p.dns.blockResponse,
          options: const ['', 'nxdomain', 'zero'],
          labels: {'': '${l.policyNotSet} (nxdomain)', 'nxdomain': 'NXDOMAIN', 'zero': '0.0.0.0 / ::'},
          onChanged: (v) => _set(() => p.dns.blockResponse = v),
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            Expanded(child: Text(l.policyBlocklists, style: Theme.of(context).textTheme.titleSmall)),
            TextButton.icon(
              onPressed: () => _editBlocklist(context, null),
              icon: const Icon(Icons.add),
              label: Text(l.actionAdd),
            ),
          ],
        ),
        for (final (i, b) in p.dns.blocklists.indexed)
          ListTile(
            contentPadding: EdgeInsets.zero,
            leading: const Icon(Icons.playlist_remove),
            title: Text(b.name.isEmpty ? b.id : '${b.name} (${b.id})'),
            subtitle: Text('${b.category.isEmpty ? '—' : b.category} · ${l.blocklistDomainsCount(b.domains.length)}'),
            trailing: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                IconButton(
                  tooltip: l.actionEdit,
                  icon: const Icon(Icons.edit),
                  onPressed: () => _editBlocklist(context, i),
                ),
                IconButton(
                  tooltip: l.actionDelete,
                  icon: const Icon(Icons.delete_outline),
                  onPressed: () => _set(() => p.dns.blocklists.removeAt(i)),
                ),
              ],
            ),
          ),
        const SizedBox(height: 12),
        LinesField(
          key: const Key('dns_allow'),
          label: l.policyAllowDomains,
          helper: l.policyOnePerLine,
          value: p.dns.allowDomains,
          enabled: on,
          onChanged: (v) => _set(() => p.dns.allowDomains = v),
        ),
        const SizedBox(height: 12),
        LinesField(
          key: const Key('dns_block'),
          label: l.policyBlockDomains,
          helper: l.policyOnePerLine,
          value: p.dns.blockDomains,
          enabled: on,
          onChanged: (v) => _set(() => p.dns.blockDomains = v),
        ),
      ],
    );
  }

  Widget _decide(BuildContext context) {
    final l = context.l10n;
    final on = editor.canEditForm;
    return SectionCard(
      title: l.policyDecide,
      children: [
        _ActionSelect(
          key: const Key('decide_default'),
          label: l.policyDecideDefault,
          value: p.decideDefault,
          options: const ['', Verdicts.allow, Verdicts.block],
          onChanged: (v) => _set(() => p.decideDefault = v),
        ),
        const SizedBox(height: 12),
        LinesField(
          label: l.policyDecideBlockDomains,
          helper: l.policyOnePerLine,
          value: p.decideBlockDomains,
          enabled: on,
          onChanged: (v) => _set(() => p.decideBlockDomains = v),
        ),
        const SizedBox(height: 12),
        LinesField(
          label: l.policyDecideBlockCidrs,
          value: p.decideBlockCidrs,
          enabled: on,
          onChanged: (v) => _set(() => p.decideBlockCidrs = v),
        ),
      ],
    );
  }

  Widget _posture(BuildContext context) {
    final l = context.l10n;
    final on = editor.canEditForm;
    final tt = Theme.of(context).textTheme;
    const osList = ['android', 'windows', 'linux', 'macos', 'ios'];
    return SectionCard(
      title: l.policyPosture,
      subtitle: l.policyPostureHelp,
      children: [
        Text(l.postureMinOsVersion, style: tt.titleSmall),
        const SizedBox(height: 8),
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            for (final os in osList)
              SizedBox(
                width: 160,
                child: TextFormField(
                  key: ValueKey('posture_min_os_$os'),
                  initialValue: p.posture.minOsVersion[os] ?? '',
                  enabled: on,
                  decoration: InputDecoration(labelText: os, border: const OutlineInputBorder()),
                  onChanged: (v) => _set(() {
                    final trimmed = v.trim();
                    if (trimmed.isEmpty) {
                      p.posture.minOsVersion.remove(os);
                    } else {
                      p.posture.minOsVersion[os] = trimmed;
                    }
                  }),
                ),
              ),
          ],
        ),
        const SizedBox(height: 16),
        TextFormField(
          key: const ValueKey('posture_min_client_version'),
          initialValue: p.posture.minClientVersion,
          enabled: on,
          decoration: InputDecoration(labelText: l.postureMinClientVersion, border: const OutlineInputBorder()),
          onChanged: (v) => _set(() => p.posture.minClientVersion = v.trim()),
        ),
        const SizedBox(height: 16),
        Text(l.postureRequire, style: tt.titleSmall),
        CheckboxListTile(
          key: const ValueKey('posture_require_diskEncryption'),
          contentPadding: EdgeInsets.zero,
          title: Text(l.postureCheckDiskEncryption),
          value: p.posture.require.contains('diskEncryption'),
          onChanged: on
              ? (v) => _set(() {
                  if (v == true) {
                    if (!p.posture.require.contains('diskEncryption')) p.posture.require.add('diskEncryption');
                  } else {
                    p.posture.require.remove('diskEncryption');
                  }
                })
              : null,
        ),
        CheckboxListTile(
          key: const ValueKey('posture_require_screenLock'),
          contentPadding: EdgeInsets.zero,
          title: Text(l.postureCheckScreenLock),
          value: p.posture.require.contains('screenLock'),
          onChanged: on
              ? (v) => _set(() {
                  if (v == true) {
                    if (!p.posture.require.contains('screenLock')) p.posture.require.add('screenLock');
                  } else {
                    p.posture.require.remove('screenLock');
                  }
                })
              : null,
        ),
        CheckboxListTile(
          key: const ValueKey('posture_require_firewall'),
          contentPadding: EdgeInsets.zero,
          title: Text(l.postureCheckFirewall),
          value: p.posture.require.contains('firewall'),
          onChanged: on
              ? (v) => _set(() {
                  if (v == true) {
                    if (!p.posture.require.contains('firewall')) p.posture.require.add('firewall');
                  } else {
                    p.posture.require.remove('firewall');
                  }
                })
              : null,
        ),
        CheckboxListTile(
          key: const ValueKey('posture_require_managed'),
          contentPadding: EdgeInsets.zero,
          title: Text(l.postureCheckManaged),
          value: p.posture.require.contains('managed'),
          onChanged: on
              ? (v) => _set(() {
                  if (v == true) {
                    if (!p.posture.require.contains('managed')) p.posture.require.add('managed');
                  } else {
                    p.posture.require.remove('managed');
                  }
                })
              : null,
        ),
        const SizedBox(height: 8),
        SwitchListTile(
          key: const ValueKey('posture_restrict'),
          contentPadding: EdgeInsets.zero,
          title: Text(l.postureRestrict),
          subtitle: Text(l.postureRestrictHelp),
          value: p.posture.restrict,
          onChanged: on ? (v) => _set(() => p.posture.restrict = v) : null,
        ),
        const SizedBox(height: 16),
        _RemediationDomainsChips(
          domains: p.posture.remediationDomains,
          enabled: on,
          onChanged: (v) => _set(() => p.posture.remediationDomains = v),
        ),
      ],
    );
  }
}

class _RemediationDomainsChips extends StatefulWidget {
  const _RemediationDomainsChips({required this.domains, required this.onChanged, required this.enabled});

  final List<String> domains;
  final ValueChanged<List<String>> onChanged;
  final bool enabled;

  @override
  State<_RemediationDomainsChips> createState() => _RemediationDomainsChipsState();
}

class _RemediationDomainsChipsState extends State<_RemediationDomainsChips> {
  final _c = TextEditingController();

  void _add() {
    final v = _c.text.trim();
    if (v.isNotEmpty && !widget.domains.contains(v)) {
      widget.onChanged([...widget.domains, v]);
      _c.clear();
    }
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (widget.domains.isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Wrap(
              spacing: 8,
              runSpacing: 4,
              children: [
                for (final d in widget.domains)
                  InputChip(
                    key: ValueKey('remediation_chip_$d'),
                    label: Text(d),
                    onDeleted: widget.enabled
                        ? () {
                            final next = List<String>.from(widget.domains)..remove(d);
                            widget.onChanged(next);
                          }
                        : null,
                  ),
              ],
            ),
          ),
        if (widget.enabled)
          Row(
            children: [
              Expanded(
                child: TextField(
                  key: const ValueKey('remediation_domain_input'),
                  controller: _c,
                  decoration: InputDecoration(
                    labelText: l.postureRemediationDomains,
                    hintText: 'remediation.example.com',
                    helperText: l.postureRemediationDomainsHelp,
                    border: const OutlineInputBorder(),
                  ),
                  onSubmitted: (_) => _add(),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.tonal(
                key: const ValueKey('remediation_domain_add'),
                onPressed: _add,
                child: Text(l.actionAdd),
              ),
            ],
          ),
      ],
    );
  }
}

/// A dropdown over string options, following external value changes.
class _ActionSelect extends StatelessWidget {
  const _ActionSelect({
    super.key,
    required this.label,
    required this.value,
    required this.options,
    required this.onChanged,
    this.labels,
  });

  final String label;
  final String value;
  final List<String> options;
  final Map<String, String>? labels;
  final ValueChanged<String> onChanged;

  @override
  Widget build(BuildContext context) {
    final opts = options.contains(value) ? options : [...options, value];
    String text(String v) => labels?[v] ?? (v.isEmpty ? context.l10n.policyNotSet : actionLabel(context, v));
    return DropdownMenu<String>(
      // Rebuilt when the value changes elsewhere (JSON tab), since initialSelection is read once.
      key: ValueKey(value),
      initialSelection: value,
      label: Text(label),
      width: 360,
      dropdownMenuEntries: [for (final v in opts) DropdownMenuEntry(value: v, label: text(v))],
      onSelected: (v) {
        if (v != null && v != value) onChanged(v);
      },
    );
  }
}
