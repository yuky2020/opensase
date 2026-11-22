import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_api.dart';
import '../api/admin_models.dart';
import '../data/session.dart';
import 'common.dart';
import 'fields_dialog.dart';
import 'policy_screen.dart';
import 'theme.dart';

/// Web inspection (ADR-0018): TLS interception at the Edge, bypassed domains, URL rules and
/// injected request headers. Saves TenantPolicy.web with the policy PUT.
class WebScreen extends ConsumerWidget {
  const WebScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) => TenantScoped(
    builder: (tenant) => AsyncBody(
      value: ref.watch(policyProvider(tenant)),
      onRetry: () => ref.invalidate(policyProvider(tenant)),
      builder: (p) => _WebEditor(key: ValueKey('web-$tenant'), tenant: tenant, initial: p.web),
    ),
  );
}

List<String> _split(String s) => [
  for (final x in s.split(RegExp(r'[,\s]+')))
    if (x.trim().isNotEmpty) x.trim(),
];

class _WebEditor extends ConsumerStatefulWidget {
  const _WebEditor({super.key, required this.tenant, required this.initial});

  final String tenant;
  final WebPolicy initial;

  @override
  ConsumerState<_WebEditor> createState() => _WebEditorState();
}

class _WebEditorState extends ConsumerState<_WebEditor> {
  late WebPolicy _p = _copy(widget.initial);
  bool _dirty = false;
  bool _saving = false;
  String? _error;

  static WebPolicy _copy(WebPolicy p) => WebPolicy.fromJson(p.toJson());

  @override
  void didUpdateWidget(_WebEditor old) {
    super.didUpdateWidget(old);
    if (!_dirty && !identical(old.initial, widget.initial)) _p = _copy(widget.initial);
  }

  void _edit(void Function() f) => setState(() {
    f();
    _dirty = true;
  });

  Future<void> _save() async {
    setState(() {
      _saving = true;
      _error = null;
    });
    final api = ref.read(apiProvider);
    try {
      // Re-read the policy so that only the web section changes.
      final p = await api.getPolicy(widget.tenant);
      p.web = _p;
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

  Future<void> _addRule() async {
    final l = context.l10n;
    final v = await showFieldsDialog(
      context,
      title: l.webAddRule,
      fields: [
        FieldSpec('id', l.fieldId, validator: (s) => s.isEmpty || s.contains(' ') ? l.fieldRequired : null),
        FieldSpec(
          'domains',
          l.webDomains,
          hint: 'app.example.com, *.files.example',
          validator: (s) => _split(s).isEmpty ? l.fieldRequired : null,
        ),
        FieldSpec(
          'paths',
          l.webPaths,
          hint: '/admin, /upload',
          validator: (s) => _split(s).any((p) => !p.startsWith('/')) ? l.webPathsInvalid : null,
        ),
        FieldSpec('methods', l.webMethods, hint: 'POST, PUT'),
        FieldSpec(
          'action',
          l.webAction,
          initial: 'block',
          validator: (s) => s == 'block' || s == 'allow' ? null : 'allow | block',
        ),
      ],
    );
    if (v == null) return;
    _edit(
      () => _p.rules.add(
        WebRule(
          id: v['id']!,
          domains: _split(v['domains']!),
          pathPrefixes: _split(v['paths']!),
          methods: [for (final m in _split(v['methods']!)) m.toUpperCase()],
          action: v['action']!,
        ),
      ),
    );
  }

  Future<void> _addHeader() async {
    final l = context.l10n;
    final v = await showFieldsDialog(
      context,
      title: l.webAddHeader,
      fields: [
        FieldSpec('domains', l.webDomains, validator: (s) => _split(s).isEmpty ? l.fieldRequired : null),
        FieldSpec('name', l.webHeaderName, validator: (s) => s.isEmpty ? l.fieldRequired : null),
        FieldSpec('value', l.webHeaderValue),
      ],
    );
    if (v == null) return;
    _edit(() => _p.headers.add(WebHeader(domains: _split(v['domains']!), name: v['name']!, value: v['value']!)));
  }

  Future<void> _addDlp() async {
    final l = context.l10n;
    final v = await showFieldsDialog(
      context,
      title: l.webAddDlp,
      description: l.webDlpDetectorsHelp(DlpRule.builtinDetectors.join(', ')),
      fields: [
        FieldSpec('id', l.fieldId, validator: (s) => s.isEmpty || s.contains(' ') ? l.fieldRequired : null),
        FieldSpec(
          'detectors',
          l.webDlpDetectors,
          initial: 'credit-card',
          validator: (s) => _split(s).any((d) => !DlpRule.builtinDetectors.contains(d)) ? l.webDlpUnknown : null,
        ),
        FieldSpec('datasets', l.webDlpDatasets, helper: l.webDlpDatasetsHelp),
        FieldSpec('patterns', l.webDlpPatterns),
        FieldSpec('domains', l.webDlpDomains),
        FieldSpec(
          'min',
          l.webDlpMin,
          initial: '1',
          validator: (s) => (int.tryParse(s) ?? 0) < 1 ? l.webDlpMinInvalid : null,
        ),
        FieldSpec(
          'action',
          l.webAction,
          initial: 'block',
          validator: (s) => s == 'block' || s == 'allow' ? null : 'allow | block',
        ),
      ],
    );
    if (v == null) return;
    final patterns = [
      for (final p in v['patterns']!.split('\n'))
        if (p.trim().isNotEmpty) p.trim(),
    ];
    if (_split(v['detectors']!).isEmpty && patterns.isEmpty && _split(v['datasets']!).isEmpty) return;
    _edit(
      () => _p.dlp.add(
        DlpRule(
          id: v['id']!,
          detectors: _split(v['detectors']!),
          datasets: _split(v['datasets']!),
          patterns: patterns,
          domains: _split(v['domains']!),
          minMatches: int.parse(v['min']!) == 1 ? 0 : int.parse(v['min']!),
          action: v['action']!,
        ),
      ),
    );
  }

  Future<void> _showRoot() async {
    final l = context.l10n;
    try {
      final pem = await ref.read(apiProvider).inspectionRoot(widget.tenant);
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (c) => AlertDialog(
          title: Text(l.webRootTitle),
          content: SizedBox(
            width: 560,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(l.webRootHelp),
                const SizedBox(height: 12),
                OneTimeSecret(secret: pem.trim()),
              ],
            ),
          ),
          actions: [TextButton(onPressed: () => Navigator.pop(c), child: Text(l.actionClose))],
        ),
      );
    } on ApiException catch (e) {
      if (mounted) setState(() => _error = context.l10n.policyServerError(e.message));
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final scheme = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;
    return PageFrame(
      title: l.navWeb,
      subtitle: l.webHelp,
      actions: [
        if (_dirty) Chip(label: Text(l.policyUnsaved), avatar: const Icon(Icons.edit_note, size: 18)),
        OutlinedButton.icon(
          key: const Key('web_root'),
          onPressed: _showRoot,
          icon: const Icon(Icons.verified_user_outlined),
          label: Text(l.webRootButton),
        ),
        FilledButton.icon(
          key: const Key('web_save'),
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
          Card(
            margin: const EdgeInsets.only(bottom: 12),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  SwitchListTile(
                    key: const Key('web_inspect'),
                    contentPadding: EdgeInsets.zero,
                    title: Text(l.webInspect, style: text.titleMedium),
                    subtitle: Text(l.webInspectHelp),
                    value: _p.inspect,
                    onChanged: (v) => _edit(() => _p.inspect = v),
                  ),
                  SwitchListTile(
                    key: const Key('web_block_ech'),
                    contentPadding: EdgeInsets.zero,
                    title: Text(l.webBlockEch, style: text.titleMedium),
                    subtitle: Text(l.webBlockEchHelp),
                    value: _p.blockEch,
                    onChanged: (v) => _edit(() => _p.blockEch = v),
                  ),
                  SwitchListTile(
                    key: const Key('web_av_uploads'),
                    contentPadding: EdgeInsets.zero,
                    title: Text(l.webAvUploads),
                    value: _p.malware.uploads,
                    onChanged: (v) => _edit(() => _p.malware.uploads = v),
                  ),
                  SwitchListTile(
                    key: const Key('web_av_downloads'),
                    contentPadding: EdgeInsets.zero,
                    title: Text(l.webAvDownloads),
                    subtitle: Text(l.webAvDownloadsHelp),
                    value: _p.malware.downloads,
                    onChanged: (v) => _edit(() => _p.malware.downloads = v),
                  ),
                  SwitchListTile(
                    key: const Key('web_av_unscanned'),
                    contentPadding: EdgeInsets.zero,
                    title: Text(l.webAvBlockUnscanned),
                    subtitle: Text(l.webAvBlockUnscannedHelp),
                    value: _p.malware.blockUnscanned,
                    onChanged: (v) => _edit(() => _p.malware.blockUnscanned = v),
                  ),
                  const SizedBox(height: 8),
                  LinesField(
                    label: l.webBypass,
                    helper: l.webBypassHelp,
                    value: _p.bypass,
                    onChanged: (v) => _edit(() => _p.bypass = v),
                  ),
                ],
              ),
            ),
          ),
          Card(
            margin: const EdgeInsets.only(bottom: 12),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(
                    children: [
                      Expanded(child: Text(l.webRules, style: text.titleMedium)),
                      TextButton.icon(
                        key: const Key('web_add_rule'),
                        onPressed: _addRule,
                        icon: const Icon(Icons.add),
                        label: Text(l.webAddRule),
                      ),
                    ],
                  ),
                  Text(l.webRulesHelp, style: text.bodySmall),
                  for (final (i, r) in _p.rules.indexed)
                    ListTile(
                      key: Key('web_rule_${r.id}'),
                      contentPadding: EdgeInsets.zero,
                      leading: StatusChip(
                        label: r.action == 'allow' ? l.statusAllowed : l.statusBlocked,
                        color: r.action == 'allow' ? context.verdicts.allow : context.verdicts.block,
                      ),
                      title: Text('${r.id} · ${r.domains.join(', ')}'),
                      subtitle: Text(
                        [
                          if (r.methods.isNotEmpty) r.methods.join(' '),
                          r.pathPrefixes.isEmpty ? '/*' : r.pathPrefixes.join(', '),
                        ].join(' · '),
                      ),
                      trailing: IconButton(
                        tooltip: l.actionDelete,
                        icon: const Icon(Icons.delete_outline),
                        onPressed: () => _edit(() => _p.rules.removeAt(i)),
                      ),
                    ),
                ],
              ),
            ),
          ),
          Card(
            margin: const EdgeInsets.only(bottom: 12),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(
                    children: [
                      Expanded(child: Text(l.webDlp, style: text.titleMedium)),
                      TextButton.icon(
                        key: const Key('web_add_dlp'),
                        onPressed: _addDlp,
                        icon: const Icon(Icons.add),
                        label: Text(l.webAddDlp),
                      ),
                    ],
                  ),
                  Text(l.webDlpHelp, style: text.bodySmall),
                  for (final (i, d) in _p.dlp.indexed)
                    ListTile(
                      key: Key('web_dlp_${d.id}'),
                      contentPadding: EdgeInsets.zero,
                      leading: StatusChip(
                        label: d.action == 'allow' ? l.webDlpLog : l.statusBlocked,
                        color: d.action == 'allow' ? context.verdicts.allow : context.verdicts.block,
                      ),
                      title: Text(
                        '${d.id} · ${[...d.detectors, ...d.datasets.map((x) => '#$x'), if (d.patterns.isNotEmpty) l.webDlpPatternCount(d.patterns.length)].join(', ')}',
                      ),
                      subtitle: Text(
                        [
                          d.downloads ? l.webDlpBoth : l.webDlpUploadsOnly,
                          d.domains.isEmpty ? l.webDlpAllHosts : d.domains.join(', '),
                          if (d.minMatches > 1) '≥ ${d.minMatches}',
                        ].join(' · '),
                      ),
                      trailing: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Tooltip(
                            message: l.webDlpDownloads,
                            child: IconButton(
                              key: Key('web_dlp_downloads_${d.id}'),
                              isSelected: d.downloads,
                              icon: const Icon(Icons.download_outlined),
                              selectedIcon: const Icon(Icons.download),
                              onPressed: () => _edit(() => d.downloads = !d.downloads),
                            ),
                          ),
                          Tooltip(
                            message: l.webDlpBlockUnscanned,
                            child: Switch(
                              key: Key('web_dlp_unscanned_${d.id}'),
                              value: d.blockUnscanned,
                              onChanged: (v) => _edit(() => d.blockUnscanned = v),
                            ),
                          ),
                          IconButton(
                            tooltip: l.actionDelete,
                            icon: const Icon(Icons.delete_outline),
                            onPressed: () => _edit(() => _p.dlp.removeAt(i)),
                          ),
                        ],
                      ),
                    ),
                ],
              ),
            ),
          ),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(
                    children: [
                      Expanded(child: Text(l.webHeaders, style: text.titleMedium)),
                      TextButton.icon(
                        key: const Key('web_add_header'),
                        onPressed: _addHeader,
                        icon: const Icon(Icons.add),
                        label: Text(l.webAddHeader),
                      ),
                    ],
                  ),
                  Text(l.webHeadersHelp, style: text.bodySmall),
                  for (final (i, h) in _p.headers.indexed)
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      title: Text('${h.name}: ${h.value}'),
                      subtitle: Text(h.domains.join(', ')),
                      trailing: IconButton(
                        tooltip: l.actionDelete,
                        icon: const Icon(Icons.delete_outline),
                        onPressed: () => _edit(() => _p.headers.removeAt(i)),
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
