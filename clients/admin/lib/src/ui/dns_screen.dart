import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_api.dart';
import '../api/admin_models.dart';
import '../api/policy_models.dart';
import '../data/providers.dart';
import '../data/session.dart';
import 'common.dart';
import 'policy_screen.dart' show policyProvider;

/// DNS policy and internal resolver management (issues #62 and #63).
class DnsScreen extends ConsumerWidget {
  const DnsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) => TenantScoped(
    builder: (tenant) => AsyncBody(
      value: ref.watch(policyProvider(tenant)),
      onRetry: () => ref.invalidate(policyProvider(tenant)),
      builder: (p) => DnsEditorView(key: ValueKey('dns-$tenant'), tenant: tenant, initial: p),
    ),
  );
}

class DnsEditorView extends ConsumerStatefulWidget {
  const DnsEditorView({super.key, required this.tenant, required this.initial});

  final String tenant;
  final TenantPolicy initial;

  @override
  ConsumerState<DnsEditorView> createState() => _DnsEditorViewState();
}

class _DnsEditorViewState extends ConsumerState<DnsEditorView> {
  late DnsPolicy _dns = widget.initial.dns.copy();
  late List<CustomList> _customLists = [for (final l in widget.initial.customLists) l.copy()];
  late List<String> _builtinLists = [...widget.initial.builtinLists];
  late String _etag = widget.initial.etag;

  late final TextEditingController _zoneCtrl = TextEditingController(text: _dns.zone);
  late final TextEditingController _allowDomainCtrl = TextEditingController();
  late final TextEditingController _blockDomainCtrl = TextEditingController();

  bool _dirty = false;
  bool _saving = false;
  String? _error;

  @override
  void didUpdateWidget(DnsEditorView old) {
    super.didUpdateWidget(old);
    if (!_dirty && !identical(old.initial, widget.initial)) {
      _reset(widget.initial);
    }
  }

  void _reset(TenantPolicy p) {
    _dns = p.dns.copy();
    _customLists = [for (final l in p.customLists) l.copy()];
    _builtinLists = [...p.builtinLists];
    _etag = p.etag;
    _zoneCtrl.text = _dns.zone;
    _dirty = false;
    _error = null;
  }

  @override
  void dispose() {
    _zoneCtrl.dispose();
    _allowDomainCtrl.dispose();
    _blockDomainCtrl.dispose();
    super.dispose();
  }

  void _edit(void Function() f) {
    setState(() {
      f();
      _dirty = true;
    });
  }

  Future<void> _save() async {
    setState(() {
      _saving = true;
      _error = null;
    });
    final api = ref.read(apiProvider);
    try {
      final p = widget.initial.copy();
      p.etag = _etag;
      p.dns = _dns;
      p.customLists = _customLists;
      p.builtinLists = _builtinLists;
      await api.putPolicy(widget.tenant, p);
      if (!mounted) return;
      setState(() {
        _etag = p.etag;
        _dirty = false;
      });
      showSnack(context, context.l10n.msgSaved);
      ref.invalidate(policyProvider(widget.tenant));
    } on ApiException catch (e) {
      if (e.status == 401) {
        ref.read(sessionProvider.notifier).logout();
      } else if (mounted) {
        setState(() {
          _error = context.l10n.policyServerError(e.field.isEmpty ? e.message : '${e.field}: ${e.message}');
        });
      }
    } on Object catch (e) {
      if (mounted) setState(() => _error = context.l10n.policyServerError('$e'));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _reload() async {
    final p = await runAction(context, ref, () => ref.read(apiProvider).getPolicy(widget.tenant));
    if (p == null) return;
    setState(() => _reset(p));
  }

  void _addAllowDomain() {
    final d = _allowDomainCtrl.text.trim();
    if (d.isEmpty) return;
    if (!_dns.allowDomains.contains(d)) {
      _edit(() => _dns.allowDomains.add(d));
    }
    _allowDomainCtrl.clear();
  }

  void _addBlockDomain() {
    final d = _blockDomainCtrl.text.trim();
    if (d.isEmpty) return;
    if (!_dns.blockDomains.contains(d)) {
      _edit(() => _dns.blockDomains.add(d));
    }
    _blockDomainCtrl.clear();
  }

  Future<void> _addOrEditRecord(int? index) async {
    final rec = index != null ? _dns.records[index] : null;
    final res = await showDialog<DnsRecord>(
      context: context,
      builder: (_) => _RecordDialog(initial: rec),
    );
    if (res == null) return;
    _edit(() {
      if (index != null) {
        _dns.records[index] = res;
      } else {
        _dns.records.add(res);
      }
    });
  }

  Future<void> _addOrEditForwarder(int? index) async {
    final fwd = index != null ? _dns.forwarders[index] : null;
    final res = await showDialog<DnsForwarder>(
      context: context,
      builder: (_) => _ForwarderDialog(initial: fwd),
    );
    if (res == null) return;
    _edit(() {
      if (index != null) {
        _dns.forwarders[index] = res;
      } else {
        _dns.forwarders.add(res);
      }
    });
  }

  Future<void> _addOrEditCustomList(int? index) async {
    final cur = index != null ? _customLists[index] : null;
    final res = await showDialog<CustomList>(
      context: context,
      builder: (_) => _CustomListDialog(initial: cur),
    );
    if (res == null) return;
    _edit(() {
      if (index != null) {
        _customLists[index] = res;
      } else {
        _customLists.add(res);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final scheme = Theme.of(context).colorScheme;
    const gap = SizedBox(height: 16);

    return PageFrame(
      title: l.dnsTitle,
      subtitle: l.dnsSubtitle,
      actions: [
        if (_dirty) Chip(label: Text(l.policyUnsaved), avatar: const Icon(Icons.edit_note, size: 18)),
        OutlinedButton.icon(
          key: const ValueKey('dns_reload'),
          onPressed: _reload,
          icon: const Icon(Icons.restore),
          label: Text(l.actionReload),
        ),
        FilledButton.icon(
          key: const ValueKey('dns_save'),
          onPressed: _saving || !_dirty ? null : _save,
          icon: const Icon(Icons.save),
          label: Text(l.actionSave),
        ),
      ],
      child: ListView(
        padding: const EdgeInsets.symmetric(vertical: 12),
        children: [
          if (_error != null)
            Container(
              margin: const EdgeInsets.only(bottom: 12),
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(color: scheme.errorContainer, borderRadius: BorderRadius.circular(12)),
              child: SelectableText(_error!, style: TextStyle(color: scheme.onErrorContainer)),
            ),
          _buildResolverSection(context),
          gap,
          _buildInternalZoneSection(context),
          gap,
          _buildBlocklistsSection(context),
          gap,
          _buildDomainOverridesSection(context),
          gap,
        ],
      ),
    );
  }

  Widget _buildResolverSection(BuildContext context) {
    final l = context.l10n;
    return SectionCard(
      title: l.dnsResolver,
      children: [
        DropdownButtonFormField<String>(
          key: const ValueKey('dns_block_response'),
          initialValue: _dns.blockResponse.isEmpty ? 'nxdomain' : _dns.blockResponse,
          decoration: InputDecoration(labelText: l.dnsBlockResponse, border: const OutlineInputBorder()),
          items: [
            DropdownMenuItem(value: 'nxdomain', child: Text(l.dnsBlockResponseNxdomain)),
            DropdownMenuItem(value: 'zero', child: Text(l.dnsBlockResponseZero)),
          ],
          onChanged: (v) {
            if (v != null) {
              _edit(() => _dns.blockResponse = v);
            }
          },
        ),
        const SizedBox(height: 8),
        SwitchListTile(
          key: const ValueKey('dns_redirect_queries'),
          title: Text(l.dnsRedirectQueries),
          subtitle: Text(l.dnsRedirectQueriesHelp),
          value: _dns.redirectQueries,
          onChanged: (v) => _edit(() => _dns.redirectQueries = v),
        ),
        SwitchListTile(
          key: const ValueKey('dns_log_queries'),
          title: Text(l.dnsLogQueries),
          subtitle: Text(l.dnsLogQueriesHelp),
          value: _dns.logQueries,
          onChanged: (v) => _edit(() => _dns.logQueries = v),
        ),
      ],
    );
  }

  Widget _buildInternalZoneSection(BuildContext context) {
    final l = context.l10n;
    return SectionCard(
      title: l.dnsInternalZone,
      children: [
        TextFormField(
          key: const ValueKey('dns_zone'),
          controller: _zoneCtrl,
          decoration: InputDecoration(
            labelText: l.dnsZoneName,
            helperText: l.dnsZoneHelp,
            border: const OutlineInputBorder(),
          ),
          onChanged: (v) => _edit(() => _dns.zone = v.trim()),
        ),
        const SizedBox(height: 20),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(l.dnsRecords, style: Theme.of(context).textTheme.titleSmall),
            FilledButton.tonalIcon(
              key: const ValueKey('record_add'),
              onPressed: () => _addOrEditRecord(null),
              icon: const Icon(Icons.add),
              label: Text(l.actionAdd),
            ),
          ],
        ),
        const SizedBox(height: 8),
        if (_dns.records.isEmpty)
          Padding(padding: const EdgeInsets.symmetric(vertical: 8), child: Text(l.emptyNothingHere))
        else
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              columns: [
                DataColumn(label: Text(l.dnsRecordName)),
                DataColumn(label: Text(l.dnsRecordType)),
                DataColumn(label: Text(l.dnsRecordValue)),
                DataColumn(label: Text(l.dnsRecordTtl), numeric: true),
                const DataColumn(label: SizedBox.shrink()),
              ],
              rows: [
                for (final (i, r) in _dns.records.indexed)
                  DataRow(
                    key: ValueKey('record_row_${r.name}'),
                    cells: [
                      DataCell(Text(r.name)),
                      DataCell(Text(r.type)),
                      DataCell(Text(r.value)),
                      DataCell(Text(r.ttl == 0 ? '300 (default)' : '${r.ttl}')),
                      DataCell(
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            IconButton(
                              key: ValueKey('record_edit_${r.name}'),
                              tooltip: l.actionEdit,
                              icon: const Icon(Icons.edit),
                              onPressed: () => _addOrEditRecord(i),
                            ),
                            IconButton(
                              key: ValueKey('record_delete_${r.name}'),
                              tooltip: l.actionDelete,
                              icon: const Icon(Icons.delete_outline),
                              onPressed: () => _edit(() => _dns.records.removeAt(i)),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
              ],
            ),
          ),
        const SizedBox(height: 24),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(l.dnsForwarders, style: Theme.of(context).textTheme.titleSmall),
            FilledButton.tonalIcon(
              key: const ValueKey('forwarder_add'),
              onPressed: () => _addOrEditForwarder(null),
              icon: const Icon(Icons.add),
              label: Text(l.actionAdd),
            ),
          ],
        ),
        const SizedBox(height: 8),
        if (_dns.forwarders.isEmpty)
          Padding(padding: const EdgeInsets.symmetric(vertical: 8), child: Text(l.emptyNothingHere))
        else
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              columns: [
                DataColumn(label: Text(l.dnsForwarderZone)),
                DataColumn(label: Text(l.dnsForwarderServers)),
                const DataColumn(label: SizedBox.shrink()),
              ],
              rows: [
                for (final (i, f) in _dns.forwarders.indexed)
                  DataRow(
                    key: ValueKey('forwarder_row_${f.zone}'),
                    cells: [
                      DataCell(Text(f.zone)),
                      DataCell(Text(f.servers.join(', '))),
                      DataCell(
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            IconButton(
                              key: ValueKey('forwarder_edit_${f.zone}'),
                              tooltip: l.actionEdit,
                              icon: const Icon(Icons.edit),
                              onPressed: () => _addOrEditForwarder(i),
                            ),
                            IconButton(
                              key: ValueKey('forwarder_delete_${f.zone}'),
                              tooltip: l.actionDelete,
                              icon: const Icon(Icons.delete_outline),
                              onPressed: () => _edit(() => _dns.forwarders.removeAt(i)),
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

  Widget _buildBlocklistsSection(BuildContext context) {
    final l = context.l10n;
    final builtin = ref.watch(blocklistsProvider);

    return SectionCard(
      title: l.dnsSecurityBlocklists,
      children: [
        Text(l.dnsBuiltinLists, style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 8),
        builtin.when(
          data: (lists) {
            if (lists.isEmpty) {
              return Text(l.dnsBuiltinEmpty);
            }
            return Column(
              children: [
                for (final b in lists)
                  SwitchListTile(
                    key: ValueKey('builtin_switch_${b.id}'),
                    title: Text(b.title),
                    subtitle: Text(b.licence.isNotEmpty ? '${b.licence} · ${b.url}' : b.url),
                    value: _builtinLists.contains(b.id),
                    onChanged: (v) => _edit(() {
                      if (v) {
                        if (!_builtinLists.contains(b.id)) _builtinLists.add(b.id);
                      } else {
                        _builtinLists.remove(b.id);
                      }
                    }),
                  ),
              ],
            );
          },
          loading: () => const Center(
            child: Padding(padding: EdgeInsets.all(12), child: CircularProgressIndicator()),
          ),
          error: (e, _) => SelectableText(context.l10n.msgError(errorText(e))),
        ),
        const SizedBox(height: 24),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(l.dnsCustomLists, style: Theme.of(context).textTheme.titleSmall),
            FilledButton.tonalIcon(
              key: const ValueKey('custom_list_add'),
              onPressed: () => _addOrEditCustomList(null),
              icon: const Icon(Icons.add),
              label: Text(l.actionAdd),
            ),
          ],
        ),
        const SizedBox(height: 8),
        if (_customLists.isEmpty)
          Padding(padding: const EdgeInsets.symmetric(vertical: 8), child: Text(l.emptyNothingHere))
        else
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              columns: [
                DataColumn(label: Text(l.dnsCustomListId)),
                DataColumn(label: Text(l.dnsCustomListTitle)),
                DataColumn(label: Text(l.dnsCustomListUrl)),
                const DataColumn(label: SizedBox.shrink()),
              ],
              rows: [
                for (final (i, cl) in _customLists.indexed)
                  DataRow(
                    key: ValueKey('custom_list_row_${cl.id}'),
                    cells: [
                      DataCell(Text(cl.id)),
                      DataCell(Text(cl.title.isEmpty ? '—' : cl.title)),
                      DataCell(Text(cl.url)),
                      DataCell(
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            IconButton(
                              key: ValueKey('custom_list_edit_${cl.id}'),
                              tooltip: l.actionEdit,
                              icon: const Icon(Icons.edit),
                              onPressed: () => _addOrEditCustomList(i),
                            ),
                            IconButton(
                              key: ValueKey('custom_list_delete_${cl.id}'),
                              tooltip: l.actionDelete,
                              icon: const Icon(Icons.delete_outline),
                              onPressed: () => _edit(() => _customLists.removeAt(i)),
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

  Widget _buildDomainOverridesSection(BuildContext context) {
    final l = context.l10n;

    return SectionCard(
      title: l.dnsDomainOverrides,
      children: [
        Text(l.dnsAllowDomains, style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            for (final d in _dns.allowDomains)
              InputChip(
                key: ValueKey('allow_chip_$d'),
                label: Text(d),
                onDeleted: () => _edit(() => _dns.allowDomains.remove(d)),
              ),
          ],
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: TextField(
                key: const ValueKey('allow_domain_input'),
                controller: _allowDomainCtrl,
                decoration: InputDecoration(
                  hintText: l.dnsDomainHint,
                  isDense: true,
                  border: const OutlineInputBorder(),
                ),
                onSubmitted: (_) => _addAllowDomain(),
              ),
            ),
            const SizedBox(width: 8),
            IconButton(
              key: const ValueKey('allow_domain_add'),
              tooltip: l.dnsAddDomain,
              icon: const Icon(Icons.add),
              onPressed: _addAllowDomain,
            ),
          ],
        ),
        const SizedBox(height: 24),
        Text(l.dnsBlockDomains, style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            for (final d in _dns.blockDomains)
              InputChip(
                key: ValueKey('block_chip_$d'),
                label: Text(d),
                onDeleted: () => _edit(() => _dns.blockDomains.remove(d)),
              ),
          ],
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: TextField(
                key: const ValueKey('block_domain_input'),
                controller: _blockDomainCtrl,
                decoration: InputDecoration(
                  hintText: l.dnsDomainHint,
                  isDense: true,
                  border: const OutlineInputBorder(),
                ),
                onSubmitted: (_) => _addBlockDomain(),
              ),
            ),
            const SizedBox(width: 8),
            IconButton(
              key: const ValueKey('block_domain_add'),
              tooltip: l.dnsAddDomain,
              icon: const Icon(Icons.add),
              onPressed: _addBlockDomain,
            ),
          ],
        ),
      ],
    );
  }
}

class _RecordDialog extends StatefulWidget {
  const _RecordDialog({this.initial});

  final DnsRecord? initial;

  @override
  State<_RecordDialog> createState() => _RecordDialogState();
}

class _RecordDialogState extends State<_RecordDialog> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _nameCtrl = TextEditingController(text: widget.initial?.name ?? '');
  late String _type = widget.initial?.type.isNotEmpty == true ? widget.initial!.type : 'A';
  late final TextEditingController _valueCtrl = TextEditingController(text: widget.initial?.value ?? '');
  late final TextEditingController _ttlCtrl = TextEditingController(
    text: (widget.initial != null && widget.initial!.ttl > 0) ? '${widget.initial!.ttl}' : '',
  );

  @override
  void dispose() {
    _nameCtrl.dispose();
    _valueCtrl.dispose();
    _ttlCtrl.dispose();
    super.dispose();
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) return;
    final ttlVal = int.tryParse(_ttlCtrl.text.trim()) ?? 0;
    Navigator.pop(
      context,
      DnsRecord(name: _nameCtrl.text.trim(), type: _type, value: _valueCtrl.text.trim(), ttl: ttlVal),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final isNew = widget.initial == null;

    return AlertDialog(
      title: Text(isNew ? l.dnsAddRecord : l.dnsEditRecord),
      content: SizedBox(
        width: 440,
        child: Form(
          key: _formKey,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextFormField(
                key: const ValueKey('record_name'),
                controller: _nameCtrl,
                decoration: InputDecoration(labelText: l.dnsRecordName, border: const OutlineInputBorder()),
                validator: (s) => (s == null || s.trim().isEmpty) ? l.dnsErrorNameRequired : null,
              ),
              const SizedBox(height: 12),
              DropdownButtonFormField<String>(
                key: const ValueKey('record_type'),
                initialValue: _type,
                decoration: InputDecoration(labelText: l.dnsRecordType, border: const OutlineInputBorder()),
                items: const [
                  DropdownMenuItem(value: 'A', child: Text('A')),
                  DropdownMenuItem(value: 'AAAA', child: Text('AAAA')),
                  DropdownMenuItem(value: 'CNAME', child: Text('CNAME')),
                  DropdownMenuItem(value: 'TXT', child: Text('TXT')),
                ],
                onChanged: (v) {
                  if (v != null) {
                    setState(() => _type = v);
                  }
                },
              ),
              const SizedBox(height: 12),
              TextFormField(
                key: const ValueKey('record_value'),
                controller: _valueCtrl,
                decoration: InputDecoration(labelText: l.dnsRecordValue, border: const OutlineInputBorder()),
                validator: (s) {
                  final v = s?.trim() ?? '';
                  if (v.isEmpty) return l.dnsErrorValueRequired;
                  if (_type == 'A') {
                    if (!isValidIPv4(v)) return l.dnsErrorInvalidIpv4;
                  } else if (_type == 'AAAA') {
                    if (!isValidIPv6(v)) return l.dnsErrorInvalidIpv6;
                  }
                  return null;
                },
              ),
              const SizedBox(height: 12),
              TextFormField(
                key: const ValueKey('record_ttl'),
                controller: _ttlCtrl,
                decoration: InputDecoration(
                  labelText: l.dnsRecordTtl,
                  hintText: '300',
                  border: const OutlineInputBorder(),
                ),
                validator: (s) {
                  final v = s?.trim() ?? '';
                  if (v.isEmpty) return null;
                  final n = int.tryParse(v);
                  if (n == null || n < 0 || n > 86400) return l.dnsErrorInvalidTtl;
                  return null;
                },
              ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(l.actionCancel)),
        FilledButton(
          key: const ValueKey('record_dialog_submit'),
          onPressed: _submit,
          child: Text(isNew ? l.actionAdd : l.actionSave),
        ),
      ],
    );
  }
}

class _ForwarderDialog extends StatefulWidget {
  const _ForwarderDialog({this.initial});

  final DnsForwarder? initial;

  @override
  State<_ForwarderDialog> createState() => _ForwarderDialogState();
}

class _ForwarderDialogState extends State<_ForwarderDialog> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _zoneCtrl = TextEditingController(text: widget.initial?.zone ?? '');
  late final TextEditingController _serversCtrl = TextEditingController(text: widget.initial?.servers.join(', ') ?? '');

  @override
  void dispose() {
    _zoneCtrl.dispose();
    _serversCtrl.dispose();
    super.dispose();
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) return;
    Navigator.pop(context, DnsForwarder(zone: _zoneCtrl.text.trim(), servers: _splitServers(_serversCtrl.text)));
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final isNew = widget.initial == null;

    return AlertDialog(
      title: Text(isNew ? l.dnsAddForwarder : l.dnsEditForwarder),
      content: SizedBox(
        width: 440,
        child: Form(
          key: _formKey,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextFormField(
                key: const ValueKey('forwarder_zone'),
                controller: _zoneCtrl,
                decoration: InputDecoration(labelText: l.dnsForwarderZone, border: const OutlineInputBorder()),
                validator: (s) => (s == null || s.trim().isEmpty) ? l.dnsErrorZoneRequired : null,
              ),
              const SizedBox(height: 12),
              TextFormField(
                key: const ValueKey('forwarder_servers'),
                controller: _serversCtrl,
                decoration: InputDecoration(
                  labelText: l.dnsForwarderServers,
                  hintText: '10.0.0.1, 10.0.0.2:53',
                  border: const OutlineInputBorder(),
                ),
                validator: (s) {
                  final srvs = _splitServers(s ?? '');
                  if (srvs.isEmpty) return l.dnsErrorInvalidServers;
                  for (final srv in srvs) {
                    if (!isValidIPOrIPPort(srv)) return l.dnsErrorInvalidServers;
                  }
                  return null;
                },
              ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(l.actionCancel)),
        FilledButton(
          key: const ValueKey('forwarder_dialog_submit'),
          onPressed: _submit,
          child: Text(isNew ? l.actionAdd : l.actionSave),
        ),
      ],
    );
  }
}

class _CustomListDialog extends StatefulWidget {
  const _CustomListDialog({this.initial});

  final CustomList? initial;

  @override
  State<_CustomListDialog> createState() => _CustomListDialogState();
}

class _CustomListDialogState extends State<_CustomListDialog> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _idCtrl = TextEditingController(text: widget.initial?.id ?? '');
  late final TextEditingController _titleCtrl = TextEditingController(text: widget.initial?.title ?? '');
  late final TextEditingController _urlCtrl = TextEditingController(text: widget.initial?.url ?? '');

  @override
  void dispose() {
    _idCtrl.dispose();
    _titleCtrl.dispose();
    _urlCtrl.dispose();
    super.dispose();
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) return;
    Navigator.pop(
      context,
      CustomList(id: _idCtrl.text.trim(), title: _titleCtrl.text.trim(), url: _urlCtrl.text.trim()),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final isNew = widget.initial == null;

    return AlertDialog(
      title: Text(isNew ? l.dnsAddCustomList : l.dnsEditCustomList),
      content: SizedBox(
        width: 440,
        child: Form(
          key: _formKey,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextFormField(
                key: const ValueKey('custom_list_id'),
                controller: _idCtrl,
                enabled: isNew,
                decoration: InputDecoration(
                  labelText: l.dnsCustomListId,
                  hintText: 'corp-bad',
                  border: const OutlineInputBorder(),
                ),
                validator: (s) {
                  final v = s?.trim() ?? '';
                  if (v.isEmpty) return l.fieldRequired;
                  if (!RegExp(r'^[a-z0-9][a-z0-9-]*$').hasMatch(v)) {
                    return l.dnsErrorInvalidListId;
                  }
                  return null;
                },
              ),
              const SizedBox(height: 12),
              TextFormField(
                key: const ValueKey('custom_list_title'),
                controller: _titleCtrl,
                decoration: InputDecoration(labelText: l.dnsCustomListTitle, border: const OutlineInputBorder()),
              ),
              const SizedBox(height: 12),
              TextFormField(
                key: const ValueKey('custom_list_url'),
                controller: _urlCtrl,
                decoration: InputDecoration(
                  labelText: l.dnsCustomListUrl,
                  hintText: 'https://lists.example.com/hosts.txt',
                  border: const OutlineInputBorder(),
                ),
                validator: (s) {
                  final v = s?.trim() ?? '';
                  if (v.isEmpty) return l.fieldRequired;
                  final uri = Uri.tryParse(v);
                  if (uri == null || uri.scheme != 'https' || uri.host.isEmpty) {
                    return l.dnsErrorInvalidHttpsUrl;
                  }
                  return null;
                },
              ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(l.actionCancel)),
        FilledButton(
          key: const ValueKey('custom_list_dialog_submit'),
          onPressed: _submit,
          child: Text(isNew ? l.actionAdd : l.actionSave),
        ),
      ],
    );
  }
}

List<String> _splitServers(String s) => [
  for (final x in s.split(RegExp(r'[,\s]+')))
    if (x.trim().isNotEmpty) x.trim(),
];

bool isValidIPv4(String s) {
  final parts = s.split('.');
  if (parts.length != 4) return false;
  for (final p in parts) {
    final n = int.tryParse(p);
    if (n == null || n < 0 || n > 255 || (p.length > 1 && p.startsWith('0'))) {
      return false;
    }
  }
  return true;
}

bool isValidIPv6(String s) {
  try {
    Uri.parseIPv6Address(s);
    return true;
  } on FormatException {
    return false;
  }
}

bool isValidIPOrIPPort(String s) {
  s = s.trim();
  if (s.isEmpty) return false;
  if (s.startsWith('[')) {
    final closeIdx = s.indexOf(']');
    if (closeIdx == -1) return false;
    final ipStr = s.substring(1, closeIdx);
    if (!isValidIPv6(ipStr)) return false;
    final rest = s.substring(closeIdx + 1);
    if (rest.isEmpty) return true;
    if (!rest.startsWith(':')) return false;
    final port = int.tryParse(rest.substring(1));
    return port != null && port > 0 && port <= 65535;
  }
  if (s.contains(':')) {
    final colonCount = ':'.allMatches(s).length;
    if (colonCount == 1) {
      final parts = s.split(':');
      if (!isValidIPv4(parts[0])) return false;
      final port = int.tryParse(parts[1]);
      return port != null && port > 0 && port <= 65535;
    } else {
      return isValidIPv6(s);
    }
  }
  return isValidIPv4(s);
}
