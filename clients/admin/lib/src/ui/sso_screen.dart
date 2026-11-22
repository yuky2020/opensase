import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_models.dart';
import '../data/providers.dart';
import '../data/session.dart';
import 'common.dart';
import 'theme.dart';

/// Single sign-on configuration screen for tenant administrators (issue #17, slice C, ADR-0031).
class SsoScreen extends ConsumerWidget {
  const SsoScreen({super.key});

  Future<void> _edit(BuildContext context, WidgetRef ref, String tenant, TenantOidc? existing) async {
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => _SsoEditDialog(tenant: tenant, existing: existing),
    );
  }

  Future<void> _delete(BuildContext context, WidgetRef ref, String tenant) async {
    final l = context.l10n;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l.ssoDeleteConfirmTitle),
        content: Text(l.ssoDeleteConfirmBody),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: Text(l.actionCancel)),
          FilledButton(
            key: const Key('confirm_delete'),
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(ctx).colorScheme.error,
              foregroundColor: Theme.of(ctx).colorScheme.onError,
            ),
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(l.actionDelete),
          ),
        ],
      ),
    );
    if (confirmed != true || !context.mounted) return;
    await runAction(context, ref, () => ref.read(apiProvider).deleteTenantOidc(tenant));
    if (context.mounted) {
      showSnack(context, l.ssoDeleted);
      ref.invalidate(tenantOidcProvider(tenant));
    }
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    return TenantScoped(
      builder: (tenant) {
        final oidcAsync = ref.watch(tenantOidcProvider(tenant));
        final oidc = oidcAsync.value;
        return PageFrame(
          title: l.navSso,
          subtitle: l.ssoSubtitle,
          actions: [
            IconButton(
              tooltip: l.actionRefresh,
              onPressed: () => ref.invalidate(tenantOidcProvider(tenant)),
              icon: const Icon(Icons.refresh),
            ),
            if (oidc != null) ...[
              OutlinedButton.icon(
                key: const Key('sso_delete'),
                onPressed: () => _delete(context, ref, tenant),
                icon: const Icon(Icons.delete_outline),
                label: Text(l.actionDelete),
              ),
              FilledButton.icon(
                key: const Key('sso_edit'),
                onPressed: () => _edit(context, ref, tenant, oidc),
                icon: const Icon(Icons.edit),
                label: Text(l.actionEdit),
              ),
            ] else if (oidcAsync.hasValue) ...[
              FilledButton.icon(
                key: const Key('sso_configure'),
                onPressed: () => _edit(context, ref, tenant, null),
                icon: const Icon(Icons.add),
                label: Text(l.ssoConfigure),
              ),
            ],
          ],
          child: AsyncBody(
            value: oidcAsync,
            onRetry: () => ref.invalidate(tenantOidcProvider(tenant)),
            builder: (data) {
              if (data == null) {
                return Center(
                  child: Padding(
                    padding: const EdgeInsets.all(32),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.badge_outlined, size: 48, color: Theme.of(context).colorScheme.outline),
                        const SizedBox(height: 12),
                        Text(l.ssoNotConfigured, textAlign: TextAlign.center),
                        const SizedBox(height: 16),
                        FilledButton.icon(
                          key: const Key('sso_configure_empty'),
                          onPressed: () => _edit(context, ref, tenant, null),
                          icon: const Icon(Icons.add),
                          label: Text(l.ssoConfigure),
                        ),
                      ],
                    ),
                  ),
                );
              }

              final sortedGroups = data.groupRoles.keys.toList()..sort();
              return SingleChildScrollView(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(16),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(l.ssoIssuer, style: Theme.of(context).textTheme.labelLarge),
                            const SizedBox(height: 4),
                            SelectableText(data.issuer, key: const Key('sso_view_issuer')),
                            const Divider(height: 24),
                            Text(l.ssoClientId, style: Theme.of(context).textTheme.labelLarge),
                            const SizedBox(height: 4),
                            SelectableText(data.clientId, key: const Key('sso_view_client_id')),
                            const Divider(height: 24),
                            Text(l.ssoSecretSet, style: Theme.of(context).textTheme.labelLarge),
                            const SizedBox(height: 4),
                            Row(
                              children: [
                                StatusChip(
                                  label: data.hasSecret ? l.yes : l.no,
                                  color: data.hasSecret
                                      ? context.verdicts.allow
                                      : Theme.of(context).colorScheme.outline,
                                ),
                              ],
                            ),
                            const Divider(height: 24),
                            Text(l.ssoRedirectUrl, style: Theme.of(context).textTheme.labelLarge),
                            const SizedBox(height: 4),
                            Text(
                              l.ssoRedirectUrlHelp,
                              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                color: Theme.of(context).colorScheme.onSurfaceVariant,
                              ),
                            ),
                            const SizedBox(height: 8),
                            Container(
                              padding: const EdgeInsets.fromLTRB(12, 4, 4, 4),
                              decoration: BoxDecoration(
                                color: Theme.of(context).colorScheme.surfaceContainerHighest,
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: Row(
                                children: [
                                  Expanded(
                                    child: SelectableText(
                                      data.redirectUrl,
                                      key: const Key('sso_view_redirect_url'),
                                      style: const TextStyle(fontFamily: 'monospace'),
                                    ),
                                  ),
                                  IconButton(
                                    tooltip: l.actionCopy,
                                    icon: const Icon(Icons.copy),
                                    onPressed: () async {
                                      await Clipboard.setData(ClipboardData(text: data.redirectUrl));
                                      if (context.mounted) showSnack(context, l.msgCopied);
                                    },
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 16),
                    Text(l.ssoGroupRoles, style: Theme.of(context).textTheme.titleMedium),
                    const SizedBox(height: 8),
                    ScrollTable(
                      columns: [
                        DataColumn(label: Text(l.ssoGroup)),
                        DataColumn(label: Text(l.ssoRole)),
                      ],
                      rows: [
                        for (final grp in sortedGroups)
                          DataRow(
                            cells: [
                              DataCell(SelectableText(grp)),
                              DataCell(Text(data.groupRoles[grp] ?? '')),
                            ],
                          ),
                      ],
                    ),
                  ],
                ),
              );
            },
          ),
        );
      },
    );
  }
}

class _GroupRoleRow {
  _GroupRoleRow({required this.group, required this.role});

  final TextEditingController group;
  String role;
}

class _SsoEditDialog extends ConsumerStatefulWidget {
  const _SsoEditDialog({required this.tenant, this.existing});

  final String tenant;
  final TenantOidc? existing;

  @override
  ConsumerState<_SsoEditDialog> createState() => _SsoEditDialogState();
}

class _SsoEditDialogState extends ConsumerState<_SsoEditDialog> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _issuer;
  late final TextEditingController _clientId;
  final _clientSecret = TextEditingController();
  bool _obscureSecret = true;
  bool _busy = false;
  final _rows = <_GroupRoleRow>[];

  @override
  void initState() {
    super.initState();
    _issuer = TextEditingController(text: widget.existing?.issuer ?? '');
    _clientId = TextEditingController(text: widget.existing?.clientId ?? '');
    if (widget.existing != null && widget.existing!.groupRoles.isNotEmpty) {
      final sorted = widget.existing!.groupRoles.keys.toList()..sort();
      for (final g in sorted) {
        _rows.add(_GroupRoleRow(
          group: TextEditingController(text: g),
          role: widget.existing!.groupRoles[g] ?? 'viewer',
        ));
      }
    } else {
      _rows.add(_GroupRoleRow(group: TextEditingController(), role: 'admin'));
    }
  }

  @override
  void dispose() {
    _issuer.dispose();
    _clientId.dispose();
    _clientSecret.dispose();
    for (final r in _rows) {
      r.group.dispose();
    }
    super.dispose();
  }

  void _addRow() {
    setState(() {
      _rows.add(_GroupRoleRow(group: TextEditingController(), role: 'viewer'));
    });
  }

  void _removeRow(int index) {
    if (_rows.length <= 1) return;
    setState(() {
      final r = _rows.removeAt(index);
      r.group.dispose();
    });
  }

  Future<void> _save() async {
    final l = context.l10n;
    if (!_formKey.currentState!.validate()) return;
    if (_rows.isEmpty || _rows.every((r) => r.group.text.trim().isEmpty)) {
      showSnack(context, l.ssoErrorGroups);
      return;
    }

    final groupRoles = <String, String>{};
    for (final r in _rows) {
      final g = r.group.text.trim();
      if (g.isNotEmpty) {
        groupRoles[g] = r.role;
      }
    }
    if (groupRoles.isEmpty) {
      showSnack(context, l.ssoErrorGroups);
      return;
    }

    setState(() => _busy = true);
    try {
      final oidc = TenantOidc(
        issuer: _issuer.text.trim(),
        clientId: _clientId.text.trim(),
        groupRoles: groupRoles,
      );
      final secret = _clientSecret.text.trim();
      await ref.read(apiProvider).putTenantOidc(
        widget.tenant,
        oidc,
        clientSecret: secret.isEmpty ? null : secret,
      );
      if (mounted) {
        showSnack(context, l.ssoSaved);
        ref.invalidate(tenantOidcProvider(widget.tenant));
        Navigator.pop(context);
      }
    } on Object catch (e) {
      if (mounted) showSnack(context, errorText(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return AlertDialog(
      title: Text(l.ssoEditTitle),
      content: SizedBox(
        width: 520,
        child: Form(
          key: _formKey,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                TextFormField(
                  key: const Key('sso_field_issuer'),
                  controller: _issuer,
                  decoration: InputDecoration(
                    labelText: l.ssoIssuer,
                    hintText: 'https://idp.example.com',
                    border: const OutlineInputBorder(),
                  ),
                  validator: (v) {
                    final s = v?.trim() ?? '';
                    if (s.isEmpty) return l.fieldRequired;
                    final u = Uri.tryParse(s);
                    final local = u != null &&
                        (u.host == 'localhost' || u.host == '127.0.0.1' || u.host == '::1');
                    if (u == null || (u.scheme != 'https' && (u.scheme != 'http' || !local))) {
                      return l.ssoErrorIssuer;
                    }
                    return null;
                  },
                ),
                const SizedBox(height: 12),
                TextFormField(
                  key: const Key('sso_field_client_id'),
                  controller: _clientId,
                  decoration: InputDecoration(
                    labelText: l.ssoClientId,
                    border: const OutlineInputBorder(),
                  ),
                  validator: (v) => (v?.trim().isEmpty ?? true) ? l.ssoErrorClientId : null,
                ),
                const SizedBox(height: 12),
                TextFormField(
                  key: const Key('sso_field_client_secret'),
                  controller: _clientSecret,
                  obscureText: _obscureSecret,
                  decoration: InputDecoration(
                    labelText: l.ssoClientSecret,
                    helperText: l.ssoClientSecretHelp,
                    helperMaxLines: 2,
                    border: const OutlineInputBorder(),
                    suffixIcon: IconButton(
                      icon: Icon(_obscureSecret ? Icons.visibility : Icons.visibility_off),
                      onPressed: () => setState(() => _obscureSecret = !_obscureSecret),
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(l.ssoGroupRoles, style: Theme.of(context).textTheme.titleSmall),
                    TextButton.icon(
                      key: const Key('sso_add_group'),
                      onPressed: _addRow,
                      icon: const Icon(Icons.add, size: 18),
                      label: Text(l.ssoAddGroupMapping),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                for (var i = 0; i < _rows.length; i++) ...[
                  Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(
                          flex: 3,
                          child: TextFormField(
                            key: Key('sso_group_$i'),
                            controller: _rows[i].group,
                            decoration: InputDecoration(
                              labelText: l.ssoGroup,
                              border: const OutlineInputBorder(),
                              contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                            ),
                            validator: (v) => (v?.trim().isEmpty ?? true) ? l.fieldRequired : null,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          flex: 2,
                          child: DropdownButtonFormField<String>(
                            key: Key('sso_role_$i'),
                            initialValue: _rows[i].role,
                            decoration: const InputDecoration(
                              border: OutlineInputBorder(),
                              contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                            ),
                            items: const [
                              DropdownMenuItem(value: 'admin', child: Text('admin')),
                              DropdownMenuItem(value: 'policy-editor', child: Text('policy-editor')),
                              DropdownMenuItem(value: 'viewer', child: Text('viewer')),
                            ],
                            onChanged: (v) {
                              if (v != null) {
                                setState(() => _rows[i].role = v);
                              }
                            },
                          ),
                        ),
                        if (_rows.length > 1) ...[
                          const SizedBox(width: 4),
                          IconButton(
                            key: Key('sso_remove_$i'),
                            icon: const Icon(Icons.remove_circle_outline),
                            tooltip: l.actionDelete,
                            onPressed: () => _removeRow(i),
                          ),
                        ],
                      ],
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
      actions: [
        TextButton(onPressed: _busy ? null : () => Navigator.pop(context), child: Text(l.actionCancel)),
        FilledButton(
          key: const Key('dialog_submit'),
          onPressed: _busy ? null : _save,
          child: _busy
              ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
              : Text(l.actionSave),
        ),
      ],
    );
  }
}
