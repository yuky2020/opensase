import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../api/admin_models.dart';
import '../data/enroll_link.dart';
import '../data/providers.dart';
import '../data/session.dart';
import 'common.dart';
import 'fields_dialog.dart';

class UsersScreen extends ConsumerWidget {
  const UsersScreen({super.key});

  Future<void> _create(BuildContext context, WidgetRef ref, String tenant) async {
    final l = context.l10n;
    final v = await showFieldsDialog(
      context,
      title: l.usersCreate,
      fields: [
        FieldSpec('email', l.fieldEmail, validator: (s) => s.contains('@') ? null : l.fieldRequired),
        FieldSpec('name', l.fieldName, validator: (s) => s.isEmpty ? l.fieldRequired : null),
      ],
    );
    if (v == null || !context.mounted) return;
    final u = await runAction(
      context,
      ref,
      () => ref.read(apiProvider).createUser(tenant, AdminUser(email: v['email']!, name: v['name']!)),
    );
    if (u != null) ref.invalidate(usersProvider(tenant));
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    return TenantScoped(
      builder: (tenant) {
        final users = ref.watch(usersProvider(tenant));
        return PageFrame(
          title: l.navUsers,
          actions: [
            IconButton(
              tooltip: l.actionRefresh,
              onPressed: () => ref.invalidate(usersProvider(tenant)),
              icon: const Icon(Icons.refresh),
            ),
            FilledButton.icon(
              onPressed: () => _create(context, ref, tenant),
              icon: const Icon(Icons.person_add),
              label: Text(l.usersCreate),
            ),
          ],
          child: AsyncBody(
            value: users,
            onRetry: () => ref.invalidate(usersProvider(tenant)),
            builder: (list) => list.isEmpty
                ? EmptyState(text: l.emptyNothingHere)
                : ScrollTable(
                    columns: [
                      DataColumn(label: Text(l.fieldId)),
                      DataColumn(label: Text(l.fieldEmail)),
                      DataColumn(label: Text(l.fieldName)),
                      const DataColumn(label: SizedBox.shrink()),
                    ],
                    rows: [
                      for (final u in list)
                        DataRow(
                          cells: [
                            DataCell(SelectableText(u.id)),
                            DataCell(Text(u.email)),
                            DataCell(Text(u.name)),
                            DataCell(
                              TextButton.icon(
                                key: Key('provision_${u.id}'),
                                onPressed: () => showDialog<void>(
                                  context: context,
                                  barrierDismissible: false,
                                  builder: (_) => ProvisioningKeyDialog(tenant: tenant, user: u),
                                ),
                                icon: const Icon(Icons.qr_code_2),
                                label: Text(l.usersProvisioningKey),
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

/// Requests a provisioning key for a user and shows it once, with the enrollment QR code.
class ProvisioningKeyDialog extends ConsumerStatefulWidget {
  const ProvisioningKeyDialog({super.key, required this.tenant, required this.user});

  final String tenant;
  final AdminUser user;

  @override
  ConsumerState<ProvisioningKeyDialog> createState() => _ProvisioningKeyDialogState();
}

class _ProvisioningKeyDialogState extends ConsumerState<ProvisioningKeyDialog> {
  final _uses = TextEditingController(text: '1');
  final _hours = TextEditingController(text: '24');
  ProvisioningKey? _key;
  bool _busy = false;

  @override
  void dispose() {
    _uses.dispose();
    _hours.dispose();
    super.dispose();
  }

  Future<void> _generate() async {
    final uses = int.tryParse(_uses.text.trim()) ?? 1;
    final hours = int.tryParse(_hours.text.trim()) ?? 24;
    setState(() => _busy = true);
    final k = await runAction(
      context,
      ref,
      () => ref
          .read(apiProvider)
          .createProvisioningKey(
            widget.tenant,
            ProvisioningKeyRequest(userId: widget.user.id, maxUses: uses < 1 ? 1 : uses, validFor: hours * 3600),
          ),
    );
    if (mounted) {
      setState(() {
        _busy = false;
        _key = k;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final key = _key;
    return AlertDialog(
      title: Text(l.provTitle(widget.user.email.isEmpty ? widget.user.id : widget.user.email)),
      content: SizedBox(
        width: 440,
        child: SingleChildScrollView(child: key == null ? _request(context) : _result(context, key)),
      ),
      actions: [
        if (key == null) ...[
          TextButton(onPressed: () => Navigator.pop(context), child: Text(l.actionCancel)),
          FilledButton(onPressed: _busy ? null : _generate, child: Text(l.provGenerate)),
        ] else
          FilledButton(onPressed: () => Navigator.pop(context), child: Text(l.actionClose)),
      ],
    );
  }

  Widget _request(BuildContext context) {
    final l = context.l10n;
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        TextField(
          controller: _uses,
          keyboardType: TextInputType.number,
          decoration: InputDecoration(labelText: l.provMaxUses, border: const OutlineInputBorder()),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _hours,
          keyboardType: TextInputType.number,
          decoration: InputDecoration(labelText: l.provValidHours, border: const OutlineInputBorder()),
        ),
      ],
    );
  }

  Widget _result(BuildContext context, ProvisioningKey key) {
    final l = context.l10n;
    final control = ref.watch(effectiveControlUrlProvider);
    final controlOk = controlUrlError(control) == null;
    final link = controlOk ? enrollLink(controlUrl: control, key: key.key) : null;
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(l.provShownOnce, style: TextStyle(color: Theme.of(context).colorScheme.error)),
        const SizedBox(height: 12),
        OneTimeSecret(secret: key.key),
        const SizedBox(height: 4),
        Text(l.provExpires(formatTime(context, key.expiresAt)), style: Theme.of(context).textTheme.bodySmall),
        const SizedBox(height: 16),
        if (link != null) ...[
          Center(
            child: Container(
              color: Colors.white,
              padding: const EdgeInsets.all(12),
              child: QrImageView(key: const Key('enroll_qr'), data: link, size: 240),
            ),
          ),
          const SizedBox(height: 8),
          Text(l.provScan, textAlign: TextAlign.center),
          const SizedBox(height: 12),
          Text(l.provLink, style: Theme.of(context).textTheme.labelMedium),
          OneTimeSecret(secret: link),
        ] else
          Text(l.provNoControlUrl),
      ],
    );
  }
}
