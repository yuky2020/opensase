import 'package:material_ui/material_ui.dart';

import '../api/admin_models.dart';
import '../api/policy_models.dart';
import '../data/parsers.dart';
import 'common.dart';

InputDecoration _dec(String label, {String? hint, String? helper}) => InputDecoration(
  labelText: label,
  hintText: hint,
  helperText: helper,
  helperMaxLines: 2,
  border: const OutlineInputBorder(),
  alignLabelWithHint: true,
);

String? _portsError(String s) {
  try {
    parsePorts(s);
    return null;
  } on FormatException catch (e) {
    return e.message;
  }
}

String? _listError(String s, String? Function(String) check) {
  for (final d in parseList(s)) {
    final e = check(d);
    if (e != null) return e;
  }
  return null;
}

class _DialogFrame extends StatelessWidget {
  const _DialogFrame({required this.title, required this.formKey, required this.onSave, required this.children});

  final String title;
  final GlobalKey<FormState> formKey;
  final VoidCallback onSave;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return AlertDialog(
      title: Text(title),
      content: SizedBox(
        width: 560,
        child: Form(
          key: formKey,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [for (final c in children) Padding(padding: const EdgeInsets.only(bottom: 12), child: c)],
            ),
          ),
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(l.actionCancel)),
        FilledButton(key: const Key('dialog_save'), onPressed: onSave, child: Text(l.actionSave)),
      ],
    );
  }
}

Widget _actionDropdown(
  BuildContext context, {
  required String label,
  required String value,
  required ValueChanged<String> onChanged,
  bool allowUnset = false,
  Key? key,
}) {
  final options = [if (allowUnset) '', ...Verdicts.all];
  return DropdownButtonFormField<String>(
    key: key,
    isExpanded: true,
    initialValue: options.contains(value) ? value : options.first,
    decoration: _dec(label),
    items: [for (final a in options) DropdownMenuItem(value: a, child: Text(actionLabel(context, a)))],
    onChanged: (v) => onChanged(v ?? ''),
  );
}

Widget _postureDropdown(
  BuildContext context, {
  required String value,
  required ValueChanged<String> onChanged,
  Key? key,
}) {
  final l = context.l10n;
  final options = const ['', 'compliant', 'noncompliant'];
  String label(String v) => switch (v) {
    'compliant' => l.postureConditionCompliant,
    'noncompliant' => l.postureConditionNoncompliant,
    _ => l.postureConditionAny,
  };
  return DropdownButtonFormField<String>(
    key: key,
    isExpanded: true,
    initialValue: options.contains(value) ? value : options.first,
    decoration: _dec(l.fieldPosture),
    items: [for (final a in options) DropdownMenuItem(value: a, child: Text(label(a)))],
    onChanged: (v) => onChanged(v ?? ''),
  );
}

/// Edits one tenant firewall rule, all Match fields included.
class RuleDialog extends StatefulWidget {
  const RuleDialog({super.key, required this.rule, required this.isNew, required this.existingIds});

  final Rule rule;
  final bool isNew;
  final Set<String> existingIds;

  @override
  State<RuleDialog> createState() => _RuleDialogState();
}

class _RuleDialogState extends State<RuleDialog> {
  final _form = GlobalKey<FormState>();
  late final Rule _r = widget.rule.copy();
  late final _id = TextEditingController(text: _r.id);
  late final _priority = TextEditingController(text: '${_r.priority}');
  late final _desc = TextEditingController(text: _r.description);
  late final _apps = TextEditingController(text: _r.match.apps.join('\n'));
  late final _cidrs = TextEditingController(text: _r.match.cidrs.join('\n'));
  late final _ports = TextEditingController(text: formatPorts(_r.match.ports));
  late final _domains = TextEditingController(text: _r.match.domains.join('\n'));

  @override
  void dispose() {
    for (final c in [_id, _priority, _desc, _apps, _cidrs, _ports, _domains]) {
      c.dispose();
    }
    super.dispose();
  }

  void _save() {
    if (!_form.currentState!.validate()) return;
    _r
      ..id = _id.text.trim()
      ..source = 'tenant'
      ..priority = int.parse(_priority.text.trim())
      ..description = _desc.text.trim()
      ..match.apps = parseList(_apps.text)
      ..match.cidrs = parseList(_cidrs.text)
      ..match.ports = parsePorts(_ports.text)
      ..match.domains = parseList(_domains.text);
    Navigator.pop(context, _r);
  }

  Widget _chips(List<String> all, List<String> selected, String Function(String) label) => Wrap(
    spacing: 8,
    runSpacing: 4,
    children: [
      for (final v in all)
        FilterChip(
          label: Text(label(v)),
          selected: selected.contains(v),
          onSelected: (on) => setState(() => on ? selected.add(v) : selected.remove(v)),
        ),
    ],
  );

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final tt = Theme.of(context).textTheme;
    return _DialogFrame(
      title: widget.isNew ? l.ruleNew : l.ruleEdit,
      formKey: _form,
      onSave: _save,
      children: [
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              flex: 2,
              child: TextFormField(
                key: const Key('rule_id'),
                controller: _id,
                decoration: _dec(l.fieldId),
                validator: (s) {
                  s = s?.trim() ?? '';
                  if (s.isEmpty) return l.fieldRequired;
                  if (s != widget.rule.id && widget.existingIds.contains(s)) return 'duplicate';
                  return null;
                },
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: TextFormField(
                key: const Key('rule_priority'),
                controller: _priority,
                decoration: _dec(l.rulePriority),
                keyboardType: TextInputType.number,
                validator: (s) => int.tryParse(s?.trim() ?? '') == null ? l.fieldRequired : null,
              ),
            ),
          ],
        ),
        _actionDropdown(
          context,
          key: const Key('rule_action'),
          label: l.ruleAction,
          value: _r.action,
          onChanged: (v) => _r.action = v,
        ),
        _postureDropdown(
          context,
          key: const ValueKey('rule_posture'),
          value: _r.posture,
          onChanged: (v) => _r.posture = v,
        ),
        TextFormField(controller: _desc, decoration: _dec(l.ruleDescription)),
        CheckboxListTile(
          contentPadding: EdgeInsets.zero,
          value: _r.log,
          onChanged: (v) => setState(() => _r.log = v ?? false),
          title: Text(l.ruleLog),
        ),
        Text(l.ruleMatch, style: tt.titleSmall),
        TextFormField(
          key: const Key('rule_domains'),
          controller: _domains,
          minLines: 2,
          maxLines: 6,
          decoration: _dec(l.matchDomains, helper: l.policyOnePerLine),
          validator: (s) => _listError(s ?? '', domainError),
        ),
        TextFormField(
          key: const Key('rule_ports'),
          controller: _ports,
          decoration: _dec(l.matchPorts, hint: l.matchPortsHint),
          validator: (s) => _portsError(s ?? ''),
        ),
        TextFormField(
          controller: _cidrs,
          minLines: 1,
          maxLines: 6,
          decoration: _dec(l.matchCidrs, hint: '10.0.0.0/8'),
          validator: (s) => _listError(s ?? '', cidrError),
        ),
        Text(l.matchProtocols, style: tt.labelLarge),
        _chips(Protocols.all, _r.match.protocols, (v) => v.toUpperCase()),
        Text(l.matchNetworks, style: tt.labelLarge),
        _chips(Networks.all, _r.match.networks, (v) => networkLabel(context, v)),
        TextFormField(
          controller: _apps,
          minLines: 1,
          maxLines: 6,
          decoration: _dec(l.matchApps, hint: 'com.example.app'),
        ),
      ],
    );
  }
}

/// Edits one per-app policy (package + verdict per network).
class AppPolicyDialog extends StatefulWidget {
  const AppPolicyDialog({super.key, required this.package, required this.policy, required this.existing});

  final String package;
  final AppPolicy policy;
  final Set<String> existing;

  @override
  State<AppPolicyDialog> createState() => _AppPolicyDialogState();
}

class _AppPolicyDialogState extends State<AppPolicyDialog> {
  final _form = GlobalKey<FormState>();
  late final _pkg = TextEditingController(text: widget.package);
  late final AppPolicy _p = AppPolicy.fromJson(widget.policy.toJson());

  @override
  void dispose() {
    _pkg.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return _DialogFrame(
      title: widget.package.isEmpty ? l.appNew : widget.package,
      formKey: _form,
      onSave: () {
        if (!_form.currentState!.validate()) return;
        Navigator.pop(context, (_pkg.text.trim(), _p));
      },
      children: [
        TextFormField(
          controller: _pkg,
          decoration: _dec(l.appPackage, hint: 'com.example.app'),
          validator: (s) {
            s = s?.trim() ?? '';
            if (s.isEmpty) return l.fieldRequired;
            if (s != widget.package && widget.existing.contains(s)) return 'duplicate';
            return null;
          },
        ),
        _actionDropdown(context, label: l.networkWifi, value: _p.wifi, allowUnset: true, onChanged: (v) => _p.wifi = v),
        _actionDropdown(
          context,
          label: l.networkCellular,
          value: _p.cellular,
          allowUnset: true,
          onChanged: (v) => _p.cellular = v,
        ),
        _actionDropdown(
          context,
          label: l.networkRoaming,
          value: _p.roaming,
          allowUnset: true,
          onChanged: (v) => _p.roaming = v,
        ),
      ],
    );
  }
}

/// Edits one DNS blocklist.
class BlocklistDialog extends StatefulWidget {
  const BlocklistDialog({super.key, required this.list, required this.isNew});

  final Blocklist list;
  final bool isNew;

  @override
  State<BlocklistDialog> createState() => _BlocklistDialogState();
}

class _BlocklistDialogState extends State<BlocklistDialog> {
  final _form = GlobalKey<FormState>();
  late final _id = TextEditingController(text: widget.list.id);
  late final _name = TextEditingController(text: widget.list.name);
  late final _cat = TextEditingController(text: widget.list.category);
  late final _domains = TextEditingController(text: widget.list.domains.join('\n'));

  @override
  void dispose() {
    for (final c in [_id, _name, _cat, _domains]) {
      c.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return _DialogFrame(
      title: widget.isNew ? l.blocklistNew : widget.list.name,
      formKey: _form,
      onSave: () {
        if (!_form.currentState!.validate()) return;
        Navigator.pop(
          context,
          Blocklist(
            id: _id.text.trim(),
            name: _name.text.trim(),
            category: _cat.text.trim(),
            domains: parseList(_domains.text),
          ),
        );
      },
      children: [
        TextFormField(
          controller: _id,
          decoration: _dec(l.fieldId),
          validator: (s) => (s?.trim() ?? '').isEmpty ? l.fieldRequired : null,
        ),
        TextFormField(controller: _name, decoration: _dec(l.fieldName)),
        TextFormField(
          controller: _cat,
          decoration: _dec(l.blocklistCategory, hint: 'ads, trackers, malware, adult'),
        ),
        TextFormField(
          controller: _domains,
          minLines: 4,
          maxLines: 14,
          decoration: _dec(l.matchDomains, helper: l.policyOnePerLine),
          validator: (s) => _listError(s ?? '', domainError),
        ),
      ],
    );
  }
}

/// Edits one ZTNA private app (ADR-0013).
class PrivateAppDialog extends StatefulWidget {
  const PrivateAppDialog({super.key, required this.app, required this.isNew, required this.existingIds});

  final TenantPrivateApp app;
  final bool isNew;
  final Set<String> existingIds;

  @override
  State<PrivateAppDialog> createState() => _PrivateAppDialogState();
}

class _PrivateAppDialogState extends State<PrivateAppDialog> {
  final _form = GlobalKey<FormState>();
  late final _id = TextEditingController(text: widget.app.id);
  late final _name = TextEditingController(text: widget.app.name);
  late final _domains = TextEditingController(text: widget.app.domains.join('\n'));
  late final _ports = TextEditingController(text: formatPorts(widget.app.ports));
  late final _group = TextEditingController(
    text: widget.app.connectorGroup.isEmpty ? 'default' : widget.app.connectorGroup,
  );
  late final _users = TextEditingController(text: widget.app.users.join('\n'));
  late String _posture = widget.app.posture;

  @override
  void dispose() {
    for (final c in [_id, _name, _domains, _ports, _group, _users]) {
      c.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return _DialogFrame(
      title: widget.isNew ? l.privateAppNew : l.privateAppEdit,
      formKey: _form,
      onSave: () {
        if (!_form.currentState!.validate()) return;
        Navigator.pop(
          context,
          TenantPrivateApp(
            id: _id.text.trim(),
            name: _name.text.trim(),
            domains: parseList(_domains.text),
            ports: parsePorts(_ports.text),
            connectorGroup: _group.text.trim(),
            posture: _posture,
            users: parseList(_users.text),
            extra: widget.app.extra,
          ),
        );
      },
      children: [
        TextFormField(
          key: const Key('papp_id'),
          controller: _id,
          decoration: _dec(l.fieldId),
          validator: (s) {
            s = s?.trim() ?? '';
            if (!validId(s)) return l.fieldInvalidId;
            if (s != widget.app.id && widget.existingIds.contains(s)) return 'duplicate';
            return null;
          },
        ),
        TextFormField(key: const Key('papp_name'), controller: _name, decoration: _dec(l.fieldName)),
        TextFormField(
          key: const Key('papp_domains'),
          controller: _domains,
          minLines: 2,
          maxLines: 6,
          decoration: _dec(l.matchDomains, helper: l.policyOnePerLine, hint: 'intranet.acme.internal'),
          validator: (s) => parseList(s ?? '').isEmpty ? l.fieldRequired : _listError(s ?? '', domainError),
        ),
        TextFormField(
          key: const Key('papp_ports'),
          controller: _ports,
          decoration: _dec(l.privateAppPorts, hint: '443, 8080-8090'),
          validator: (s) => parseList(s ?? '').isEmpty ? l.fieldRequired : _portsError(s ?? ''),
        ),
        TextFormField(
          key: const Key('papp_group'),
          controller: _group,
          decoration: _dec(l.privateAppConnectorGroup),
          validator: (s) => (s?.trim() ?? '').isEmpty ? l.fieldRequired : null,
        ),
        _postureDropdown(context, key: const ValueKey('papp_posture'), value: _posture, onChanged: (v) => _posture = v),
        TextFormField(controller: _users, minLines: 1, maxLines: 6, decoration: _dec(l.privateAppUsers)),
      ],
    );
  }
}
