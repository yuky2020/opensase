import 'package:material_ui/material_ui.dart';

import 'common.dart';

class FieldSpec {
  const FieldSpec(this.name, this.label, {this.initial = '', this.validator, this.hint, this.helper});

  final String name;
  final String label;
  final String initial;
  final String? hint;
  final String? helper;
  final String? Function(String)? validator;
}

/// A simple form dialog of text fields. Returns the values by field name, or null on cancel.
Future<Map<String, String>?> showFieldsDialog(
  BuildContext context, {
  required String title,
  required List<FieldSpec> fields,
  String? confirmLabel,
  String? description,
}) {
  return showDialog<Map<String, String>>(
    context: context,
    builder: (_) => _FieldsDialog(title: title, fields: fields, confirmLabel: confirmLabel, description: description),
  );
}

class _FieldsDialog extends StatefulWidget {
  const _FieldsDialog({required this.title, required this.fields, this.confirmLabel, this.description});

  final String title;
  final String? description;
  final List<FieldSpec> fields;
  final String? confirmLabel;

  @override
  State<_FieldsDialog> createState() => _FieldsDialogState();
}

class _FieldsDialogState extends State<_FieldsDialog> {
  final _form = GlobalKey<FormState>();
  late final Map<String, TextEditingController> _c = {
    for (final f in widget.fields) f.name: TextEditingController(text: f.initial),
  };

  @override
  void dispose() {
    for (final c in _c.values) {
      c.dispose();
    }
    super.dispose();
  }

  void _submit() {
    if (!_form.currentState!.validate()) return;
    Navigator.pop(context, {for (final e in _c.entries) e.key: e.value.text.trim()});
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return AlertDialog(
      title: Text(widget.title),
      content: SizedBox(
        width: 420,
        child: Form(
          key: _form,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (widget.description != null)
                Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(widget.description!)),
              for (final f in widget.fields)
                Padding(
                  padding: const EdgeInsets.only(bottom: 12),
                  child: TextFormField(
                    key: Key('field_${f.name}'),
                    controller: _c[f.name],
                    decoration: InputDecoration(
                      labelText: f.label,
                      hintText: f.hint,
                      helperText: f.helper,
                      helperMaxLines: 3,
                      border: const OutlineInputBorder(),
                    ),
                    validator: f.validator == null ? null : (v) => f.validator!(v?.trim() ?? ''),
                    onFieldSubmitted: (_) => _submit(),
                  ),
                ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(l.actionCancel)),
        FilledButton(
          key: const Key('dialog_submit'),
          onPressed: _submit,
          child: Text(widget.confirmLabel ?? l.actionCreate),
        ),
      ],
    );
  }
}
