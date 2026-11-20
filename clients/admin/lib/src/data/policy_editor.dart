import 'dart:convert';

import 'package:flutter/foundation.dart';

import '../api/admin_models.dart';
import 'validation.dart';

const _encoder = JsonEncoder.withIndent('  ');

/// Draft of a TenantPolicy, edited both through the form and as raw JSON.
///
/// The form edits [policy] in place and calls [formChanged], which regenerates [jsonText].
/// The JSON tab calls [setJson] on every keystroke: valid JSON that decodes as a TenantPolicy
/// replaces [policy]; anything else sets [jsonError] and leaves [policy] as it was, and the
/// form is read-only until the JSON is fixed.
class PolicyEditor extends ChangeNotifier {
  PolicyEditor(TenantPolicy initial) : policy = initial.copy() {
    jsonText = _encoder.convert(policy.toJson());
    _saved = jsonText;
  }

  TenantPolicy policy;
  late String jsonText;
  String? jsonError;
  late String _saved;

  /// Increases on every form-originated change, so the JSON tab knows to replace its text.
  int formRevision = 0;

  bool get dirty => jsonError != null || (jsonText != _saved && _canonical(jsonText) != _saved);

  bool get canEditForm => jsonError == null;

  /// Call after mutating [policy] from the form.
  void formChanged() {
    jsonText = _encoder.convert(policy.toJson());
    jsonError = null;
    formRevision++;
    notifyListeners();
  }

  /// Applies raw JSON typed by the admin.
  void setJson(String text) {
    jsonText = text;
    try {
      final v = jsonDecode(text);
      if (v is! Map) throw const FormatException('the policy must be a JSON object');
      policy = TenantPolicy.fromJson(v.cast<String, dynamic>());
      jsonError = null;
    } on FormatException catch (e) {
      jsonError = e.message;
    } on TypeError catch (e) {
      jsonError = e.toString();
    }
    notifyListeners();
  }

  /// Validation issues of the current draft (JSON syntax errors first).
  List<PolicyIssue> validate() {
    if (jsonError != null) return [PolicyIssue('json', jsonError!)];
    return validateTenantPolicy(policy);
  }

  /// Marks [p] (the policy just stored by the server) as the saved state.
  void markSaved() {
    _saved = _encoder.convert(policy.toJson());
    jsonText = _saved;
    formRevision++;
    notifyListeners();
  }

  /// Replaces the draft with [p] (after reloading from the server).
  void reset(TenantPolicy p) {
    policy = p.copy();
    jsonError = null;
    markSaved();
  }

  static String _canonical(String text) {
    try {
      final v = jsonDecode(text);
      if (v is Map) return _encoder.convert(TenantPolicy.fromJson(v.cast<String, dynamic>()).toJson());
    } on Object {
      // fall through
    }
    return text;
  }
}
