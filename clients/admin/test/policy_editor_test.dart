import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:opensase_admin/src/api/admin_models.dart';
import 'package:opensase_admin/src/data/policy_editor.dart';
import 'package:opensase_admin/src/data/session.dart';
import 'package:opensase_admin/src/ui/policy_screen.dart';

import 'helpers.dart';
import 'models_test.dart' show tenantPolicyJson;

Future<FakeControlPlane> _pump(WidgetTester t, {Object? putBody}) async {
  desktopView(t);
  final cp = FakeControlPlane()..json('GET /v1/admin/tenants/acme/policy', jsonDecode(tenantPolicyJson) as Object);
  cp.routes['PUT /v1/admin/tenants/acme/policy'] = (r) => putBody == null ? http204() : http400(putBody);
  final tab = overridesFor(cp);
  final initial = TenantPolicy.fromJson(jsonDecode(tenantPolicyJson) as Map<String, dynamic>);
  await t.pumpWidget(
    ProviderScope(
      retry: (_, _) => null,
      overrides: [...tab, sessionProvider.overrideWith(_SignedIn.new)],
      child: testApp(PolicyEditorView(tenant: 'acme', initial: initial)),
    ),
  );
  await t.pumpAndSettle();
  return cp;
}

class _SignedIn extends SessionNotifier {
  @override
  String? build() => 'good-token';
}

String _jsonText(WidgetTester t) => t.widget<TextField>(find.byKey(const Key('policy_json'))).controller!.text;

void main() {
  testWidgets('form edits show up in the JSON tab', (t) async {
    await _pump(t);
    expect(find.text('allow-web\nweb'), findsOneWidget);
    await t.tap(find.byKey(const Key('lockdown')));
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('tab_json')));
    await t.pumpAndSettle();
    final j = jsonDecode(_jsonText(t)) as Map<String, dynamic>;
    expect(j['lockdown'], isTrue);
    expect((j['rules'] as List).single['id'], 'allow-web');
  });

  testWidgets('JSON edits show up in the form, invalid JSON locks it', (t) async {
    await _pump(t);
    await t.tap(find.byKey(const Key('tab_json')));
    await t.pumpAndSettle();
    final j = jsonDecode(_jsonText(t)) as Map<String, dynamic>
      ..['allowUserRules'] = false
      ..['defaultAction'] = 'allow'
      ..['rules'] = [
        {'id': 'from-json', 'source': 'tenant', 'priority': 5, 'action': 'block', 'match': {}, 'log': false},
      ];
    (j['dns'] as Map)['blockDomains'] = ['x.example', 'y.example'];
    await t.enterText(find.byKey(const Key('policy_json')), jsonEncode(j));
    await t.pump();

    await t.tap(find.byKey(const Key('tab_form')));
    await t.pumpAndSettle();
    expect(t.widget<SwitchListTile>(find.byKey(const Key('allow_user_rules'))).value, isFalse);
    expect(find.text('from-json'), findsOneWidget);
    expect(find.text('allow-web\nweb'), findsNothing);
    expect(find.descendant(of: find.byKey(const Key('default_action')), matching: find.text('Allow')), findsWidgets);
    final blockField = find.descendant(of: find.byKey(const Key('dns_block')), matching: find.byType(TextField));
    expect(t.widget<TextField>(blockField).controller!.text, 'x.example\ny.example');

    // Broken JSON: error in the JSON tab, form read-only.
    await t.tap(find.byKey(const Key('tab_json')));
    await t.pumpAndSettle();
    await t.enterText(find.byKey(const Key('policy_json')), '{"lockdown": ');
    await t.pump();
    expect(find.textContaining('Invalid JSON'), findsOneWidget);
    await t.tap(find.byKey(const Key('tab_form')));
    await t.pumpAndSettle();
    expect(find.byKey(const Key('form_locked')), findsOneWidget);
  });

  testWidgets('validation runs before the PUT', (t) async {
    final cp = await _pump(t);
    await t.tap(find.byKey(const Key('tab_json')));
    await t.pumpAndSettle();
    final j = jsonDecode(_jsonText(t)) as Map<String, dynamic>..['decideDefault'] = 'maybe';
    await t.enterText(find.byKey(const Key('policy_json')), jsonEncode(j));
    await t.pump();
    await t.tap(find.byKey(const Key('policy_save')));
    await t.pumpAndSettle();
    expect(find.byKey(const Key('policy_issues')), findsOneWidget);
    expect(find.textContaining('decideDefault'), findsWidgets);
    expect(cp.requests.where((r) => r.method == 'PUT'), isEmpty);
  });

  testWidgets('save PUTs the draft; server errors are shown', (t) async {
    final cp = await _pump(
      t,
      putBody: {'error': 'policy: invalid rules[0].match.domains[0]: bad', 'field': 'rules[0].match.domains[0]'},
    );
    await t.tap(find.byKey(const Key('lockdown')));
    await t.pumpAndSettle();
    await t.tap(find.byKey(const Key('policy_save')));
    await t.pumpAndSettle();
    final put = cp.requests.singleWhere((r) => r.method == 'PUT');
    expect(put.headers['Authorization'], 'Bearer good-token');
    expect((jsonDecode(put.body) as Map)['lockdown'], isTrue);
    expect(find.byKey(const Key('policy_server_error')), findsOneWidget);
    expect(find.textContaining('rules[0].match.domains[0]'), findsOneWidget);
  });

  test('PolicyEditor dirty tracking ignores formatting-only JSON changes', () {
    final e = PolicyEditor(TenantPolicy.fromJson(jsonDecode(tenantPolicyJson) as Map<String, dynamic>));
    expect(e.dirty, isFalse);
    e.setJson(jsonEncode(jsonDecode(e.jsonText)));
    expect(e.dirty, isFalse);
    e.policy.lockdown = true;
    e.formChanged();
    expect(e.dirty, isTrue);
    e.markSaved();
    expect(e.dirty, isFalse);
  });
}
