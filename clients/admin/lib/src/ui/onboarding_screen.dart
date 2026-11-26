import 'dart:async';
import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:material_ui/material_ui.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../api/admin_models.dart';
import '../data/browser_nav.dart';
import '../data/enroll_link.dart';
import '../data/providers.dart';
import '../data/session.dart';
import 'common.dart';
import 'policy_screen.dart' show policyProvider;
import 'theme.dart';

/// First-run onboarding wizard for the admin portal (issue #77, flow decided in #48).
class OnboardingScreen extends ConsumerStatefulWidget {
  const OnboardingScreen({super.key});

  @override
  ConsumerState<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends ConsumerState<OnboardingScreen> {
  int _currentStep = 0;
  Timer? _liveTimer;

  // Step 2: Organisation
  final _orgNameCtrl = TextEditingController();
  final _orgIdCtrl = TextEditingController();
  bool _creatingOrg = false;

  // Step 3: Sign-in
  bool _skippedSso = false;
  final _ssoIssuerCtrl = TextEditingController();
  final _ssoClientIdCtrl = TextEditingController();
  final _ssoClientSecretCtrl = TextEditingController();
  final _ssoGroupRoles = <String, String>{};
  final _newGroupNameCtrl = TextEditingController();
  String _newGroupRole = 'admin';
  bool _ssoSaved = false;

  // Step 4: First policy
  String _policyTemplate = 'recommended'; // 'recommended' | 'permissive'
  bool _policySaved = false;
  bool _savingPolicy = false;

  // Step 5: DNS
  final _dnsZoneCtrl = TextEditingController();
  bool _dnsRedirectQueries = false;
  bool _builtinBlocklistEnabled = false;
  bool _dnsInitialized = false;
  bool _dnsSaved = false;
  bool _savingDns = false;

  // Step 6: Private apps
  bool _skippedConnectors = false;
  final _connectorNameCtrl = TextEditingController(text: 'connector-1');
  String? _createdConnectorKey;
  bool _creatingConnector = false;

  // Step 7: Devices
  final _userIdCtrl = TextEditingController(text: 'admin');
  String? _createdProvisioningKey;
  bool _creatingKey = false;

  @override
  void initState() {
    super.initState();
    _startLiveTimer();
  }

  void _startLiveTimer() {
    _liveTimer?.cancel();
    _liveTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      final t = ref.read(currentTenantProvider);
      if (t != null && mounted) {
        if (_currentStep == 5) {
          ref.invalidate(connectorsProvider(t));
        } else if (_currentStep == 6) {
          ref.invalidate(devicesProvider(t));
        }
      }
    });
  }

  @override
  void dispose() {
    _liveTimer?.cancel();
    _orgNameCtrl.dispose();
    _orgIdCtrl.dispose();
    _ssoIssuerCtrl.dispose();
    _ssoClientIdCtrl.dispose();
    _ssoClientSecretCtrl.dispose();
    _newGroupNameCtrl.dispose();
    _dnsZoneCtrl.dispose();
    _connectorNameCtrl.dispose();
    _userIdCtrl.dispose();
    super.dispose();
  }

  bool _isStepDone(int step, {String? tenant, TenantPolicy? policy, TenantOidc? oidc}) {
    switch (step) {
      case 0:
        return true;
      case 1:
        return tenant != null && tenant.isNotEmpty;
      case 2:
        return _skippedSso || _ssoSaved || (oidc != null && oidc.issuer.isNotEmpty);
      case 3:
        return _policySaved ||
            (policy != null &&
                (policy.categories.isNotEmpty ||
                    policy.safeSearch ||
                    policy.rules.isNotEmpty ||
                    policy.defaultAction.isNotEmpty));
      case 4:
        return _dnsSaved ||
            (policy != null &&
                (policy.dns.zone.isNotEmpty || policy.builtinLists.isNotEmpty || policy.dns.redirectQueries));
      case 5:
        if (_skippedConnectors) return true;
        if (tenant == null) return false;
        final conns = ref.watch(connectorsProvider(tenant)).value;
        return conns != null && conns.isNotEmpty;
      case 6:
        if (_createdProvisioningKey != null) return true;
        if (tenant == null) return false;
        final devs = ref.watch(devicesProvider(tenant)).value;
        return devs != null && devs.isNotEmpty;
      case 7:
        return _currentStep == 7;
      default:
        return false;
    }
  }

  StepState _stepState(int step, {String? tenant, TenantPolicy? policy, TenantOidc? oidc}) {
    if (_currentStep == step) return StepState.editing;
    if (_isStepDone(step, tenant: tenant, policy: policy, oidc: oidc)) return StepState.complete;
    return StepState.indexed;
  }

  TenantPolicy _applyTemplate(TenantPolicy base, String template) {
    final p = base.copy();
    p.defaultAction = 'allow';
    if (template == 'recommended') {
      p.categories = ['malware', 'phishing']..sort();
      p.safeSearch = true;
    } else {
      p.categories = [];
      p.safeSearch = false;
    }
    return p;
  }

  // --- Step 2 actions ---
  Future<void> _createOrganisation() async {
    final name = _orgNameCtrl.text.trim();
    if (name.isEmpty) return;
    setState(() => _creatingOrg = true);
    try {
      final t = await ref.read(apiProvider).createTenant(AdminTenant(id: _orgIdCtrl.text.trim(), name: name));
      ref.invalidate(tenantsProvider);
      ref.read(selectedTenantProvider.notifier).select(t.id);
      if (mounted) {
        showSnack(context, context.l10n.msgSaved);
        setState(() => _currentStep = 2);
      }
    } on Object catch (e) {
      if (mounted) showSnack(context, context.l10n.msgError(errorText(e)));
    } finally {
      if (mounted) setState(() => _creatingOrg = false);
    }
  }

  // --- Step 3 actions ---
  Future<void> _saveSso(String tenant) async {
    final issuer = _ssoIssuerCtrl.text.trim();
    final clientId = _ssoClientIdCtrl.text.trim();
    final clientSecret = _ssoClientSecretCtrl.text.trim();
    if (issuer.isEmpty || clientId.isEmpty) return;

    final oidc = TenantOidc(
      issuer: issuer,
      clientId: clientId,
      groupRoles: _ssoGroupRoles.isEmpty ? {'admin': 'admin'} : _ssoGroupRoles,
    );
    try {
      await ref
          .read(apiProvider)
          .putTenantOidc(tenant, oidc, clientSecret: clientSecret.isNotEmpty ? clientSecret : null);
      ref.invalidate(tenantOidcProvider(tenant));
      if (mounted) {
        showSnack(context, context.l10n.ssoSaved);
        setState(() {
          _ssoSaved = true;
          _currentStep = 3;
        });
      }
    } on Object catch (e) {
      if (mounted) showSnack(context, context.l10n.msgError(errorText(e)));
    }
  }

  void _safeGo(BuildContext context, String path) {
    try {
      context.go(path);
    } catch (_) {}
  }

  void _testSignIn(String tenant) {
    final base = ref.read(apiBaseProvider);
    final url = buildOidcLoginUrl(tenant, base: base);
    ref.read(browserTabNavProvider)(url);
  }

  // --- Step 4 actions ---
  Future<void> _applyPolicy(String tenant, TenantPolicy initial) async {
    setState(() => _savingPolicy = true);
    try {
      final resulting = _applyTemplate(initial, _policyTemplate);
      await ref.read(apiProvider).putPolicy(tenant, resulting);
      ref.invalidate(policyProvider(tenant));
      if (mounted) {
        showSnack(context, context.l10n.msgSaved);
        setState(() {
          _policySaved = true;
          _currentStep = 4;
        });
      }
    } on Object catch (e) {
      if (mounted) showSnack(context, context.l10n.msgError(errorText(e)));
    } finally {
      if (mounted) setState(() => _savingPolicy = false);
    }
  }

  // --- Step 5 actions ---
  Future<void> _saveDns(String tenant, TenantPolicy initial, BuiltinBlocklist? firstBlocklist) async {
    setState(() => _savingDns = true);
    try {
      final p = initial.copy();
      p.dns.zone = _dnsZoneCtrl.text.trim();
      p.dns.redirectQueries = _dnsRedirectQueries;
      if (firstBlocklist != null) {
        if (_builtinBlocklistEnabled) {
          if (!p.builtinLists.contains(firstBlocklist.id)) {
            p.builtinLists.add(firstBlocklist.id);
          }
        } else {
          p.builtinLists.remove(firstBlocklist.id);
        }
      }
      await ref.read(apiProvider).putPolicy(tenant, p);
      ref.invalidate(policyProvider(tenant));
      if (mounted) {
        showSnack(context, context.l10n.msgSaved);
        setState(() {
          _dnsSaved = true;
          _currentStep = 5;
        });
      }
    } on Object catch (e) {
      if (mounted) showSnack(context, context.l10n.msgError(errorText(e)));
    } finally {
      if (mounted) setState(() => _savingDns = false);
    }
  }

  // --- Step 6 actions ---
  Future<void> _createConnector(String tenant) async {
    final name = _connectorNameCtrl.text.trim();
    if (name.isEmpty) return;
    setState(() => _creatingConnector = true);
    try {
      final created = await ref
          .read(apiProvider)
          .createConnector(tenant, AdminConnectorRequest(name: name, group: 'default'));
      ref.invalidate(connectorsProvider(tenant));
      if (mounted) {
        setState(() => _createdConnectorKey = created.provisioningKey);
      }
    } on Object catch (e) {
      if (mounted) showSnack(context, context.l10n.msgError(errorText(e)));
    } finally {
      if (mounted) setState(() => _creatingConnector = false);
    }
  }

  // --- Step 7 actions ---
  Future<void> _createProvisioningKey(String tenant) async {
    final userId = _userIdCtrl.text.trim();
    if (userId.isEmpty) return;
    setState(() => _creatingKey = true);
    try {
      final pk = await ref
          .read(apiProvider)
          .createProvisioningKey(tenant, ProvisioningKeyRequest(userId: userId, maxUses: 1, validFor: 86400));
      if (mounted) {
        setState(() => _createdProvisioningKey = pk.key);
      }
    } on Object catch (e) {
      if (mounted) showSnack(context, context.l10n.msgError(errorText(e)));
    } finally {
      if (mounted) setState(() => _creatingKey = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final isSuper = ref.watch(isSuperProvider);
    final tenant = ref.watch(currentTenantProvider);
    final policy = tenant == null ? null : ref.watch(policyProvider(tenant)).value;
    final oidc = tenant == null ? null : ref.watch(tenantOidcProvider(tenant)).value;
    final blocklists = ref.watch(blocklistsProvider).value ?? const <BuiltinBlocklist>[];
    final firstBlocklist = blocklists.isNotEmpty ? blocklists.first : null;

    if (policy != null && !_dnsInitialized) {
      _dnsZoneCtrl.text = policy.dns.zone;
      _dnsRedirectQueries = policy.dns.redirectQueries;
      if (firstBlocklist != null) {
        _builtinBlocklistEnabled = policy.builtinLists.contains(firstBlocklist.id);
      }
      _dnsInitialized = true;
    }

    if (oidc != null && _ssoIssuerCtrl.text.isEmpty && _ssoClientIdCtrl.text.isEmpty) {
      _ssoIssuerCtrl.text = oidc.issuer;
      _ssoClientIdCtrl.text = oidc.clientId;
      _ssoGroupRoles.addAll(oidc.groupRoles);
    }

    final tenants = ref.watch(tenantsProvider).value ?? const <AdminTenant>[];
    final currentTenantObj = tenants.where((t) => t.id == tenant).firstOrNull;

    return PageFrame(
      title: l.onboardingTitle,
      subtitle: l.onboardingSubtitle,
      child: Stepper(
        type: StepperType.vertical,
        currentStep: _currentStep,
        onStepTapped: (step) => setState(() => _currentStep = step),
        controlsBuilder: (context, details) => const SizedBox.shrink(),
        steps: [
          // Step 1: Welcome
          Step(
            title: Text(l.onboardingStepWelcome),
            subtitle: Text(l.onboardingWelcomeSuper),
            isActive: _currentStep == 0,
            state: _stepState(0, tenant: tenant, policy: policy, oidc: oidc),
            content: _buildWelcomeStep(context, isSuper, tenant, policy, oidc),
          ),
          // Step 2: Organisation
          Step(
            title: Text(l.onboardingStepOrg),
            subtitle: Text(l.onboardingOrgHelp),
            isActive: _currentStep == 1,
            state: _stepState(1, tenant: tenant, policy: policy, oidc: oidc),
            content: _buildOrgStep(context, isSuper, tenant, currentTenantObj),
          ),
          // Step 3: Sign-in
          Step(
            title: Text(l.onboardingStepSso),
            subtitle: Text(l.onboardingSsoHelp),
            isActive: _currentStep == 2,
            state: _stepState(2, tenant: tenant, policy: policy, oidc: oidc),
            content: _buildSsoStep(context, tenant, oidc),
          ),
          // Step 4: First policy
          Step(
            title: Text(l.onboardingStepPolicy),
            subtitle: Text(l.onboardingPolicyHelp),
            isActive: _currentStep == 3,
            state: _stepState(3, tenant: tenant, policy: policy, oidc: oidc),
            content: _buildPolicyStep(context, tenant, policy),
          ),
          // Step 5: DNS
          Step(
            title: Text(l.onboardingStepDns),
            subtitle: Text(l.onboardingDnsHelp),
            isActive: _currentStep == 4,
            state: _stepState(4, tenant: tenant, policy: policy, oidc: oidc),
            content: _buildDnsStep(context, tenant, policy, firstBlocklist),
          ),
          // Step 6: Private apps
          Step(
            title: Text(l.onboardingStepConnectors),
            subtitle: Text(l.onboardingConnectorHelp),
            isActive: _currentStep == 5,
            state: _stepState(5, tenant: tenant, policy: policy, oidc: oidc),
            content: _buildConnectorsStep(context, tenant),
          ),
          // Step 7: Devices
          Step(
            title: Text(l.onboardingStepDevices),
            subtitle: Text(l.onboardingDevicesHelp),
            isActive: _currentStep == 6,
            state: _stepState(6, tenant: tenant, policy: policy, oidc: oidc),
            content: _buildDevicesStep(context, tenant),
          ),
          // Step 8: Done
          Step(
            title: Text(l.onboardingStepDone),
            subtitle: Text(l.onboardingDoneSubtitle),
            isActive: _currentStep == 7,
            state: _stepState(7, tenant: tenant, policy: policy, oidc: oidc),
            content: _buildDoneStep(context),
          ),
        ],
      ),
    );
  }

  Widget _buildWelcomeStep(BuildContext context, bool isSuper, String? tenant, TenantPolicy? policy, TenantOidc? oidc) {
    final l = context.l10n;
    final now = ref.watch(clockProvider)();
    final scheme = Theme.of(context).colorScheme;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (isSuper) ...[
          AsyncBody(
            value: ref.watch(statusProvider),
            onRetry: () => ref.invalidate(statusProvider),
            builder: (st) {
              final reporting = st.edges.where((e) => e.reporting).length;
              final expiring = st.certificates.where((c) {
                if (c.notAfter == null) return false;
                return c.notAfter!.difference(now).inDays < 14;
              }).toList();

              return Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(l.navStatus, style: Theme.of(context).textTheme.titleMedium),
                      const SizedBox(height: 8),
                      Row(
                        children: [
                          Icon(Icons.cell_tower, color: scheme.primary),
                          const SizedBox(width: 8),
                          Text(l.onboardingEdgesReporting(reporting, st.edges.length)),
                        ],
                      ),
                      const SizedBox(height: 8),
                      if (expiring.isNotEmpty) ...[
                        for (final c in expiring)
                          Padding(
                            padding: const EdgeInsets.only(top: 4),
                            child: Row(
                              children: [
                                Icon(Icons.warning_amber_rounded, color: scheme.error),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: Text(
                                    l.onboardingCertWarning(
                                      c.name,
                                      c.notAfter == null ? 0 : c.notAfter!.difference(now).inDays,
                                    ),
                                    style: TextStyle(color: scheme.error),
                                  ),
                                ),
                              ],
                            ),
                          ),
                      ] else
                        Row(
                          children: [
                            Icon(Icons.check_circle_outline, color: context.verdicts.allow),
                            const SizedBox(width: 8),
                            Text(l.onboardingCertsHealthy),
                          ],
                        ),
                    ],
                  ),
                ),
              );
            },
          ),
        ] else
          Padding(padding: const EdgeInsets.symmetric(vertical: 8), child: Text(l.onboardingWelcomeTenant)),
        const SizedBox(height: 16),
        Text(l.onboardingTitle, style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 8),
        Card(
          child: Column(
            children: [
              _stepItem(1, l.onboardingStepOrg, _isStepDone(1, tenant: tenant, policy: policy, oidc: oidc)),
              _stepItem(2, l.onboardingStepSso, _isStepDone(2, tenant: tenant, policy: policy, oidc: oidc)),
              _stepItem(3, l.onboardingStepPolicy, _isStepDone(3, tenant: tenant, policy: policy, oidc: oidc)),
              _stepItem(4, l.onboardingStepDns, _isStepDone(4, tenant: tenant, policy: policy, oidc: oidc)),
              _stepItem(5, l.onboardingStepConnectors, _isStepDone(5, tenant: tenant, policy: policy, oidc: oidc)),
              _stepItem(6, l.onboardingStepDevices, _isStepDone(6, tenant: tenant, policy: policy, oidc: oidc)),
            ],
          ),
        ),
        const SizedBox(height: 16),
        Align(
          alignment: Alignment.centerLeft,
          child: FilledButton(
            key: const ValueKey('welcome_continue_button'),
            onPressed: () => setState(() => _currentStep = 1),
            child: Text(l.onboardingNext),
          ),
        ),
      ],
    );
  }

  Widget _stepItem(int step, String title, bool done) {
    final l = context.l10n;
    return ListTile(
      leading: Icon(
        done ? Icons.check_circle : Icons.radio_button_unchecked,
        color: done ? context.verdicts.allow : Theme.of(context).colorScheme.outline,
      ),
      title: Text(title),
      trailing: Text(
        done ? l.onboardingStepStatusDone : l.onboardingStepStatusTodo,
        style: TextStyle(color: done ? context.verdicts.allow : Theme.of(context).colorScheme.outline, fontSize: 12),
      ),
      onTap: () => setState(() => _currentStep = step),
    );
  }

  Widget _buildOrgStep(BuildContext context, bool isSuper, String? tenant, AdminTenant? current) {
    final l = context.l10n;
    final exists = tenant != null && tenant.isNotEmpty;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (exists) ...[
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    l.onboardingOrgCurrent(current?.name ?? tenant, tenant),
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                  const SizedBox(height: 4),
                  StatusChip(label: l.onboardingStepStatusDone, color: context.verdicts.allow),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
        ],
        if (!exists && isSuper) ...[
          TextField(
            key: const ValueKey('onboarding_org_name'),
            controller: _orgNameCtrl,
            decoration: InputDecoration(labelText: l.fieldName, border: const OutlineInputBorder()),
          ),
          const SizedBox(height: 12),
          TextField(
            key: const ValueKey('onboarding_org_id'),
            controller: _orgIdCtrl,
            decoration: InputDecoration(labelText: l.fieldIdOptional, border: const OutlineInputBorder()),
          ),
          const SizedBox(height: 16),
          Align(
            alignment: Alignment.centerLeft,
            child: FilledButton.icon(
              key: const ValueKey('onboarding_create_org_button'),
              onPressed: _creatingOrg ? null : _createOrganisation,
              icon: const Icon(Icons.add),
              label: Text(l.onboardingOrgCreate),
            ),
          ),
        ] else ...[
          Row(
            children: [
              OutlinedButton(onPressed: () => setState(() => _currentStep = 0), child: Text(l.onboardingBack)),
              const SizedBox(width: 8),
              FilledButton(
                key: const ValueKey('org_next_button'),
                onPressed: () => setState(() => _currentStep = 2),
                child: Text(l.onboardingNext),
              ),
            ],
          ),
        ],
      ],
    );
  }

  Widget _buildSsoStep(BuildContext context, String? tenant, TenantOidc? oidc) {
    final l = context.l10n;
    if (tenant == null) {
      return Text(l.emptyNoTenant);
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        TextField(
          key: const ValueKey('onboarding_oidc_issuer'),
          controller: _ssoIssuerCtrl,
          decoration: InputDecoration(
            labelText: l.ssoIssuer,
            hintText: 'https://auth.example.com',
            border: const OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          key: const ValueKey('onboarding_oidc_client_id'),
          controller: _ssoClientIdCtrl,
          decoration: InputDecoration(labelText: l.ssoClientId, border: const OutlineInputBorder()),
        ),
        const SizedBox(height: 12),
        TextField(
          key: const ValueKey('onboarding_oidc_client_secret'),
          controller: _ssoClientSecretCtrl,
          obscureText: true,
          decoration: InputDecoration(
            labelText: l.ssoClientSecret,
            helperText: l.ssoClientSecretHelp,
            border: const OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 12),
        Text(l.ssoGroupRoles, style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 8),
        if (_ssoGroupRoles.isNotEmpty)
          Card(
            child: Column(
              children: [
                for (final e in _ssoGroupRoles.entries)
                  ListTile(
                    title: Text(e.key),
                    subtitle: Text(e.value),
                    trailing: IconButton(
                      icon: const Icon(Icons.delete_outline),
                      onPressed: () => setState(() => _ssoGroupRoles.remove(e.key)),
                    ),
                  ),
              ],
            ),
          ),
        Row(
          children: [
            Expanded(
              child: TextField(
                controller: _newGroupNameCtrl,
                decoration: InputDecoration(labelText: l.ssoGroup, border: const OutlineInputBorder()),
              ),
            ),
            const SizedBox(width: 8),
            DropdownButton<String>(
              value: _newGroupRole,
              items: const [
                DropdownMenuItem(value: 'admin', child: Text('admin')),
                DropdownMenuItem(value: 'policy-editor', child: Text('policy-editor')),
                DropdownMenuItem(value: 'viewer', child: Text('viewer')),
              ],
              onChanged: (v) {
                if (v != null) setState(() => _newGroupRole = v);
              },
            ),
            const SizedBox(width: 8),
            FilledButton.tonal(
              onPressed: () {
                final grp = _newGroupNameCtrl.text.trim();
                if (grp.isNotEmpty) {
                  setState(() {
                    _ssoGroupRoles[grp] = _newGroupRole;
                    _newGroupNameCtrl.clear();
                  });
                }
              },
              child: Text(l.onboardingAddGroup),
            ),
          ],
        ),
        const SizedBox(height: 16),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            FilledButton(
              key: const ValueKey('onboarding_sso_save_button'),
              onPressed: () => _saveSso(tenant),
              child: Text(l.actionSave),
            ),
            FilledButton.tonal(
              key: const ValueKey('test_signin_button'),
              onPressed: () => _testSignIn(tenant),
              child: Text(l.onboardingTestSignin),
            ),
            OutlinedButton(
              key: const ValueKey('skip_sso_button'),
              onPressed: () => setState(() {
                _skippedSso = true;
                _currentStep = 3;
              }),
              child: Text(l.onboardingSkipSso),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildPolicyStep(BuildContext context, String? tenant, TenantPolicy? policy) {
    final l = context.l10n;
    if (tenant == null) {
      return Text(l.emptyNoTenant);
    }
    final initial = policy ?? TenantPolicy();
    final resulting = _applyTemplate(initial, _policyTemplate);
    const encoder = JsonEncoder.withIndent('  ');
    final previewText = encoder.convert(resulting.toJson());

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        RadioGroup<String>(
          groupValue: _policyTemplate,
          onChanged: (v) => setState(() => _policyTemplate = v!),
          child: Column(
            children: [
              RadioListTile<String>(
                key: const ValueKey('template_recommended'),
                title: Text(l.onboardingTemplateRecommended),
                subtitle: Text(l.onboardingTemplateRecommendedDesc),
                value: 'recommended',
              ),
              RadioListTile<String>(
                key: const ValueKey('template_permissive'),
                title: Text(l.onboardingTemplatePermissive),
                subtitle: Text(l.onboardingTemplatePermissiveDesc),
                value: 'permissive',
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        Text(l.onboardingPolicyPreview, style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 8),
        Container(
          key: const ValueKey('policy_preview_container'),
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
          ),
          child: SelectableText(
            previewText,
            key: const ValueKey('policy_preview_json'),
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
          ),
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            OutlinedButton(onPressed: () => setState(() => _currentStep = 2), child: Text(l.onboardingBack)),
            const SizedBox(width: 8),
            FilledButton(
              key: const ValueKey('policy_apply_button'),
              onPressed: _savingPolicy ? null : () => _applyPolicy(tenant, initial),
              child: Text(l.onboardingApply),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildDnsStep(BuildContext context, String? tenant, TenantPolicy? policy, BuiltinBlocklist? firstBlocklist) {
    final l = context.l10n;
    if (tenant == null) {
      return Text(l.emptyNoTenant);
    }
    final initial = policy ?? TenantPolicy();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        TextField(
          key: const ValueKey('onboarding_dns_zone'),
          controller: _dnsZoneCtrl,
          decoration: InputDecoration(
            labelText: l.onboardingDnsZone,
            hintText: 'corp.internal',
            border: const OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 12),
        if (firstBlocklist != null)
          SwitchListTile(
            key: ValueKey('builtin_switch_${firstBlocklist.id}'),
            title: Text(firstBlocklist.title),
            subtitle: Text(firstBlocklist.url),
            value: _builtinBlocklistEnabled,
            onChanged: (v) => setState(() => _builtinBlocklistEnabled = v),
          ),
        SwitchListTile(
          key: const ValueKey('dns_redirect_queries_switch'),
          title: Text(l.dnsRedirectQueries),
          subtitle: Text(l.dnsRedirectQueriesHelp),
          value: _dnsRedirectQueries,
          onChanged: (v) => setState(() => _dnsRedirectQueries = v),
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            OutlinedButton(onPressed: () => setState(() => _currentStep = 3), child: Text(l.onboardingBack)),
            const SizedBox(width: 8),
            FilledButton(
              key: const ValueKey('dns_save_button'),
              onPressed: _savingDns ? null : () => _saveDns(tenant, initial, firstBlocklist),
              child: Text(l.actionSave),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildConnectorsStep(BuildContext context, String? tenant) {
    final l = context.l10n;
    if (tenant == null) {
      return Text(l.emptyNoTenant);
    }
    final conns = ref.watch(connectorsProvider(tenant)).value ?? const <AdminConnector>[];
    final now = ref.watch(clockProvider)();
    final control = ref.watch(effectiveControlUrlProvider);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(
              child: TextField(
                key: const ValueKey('onboarding_connector_name'),
                controller: _connectorNameCtrl,
                decoration: InputDecoration(labelText: l.fieldName, border: const OutlineInputBorder()),
              ),
            ),
            const SizedBox(width: 8),
            FilledButton.icon(
              key: const ValueKey('create_connector_button'),
              onPressed: _creatingConnector ? null : () => _createConnector(tenant),
              icon: const Icon(Icons.add),
              label: Text(l.onboardingConnectorCreate),
            ),
          ],
        ),
        if (_createdConnectorKey != null) ...[
          const SizedBox(height: 16),
          Text(l.onboardingConnectorDocker, style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 4),
          Text(l.onboardingConnectorDockerHelp, style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: 8),
          OneTimeSecret(
            secret:
                'docker run -d --name connector --restart unless-stopped '
                '-e OPENSASE_CONNECTOR_KEY="$_createdConnectorKey" '
                '-v /path/to/connector-state:/var/lib/opensase-connector '
                'ghcr.io/yuky2020/opensase-connector:latest '
                '-control $control',
          ),
        ],
        const SizedBox(height: 16),
        Text(l.onboardingConnectorStatus, style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 8),
        if (conns.isEmpty)
          Padding(padding: const EdgeInsets.symmetric(vertical: 8), child: Text(l.emptyNothingHere))
        else
          Card(
            child: Column(
              children: [
                for (final c in conns)
                  ListTile(
                    title: Text(c.name.isEmpty ? c.id : c.name),
                    subtitle: Text('${c.group} · ${formatTime(context, c.lastSeen)}'),
                    trailing: StatusChip(
                      label: c.revoked
                          ? l.statusRevoked
                          : c.isOnline(now)
                          ? l.statusOnline
                          : l.statusOffline,
                      color: c.revoked
                          ? context.verdicts.block
                          : c.isOnline(now)
                          ? context.verdicts.allow
                          : Theme.of(context).colorScheme.outline,
                    ),
                  ),
              ],
            ),
          ),
        const SizedBox(height: 12),
        Align(
          alignment: Alignment.centerLeft,
          child: TextButton.icon(
            key: const ValueKey('link_private_apps'),
            onPressed: () => _safeGo(context, '/private-apps'),
            icon: const Icon(Icons.lock_outline),
            label: Text(l.onboardingPrivateAppsLink),
          ),
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            OutlinedButton(onPressed: () => setState(() => _currentStep = 4), child: Text(l.onboardingBack)),
            const SizedBox(width: 8),
            TextButton(
              key: const ValueKey('skip_connectors_button'),
              onPressed: () => setState(() {
                _skippedConnectors = true;
                _currentStep = 6;
              }),
              child: Text(l.onboardingSkip),
            ),
            const SizedBox(width: 8),
            FilledButton(onPressed: () => setState(() => _currentStep = 6), child: Text(l.onboardingNext)),
          ],
        ),
      ],
    );
  }

  Widget _buildDevicesStep(BuildContext context, String? tenant) {
    final l = context.l10n;
    if (tenant == null) {
      return Text(l.emptyNoTenant);
    }
    final control = ref.watch(effectiveControlUrlProvider);
    final controlOk = controlUrlError(control) == null;
    final devs = ref.watch(devicesProvider(tenant)).value ?? const <AdminDevice>[];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(
              child: TextField(
                key: const ValueKey('onboarding_user_id'),
                controller: _userIdCtrl,
                decoration: InputDecoration(labelText: l.fieldUser, border: const OutlineInputBorder()),
              ),
            ),
            const SizedBox(width: 8),
            FilledButton.icon(
              key: const ValueKey('generate_provisioning_key_button'),
              onPressed: _creatingKey ? null : () => _createProvisioningKey(tenant),
              icon: const Icon(Icons.key),
              label: Text(l.onboardingKeyCreate),
            ),
          ],
        ),
        if (_createdProvisioningKey != null) ...[
          const SizedBox(height: 16),
          () {
            final link = controlOk
                ? enrollLink(controlUrl: control, key: _createdProvisioningKey!)
                : _createdProvisioningKey!;
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Center(
                  child: Container(
                    color: Colors.white,
                    padding: const EdgeInsets.all(12),
                    child: QrImageView(key: const ValueKey('enroll_qr'), data: link, size: 240),
                  ),
                ),
                const SizedBox(height: 8),
                Text(l.provScan, textAlign: TextAlign.center),
                const SizedBox(height: 8),
                OneTimeSecret(secret: link),
              ],
            );
          }(),
        ],
        const SizedBox(height: 16),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(l.onboardingPlatformAndroid, style: Theme.of(context).textTheme.titleSmall),
                const SizedBox(height: 4),
                Text(l.onboardingPlatformAndroidDesc),
                const Divider(height: 24),
                Text(l.onboardingPlatformWindows, style: Theme.of(context).textTheme.titleSmall),
                const SizedBox(height: 4),
                Text(l.onboardingPlatformWindowsDesc),
                const Divider(height: 24),
                Text(l.onboardingPlatformLinux, style: Theme.of(context).textTheme.titleSmall),
                const SizedBox(height: 4),
                Text(l.onboardingPlatformLinuxDesc),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),
        Text(l.onboardingDevicesLive, style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 8),
        if (devs.isEmpty)
          Padding(padding: const EdgeInsets.symmetric(vertical: 8), child: Text(l.emptyNothingHere))
        else
          Card(
            child: Column(
              children: [
                for (final d in devs)
                  ListTile(
                    title: Text(d.name.isEmpty ? d.id : d.name),
                    subtitle: Text('${d.platform} · ${d.userId} · ${formatTime(context, d.createdAt)}'),
                    trailing: revokedChip(context, d.revoked),
                  ),
              ],
            ),
          ),
        const SizedBox(height: 16),
        Row(
          children: [
            OutlinedButton(onPressed: () => setState(() => _currentStep = 5), child: Text(l.onboardingBack)),
            const SizedBox(width: 8),
            FilledButton(onPressed: () => setState(() => _currentStep = 7), child: Text(l.onboardingNext)),
          ],
        ),
      ],
    );
  }

  Widget _buildDoneStep(BuildContext context) {
    final l = context.l10n;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(Icons.check_circle, color: context.verdicts.allow, size: 36),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(l.onboardingDoneTitle, style: Theme.of(context).textTheme.titleLarge),
                  Text(l.onboardingDoneSubtitle),
                ],
              ),
            ),
          ],
        ),
        const SizedBox(height: 24),
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            FilledButton.icon(
              key: const ValueKey('link_status'),
              onPressed: () => _safeGo(context, '/status'),
              icon: const Icon(Icons.monitor_heart_outlined),
              label: Text(l.onboardingLinkStatus),
            ),
            FilledButton.icon(
              key: const ValueKey('link_policy'),
              onPressed: () => _safeGo(context, '/policy'),
              icon: const Icon(Icons.rule_outlined),
              label: Text(l.onboardingLinkPolicy),
            ),
            FilledButton.icon(
              key: const ValueKey('link_dns'),
              onPressed: () => _safeGo(context, '/dns'),
              icon: const Icon(Icons.dns_outlined),
              label: Text(l.onboardingLinkDns),
            ),
            OutlinedButton.icon(
              key: const ValueKey('link_docs'),
              onPressed: () => ref.read(browserTabNavProvider)('https://opensase.org/docs'),
              icon: const Icon(Icons.menu_book_outlined),
              label: Text(l.onboardingLinkDocs),
            ),
          ],
        ),
      ],
    );
  }
}
