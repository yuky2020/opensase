import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../data/core_state.dart';
import '../data/enrollment_code.dart';
import '../data/sso_pending.dart';
import '../engine/engine.dart';
import '../platform_info.dart';
import 'common.dart';

/// Default for the Android emulator: the host's Control Plane.
const defaultControlUrl = 'https://10.0.2.2:9443';

class OnboardingScreen extends ConsumerStatefulWidget {
  const OnboardingScreen({super.key});

  @override
  ConsumerState<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends ConsumerState<OnboardingScreen> {
  final _code = TextEditingController();
  final _url = TextEditingController(text: defaultControlUrl);
  final _key = TextEditingController();
  final _name = TextEditingController(text: 'Android');
  final _ssoUrl = TextEditingController(text: defaultControlUrl);
  final _ssoTenant = TextEditingController();
  bool _busy = false;
  bool _codeInvalid = false;
  bool _codeApplied = false;
  bool _urlInvalid = false;
  bool _ssoUrlInvalid = false;
  bool _ssoTenantInvalid = false;
  String? _error;
  StreamSubscription<EngineEvent>? _links;

  @override
  void initState() {
    super.initState();
    // A deep link only pre-fills the form: enrolling always needs the user's tap.
    // For SSO result links, it automatically completes enrollment with the stored pending record.
    final engine = ref.read(engineProvider);
    _links = engine.events.where((e) => e.kind == EngineEvent.enrollLink).listen((e) => _fromLink(e.payload));
    engine.takeEnrollLink().then((l) {
      if (l != null && mounted) _fromLink(l);
    }, onError: (_) {});
  }

  void _fromLink(String uri) {
    final parsed = EnrollmentResult.parse(uri);
    if (parsed is EnrollmentSsoResult) {
      _handleSsoResult(parsed);
      return;
    }
    _code.text = uri;
    _applyCode(uri);
  }

  Future<void> _handleSsoResult(EnrollmentSsoResult sso) async {
    final l = context.l10n;
    final pending = await SsoPending.load();
    if (pending == null || pending.state != sso.state) {
      if (mounted) {
        setState(() {
          _error = l.onboardingSsoError;
        });
      }
      await SsoPending.clear();
      return;
    }
    if (!mounted) return;

    setState(() {
      _busy = true;
      _error = null;
    });

    try {
      final deviceName = _name.text.trim().isNotEmpty ? _name.text.trim() : 'Android';
      await ref.read(coreProvider.notifier).enroll(pending.controlUrl, sso.code, deviceName);
      await SsoPending.clear();
      _key.clear();
      _code.clear();
    } on EngineException catch (e) {
      if (mounted) setState(() => _error = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  void dispose() {
    _links?.cancel();
    for (final c in [_code, _url, _key, _name, _ssoUrl, _ssoTenant]) {
      c.dispose();
    }
    super.dispose();
  }

  void _applyCode(String text) {
    if (text.trim().isEmpty) {
      setState(() => _codeInvalid = false);
      return;
    }
    final parsed = EnrollmentResult.parse(text);
    if (parsed is EnrollmentSsoResult) {
      _handleSsoResult(parsed);
      return;
    }
    final code = parsed is EnrollmentCode ? parsed : null;
    setState(() {
      _codeInvalid = code == null;
      if (code != null) {
        _url.text = code.controlUrl;
        _ssoUrl.text = code.controlUrl;
        if (code.provisioningKey.isNotEmpty) _key.text = code.provisioningKey;
        if (code.deviceName.isNotEmpty) _name.text = code.deviceName;
        // A code with a key: do not leave the key readable on screen.
        if (code.provisioningKey.isNotEmpty) {
          _code.clear();
          _codeApplied = true;
        }
      }
    });
  }

  bool get _canSubmitSso => !_busy && _ssoUrl.text.trim().isNotEmpty && _ssoTenant.text.trim().isNotEmpty;

  Future<void> _startSso() async {
    final url = _ssoUrl.text.trim();
    if (!url.startsWith('https://') || url.length <= 'https://'.length) {
      setState(() => _ssoUrlInvalid = true);
      return;
    }
    final tenant = _ssoTenant.text.trim();
    final tenantPattern = RegExp(r'^[a-z0-9-]+$');
    if (!tenantPattern.hasMatch(tenant)) {
      setState(() => _ssoTenantInvalid = true);
      return;
    }

    setState(() {
      _error = null;
    });

    final state = SsoPending.generateState();
    final pending = SsoPending(controlUrl: url, tenantId: tenant, state: state, createdAt: DateTime.now());
    await pending.save();

    final startUrl = buildSsoStartUrl(url, tenant, state);
    try {
      await ref.read(engineProvider).openBrowser(startUrl);
    } on EngineException catch (e) {
      if (mounted) setState(() => _error = e.message);
    }
  }

  bool get _canSubmit =>
      !_busy && _url.text.trim().isNotEmpty && _key.text.trim().isNotEmpty && _name.text.trim().isNotEmpty;

  Future<void> _enroll() async {
    final url = _url.text.trim();
    if (!url.startsWith('https://') || url.length <= 'https://'.length) {
      setState(() => _urlInvalid = true);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final deviceName = _name.text.trim().isNotEmpty ? _name.text.trim() : 'Android';
      await ref.read(coreProvider.notifier).enroll(url, _key.text, deviceName);
      // The key is single-use and sensitive: do not keep it around.
      _key.clear();
      _code.clear();
    } on EngineException catch (e) {
      if (mounted) setState(() => _error = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final t = Theme.of(context);
    final pinned = _url.text.contains('#sha256=');
    final ssoPinned = _ssoUrl.text.contains('#sha256=');
    final s = ref.watch(coreProvider);
    return Scaffold(
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            if (isDesktop && !s.daemonConnected) ...[const DaemonUnreachableBanner(), const SizedBox(height: 16)],
            const SizedBox(height: 16),
            Icon(Icons.shield, size: 56, color: t.colorScheme.primary),
            const SizedBox(height: 16),
            Text(l.onboardingTitle, style: t.textTheme.headlineMedium),
            const SizedBox(height: 8),
            Text(l.onboardingSubtitle, style: t.textTheme.bodyMedium?.copyWith(color: t.colorScheme.onSurfaceVariant)),
            const SizedBox(height: 24),
            TextField(
              key: const ValueKey('enroll_code'),
              controller: _code,
              onChanged: _applyCode,
              minLines: 1,
              maxLines: 3,
              decoration: InputDecoration(
                labelText: l.onboardingCode,
                helperText: _codeApplied ? l.onboardingCodeApplied : l.onboardingCodeHint,
                helperMaxLines: 2,
                errorText: _codeInvalid ? l.onboardingCodeInvalid : null,
                border: const OutlineInputBorder(),
                suffixIcon: IconButton(
                  icon: const Icon(Icons.qr_code_scanner),
                  tooltip: l.onboardingScan,
                  onPressed: () =>
                      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(l.onboardingScanSoon))),
                ),
              ),
            ),
            const SizedBox(height: 16),
            ExpansionTile(
              key: const ValueKey('sso_expand'),
              tilePadding: EdgeInsets.zero,
              childrenPadding: const EdgeInsets.only(top: 8, bottom: 8),
              leading: const Icon(Icons.business),
              title: Text(l.onboardingOrSso),
              children: [
                TextField(
                  key: const ValueKey('sso_url'),
                  controller: _ssoUrl,
                  keyboardType: TextInputType.url,
                  autocorrect: false,
                  onChanged: (_) => setState(() => _ssoUrlInvalid = false),
                  decoration: InputDecoration(
                    labelText: l.onboardingControlUrl,
                    errorText: _ssoUrlInvalid ? l.onboardingControlUrlInvalid : null,
                    helperText: ssoPinned ? l.onboardingPinned : null,
                    border: const OutlineInputBorder(),
                    prefixIcon: Icon(ssoPinned ? Icons.lock : Icons.link),
                  ),
                ),
                const SizedBox(height: 16),
                TextField(
                  key: const ValueKey('sso_tenant'),
                  controller: _ssoTenant,
                  autocorrect: false,
                  enableSuggestions: false,
                  onChanged: (_) => setState(() => _ssoTenantInvalid = false),
                  decoration: InputDecoration(
                    labelText: l.onboardingSsoTenant,
                    hintText: l.onboardingSsoTenantHint,
                    errorText: _ssoTenantInvalid ? l.onboardingSsoTenantInvalid : null,
                    border: const OutlineInputBorder(),
                    prefixIcon: const Icon(Icons.business),
                  ),
                ),
                const SizedBox(height: 16),
                SizedBox(
                  height: 48,
                  child: OutlinedButton.icon(
                    key: const ValueKey('sso_submit'),
                    onPressed: _canSubmitSso ? _startSso : null,
                    icon: const Icon(Icons.open_in_browser),
                    label: Text(l.onboardingSsoButton),
                  ),
                ),
              ],
            ),
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 16),
              child: Row(
                children: [
                  const Expanded(child: Divider()),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 8),
                    child: Text(l.onboardingOrKey, style: t.textTheme.labelMedium, overflow: TextOverflow.ellipsis),
                  ),
                  const Expanded(child: Divider()),
                ],
              ),
            ),
            TextField(
              key: const ValueKey('enroll_url'),
              controller: _url,
              keyboardType: TextInputType.url,
              autocorrect: false,
              onChanged: (_) => setState(() => _urlInvalid = false),
              decoration: InputDecoration(
                labelText: l.onboardingControlUrl,
                errorText: _urlInvalid ? l.onboardingControlUrlInvalid : null,
                helperText: pinned ? l.onboardingPinned : null,
                border: const OutlineInputBorder(),
                prefixIcon: Icon(pinned ? Icons.lock : Icons.link),
              ),
            ),
            const SizedBox(height: 16),
            TextField(
              key: const ValueKey('enroll_key'),
              controller: _key,
              obscureText: true,
              autocorrect: false,
              enableSuggestions: false,
              onChanged: (_) => setState(() {}),
              decoration: InputDecoration(
                labelText: l.onboardingKey,
                helperText: l.onboardingKeyHint,
                border: const OutlineInputBorder(),
                prefixIcon: const Icon(Icons.key),
              ),
            ),
            const SizedBox(height: 16),
            TextField(
              key: const ValueKey('enroll_name'),
              controller: _name,
              onChanged: (_) => setState(() {}),
              decoration: InputDecoration(
                labelText: l.onboardingDeviceName,
                border: const OutlineInputBorder(),
                prefixIcon: const Icon(Icons.smartphone),
              ),
            ),
            if (_error != null) ...[const SizedBox(height: 16), InfoBanner(l.onboardingFailed(_error!), warning: true)],
            const SizedBox(height: 24),
            SizedBox(
              height: 52,
              child: FilledButton(
                key: const ValueKey('enroll_submit'),
                onPressed: _canSubmit ? _enroll : null,
                child: _busy
                    ? Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2)),
                          const SizedBox(width: 12),
                          Text(l.onboardingEnrolling),
                        ],
                      )
                    : Text(l.onboardingEnroll),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
