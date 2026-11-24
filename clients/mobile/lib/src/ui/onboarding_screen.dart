import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../data/core_state.dart';
import '../data/enrollment_code.dart';
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
  bool _busy = false;
  bool _codeInvalid = false;
  bool _codeApplied = false;
  bool _urlInvalid = false;
  String? _error;
  StreamSubscription<EngineEvent>? _links;

  @override
  void initState() {
    super.initState();
    // A deep link only pre-fills the form: enrolling always needs the user's tap.
    final engine = ref.read(engineProvider);
    _links = engine.events.where((e) => e.kind == EngineEvent.enrollLink).listen((e) => _fromLink(e.payload));
    engine.takeEnrollLink().then((l) {
      if (l != null && mounted) _fromLink(l);
    }, onError: (_) {});
  }

  void _fromLink(String uri) {
    _code.text = uri;
    _applyCode(uri);
  }

  @override
  void dispose() {
    _links?.cancel();
    for (final c in [_code, _url, _key, _name]) {
      c.dispose();
    }
    super.dispose();
  }

  void _applyCode(String text) {
    if (text.trim().isEmpty) {
      setState(() => _codeInvalid = false);
      return;
    }
    final code = EnrollmentCode.parse(text);
    setState(() {
      _codeInvalid = code == null;
      if (code != null) {
        _url.text = code.controlUrl;
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
      await ref.read(coreProvider.notifier).enroll(url, _key.text, _name.text);
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
              key: const Key('enroll_code'),
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
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 16),
              child: Row(
                children: [
                  const Expanded(child: Divider()),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 8),
                    child: Text(l.onboardingOr, style: t.textTheme.labelMedium),
                  ),
                  const Expanded(child: Divider()),
                ],
              ),
            ),
            TextField(
              key: const Key('enroll_url'),
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
              key: const Key('enroll_key'),
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
              key: const Key('enroll_name'),
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
                key: const Key('enroll_submit'),
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
