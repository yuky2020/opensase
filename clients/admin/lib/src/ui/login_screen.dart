import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../data/browser_nav.dart';
import '../data/session.dart';
import 'common.dart';

class LoginScreen extends ConsumerStatefulWidget {
  const LoginScreen({super.key});

  @override
  ConsumerState<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends ConsumerState<LoginScreen> {
  final _token = TextEditingController();
  final _oidcTenant = TextEditingController();
  bool _remember = false;
  bool _busy = false;
  bool _obscure = true;
  String? _error;
  String? _oidcError;

  @override
  void dispose() {
    _token.dispose();
    _oidcTenant.dispose();
    super.dispose();
  }

  void _submitOidc() {
    final l = context.l10n;
    final tenant = _oidcTenant.text.trim();
    if (tenant.isEmpty) {
      setState(() => _oidcError = l.loginOidcTenantRequired);
      return;
    }
    setState(() => _oidcError = null);
    final base = ref.read(apiBaseProvider);
    final url = buildOidcLoginUrl(tenant, base: base);
    ref.read(browserNavProvider)(url);
  }

  Future<void> _submit() async {
    final l = context.l10n;
    if (_token.text.trim().isEmpty) {
      setState(() => _error = l.loginTokenRequired);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref.read(sessionProvider.notifier).login(_token.text, rememberForTab: _remember);
    } on Object catch (e) {
      if (mounted) setState(() => _error = l.loginFailed(errorText(e)));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final tt = Theme.of(context).textTheme;
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 440),
            child: Card(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: AutofillGroup(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Icon(Icons.admin_panel_settings, size: 48, color: Theme.of(context).colorScheme.primary),
                      const SizedBox(height: 12),
                      Text(l.loginTitle, style: tt.headlineSmall, textAlign: TextAlign.center),
                      const SizedBox(height: 8),
                      Text(l.loginSubtitle, textAlign: TextAlign.center),
                      const SizedBox(height: 24),
                      TextField(
                        key: const Key('login_token'),
                        controller: _token,
                        obscureText: _obscure,
                        autocorrect: false,
                        enableSuggestions: false,
                        autofillHints: const [AutofillHints.password],
                        decoration: InputDecoration(
                          labelText: l.loginToken,
                          border: const OutlineInputBorder(),
                          suffixIcon: IconButton(
                            icon: Icon(_obscure ? Icons.visibility : Icons.visibility_off),
                            onPressed: () => setState(() => _obscure = !_obscure),
                          ),
                        ),
                        onSubmitted: (_) => _busy ? null : _submit(),
                      ),
                      const SizedBox(height: 8),
                      CheckboxListTile(
                        key: const Key('login_remember'),
                        contentPadding: EdgeInsets.zero,
                        controlAffinity: ListTileControlAffinity.leading,
                        value: _remember,
                        onChanged: (v) => setState(() => _remember = v ?? false),
                        title: Text(l.loginRemember),
                        subtitle: Text(l.loginRememberHint),
                      ),
                      if (_error != null) ...[
                        const SizedBox(height: 8),
                        Text(
                          _error!,
                          key: const Key('login_error'),
                          style: TextStyle(color: Theme.of(context).colorScheme.error),
                        ),
                      ],
                      const SizedBox(height: 16),
                      FilledButton(
                        key: const Key('login_submit'),
                        onPressed: _busy ? null : _submit,
                        child: _busy
                            ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                            : Text(l.loginSubmit),
                      ),
                      const SizedBox(height: 24),
                      Row(
                        children: [
                          const Expanded(child: Divider()),
                          Padding(
                            padding: const EdgeInsets.symmetric(horizontal: 16),
                            child: Text(l.loginOr, style: tt.bodySmall),
                          ),
                          const Expanded(child: Divider()),
                        ],
                      ),
                      const SizedBox(height: 20),
                      Text(l.loginOidcTitle, style: tt.titleMedium, textAlign: TextAlign.center),
                      const SizedBox(height: 16),
                      TextField(
                        key: const Key('login_oidc_tenant'),
                        controller: _oidcTenant,
                        autocorrect: false,
                        enableSuggestions: false,
                        decoration: InputDecoration(labelText: l.loginOidcTenant, border: const OutlineInputBorder()),
                        onSubmitted: (_) => _submitOidc(),
                      ),
                      if (_oidcError != null) ...[
                        const SizedBox(height: 8),
                        Text(
                          _oidcError!,
                          key: const Key('login_oidc_error'),
                          style: TextStyle(color: Theme.of(context).colorScheme.error),
                        ),
                      ],
                      const SizedBox(height: 16),
                      OutlinedButton.icon(
                        key: const Key('login_oidc_submit'),
                        onPressed: _submitOidc,
                        icon: const Icon(Icons.corporate_fare),
                        label: Text(l.loginOidcSubmit),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
