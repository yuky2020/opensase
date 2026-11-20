import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../data/enroll_link.dart';
import '../data/providers.dart';
import 'common.dart';

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key});

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  late final TextEditingController _url = TextEditingController(
    text: ref.read(controlUrlProvider).isEmpty ? defaultControlUrl(Uri.base) : ref.read(controlUrlProvider),
  );
  String? _error;

  @override
  void initState() {
    super.initState();
    _error = _validate(_url.text);
  }

  String? _validate(String s) => s.trim().isEmpty ? null : controlUrlError(s.trim());

  @override
  void dispose() {
    _url.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return PageFrame(
      title: l.navSettings,
      child: ListView(
        children: [
          SectionCard(
            title: l.settingsControlUrl,
            subtitle: l.settingsControlUrlHelp,
            children: [
              TextField(
                key: const Key('settings_control_url'),
                controller: _url,
                decoration: InputDecoration(
                  hintText: l.settingsControlUrlHint,
                  errorText: _error,
                  border: const OutlineInputBorder(),
                ),
                onChanged: (s) => setState(() => _error = _validate(s)),
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                children: [
                  OutlinedButton(
                    onPressed: () => setState(() {
                      final pin = _url.text.contains('#') ? _url.text.substring(_url.text.indexOf('#')) : '';
                      _url.text = defaultControlUrl(Uri.base) + pin;
                      _error = _validate(_url.text);
                    }),
                    child: Text(l.settingsUseOrigin),
                  ),
                  FilledButton(
                    onPressed: _error != null
                        ? null
                        : () {
                            ref.read(controlUrlProvider.notifier).set(_url.text);
                            showSnack(context, l.msgSettingsSaved);
                          },
                    child: Text(l.actionSave),
                  ),
                ],
              ),
            ],
          ),
          const SizedBox(height: 16),
          SectionCard(title: l.loginToken, children: [Text(l.settingsTokenInfo)]),
        ],
      ),
    );
  }
}
