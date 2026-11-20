import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../data/core_state.dart';
import 'common.dart';

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key, required this.appVersion});
  final String appVersion;

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  bool _connectOnBoot = true;

  void _snack(String text) => ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));

  Future<void> _export() async {
    final engine = ref.read(engineProvider);
    try {
      final json = await engine.recentFlows(2048);
      final ok = await engine.saveFile('opensase-flows.json', json);
      if (mounted && ok) _snack(context.l10n.settingsExportDone);
    } catch (e) {
      if (mounted) _snack(context.l10n.msgError('$e'));
    }
  }

  Future<void> _unenroll() async {
    final l = context.l10n;
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        content: Text(l.settingsUnenrollConfirm),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: Text(l.actionCancel)),
          TextButton(onPressed: () => Navigator.pop(c, true), child: Text(l.settingsUnenroll)),
        ],
      ),
    );
    if (ok != true) return;
    try {
      final n = ref.read(coreProvider.notifier);
      await n.disconnect();
      await n.unenroll();
    } catch (e) {
      if (mounted) _snack(l.msgError('$e'));
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final t = Theme.of(context);
    final s = ref.watch(coreProvider);
    final engine = ref.read(engineProvider);
    final snap = s.policy.snapshot;
    final fw = snap?.firewall;
    final locale = Localizations.localeOf(context).toLanguageTag();
    return ListView(
      padding: const EdgeInsets.only(bottom: 24),
      children: [
        SectionHeader(l.settingsAlwaysOn),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(l.settingsAlwaysOnDesc),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      FilledButton.icon(
                        onPressed: engine.openVpnSettings,
                        icon: const Icon(Icons.vpn_key),
                        label: Text(l.settingsOpenVpnSettings),
                      ),
                      if (s.vpn.alwaysOn) const Chip(avatar: Icon(Icons.check, size: 16), label: Text('Always-on')),
                      if (s.vpn.lockdown) const Chip(avatar: Icon(Icons.lock, size: 16), label: Text('Lockdown')),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
        SwitchListTile(
          title: Text(l.settingsConnectOnBoot),
          subtitle: Text(l.settingsConnectOnBootDesc),
          value: _connectOnBoot,
          onChanged: (v) {
            setState(() => _connectOnBoot = v);
            engine.setConnectOnBoot(v);
          },
        ),
        SectionHeader(l.settingsPolicy),
        ListTile(
          title: Text(l.settingsDefaultAction),
          trailing: fw == null ? const Text('—') : VerdictChip(fw.defaultAction),
        ),
        ListTile(
          title: Text(l.settingsLockdown),
          subtitle: Text(fw == null ? '—' : (fw.lockdown ? l.settingsLockdownOn : l.settingsLockdownOff)),
        ),
        ListTile(
          title: Text(l.settingsUserRules),
          subtitle: Text(
            fw == null ? '—' : (fw.allowUserRules ? l.settingsUserRulesAllowed : l.settingsUserRulesDenied),
          ),
        ),
        ListTile(
          title: Text(l.settingsSnapshot),
          subtitle: Text(
            snap == null ? '—' : l.settingsSnapshotValue(snap.version, Fmt.dateTime(snap.expiresAt, locale)),
          ),
        ),
        ListTile(
          key: const Key('settings_cert'),
          title: Text(l.settingsCertificate),
          subtitle: Text(
            s.status.certExpiresAt.isEmpty
                ? '—'
                : l.settingsCertificateExpires(Fmt.dateTime(s.status.certExpiresAt, locale)),
          ),
        ),
        ListTile(
          title: Text(l.settingsDevice),
          subtitle: Text(
            [
              snap?.deviceId ?? s.status.deviceId,
              if (snap != null && snap.tenantId.isNotEmpty) snap.tenantId,
            ].where((e) => e.isNotEmpty).join(' · '),
          ),
        ),
        const Divider(),
        ListTile(
          leading: const Icon(Icons.file_download_outlined),
          title: Text(l.settingsExportLogs),
          subtitle: Text(l.settingsExportLogsDesc),
          onTap: _export,
        ),
        ListTile(
          key: const Key('settings_unenroll'),
          leading: Icon(Icons.logout, color: t.colorScheme.error),
          title: Text(l.settingsUnenroll, style: TextStyle(color: t.colorScheme.error)),
          subtitle: Text(l.settingsUnenrollDesc),
          onTap: _unenroll,
        ),
        SectionHeader(l.settingsAbout),
        ListTile(
          title: Text(l.settingsVersion(widget.appVersion, engine.name)),
          subtitle: Text(engine.name == 'fake' ? l.engineFake : l.engineNative),
        ),
        ListTile(
          title: Text(l.settingsLicenses),
          subtitle: Text(l.settingsLicensesText),
          onTap: () =>
              showLicensePage(context: context, applicationName: 'OpenSASE', applicationVersion: widget.appVersion),
        ),
      ],
    );
  }
}
