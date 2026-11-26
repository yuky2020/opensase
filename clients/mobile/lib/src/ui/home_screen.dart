import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../contracts/engine_types.dart';
import '../data/core_state.dart';
import '../engine/engine.dart';
import '../platform_info.dart';
import 'common.dart';
import 'theme.dart';

class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key, required this.onOpenApp});
  final void Function(String pkg) onOpenApp;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final s = ref.watch(coreProvider);
    final l = context.l10n;
    final topBlocked = ([
      ...s.stats.where((a) => a.blocked > 0),
    ]..sort((a, b) => b.blocked.compareTo(a.blocked))).take(5).toList();
    return RefreshIndicator(
      onRefresh: () => ref.read(coreProvider.notifier).refreshAll(),
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _ConnectToggle(state: s),
          const SizedBox(height: 16),
          _StatusCard(state: s),
          if (s.status.postureFailing.isNotEmpty) ...[
            const SizedBox(height: 12),
            _PostureAttentionCard(failing: s.status.postureFailing),
          ],
          if (isDesktop && !s.daemonConnected) ...[const SizedBox(height: 12), const DaemonUnreachableBanner()],
          if (s.status.stale) ...[const SizedBox(height: 12), InfoBanner(l.homeStale, warning: true)],
          if (s.vpn.phase == VpnPhase.failed && s.vpn.message.isNotEmpty) ...[
            const SizedBox(height: 12),
            InfoBanner(l.homeFailed(s.vpn.message == 'consent' ? l.vpnConsentDenied : s.vpn.message), warning: true),
          ] else if (s.status.state == EngineStatus.errorState && s.status.error.isNotEmpty) ...[
            const SizedBox(height: 12),
            InfoBanner(l.homeFailed(s.status.error), warning: true),
          ],
          const SizedBox(height: 16),
          _CountersCard(state: s),
          if (!isDesktop) ...[
            const SizedBox(height: 16),
            Card(
              child: Padding(
                padding: const EdgeInsets.symmetric(vertical: 16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 16),
                      child: Text(l.homeTopBlocked, style: Theme.of(context).textTheme.titleMedium),
                    ),
                    if (topBlocked.isEmpty) Padding(padding: const EdgeInsets.all(16), child: Text(l.homeNoBlocked)),
                    for (final a in topBlocked)
                      ListTile(
                        leading: AppIcon(a.app, size: 36),
                        title: Text(appLabel(ref, context, a.app), maxLines: 1, overflow: TextOverflow.ellipsis),
                        trailing: Text(
                          l.homeBlockedCount(a.blocked),
                          style: TextStyle(color: context.verdicts.block, fontWeight: FontWeight.w600),
                        ),
                        onTap: a.app.isEmpty ? null : () => onOpenApp(a.app),
                      ),
                  ],
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _ConnectToggle extends ConsumerWidget {
  const _ConnectToggle({required this.state});
  final CoreState state;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    final scheme = Theme.of(context).colorScheme;
    final on = state.vpn.isOn;
    final label = switch (state.vpn.phase) {
      VpnPhase.running => state.status.isConnected ? l.stateConnected : l.stateConnecting,
      VpnPhase.connecting => l.stateConnecting,
      VpnPhase.failed => l.stateError,
      VpnPhase.idle => l.stateDisconnected,
    };
    return Column(
      children: [
        const SizedBox(height: 8),
        Semantics(
          button: true,
          toggled: on,
          label: label,
          child: Material(
            key: const Key('connect_toggle'),
            shape: const CircleBorder(),
            color: on ? scheme.primary : scheme.surfaceContainerHighest,
            elevation: on ? 8 : 2,
            child: InkWell(
              customBorder: const CircleBorder(),
              onTap: () {
                final n = ref.read(coreProvider.notifier);
                on ? n.disconnect() : n.connect();
              },
              child: SizedBox(
                width: 168,
                height: 168,
                child: Icon(Icons.power_settings_new, size: 72, color: on ? scheme.onPrimary : scheme.onSurfaceVariant),
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        Text(label, style: Theme.of(context).textTheme.headlineMedium),
        Text(
          on ? l.homeToggleOn : l.homeToggleOff,
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: scheme.onSurfaceVariant),
        ),
      ],
    );
  }
}

class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.state});
  final CoreState state;

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final st = state.status;
    Widget kv(String k, String v) => Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(k, style: TextStyle(color: Theme.of(context).colorScheme.onSurfaceVariant)),
          Flexible(
            child: Text(
              v,
              style: const TextStyle(fontWeight: FontWeight.w500),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
    String handshake() {
      if (st.lastHandshake <= 0) return '—';
      final d = DateTime.fromMillisecondsSinceEpoch(st.lastHandshake * 1000).toIso8601String();
      return Fmt.time(d);
    }

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (state.quantumSafe) ...[
              QuantumBadge(st.kex.isEmpty ? 'X25519MLKEM768' : st.kex),
              const SizedBox(height: 8),
            ],
            kv(l.homeEdge, st.edge.isEmpty ? '—' : st.edge),
            kv(l.homeSnapshotVersion, st.snapshotVersion > 0 ? 'v${st.snapshotVersion}' : '—'),
            if (st.network.isNotEmpty) kv(l.homeNetwork, st.network),
            if (st.isConnected) kv(l.homeLastHandshake, handshake()),
          ],
        ),
      ),
    );
  }
}

class _CountersCard extends StatelessWidget {
  const _CountersCard({required this.state});
  final CoreState state;

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final c = state.counters;
    final v = context.verdicts;
    Widget counter(int value, String label, Color color) => Column(
      children: [
        Text('$value', style: Theme.of(context).textTheme.headlineMedium?.copyWith(color: color)),
        Text(label, style: Theme.of(context).textTheme.labelMedium),
      ],
    );
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(l.homeToday, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
              children: [
                counter(c.allowed, l.homeAllowed, v.allow),
                counter(c.blocked, l.homeBlocked, v.block),
                counter(c.dnsBlocked, l.homeDnsBlocked, v.ask),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _PostureAttentionCard extends StatelessWidget {
  const _PostureAttentionCard({required this.failing});
  final List<String> failing;

  String _hintFor(BuildContext context, String check) {
    final l = context.l10n;
    return switch (check) {
      'osVersion' => l.postureHintOsVersion,
      'clientVersion' => l.postureHintClientVersion,
      'diskEncryption' => l.postureHintDiskEncryption,
      'screenLock' => l.postureHintScreenLock,
      'managed' => l.postureHintManaged,
      'firewall' => l.postureHintFirewall,
      _ => check,
    };
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final scheme = Theme.of(context).colorScheme;
    return Card(
      key: const ValueKey('posture_attention_card'),
      color: scheme.errorContainer,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.warning_amber_rounded, color: scheme.onErrorContainer),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    l.postureAttention,
                    style: Theme.of(context).textTheme.titleMedium
                        ?.copyWith(color: scheme.onErrorContainer, fontWeight: FontWeight.bold),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            for (final check in failing)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '• ',
                      style: TextStyle(color: scheme.onErrorContainer, fontWeight: FontWeight.bold),
                    ),
                    Expanded(
                      child: Text(_hintFor(context, check), style: TextStyle(color: scheme.onErrorContainer)),
                    ),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }
}
