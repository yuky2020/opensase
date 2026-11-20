import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../contracts/api.dart';
import '../data/core_state.dart';
import '../data/policy_logic.dart';
import 'common.dart';
import 'screen_state.dart';

class AppDetailScreen extends ConsumerWidget {
  const AppDetailScreen({super.key, required this.pkg});
  final String pkg;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    final t = Theme.of(context);
    final app = ref.watch(appsByPackageProvider)[pkg];
    final verdicts = ref.watch(appVerdictsProvider(pkg));
    final stat = ref.watch(coreProvider.select((s) => s.stats.where((a) => a.app == pkg).firstOrNull));
    final flows = ref.watch(coreProvider.select((s) => s.flows.where((f) => f.flow.app == pkg).take(100).toList()));
    final editable = verdicts.any((v) => !v.locked);

    Future<void> save(UserRules Function(UserRules) f) async {
      final r = await ref.read(coreProvider.notifier).updateUserLayer(f);
      if (context.mounted) showSaveResult(context, r);
    }

    return Scaffold(
      appBar: AppBar(title: Text(app?.label ?? pkg)),
      body: ListView(
        children: [
          Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                AppIcon(pkg, size: 56),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(app?.label ?? pkg, style: t.textTheme.titleLarge),
                      Text(pkg, style: t.textTheme.bodySmall?.copyWith(color: t.colorScheme.onSurfaceVariant)),
                      if (app != null && app.uid >= 0)
                        Text(
                          l.appDetailUid(app.uid),
                          style: t.textTheme.bodySmall?.copyWith(color: t.colorScheme.onSurfaceVariant),
                        ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Card(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
                    child: Text(l.appDetailAccess, style: t.textTheme.titleMedium),
                  ),
                  for (final v in verdicts)
                    SwitchListTile(
                      key: Key('detail_switch_${v.network.wire}'),
                      secondary: Icon(networkIcon(v.network)),
                      title: Text(networkLabel(context, v.network)),
                      subtitle: Text(switch (v.origin) {
                        VerdictOrigin.tenantRule ||
                        VerdictOrigin.tenantApp => '${l.companyPolicy}${v.ruleId.isEmpty ? '' : ' · ${v.ruleId}'}',
                        VerdictOrigin.userApp => l.originUser,
                        VerdictOrigin.defaultAction => l.originDefault,
                        VerdictOrigin.lockdown => l.originLockdown,
                      }),
                      value: v.allowed,
                      onChanged: v.locked
                          ? null
                          : (on) => save((u) => PolicyLogic.setAppNetwork(u, pkg, v.network, on)),
                    ),
                  Padding(
                    padding: const EdgeInsets.all(16),
                    child: Row(
                      children: [
                        Expanded(
                          child: OutlinedButton.icon(
                            onPressed: editable ? () => save((u) => PolicyLogic.setAppAll(u, pkg, false)) : null,
                            icon: const Icon(Icons.block),
                            label: Text(l.appDetailBlockAll),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: OutlinedButton.icon(
                            onPressed: editable ? () => save((u) => PolicyLogic.setAppAll(u, pkg, true)) : null,
                            icon: const Icon(Icons.check_circle),
                            label: Text(l.appDetailAllowAll),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(l.appDetailTraffic, style: t.textTheme.titleMedium),
                    const SizedBox(height: 4),
                    Text(
                      '${l.appDetailIn}: ${Fmt.bytes(stat?.bytesIn ?? 0)}   ${l.appDetailOut}: ${Fmt.bytes(stat?.bytesOut ?? 0)}',
                    ),
                    Text(l.statsCounts(stat?.allowed ?? 0, stat?.blocked ?? 0)),
                    if ((stat?.dnsQueries ?? 0) > 0) Text(l.statsDns(stat!.dnsQueries, stat.dnsBlocked)),
                  ],
                ),
              ),
            ),
          ),
          SectionHeader(l.appDetailRecent),
          if (flows.isEmpty) EmptyState(l.appDetailNoFlows),
          for (final f in flows) ...[FlowTile(record: f, showApp: false), const Divider(height: 1, indent: 16)],
        ],
      ),
    );
  }
}

/// One connection: app icon, destination, domain, verdict chip, rule/layer, time.
class FlowTile extends ConsumerWidget {
  const FlowTile({super.key, required this.record, this.showApp = true, this.onOpenApp});
  final FlowRecord record;
  final bool showApp;
  final void Function(String pkg)? onOpenApp;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = Theme.of(context);
    final f = record.flow;
    final d = record.decision;
    final dest = Fmt.endpoint(f.dstIp, f.dstPort);
    final rule = d.ruleId.isEmpty
        ? layerLabel(context, d.layer)
        : context.l10n.activityRule(layerLabel(context, d.layer), d.ruleId);
    return ListTile(
      leading: showApp ? AppIcon(f.app, size: 36) : null,
      onTap: showApp && f.app.isNotEmpty && onOpenApp != null ? () => onOpenApp!(f.app) : null,
      title: Text(f.domain.isEmpty ? dest : f.domain, maxLines: 1, overflow: TextOverflow.ellipsis),
      subtitle: Text(
        [if (showApp) appLabel(ref, context, f.app), '${f.protocol.toUpperCase()} $dest', rule].join(' · '),
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          VerdictChip(d.action),
          const SizedBox(height: 4),
          Text(Fmt.time(record.start), style: t.textTheme.labelSmall?.copyWith(color: t.colorScheme.onSurfaceVariant)),
        ],
      ),
    );
  }
}
