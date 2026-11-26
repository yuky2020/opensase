import 'package:fl_chart/fl_chart.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_models.dart';
import '../data/flow_stats.dart';
import '../data/providers.dart';
import '../data/session.dart';
import 'common.dart';

const onboardingSessionKey = 'opensase.admin.onboarding.checked';

/// Chart series colours: allow and block, validated for CVD separation on both surfaces
/// (dataviz validator). Red/green verdict colours of the theme fail it, so the chart uses
/// blue for allow; labels and the legend carry the identity too.
({Color allow, Color block, Color other}) _seriesColors(BuildContext context) {
  final dark = Theme.of(context).brightness == Brightness.dark;
  return (
    allow: dark ? const Color(0xFF2E9BC9) : const Color(0xFF0077B6),
    block: dark ? const Color(0xFFE0584B) : const Color(0xFFBA1A1A),
    other: Theme.of(context).colorScheme.outline,
  );
}

class OverviewScreen extends ConsumerStatefulWidget {
  const OverviewScreen({super.key});

  @override
  ConsumerState<OverviewScreen> createState() => _OverviewScreenState();
}

class _OverviewScreenState extends ConsumerState<OverviewScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _checkAutoOnboarding());
  }

  Future<void> _checkAutoOnboarding() async {
    try {
      final store = ref.read(tabStorageProvider);
      if (store.read(onboardingSessionKey) != null) return;
      store.write(onboardingSessionKey, '1');

      final tenant = ref.read(currentTenantProvider);
      if (tenant == null) {
        final tenants = await ref.read(apiProvider).listTenants();
        if (tenants.isEmpty) {
          _navigateToOnboarding();
          return;
        }
        final t = tenants.first.id;
        final devices = await ref.read(apiProvider).listDevices(t);
        final policy = await ref.read(apiProvider).getPolicy(t);
        if (devices.isEmpty && policy.rules.isEmpty) {
          _navigateToOnboarding();
        }
        return;
      }

      final devices = await ref.read(apiProvider).listDevices(tenant);
      final policy = await ref.read(apiProvider).getPolicy(tenant);
      if (devices.isEmpty && policy.rules.isEmpty) {
        _navigateToOnboarding();
      }
    } catch (_) {
      // Never block the rest of the portal.
    }
  }

  void _navigateToOnboarding() {
    if (!mounted) return;
    bool atOverview = false;
    try {
      atOverview = GoRouterState.of(context).matchedLocation == '/overview';
    } catch (_) {
      atOverview = false;
    }
    if (atOverview) {
      context.go('/onboarding');
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final now = ref.watch(clockProvider)();
    final tenant = ref.watch(currentTenantProvider);
    final isSuper = ref.watch(isSuperProvider);
    final edges = isSuper ? ref.watch(edgesProvider) : null;
    final devices = tenant == null ? null : ref.watch(devicesProvider(tenant));
    final connectors = tenant == null ? null : ref.watch(connectorsProvider(tenant));
    final flows = tenant == null ? null : ref.watch(flowsProvider(tenant));

    String count<T>(AsyncValue<List<T>>? v, int Function(List<T>) f) =>
        v?.value == null ? (v?.hasError ?? false ? '!' : '…') : '${f(v!.value as List<T>)}';

    final tiles = [
      _StatTile(
        key: const Key('stat_devices'),
        icon: Icons.phone_android,
        label: l.overviewDevices,
        value: count<AdminDevice>(devices, (d) => d.where((x) => !x.revoked).length),
      ),
      _StatTile(
        key: const Key('stat_connectors'),
        icon: Icons.hub,
        label: l.overviewConnectorsOnline,
        value: count<AdminConnector>(connectors, (c) => c.where((x) => x.isOnline(now)).length),
        detail: connectors?.value == null ? null : l.overviewOf(connectors!.value!.where((c) => !c.revoked).length),
      ),
      if (isSuper)
        _StatTile(
          key: const Key('stat_edges'),
          icon: Icons.cell_tower,
          label: l.overviewEdges,
          value: count<AdminEdge>(edges, (e) => e.where((x) => !x.revoked).length),
        ),
      _StatTile(
        key: const Key('stat_blocks'),
        icon: Icons.block,
        label: l.overviewBlocksHour,
        value: count<FlowRecord>(flows, (f) => blocksSince(f, now)),
      ),
    ];

    return PageFrame(
      title: l.navOverview,
      actions: [
        IconButton(
          tooltip: l.actionRefresh,
          icon: const Icon(Icons.refresh),
          onPressed: () {
            if (isSuper) ref.invalidate(edgesProvider);
            if (tenant != null) {
              ref
                ..invalidate(devicesProvider(tenant))
                ..invalidate(connectorsProvider(tenant))
                ..invalidate(flowsProvider(tenant));
            }
          },
        ),
      ],
      child: ListView(
        children: [
          LayoutBuilder(
            builder: (context, c) {
              final cols = c.maxWidth >= 1000 ? 4 : (c.maxWidth >= 520 ? 2 : 1);
              final w = (c.maxWidth - (cols - 1) * 12) / cols;
              return Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [for (final t in tiles) SizedBox(width: w, child: t)],
              );
            },
          ),
          const SizedBox(height: 16),
          if (tenant == null)
            EmptyState(text: l.emptyNoTenant)
          else
            AsyncBody(
              value: flows!,
              onRetry: () => ref.invalidate(flowsProvider(tenant)),
              builder: (list) => _VerdictChart(flows: list),
            ),
          const SizedBox(height: 16),
        ],
      ),
    );
  }
}

class _StatTile extends StatelessWidget {
  const _StatTile({super.key, required this.icon, required this.label, required this.value, this.detail});

  final IconData icon;
  final String label;
  final String value;
  final String? detail;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Icon(icon, color: scheme.primary, size: 32),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(label, style: tt.bodyMedium?.copyWith(color: scheme.onSurfaceVariant)),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.baseline,
                    textBaseline: TextBaseline.alphabetic,
                    children: [
                      Text(value, style: tt.displaySmall),
                      if (detail != null) ...[
                        const SizedBox(width: 8),
                        Text(detail!, style: tt.bodyMedium?.copyWith(color: scheme.onSurfaceVariant)),
                      ],
                    ],
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

/// Grouped bars: allowed / blocked / other flows per decision layer, with a legend, hover
/// tooltips and the same numbers as a table below.
class _VerdictChart extends StatelessWidget {
  const _VerdictChart({required this.flows});

  final List<FlowRecord> flows;

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final tt = Theme.of(context).textTheme;
    final scheme = Theme.of(context).colorScheme;
    final colors = _seriesColors(context);
    final byLayer = verdictsByLayer(flows);
    final layers = byLayer.keys.toList();
    final hasOther = byLayer.values.any((c) => c.other > 0);
    final maxY = byLayer.values.fold<int>(0, (m, c) => [m, c.allow, c.block, c.other].reduce((a, b) => a > b ? a : b));

    BarChartRodData rod(int v, Color c) => BarChartRodData(
      toY: v.toDouble(),
      color: c,
      width: 14,
      borderRadius: const BorderRadius.vertical(top: Radius.circular(4)),
    );

    final series = [
      (l.verdictAllow, colors.allow),
      (l.verdictBlock, colors.block),
      if (hasOther) (l.verdictOther, colors.other),
    ];

    return SectionCard(
      title: l.overviewChartTitle(flows.length),
      children: [
        Wrap(
          spacing: 16,
          children: [
            for (final (name, c) in series)
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    width: 12,
                    height: 12,
                    decoration: BoxDecoration(color: c, borderRadius: BorderRadius.circular(3)),
                  ),
                  const SizedBox(width: 6),
                  Text(name, style: tt.bodySmall),
                ],
              ),
          ],
        ),
        const SizedBox(height: 12),
        if (layers.isEmpty)
          EmptyState(text: l.emptyNothingHere, icon: Icons.bar_chart)
        else ...[
          SizedBox(
            height: 260,
            child: BarChart(
              BarChartData(
                maxY: maxY == 0 ? 1 : maxY * 1.15,
                alignment: BarChartAlignment.spaceAround,
                gridData: FlGridData(
                  drawVerticalLine: false,
                  getDrawingHorizontalLine: (_) => FlLine(color: scheme.outlineVariant, strokeWidth: 1),
                ),
                borderData: FlBorderData(show: false),
                titlesData: FlTitlesData(
                  topTitles: const AxisTitles(),
                  rightTitles: const AxisTitles(),
                  leftTitles: AxisTitles(
                    sideTitles: SideTitles(
                      showTitles: true,
                      reservedSize: 40,
                      getTitlesWidget: (v, meta) => v == v.roundToDouble()
                          ? SideTitleWidget(
                              meta: meta,
                              child: Text(v.toInt().toString(), style: tt.bodySmall),
                            )
                          : const SizedBox.shrink(),
                    ),
                  ),
                  bottomTitles: AxisTitles(
                    sideTitles: SideTitles(
                      showTitles: true,
                      getTitlesWidget: (v, meta) => SideTitleWidget(
                        meta: meta,
                        child: Text(layers[v.toInt()], style: tt.bodySmall),
                      ),
                    ),
                  ),
                ),
                barTouchData: BarTouchData(
                  touchTooltipData: BarTouchTooltipData(
                    getTooltipColor: (_) => scheme.inverseSurface,
                    getTooltipItem: (group, _, rod, rodIndex) => BarTooltipItem(
                      '${layers[group.x]} · ${series[rodIndex].$1}: ${rod.toY.toInt()}',
                      TextStyle(color: scheme.onInverseSurface),
                    ),
                  ),
                ),
                barGroups: [
                  for (final (i, layer) in layers.indexed)
                    BarChartGroupData(
                      x: i,
                      barsSpace: 2,
                      barRods: [
                        rod(byLayer[layer]!.allow, colors.allow),
                        rod(byLayer[layer]!.block, colors.block),
                        if (hasOther) rod(byLayer[layer]!.other, colors.other),
                      ],
                    ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: DataTable(
              headingRowHeight: 36,
              dataRowMinHeight: 32,
              dataRowMaxHeight: 36,
              columns: [
                DataColumn(label: Text(l.flowsLayer)),
                for (final (name, _) in series) DataColumn(label: Text(name), numeric: true),
              ],
              rows: [
                for (final layer in layers)
                  DataRow(
                    cells: [
                      DataCell(Text(layer)),
                      DataCell(Text('${byLayer[layer]!.allow}')),
                      DataCell(Text('${byLayer[layer]!.block}')),
                      if (hasOther) DataCell(Text('${byLayer[layer]!.other}')),
                    ],
                  ),
              ],
            ),
          ),
        ],
      ],
    );
  }
}
