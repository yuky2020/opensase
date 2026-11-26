import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../data/providers.dart';
import 'common.dart';
import 'theme.dart';

/// Periodic refresh interval for deployment status (default 30 seconds).
final statusRefreshPeriodProvider = Provider<Duration?>((ref) => const Duration(seconds: 30));

/// Deployment health and status page for the super-admin (issue #73).
class StatusScreen extends ConsumerStatefulWidget {
  const StatusScreen({super.key});

  @override
  ConsumerState<StatusScreen> createState() => _StatusScreenState();
}

class _StatusScreenState extends ConsumerState<StatusScreen> {
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _schedule();
  }

  void _schedule() {
    _timer?.cancel();
    final period = ref.read(statusRefreshPeriodProvider);
    if (period != null) {
      _timer = Timer.periodic(period, (_) {
        if (mounted) ref.invalidate(statusProvider);
      });
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  static String _auditChainLabel(String chain) => switch (chain) {
    'ok' => 'OK',
    'broken' => 'Broken',
    _ => 'Unknown',
  };

  static Color _auditChainColor(BuildContext context, String chain) => switch (chain) {
    'ok' => context.verdicts.allow,
    'broken' => Theme.of(context).colorScheme.error,
    _ => Theme.of(context).colorScheme.outline,
  };

  static String _formatAge(int seconds) {
    if (seconds < 0) return 'Not loaded';
    if (seconds < 60) return '$seconds s';
    final minutes = seconds ~/ 60;
    if (minutes < 60) return '$minutes min';
    final hours = minutes ~/ 60;
    final remMinutes = minutes % 60;
    if (hours < 24) return '${hours}h ${remMinutes}m';
    final days = hours ~/ 24;
    final remHours = hours % 24;
    return '${days}d ${remHours}h';
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final isSuper = ref.watch(isSuperProvider);
    if (!isSuper) {
      final identity = ref.watch(identityProvider);
      if (identity.isLoading) return const Center(child: CircularProgressIndicator());
      return PageFrame(
        title: l.navStatus,
        child: EmptyState(text: l.emptyNothingHere, icon: Icons.monitor_heart_outlined),
      );
    }

    final now = ref.watch(clockProvider)();
    final scheme = Theme.of(context).colorScheme;

    return PageFrame(
      title: l.navStatus,
      subtitle: 'Deployment health and telemetry across Edges, Connectors and Control Plane.',
      actions: [
        IconButton(
          key: const Key('status_refresh'),
          tooltip: l.actionRefresh,
          icon: const Icon(Icons.refresh),
          onPressed: () => ref.invalidate(statusProvider),
        ),
      ],
      child: AsyncBody(
        value: ref.watch(statusProvider),
        onRetry: () => ref.invalidate(statusProvider),
        builder: (st) {
          final tiles = [
            _StatTile(
              key: const Key('stat_devices'),
              icon: Icons.phone_android,
              label: 'Devices',
              value: '${st.devicesOnline}',
              detail: 'online of ${st.devicesEnrolled} enrolled',
            ),
            _StatTile(
              key: const Key('stat_connectors'),
              icon: Icons.hub,
              label: 'Connectors',
              value: '${st.connectorsOnline}',
              detail: 'online of ${st.connectorsTotal} total',
            ),
            _StatTile(
              key: const Key('stat_leader'),
              icon: Icons.dns_outlined,
              label: 'Leader',
              value: st.leader ? l.yes : l.no,
              trailing: StatusChip(
                label: st.leader ? 'Leader' : 'Follower',
                color: st.leader ? context.verdicts.allow : scheme.outline,
              ),
              detail: st.leader ? 'Active leader replica' : 'Follower replica',
            ),
            _StatTile(
              key: const Key('stat_audit_chain'),
              icon: Icons.verified_user_outlined,
              label: 'Audit chain',
              value: _auditChainLabel(st.auditChain),
              trailing: StatusChip(
                label: _auditChainLabel(st.auditChain),
                color: _auditChainColor(context, st.auditChain),
              ),
              detail: st.auditChain == 'ok'
                  ? 'Intact'
                  : (st.auditChain == 'broken' ? 'Verification failed' : 'Not verified'),
            ),
            _StatTile(
              key: const Key('stat_category_list'),
              icon: Icons.category_outlined,
              label: 'Category list age',
              value: _formatAge(st.categoryListAgeSec),
              detail: st.categoryListAgeSec < 0 ? 'No list loaded' : 'Age since loaded',
            ),
          ];

          return ListView(
            children: [
              LayoutBuilder(
                builder: (context, c) {
                  final cols = c.maxWidth >= 1200 ? 5 : (c.maxWidth >= 850 ? 3 : (c.maxWidth >= 500 ? 2 : 1));
                  final w = (c.maxWidth - (cols - 1) * 12) / cols;
                  return Wrap(
                    spacing: 12,
                    runSpacing: 12,
                    children: [for (final t in tiles) SizedBox(width: w, child: t)],
                  );
                },
              ),
              const SizedBox(height: 16),
              SectionCard(
                key: const Key('status_edges_card'),
                title: 'Edges',
                subtitle: '${st.edges.length} registered',
                children: [
                  if (st.edges.isEmpty)
                    EmptyState(text: l.emptyNothingHere, icon: Icons.cell_tower)
                  else
                    ScrollTable(
                      columns: [
                        DataColumn(label: Text(l.fieldId)),
                        const DataColumn(label: Text('Region')),
                        const DataColumn(label: Text('Sessions')),
                        const DataColumn(label: Text('Reporting')),
                      ],
                      rows: [
                        for (final e in st.edges)
                          DataRow(
                            key: ValueKey('edge_row_${e.id}'),
                            cells: [
                              DataCell(SelectableText(e.id, style: const TextStyle(fontFamily: 'monospace'))),
                              DataCell(Text(e.region.isEmpty ? '-' : e.region)),
                              DataCell(Text('${e.sessions}')),
                              DataCell(
                                StatusChip(
                                  key: Key('edge_reporting_${e.id}'),
                                  label: e.reporting ? l.yes : l.no,
                                  color: e.reporting ? context.verdicts.allow : scheme.error,
                                ),
                              ),
                            ],
                          ),
                      ],
                    ),
                ],
              ),
              const SizedBox(height: 16),
              SectionCard(
                key: const Key('status_certificates_card'),
                title: 'Certificates',
                subtitle: 'Days until certificate expiration',
                children: [
                  if (st.certificates.isEmpty)
                    EmptyState(text: l.emptyNothingHere, icon: Icons.badge_outlined)
                  else
                    ScrollTable(
                      columns: const [
                        DataColumn(label: Text('Name')),
                        DataColumn(label: Text('Expires')),
                        DataColumn(label: Text('Days until expiry')),
                      ],
                      rows: [
                        for (final cert in st.certificates)
                          () {
                            final days = cert.notAfter == null ? 0 : cert.notAfter!.difference(now).inDays;
                            final warning = days < 14;
                            final color = warning
                                ? (days < 0 ? scheme.error : context.verdicts.ask)
                                : context.verdicts.allow;
                            final label = days < 0 ? 'Expired' : (days == 1 ? '1 day' : '$days days');
                            return DataRow(
                              key: ValueKey('cert_row_${cert.name}'),
                              cells: [
                                DataCell(Text(cert.name, style: const TextStyle(fontWeight: FontWeight.w500))),
                                DataCell(Text(formatTime(context, cert.notAfter))),
                                DataCell(StatusChip(key: Key('cert_chip_${cert.name}'), label: label, color: color)),
                              ],
                            );
                          }(),
                      ],
                    ),
                ],
              ),
              const SizedBox(height: 16),
            ],
          );
        },
      ),
    );
  }
}

class _StatTile extends StatelessWidget {
  const _StatTile({
    super.key,
    required this.icon,
    required this.label,
    required this.value,
    this.detail,
    this.trailing,
  });

  final IconData icon;
  final String label;
  final String value;
  final String? detail;
  final Widget? trailing;

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
                  const SizedBox(height: 4),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.baseline,
                    textBaseline: TextBaseline.alphabetic,
                    children: [
                      Flexible(
                        child: Text(
                          value,
                          style: tt.headlineSmall?.copyWith(fontWeight: FontWeight.w600),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      if (detail != null) ...[
                        const SizedBox(width: 8),
                        Flexible(
                          child: Text(
                            detail!,
                            style: tt.bodySmall?.copyWith(color: scheme.onSurfaceVariant),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ],
                  ),
                ],
              ),
            ),
            if (trailing != null) ...[const SizedBox(width: 8), trailing!],
          ],
        ),
      ),
    );
  }
}
