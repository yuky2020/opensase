import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_models.dart';
import '../data/providers.dart';
import '../l10n/app_localizations.dart';
import 'common.dart';
import 'theme.dart';

/// Selectable time window for digital experience metrics.
enum ExperiencePeriod {
  hour1(Duration(hours: 1)),
  hours24(Duration(hours: 24)),
  days7(Duration(days: 7)),
  days30(Duration(days: 30));

  const ExperiencePeriod(this.duration);
  final Duration duration;

  String label(AppLocalizations l) => switch (this) {
    ExperiencePeriod.hour1 => l.experiencePeriodHour1,
    ExperiencePeriod.hours24 => l.experiencePeriodHours24,
    ExperiencePeriod.days7 => l.experiencePeriodDays7,
    ExperiencePeriod.days30 => l.experiencePeriodDays30,
  };
}

/// Digital experience telemetry page (issue #76).
class ExperienceScreen extends ConsumerWidget {
  const ExperienceScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) => TenantScoped(
    builder: (tenant) => _ExperienceView(key: ValueKey('experience-$tenant'), tenant: tenant),
  );
}

class _ExperienceView extends ConsumerStatefulWidget {
  const _ExperienceView({super.key, required this.tenant});

  final String tenant;

  @override
  ConsumerState<_ExperienceView> createState() => _ExperienceViewState();
}

class _ExperienceViewState extends ConsumerState<_ExperienceView> {
  ExperiencePeriod _period = ExperiencePeriod.hours24;
  String _filter = '';
  final _filterController = TextEditingController();
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _schedule();
  }

  void _schedule() {
    _timer?.cancel();
    final period = ref.read(experienceRefreshPeriodProvider);
    if (period != null) {
      _timer = Timer.periodic(period, (_) {
        if (mounted) _refresh();
      });
    }
  }

  void _refresh() {
    ref.invalidate(experienceProvider);
    ref.invalidate(devicesProvider(widget.tenant));
  }

  @override
  void dispose() {
    _timer?.cancel();
    _filterController.dispose();
    super.dispose();
  }

  static String _formatMs(double ms) => ms % 1 == 0 ? '${ms.toInt()}' : ms.toStringAsFixed(1);

  static String _formatPct(double pct) => pct % 1 == 0 ? '${pct.toInt()}' : pct.toStringAsFixed(1);

  static double _computeMedian(List<double> values) {
    if (values.isEmpty) return 0.0;
    final sorted = List<double>.from(values)..sort();
    final mid = sorted.length ~/ 2;
    if (sorted.length % 2 == 1) {
      return sorted[mid];
    }
    return (sorted[mid - 1] + sorted[mid]) / 2.0;
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final now = ref.watch(clockProvider)();
    final since = now.subtract(_period.duration);
    final query = ExperienceQuery(tenant: widget.tenant, since: since);
    final expAsync = ref.watch(experienceProvider(query));
    final devAsync = ref.watch(devicesProvider(widget.tenant));

    return PageFrame(
      title: l.navExperience,
      subtitle: l.experienceSubtitle,
      actions: [
        IconButton(
          key: const ValueKey('experience_refresh'),
          tooltip: l.actionRefresh,
          icon: const Icon(Icons.refresh),
          onPressed: _refresh,
        ),
      ],
      child: AsyncBody(
        value: expAsync,
        onRetry: _refresh,
        builder: (allRows) {
          final devices = devAsync.value ?? const <AdminDevice>[];
          final deviceMap = <String, String>{for (final d in devices) d.id: d.name};

          String resolveDeviceName(String id) {
            final name = deviceMap[id];
            if (name != null && name.trim().isNotEmpty) {
              return name.trim();
            }
            return id;
          }

          final devicesMeasured = {for (final r in allRows) r.deviceId}.length;
          final medianRttText = allRows.isEmpty
              ? '-'
              : '${_formatMs(_computeMedian([for (final r in allRows) r.rttP50Ms]))} ms';
          final highLossRows = allRows.where((r) => r.lossPct > 2.0).length;

          final tiles = [
            _StatTile(
              key: const ValueKey('stat_devices_measured'),
              icon: Icons.phone_android,
              label: l.experienceStatDevicesMeasured,
              value: '$devicesMeasured',
            ),
            _StatTile(
              key: const ValueKey('stat_median_rtt'),
              icon: Icons.speed,
              label: l.experienceStatMedianRtt,
              value: medianRttText,
            ),
            _StatTile(
              key: const ValueKey('stat_high_loss_rows'),
              icon: Icons.warning_amber_rounded,
              label: l.experienceStatHighLossRows,
              value: '$highLossRows',
              trailing: highLossRows > 0 ? StatusChip(label: '$highLossRows', color: context.verdicts.ask) : null,
            ),
          ];

          final filterTrim = _filter.trim().toLowerCase();
          final filteredRows = [
            for (final r in allRows)
              if (filterTrim.isEmpty ||
                  resolveDeviceName(r.deviceId).toLowerCase().contains(filterTrim) ||
                  r.deviceId.toLowerCase().contains(filterTrim))
                r,
          ];

          return ListView(
            children: [
              LayoutBuilder(
                builder: (context, c) {
                  final cols = c.maxWidth >= 900 ? 3 : (c.maxWidth >= 600 ? 2 : 1);
                  final w = (c.maxWidth - (cols - 1) * 12) / cols;
                  return Wrap(
                    spacing: 12,
                    runSpacing: 12,
                    children: [for (final t in tiles) SizedBox(width: w, child: t)],
                  );
                },
              ),
              const SizedBox(height: 16),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  SizedBox(
                    width: 170,
                    child: DropdownButtonFormField<ExperiencePeriod>(
                      key: const ValueKey('experience_period'),
                      initialValue: _period,
                      isExpanded: true,
                      decoration: InputDecoration(
                        labelText: l.experiencePeriod,
                        border: const OutlineInputBorder(),
                        isDense: true,
                      ),
                      items: [
                        for (final p in ExperiencePeriod.values) DropdownMenuItem(value: p, child: Text(p.label(l))),
                      ],
                      onChanged: (p) {
                        if (p != null) setState(() => _period = p);
                      },
                    ),
                  ),
                  SizedBox(
                    width: 250,
                    child: TextField(
                      key: const ValueKey('device_filter'),
                      controller: _filterController,
                      decoration: InputDecoration(
                        labelText: l.experienceFilterDevice,
                        prefixIcon: const Icon(Icons.search),
                        border: const OutlineInputBorder(),
                        isDense: true,
                        suffixIcon: _filter.isNotEmpty
                            ? IconButton(
                                icon: const Icon(Icons.clear, size: 18),
                                onPressed: () {
                                  _filterController.clear();
                                  setState(() => _filter = '');
                                },
                              )
                            : null,
                      ),
                      onChanged: (v) => setState(() => _filter = v),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              SectionCard(
                key: const ValueKey('experience_table_card'),
                title: l.navExperience,
                subtitle: '${filteredRows.length} ${filteredRows.length == 1 ? "entry" : "entries"}',
                children: [
                  if (filteredRows.isEmpty)
                    EmptyState(text: l.experienceEmpty, icon: Icons.speed_outlined)
                  else
                    ScrollTable(
                      columns: [
                        DataColumn(label: Text(l.experienceColDevice)),
                        DataColumn(label: Text(l.experienceColEdge)),
                        DataColumn(label: Text(l.experienceColSamples), numeric: true),
                        DataColumn(label: Text(l.experienceColRttP50), numeric: true),
                        DataColumn(label: Text(l.experienceColRttP95), numeric: true),
                        DataColumn(label: Text(l.experienceColLoss), numeric: true),
                        DataColumn(label: Text(l.experienceColDnsP50), numeric: true),
                        DataColumn(label: Text(l.experienceColLast)),
                      ],
                      rows: [
                        for (final row in filteredRows)
                          () {
                            final Color? lossColor;
                            if (row.lossPct > 10.0) {
                              lossColor = context.verdicts.block;
                            } else if (row.lossPct > 2.0) {
                              lossColor = context.verdicts.ask;
                            } else {
                              lossColor = null;
                            }

                            final Color? rtt95Color = row.rttP95Ms > 150.0 ? context.verdicts.ask : null;

                            return DataRow(
                              key: ValueKey('exp_row_${row.deviceId}_${row.edgeId}'),
                              cells: [
                                DataCell(
                                  Text(
                                    resolveDeviceName(row.deviceId),
                                    key: ValueKey('device_name_${row.deviceId}_${row.edgeId}'),
                                    style: const TextStyle(fontWeight: FontWeight.w500),
                                  ),
                                ),
                                DataCell(Text(row.edgeId, key: ValueKey('edge_${row.deviceId}_${row.edgeId}'))),
                                DataCell(
                                  Text('${row.samples}', key: ValueKey('samples_${row.deviceId}_${row.edgeId}')),
                                ),
                                DataCell(
                                  Text(
                                    '${_formatMs(row.rttP50Ms)} ms',
                                    key: ValueKey('rtt50_${row.deviceId}_${row.edgeId}'),
                                  ),
                                ),
                                DataCell(
                                  Text(
                                    '${_formatMs(row.rttP95Ms)} ms',
                                    key: ValueKey('rtt95_${row.deviceId}_${row.edgeId}'),
                                    style: rtt95Color != null
                                        ? TextStyle(color: rtt95Color, fontWeight: FontWeight.w600)
                                        : null,
                                  ),
                                ),
                                DataCell(
                                  Text(
                                    '${_formatPct(row.lossPct)}%',
                                    key: ValueKey('loss_${row.deviceId}_${row.edgeId}'),
                                    style: lossColor != null
                                        ? TextStyle(color: lossColor, fontWeight: FontWeight.w600)
                                        : null,
                                  ),
                                ),
                                DataCell(
                                  Text(
                                    row.dnsP50Ms > 0 ? '${_formatMs(row.dnsP50Ms)} ms' : '0 ms',
                                    key: ValueKey('dns50_${row.deviceId}_${row.edgeId}'),
                                  ),
                                ),
                                DataCell(
                                  Text(
                                    formatTime(context, row.last),
                                    key: ValueKey('last_${row.deviceId}_${row.edgeId}'),
                                  ),
                                ),
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
  const _StatTile({super.key, required this.icon, required this.label, required this.value, this.trailing});

  final IconData icon;
  final String label;
  final String value;
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
