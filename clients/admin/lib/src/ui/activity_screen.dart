import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_models.dart';
import '../api/policy_models.dart';
import '../data/flow_stats.dart';
import '../data/providers.dart';
import 'common.dart';

/// Refresh period of the Activity screen; null disables the timer (tests).
final activityRefreshProvider = Provider<Duration?>((ref) => const Duration(seconds: 10));

class ActivityScreen extends ConsumerWidget {
  const ActivityScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) => TenantScoped(
    builder: (t) => _ActivityView(key: ValueKey('activity-$t'), tenant: t),
  );
}

class _ActivityView extends ConsumerStatefulWidget {
  const _ActivityView({super.key, required this.tenant});

  final String tenant;

  @override
  ConsumerState<_ActivityView> createState() => _ActivityViewState();
}

class _ActivityViewState extends ConsumerState<_ActivityView> {
  FlowFilter _f = const FlowFilter();
  bool _auto = true;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _schedule();
  }

  void _schedule() {
    _timer?.cancel();
    final period = ref.read(activityRefreshProvider);
    if (_auto && period != null) {
      _timer = Timer.periodic(period, (_) => ref.invalidate(flowsProvider(widget.tenant)));
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Widget _dropdown(String label, String value, List<String> options, ValueChanged<String> onChanged, {Key? key}) {
    final l = context.l10n;
    final opts = ['', ...options, if (value.isNotEmpty && !options.contains(value)) value];
    return SizedBox(
      width: 180,
      child: DropdownButtonFormField<String>(
        key: key,
        initialValue: value,
        isExpanded: true,
        decoration: InputDecoration(labelText: label, border: const OutlineInputBorder(), isDense: true),
        items: [for (final o in opts) DropdownMenuItem(value: o, child: Text(o.isEmpty ? l.flowsAny : o))],
        onChanged: (v) => onChanged(v ?? ''),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final flows = ref.watch(flowsProvider(widget.tenant));
    final all = flows.value ?? const <FlowRecord>[];
    final devices = {for (final r in all) r.deviceId}.where((d) => d.isNotEmpty).toList()..sort();
    return PageFrame(
      title: l.navActivity,
      actions: [
        FilterChip(
          key: const Key('auto_refresh'),
          label: Text(l.flowsAutoRefresh),
          selected: _auto,
          onSelected: (v) {
            setState(() => _auto = v);
            _schedule();
          },
        ),
        IconButton(
          tooltip: l.actionRefresh,
          onPressed: () => ref.invalidate(flowsProvider(widget.tenant)),
          icon: const Icon(Icons.refresh),
        ),
      ],
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _dropdown(l.flowsVerdict, _f.verdict, const [
                Verdicts.allow,
                Verdicts.block,
              ], (v) => setState(() => _f = _f.copyWith(verdict: v))),
              _dropdown(l.flowsLayer, _f.layer, Layers.all, (v) => setState(() => _f = _f.copyWith(layer: v))),
              _dropdown(l.flowsWhere, _f.where, const [
                'device',
                'edge',
                'cloud',
              ], (v) => setState(() => _f = _f.copyWith(where: v))),
              _dropdown(l.flowsDevice, _f.device, devices, (v) => setState(() => _f = _f.copyWith(device: v))),
              SizedBox(
                width: 320,
                child: TextField(
                  key: const Key('flows_search'),
                  decoration: InputDecoration(
                    labelText: l.flowsSearch,
                    prefixIcon: const Icon(Icons.search),
                    border: const OutlineInputBorder(),
                    isDense: true,
                  ),
                  onChanged: (s) => setState(() => _f = _f.copyWith(text: s.trim())),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Expanded(
            child: AsyncBody(
              value: flows,
              onRetry: () => ref.invalidate(flowsProvider(widget.tenant)),
              builder: (list) {
                final shown = filterFlows(list, _f);
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(l.flowsShown(shown.length, list.length), style: Theme.of(context).textTheme.bodySmall),
                    Expanded(
                      child: shown.isEmpty
                          ? EmptyState(text: l.emptyNothingHere, icon: Icons.list_alt)
                          : ScrollTable(
                              columns: [
                                DataColumn(label: Text(l.flowsTime)),
                                DataColumn(label: Text(l.flowsVerdict)),
                                DataColumn(label: Text(l.flowsLayer)),
                                DataColumn(label: Text(l.flowsRule)),
                                DataColumn(label: Text(l.flowsDestination)),
                                DataColumn(label: Text(l.flowsApp)),
                                DataColumn(label: Text(l.flowsWhere)),
                                DataColumn(label: Text(l.flowsDevice)),
                                DataColumn(label: Text(l.flowsBytes), numeric: true),
                              ],
                              rows: [for (final r in shown.take(flowLimit)) _row(context, r)],
                            ),
                    ),
                  ],
                );
              },
            ),
          ),
        ],
      ),
    );
  }

  DataRow _row(BuildContext context, FlowRecord r) {
    final f = r.flow;
    final dst = [
      if (f.domain.isNotEmpty) f.domain,
      '${f.dstIp.contains(':') ? '[${f.dstIp}]' : f.dstIp}:${f.dstPort}',
    ].join(' ');
    return DataRow(
      cells: [
        DataCell(Text(formatTime(context, r.start))),
        DataCell(
          StatusChip(label: actionLabel(context, r.decision.action), color: verdictColor(context, r.decision.action)),
        ),
        DataCell(Text(r.decision.layer)),
        DataCell(Text(r.decision.ruleId)),
        DataCell(Text('${f.protocol.toUpperCase()} $dst')),
        DataCell(Text(f.app)),
        DataCell(Text(r.where)),
        DataCell(Text(r.deviceId)),
        DataCell(Text('${r.bytesOut}/${r.bytesIn}')),
      ],
    );
  }
}
