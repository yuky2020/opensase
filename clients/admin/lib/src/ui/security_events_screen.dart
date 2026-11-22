import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../data/providers.dart';
import '../data/security_events.dart';
import '../l10n/app_localizations.dart';
import 'common.dart';
import 'theme.dart';

/// Security events (issue #26): DLP, malware, URL rule, category, SafeSearch, SaaS and
/// inspection blocks of the tenant, from its flow records.
class SecurityEventsScreen extends ConsumerStatefulWidget {
  const SecurityEventsScreen({super.key});

  @override
  ConsumerState<SecurityEventsScreen> createState() => _SecurityEventsScreenState();
}

String securityKindLabel(AppLocalizations l, SecurityKind k) => switch (k) {
  SecurityKind.dlp => l.secKindDlp,
  SecurityKind.malware => l.secKindMalware,
  SecurityKind.url => l.secKindUrl,
  SecurityKind.category => l.secKindCategory,
  SecurityKind.safeSearch => l.secKindSafeSearch,
  SecurityKind.saas => l.secKindSaas,
  SecurityKind.inspection => l.secKindInspection,
};

class _SecurityEventsScreenState extends ConsumerState<SecurityEventsScreen> {
  SecurityKind? _kind;

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return TenantScoped(
      builder: (tenant) => PageFrame(
        title: l.navSecurityEvents,
        subtitle: l.secEventsHelp,
        actions: [
          IconButton(
            tooltip: l.actionRefresh,
            onPressed: () => ref.invalidate(flowsProvider(tenant)),
            icon: const Icon(Icons.refresh),
          ),
        ],
        child: AsyncBody(
          value: ref.watch(flowsProvider(tenant)),
          onRetry: () => ref.invalidate(flowsProvider(tenant)),
          builder: (records) {
            final ev = SecurityEvents(records);
            final shown = [
              for (final e in ev.events)
                if (_kind == null || e.kind == _kind) e,
            ];
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    ChoiceChip(
                      key: const Key('sec_all'),
                      label: Text(l.secAll(ev.events.length)),
                      selected: _kind == null,
                      onSelected: (_) => setState(() => _kind = null),
                    ),
                    for (final k in SecurityKind.values)
                      if ((ev.counts[k] ?? 0) > 0)
                        ChoiceChip(
                          key: Key('sec_${k.name}'),
                          label: Text('${securityKindLabel(l, k)} · ${ev.counts[k]}'),
                          selected: _kind == k,
                          onSelected: (_) => setState(() => _kind = _kind == k ? null : k),
                        ),
                  ],
                ),
                const SizedBox(height: 12),
                Expanded(
                  child: shown.isEmpty
                      ? EmptyState(text: l.secEmpty, icon: Icons.shield_outlined)
                      : ScrollTable(
                          columns: [
                            DataColumn(label: Text(l.fieldTime)),
                            DataColumn(label: Text(l.secFieldKind)),
                            DataColumn(label: Text(l.secFieldRule)),
                            DataColumn(label: Text(l.secFieldHost)),
                            DataColumn(label: Text(l.secFieldDevice)),
                            DataColumn(label: Text(l.fieldResult)),
                          ],
                          rows: [
                            for (final e in shown)
                              DataRow(
                                cells: [
                                  DataCell(Text(formatTime(context, e.record.start))),
                                  DataCell(Text(securityKindLabel(l, e.kind))),
                                  DataCell(
                                    SelectableText(
                                      e.record.decision.ruleId,
                                      style: const TextStyle(fontFamily: 'monospace'),
                                    ),
                                  ),
                                  DataCell(
                                    Text(e.record.flow.domain.isEmpty ? e.record.flow.dstIp : e.record.flow.domain),
                                  ),
                                  DataCell(
                                    Text(
                                      e.record.deviceId.length > 8
                                          ? e.record.deviceId.substring(0, 8)
                                          : e.record.deviceId,
                                    ),
                                  ),
                                  DataCell(
                                    e.record.decision.action == 'block'
                                        ? StatusChip(label: l.statusBlocked, color: context.verdicts.block)
                                        : StatusChip(label: l.secLogged, color: Theme.of(context).colorScheme.outline),
                                  ),
                                ],
                              ),
                          ],
                        ),
                ),
              ],
            );
          },
        ),
      ),
    );
  }
}
