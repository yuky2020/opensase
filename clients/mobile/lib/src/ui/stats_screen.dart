import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import 'common.dart';
import 'screen_state.dart';
import 'theme.dart';

class StatsScreen extends ConsumerWidget {
  const StatsScreen({super.key, required this.onOpenApp});
  final void Function(String pkg) onOpenApp;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    final rows = ref.watch(sortedStatsProvider);
    final sort = ref.watch(statsSortProvider);
    final totalIn = rows.fold<int>(0, (a, s) => a + s.bytesIn);
    final totalOut = rows.fold<int>(0, (a, s) => a + s.bytesOut);
    final maxTotal = rows.fold<int>(1, (m, s) => (s.bytesIn + s.bytesOut) > m ? s.bytesIn + s.bytesOut : m);
    final t = Theme.of(context);
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Card(
            child: ListTile(
              leading: const Icon(Icons.swap_vert),
              title: Text(l.statsTotal(Fmt.bytes(totalIn), Fmt.bytes(totalOut)), style: t.textTheme.titleMedium),
            ),
          ),
        ),
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Row(
            children: [
              Text(l.statsSort, style: t.textTheme.labelLarge),
              const SizedBox(width: 8),
              for (final (s, label) in [
                (StatsSort.total, l.statsSortTotal),
                (StatsSort.bytesIn, l.statsSortIn),
                (StatsSort.bytesOut, l.statsSortOut),
                (StatsSort.allowed, l.statsSortAllowed),
                (StatsSort.blocked, l.statsSortBlocked),
              ])
                Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: ChoiceChip(
                    label: Text(label),
                    selected: sort == s,
                    onSelected: (_) => ref.read(statsSortProvider.notifier).set(s),
                  ),
                ),
            ],
          ),
        ),
        Expanded(
          child: rows.isEmpty
              ? EmptyState(l.statsEmpty)
              : ListView.separated(
                  itemCount: rows.length,
                  separatorBuilder: (_, _) => const Divider(height: 1, indent: 72),
                  itemBuilder: (context, i) {
                    final s = rows[i];
                    return ListTile(
                      leading: AppIcon(s.app),
                      onTap: s.app.isEmpty ? null : () => onOpenApp(s.app),
                      title: Text(appLabel(ref, context, s.app), maxLines: 1, overflow: TextOverflow.ellipsis),
                      subtitle: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const SizedBox(height: 4),
                          LinearProgressIndicator(value: ((s.bytesIn + s.bytesOut) / maxTotal).clamp(0.0, 1.0)),
                          const SizedBox(height: 4),
                          Text('↓ ${Fmt.bytes(s.bytesIn)}   ↑ ${Fmt.bytes(s.bytesOut)}'),
                        ],
                      ),
                      trailing: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        crossAxisAlignment: CrossAxisAlignment.end,
                        children: [
                          Text('${s.allowed}', style: t.textTheme.labelLarge?.copyWith(color: context.verdicts.allow)),
                          Text('${s.blocked}', style: t.textTheme.labelLarge?.copyWith(color: context.verdicts.block)),
                        ],
                      ),
                    );
                  },
                ),
        ),
      ],
    );
  }
}
