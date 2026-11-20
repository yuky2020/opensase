import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import 'app_detail_screen.dart';
import 'common.dart';
import 'screen_state.dart';

class ActivityScreen extends ConsumerWidget {
  const ActivityScreen({super.key, required this.onOpenApp});
  final void Function(String pkg) onOpenApp;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.l10n;
    final c = ref.watch(activityProvider);
    final view = ref.watch(activityViewProvider);
    final n = ref.read(activityProvider.notifier);
    return Column(
      children: [
        Row(
          children: [
            Expanded(
              child: SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.fromLTRB(16, 8, 8, 4),
                child: Row(
                  children: [
                    for (final (v, label) in [
                      (VerdictFilter.all, l.activityFilterAll),
                      (VerdictFilter.allowed, l.activityFilterAllowed),
                      (VerdictFilter.blocked, l.activityFilterBlocked),
                    ])
                      Padding(
                        padding: const EdgeInsets.only(right: 8),
                        child: ChoiceChip(
                          label: Text(label),
                          selected: c.verdict == v,
                          onSelected: (_) => n.setVerdict(v),
                        ),
                      ),
                    PopupMenuButton<String?>(
                      tooltip: l.activityFilterApp,
                      initialValue: c.app,
                      onSelected: (p) => n.setApp(p == '' ? null : p),
                      itemBuilder: (context) => [
                        PopupMenuItem(value: '', child: Text(l.activityAllApps)),
                        for (final a in view.apps) PopupMenuItem(value: a, child: Text(appLabel(ref, context, a))),
                      ],
                      child: Chip(
                        avatar: const Icon(Icons.filter_list, size: 18),
                        label: Text(c.app == null ? l.activityFilterApp : appLabel(ref, context, c.app!)),
                      ),
                    ),
                  ],
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.only(right: 8, top: 4),
              child: IconButton.filledTonal(
                key: const Key('activity_pause'),
                tooltip: c.paused ? l.activityResume : l.activityPause,
                onPressed: () => n.setPaused(!c.paused),
                icon: Icon(c.paused ? Icons.play_arrow : Icons.pause),
              ),
            ),
          ],
        ),
        if (c.paused)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 0),
            child: InfoBanner(l.activityPaused, icon: Icons.pause_circle),
          ),
        Expanded(
          child: view.records.isEmpty
              ? EmptyState(l.activityEmpty)
              : ListView.separated(
                  itemCount: view.records.length,
                  separatorBuilder: (_, _) => const Divider(height: 1, indent: 72),
                  itemBuilder: (_, i) => FlowTile(record: view.records[i], onOpenApp: onOpenApp),
                ),
        ),
      ],
    );
  }
}
