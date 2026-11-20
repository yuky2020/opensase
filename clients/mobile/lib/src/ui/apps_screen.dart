import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

import '../contracts/policy.dart';
import '../data/core_state.dart';
import '../data/policy_logic.dart';
import 'common.dart';
import 'screen_state.dart';

class AppsScreen extends ConsumerStatefulWidget {
  const AppsScreen({super.key, required this.onOpen});
  final void Function(String pkg) onOpen;

  @override
  ConsumerState<AppsScreen> createState() => _AppsScreenState();
}

class _AppsScreenState extends ConsumerState<AppsScreen> {
  late final _search = TextEditingController(text: ref.read(appsFilterProvider).query);

  /// "pkg/network" toggles being saved.
  final Set<String> _saving = {};

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  Future<void> _toggle(String pkg, NetworkType net, bool allowed) async {
    final key = '$pkg/${net.wire}';
    setState(() => _saving.add(key));
    final r = await ref
        .read(coreProvider.notifier)
        .updateUserLayer((u) => PolicyLogic.setAppNetwork(u, pkg, net, allowed));
    if (!mounted) return;
    setState(() => _saving.remove(key));
    showSaveResult(context, r, quietOk: true);
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final f = ref.watch(appsFilterProvider);
    final rows = ref.watch(appRowsProvider);
    final editable = ref.watch(coreProvider.select((s) => s.policy.userLayerEditable));
    final n = ref.read(appsFilterProvider.notifier);
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
          child: TextField(
            key: const Key('apps_search'),
            controller: _search,
            onChanged: n.setQuery,
            decoration: InputDecoration(
              hintText: l.appsSearchHint,
              prefixIcon: const Icon(Icons.search),
              suffixIcon: f.query.isEmpty
                  ? null
                  : IconButton(
                      icon: const Icon(Icons.clear),
                      tooltip: l.actionClear,
                      onPressed: () {
                        _search.clear();
                        n.setQuery('');
                      },
                    ),
              border: const OutlineInputBorder(),
              isDense: true,
            ),
          ),
        ),
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Row(
            children: [
              for (final (k, label) in [
                (AppKind.all, l.appsFilterAll),
                (AppKind.user, l.appsFilterUser),
                (AppKind.system, l.appsFilterSystem),
              ])
                Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: ChoiceChip(label: Text(label), selected: f.kind == k, onSelected: (_) => n.setKind(k)),
                ),
              FilterChip(
                key: const Key('filter_internet'),
                label: Text(l.appsFilterInternet),
                selected: f.internetOnly,
                onSelected: n.setInternetOnly,
              ),
            ],
          ),
        ),
        if (!editable)
          Padding(padding: const EdgeInsets.fromLTRB(16, 8, 16, 0), child: InfoBanner(l.appsUserRulesDisabled)),
        Expanded(
          child: rows.when(
            loading: () => Column(children: [const LinearProgressIndicator(), EmptyState(l.appsLoading)]),
            error: (e, _) => EmptyState(l.msgError('$e')),
            data: (list) => list.isEmpty
                ? EmptyState(l.appsEmpty)
                : ListView.separated(
                    key: const Key('apps_list'),
                    itemCount: list.length,
                    separatorBuilder: (_, _) => const Divider(height: 1, indent: 72),
                    itemBuilder: (context, i) =>
                        AppRowTile(row: list[i], saving: _saving, onToggle: _toggle, onOpen: widget.onOpen),
                  ),
          ),
        ),
      ],
    );
  }
}

class AppRowTile extends StatelessWidget {
  const AppRowTile({super.key, required this.row, required this.saving, required this.onToggle, required this.onOpen});

  final AppRow row;
  final Set<String> saving;
  final void Function(String pkg, NetworkType net, bool allowed) onToggle;
  final void Function(String pkg) onOpen;

  @override
  Widget build(BuildContext context) {
    final pkg = row.app.packageName;
    final t = Theme.of(context);
    return InkWell(
      key: Key('app_row_$pkg'),
      onTap: () => onOpen(pkg),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 8, 8, 8),
        child: Row(
          children: [
            AppIcon(pkg),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(row.app.label, style: t.textTheme.bodyLarge, maxLines: 1, overflow: TextOverflow.ellipsis),
                  Row(
                    children: [
                      if (row.anyLocked) ...[
                        Icon(Icons.lock, key: Key('lock_$pkg'), size: 14, color: t.colorScheme.onSurfaceVariant),
                        const SizedBox(width: 4),
                      ],
                      Expanded(
                        child: Text(
                          pkg,
                          style: t.textTheme.bodySmall?.copyWith(color: t.colorScheme.onSurfaceVariant),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            for (final v in row.verdicts)
              NetworkToggle(
                pkg: pkg,
                verdict: v,
                saving: saving.contains('$pkg/${v.network.wire}'),
                onToggle: onToggle,
              ),
          ],
        ),
      ),
    );
  }
}

/// One per-network toggle: green network icon = allowed, red crossed icon = blocked.
/// Locked (tenant-mandated) toggles are disabled.
class NetworkToggle extends StatelessWidget {
  const NetworkToggle({
    super.key,
    required this.pkg,
    required this.verdict,
    required this.saving,
    required this.onToggle,
  });

  final String pkg;
  final NetworkVerdict verdict;
  final bool saving;
  final void Function(String pkg, NetworkType net, bool allowed) onToggle;

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final allowed = verdict.allowed;
    final color = verdictColor(context, allowed ? Verdict.allow : Verdict.block);
    final tip =
        '${networkLabel(context, verdict.network)}: ${allowed ? l.verdictAllow : l.verdictBlock}'
        '${verdict.locked ? ' · ${l.companyPolicyLocked}' : ''}';
    return IconButton(
      key: Key('toggle_${pkg}_${verdict.network.wire}'),
      tooltip: tip,
      isSelected: allowed,
      onPressed: verdict.locked || saving ? null : () => onToggle(pkg, verdict.network, !allowed),
      icon: Icon(
        networkIcon(verdict.network, blocked: !allowed),
        color: verdict.locked ? color.withValues(alpha: 0.45) : color,
      ),
    );
  }
}
