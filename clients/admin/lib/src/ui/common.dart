import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import 'package:material_ui/material_ui.dart';

import '../api/admin_api.dart';
import '../data/providers.dart';
import '../data/session.dart';
import '../l10n/app_localizations.dart';
import 'theme.dart';

extension L10nX on BuildContext {
  AppLocalizations get l10n => AppLocalizations.of(this);
}

String formatTime(BuildContext context, DateTime? t) {
  if (t == null) return context.l10n.never;
  return DateFormat.yMd(Localizations.localeOf(context).toLanguageTag()).add_Hms().format(t.toLocal());
}

String errorText(Object e) => e is ApiException ? e.toString() : '$e';

void showSnack(BuildContext context, String msg) {
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(msg)));
}

/// Runs an admin action, shows errors as a snackbar, and signs out on 401/403.
Future<T?> runAction<T>(BuildContext context, WidgetRef ref, Future<T> Function() f) async {
  try {
    return await f();
  } on ApiException catch (e) {
    if (!context.mounted) return null;
    if (e.status == 401) {
      showSnack(context, context.l10n.msgSessionExpired);
      ref.read(sessionProvider.notifier).logout();
    } else {
      showSnack(context, context.l10n.msgError(e.toString()));
    }
  } on Object catch (e) {
    if (context.mounted) showSnack(context, context.l10n.msgError('$e'));
  }
  return null;
}

/// Shows loading, error (with retry) or data of an [AsyncValue].
class AsyncBody<T> extends ConsumerWidget {
  const AsyncBody({super.key, required this.value, required this.onRetry, required this.builder});

  final AsyncValue<T> value;
  final VoidCallback onRetry;
  final Widget Function(T data) builder;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return value.when(
      data: builder,
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (e, _) {
        if (e is ApiException && e.status == 401) {
          WidgetsBinding.instance.addPostFrameCallback((_) => ref.read(sessionProvider.notifier).logout());
        }
        return Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.error_outline, color: Theme.of(context).colorScheme.error, size: 40),
                const SizedBox(height: 12),
                SelectableText(context.l10n.msgError(errorText(e)), textAlign: TextAlign.center),
                const SizedBox(height: 12),
                FilledButton.tonalIcon(
                  onPressed: onRetry,
                  icon: const Icon(Icons.refresh),
                  label: Text(context.l10n.actionRefresh),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}

/// Wraps a per-tenant screen: shows a hint when no tenant exists or is selected.
class TenantScoped extends ConsumerWidget {
  const TenantScoped({super.key, required this.builder});

  final Widget Function(String tenant) builder;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = ref.watch(currentTenantProvider);
    if (t == null) {
      final tenants = ref.watch(tenantsProvider);
      if (tenants.isLoading) return const Center(child: CircularProgressIndicator());
      return EmptyState(text: context.l10n.emptyNoTenant, icon: Icons.domain_add);
    }
    return builder(t);
  }
}

class EmptyState extends StatelessWidget {
  const EmptyState({super.key, required this.text, this.icon = Icons.inbox_outlined});

  final String text;
  final IconData icon;

  @override
  Widget build(BuildContext context) => Center(
    child: Padding(
      padding: const EdgeInsets.all(32),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 48, color: Theme.of(context).colorScheme.outline),
          const SizedBox(height: 12),
          Text(text, textAlign: TextAlign.center),
        ],
      ),
    ),
  );
}

/// Page scaffold for list screens: a title row with actions, then the content.
class PageFrame extends StatelessWidget {
  const PageFrame({super.key, required this.title, this.actions = const [], required this.child, this.subtitle});

  final String title;
  final String? subtitle;
  final List<Widget> actions;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            alignment: WrapAlignment.spaceBetween,
            crossAxisAlignment: WrapCrossAlignment.center,
            spacing: 8,
            runSpacing: 8,
            children: [
              Text(title, style: tt.headlineSmall),
              Wrap(spacing: 8, runSpacing: 8, children: actions),
            ],
          ),
          if (subtitle != null) ...[
            const SizedBox(height: 4),
            Text(subtitle!, style: tt.bodyMedium?.copyWith(color: Theme.of(context).colorScheme.onSurfaceVariant)),
          ],
          const SizedBox(height: 12),
          Expanded(child: child),
        ],
      ),
    );
  }
}

/// A horizontally and vertically scrollable DataTable.
class ScrollTable extends StatelessWidget {
  const ScrollTable({super.key, required this.columns, required this.rows});

  final List<DataColumn> columns;
  final List<DataRow> rows;

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, c) => SingleChildScrollView(
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: ConstrainedBox(
          constraints: BoxConstraints(minWidth: c.maxWidth),
          child: DataTable(columns: columns, rows: rows, headingRowHeight: 44),
        ),
      ),
    ),
  );
}

class StatusChip extends StatelessWidget {
  const StatusChip({super.key, required this.label, required this.color});

  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
    decoration: BoxDecoration(
      color: color.withValues(alpha: 0.15),
      borderRadius: BorderRadius.circular(8),
      border: Border.all(color: color.withValues(alpha: 0.6)),
    ),
    child: Text(
      label,
      style: TextStyle(color: color, fontWeight: FontWeight.w600, fontSize: 12),
    ),
  );
}

Widget revokedChip(BuildContext context, bool revoked) => revoked
    ? StatusChip(label: context.l10n.statusRevoked, color: context.verdicts.block)
    : StatusChip(label: context.l10n.statusActive, color: context.verdicts.allow);

Color verdictColor(BuildContext context, String action) => switch (action) {
  'allow' => context.verdicts.allow,
  'block' => context.verdicts.block,
  _ => context.verdicts.ask,
};

String actionLabel(BuildContext context, String a) => switch (a) {
  'allow' => context.l10n.actionAllow,
  'block' => context.l10n.actionBlock,
  'ask' => context.l10n.actionAsk,
  '' => context.l10n.actionUnset,
  _ => a,
};

String networkLabel(BuildContext context, String n) => switch (n) {
  'wifi' => context.l10n.networkWifi,
  'cellular' => context.l10n.networkCellular,
  'roaming' => context.l10n.networkRoaming,
  'ethernet' => context.l10n.networkEthernet,
  'unknown' => context.l10n.networkUnknown,
  _ => n,
};

/// Asks for confirmation of a destructive action.
Future<bool> confirmRevoke(BuildContext context, {required String name, required String body}) async {
  final l = context.l10n;
  final ok = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(l.revokeConfirmTitle(name)),
      content: Text(body),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx, false), child: Text(l.actionCancel)),
        FilledButton(
          key: const Key('confirm_revoke'),
          style: FilledButton.styleFrom(
            backgroundColor: Theme.of(ctx).colorScheme.error,
            foregroundColor: Theme.of(ctx).colorScheme.onError,
          ),
          onPressed: () => Navigator.pop(ctx, true),
          child: Text(l.actionRevoke),
        ),
      ],
    ),
  );
  return ok ?? false;
}

/// A secret shown once, selectable, with a copy button.
class OneTimeSecret extends StatelessWidget {
  const OneTimeSecret({super.key, required this.secret});

  final String secret;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.fromLTRB(12, 4, 4, 4),
      decoration: BoxDecoration(color: scheme.surfaceContainerHighest, borderRadius: BorderRadius.circular(8)),
      child: Row(
        children: [
          Expanded(
            child: SelectableText(secret, style: const TextStyle(fontFamily: 'monospace')),
          ),
          IconButton(
            tooltip: context.l10n.actionCopy,
            icon: const Icon(Icons.copy),
            onPressed: () async {
              await Clipboard.setData(ClipboardData(text: secret));
              if (context.mounted) showSnack(context, context.l10n.msgCopied);
            },
          ),
        ],
      ),
    );
  }
}

/// A multi-line text field holding a list of strings, one per line. It follows external
/// changes of [value] (for example from the JSON tab) without fighting the cursor.
class LinesField extends StatefulWidget {
  const LinesField({
    super.key,
    required this.label,
    required this.value,
    required this.onChanged,
    this.helper,
    this.enabled = true,
    this.minLines = 3,
  });

  final String label;
  final String? helper;
  final List<String> value;
  final ValueChanged<List<String>> onChanged;
  final bool enabled;
  final int minLines;

  @override
  State<LinesField> createState() => _LinesFieldState();
}

class _LinesFieldState extends State<LinesField> {
  late final TextEditingController _c = TextEditingController(text: widget.value.join('\n'));

  List<String> _parse(String s) => [
    for (final l in s.split('\n'))
      if (l.trim().isNotEmpty) l.trim(),
  ];

  @override
  void didUpdateWidget(LinesField old) {
    super.didUpdateWidget(old);
    if (!_listEq(_parse(_c.text), widget.value)) _c.text = widget.value.join('\n');
  }

  static bool _listEq(List<String> a, List<String> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => TextField(
    controller: _c,
    enabled: widget.enabled,
    minLines: widget.minLines,
    maxLines: 12,
    decoration: InputDecoration(
      labelText: widget.label,
      helperText: widget.helper,
      helperMaxLines: 2,
      border: const OutlineInputBorder(),
      alignLabelWithHint: true,
    ),
    onChanged: (s) => widget.onChanged(_parse(s)),
  );
}

/// Section card with a title and optional trailing action.
class SectionCard extends StatelessWidget {
  const SectionCard({super.key, required this.title, this.subtitle, this.trailing, required this.children});

  final String title;
  final String? subtitle;
  final Widget? trailing;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Expanded(child: Text(title, style: tt.titleMedium)),
                ?trailing,
              ],
            ),
            if (subtitle != null)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text(
                  subtitle!,
                  style: tt.bodySmall?.copyWith(color: Theme.of(context).colorScheme.onSurfaceVariant),
                ),
              ),
            const SizedBox(height: 12),
            ...children,
          ],
        ),
      ),
    );
  }
}
